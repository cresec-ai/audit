/**
 * Broker unit tests.
 *
 * Three things these are shaped around, beyond the ordinary happy paths:
 *
 *  - NO NETWORK, EVER. `github-app`, `aws-sts`, `vault` and `clickup` are
 *    driven through the injected `http` seam with the providers' real
 *    response bodies. A test that reached the internet would fail in CI for
 *    reasons that have nothing to do with the code it claims to check.
 *  - EVERY FAILURE PATH ASSERTS THE ABSENCE OF A TOKEN, not just the presence
 *    of a code. Invariant 1 is "fail closed", and the way that invariant
 *    breaks in practice is a response that carries `real_token` next to a
 *    denial, so it is checked on every deny.
 *  - THE CANARY. One test brokers a known value and then walks every
 *    fingerprinting surface in the redactor asserting that neither the value
 *    nor any hash of it appears. That test IS invariant 3; the code in
 *    `redactor.ts` is merely its implementation.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Buffer } from 'node:buffer';
import { createHmac, generateKeyPairSync, verify as cryptoVerify } from 'node:crypto';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Stats } from 'node:fs';

import { sha256Ref } from '../src/chain/hash.js';
import {
  BROKERED_PLACEHOLDER,
  BROKERED_REF,
  MAX_BROKERED_SECRETS,
  Redactor,
  brokeredSecretCount,
  collectEnvCredentialFingerprints,
  containsBrokeredSecret,
  forgetBrokeredSecrets,
  isBrokeredSecret,
  registerBrokeredSecret,
  scrubArgv,
  scrubToolArguments,
} from '../src/redact/redactor.js';
import type { RedactedRef } from '../src/schema/events.js';

import {
  BROKER_DEFAULT_TTL_SECONDS,
  CredentialSourceError,
  LocalBroker,
  MAX_DECISION_CACHE,
  RemoteBroker,
  SOURCE_UNHEALTHY_MS,
  SYNTHETIC_PREFIX,
  FILE_MODE_CHECK_APPLIES,
  assessConfigTrust,
  credentialsConfigHash,
  hashSynthetic,
  isSyntheticShaped,
  makeSource,
  matchRules,
  mintSynthetic,
  sigv4Headers,
  sourceKinds,
  syntheticHashesEqual,
  validateCredentialEntry,
  xmlTag,
} from '../src/broker/index.js';
import type {
  BrokerDecisionRecord,
  BrokerExchangeRequest,
  CredentialEntry,
  CredentialSource,
  CredentialSourceSpec,
  HttpSeamRequest,
  SourceSeams,
} from '../src/broker/index.js';

/* ------------------------------ fixtures ------------------------------ */

const PEPPER = Buffer.from('a'.repeat(64), 'hex');
/** A high-entropy stand-in for a real upstream token. */
const REAL = 'ghs_CanaryCanaryCanaryCanary0123456789ABCD';

function seams(over: Partial<SourceSeams> = {}): SourceSeams {
  return {
    env: {},
    now: () => 1_700_000_000_000,
    readSecretFile: () => Promise.reject(new Error('no file seam in this test')),
    exec: () => Promise.reject(new Error('no exec seam in this test')),
    http: () => Promise.reject(new Error('no http seam in this test')),
    ...over,
  };
}

function entry(over: Partial<CredentialEntry> = {}): CredentialEntry {
  return {
    id: 'github-ci',
    label: 'github ci token (issues only)',
    provider: 'github',
    scopes: ['issues:write'],
    source: { type: 'env', var: 'GITHUB_TOKEN' },
    sites: [
      {
        server: ['github'],
        tool: ['create_issue'],
        arg: 'token',
        host_from: { kind: 'server' },
      },
    ],
    allow: [{ host: ['api.github.com'], path_template: ['create_issue'] }],
    ...over,
  };
}

interface Built {
  broker: LocalBroker;
  decisions: BrokerDecisionRecord[];
  warnings: string[];
  synthetic: string;
  clock: { ms: number };
}

function build(
  over: {
    entries?: CredentialEntry[];
    env?: NodeJS.ProcessEnv;
    seams?: Partial<SourceSeams>;
    makeSource?: (spec: CredentialSourceSpec, s: SourceSeams) => CredentialSource;
    trust?: ConstructorParameters<typeof LocalBroker>[0]['configTrust'];
    ttlSeconds?: number;
  } = {},
): Built {
  const synthetic = mintSynthetic();
  const hash = hashSynthetic(synthetic, PEPPER).toString('hex');
  const entries = (over.entries ?? [entry()]).map((e) => ({ ...e, synthetic_hash: hash }));
  const decisions: BrokerDecisionRecord[] = [];
  const warnings: string[] = [];
  const clock = { ms: 1_700_000_000_000 };
  const broker = new LocalBroker({
    credentials: entries,
    pepper: PEPPER,
    seams: seams({ env: over.env ?? { GITHUB_TOKEN: REAL }, now: () => clock.ms, ...over.seams }),
    ...(over.makeSource !== undefined ? { makeSource: over.makeSource } : {}),
    now: () => clock.ms,
    ...(over.ttlSeconds !== undefined ? { ttlSeconds: over.ttlSeconds } : {}),
    configTrust: over.trust ?? { configWritableByUs: false, policy_hash: 'policy-hash' },
    onDecision: (d) => decisions.push(d),
    warn: (line) => warnings.push(line),
  });
  return { broker, decisions, warnings, synthetic, clock };
}

function req(over: Partial<BrokerExchangeRequest['request']> = {}, synthetic = ''): BrokerExchangeRequest {
  return {
    synthetic,
    data_plane_instance_id: 'local',
    request: {
      method: 'tools/call',
      host: 'api.github.com',
      path_template: 'create_issue',
      ...over,
    },
  };
}

beforeEach(() => {
  forgetBrokeredSecrets();
});
afterEach(() => {
  forgetBrokeredSecrets();
});

/* ------------------------------ protocol ------------------------------ */

describe("protocol — NHI's synthetic format", () => {
  it('mints cresec_synth_v1_ + base64url(32 bytes), unique per call', () => {
    const a = mintSynthetic();
    const b = mintSynthetic();
    expect(a.startsWith(SYNTHETIC_PREFIX)).toBe(true);
    expect(a).not.toBe(b);
    // 32 bytes base64url is 43 characters, no padding.
    expect(a.slice(SYNTHETIC_PREFIX.length)).toHaveLength(43);
    expect(isSyntheticShaped(a)).toBe(true);
  });

  it('rejects anything that is not the NHI shape', () => {
    expect(isSyntheticShaped('ghp_realtokenlooking')).toBe(false);
    expect(isSyntheticShaped(SYNTHETIC_PREFIX)).toBe(false);
    expect(isSyntheticShaped(SYNTHETIC_PREFIX + 'short')).toBe(false);
    expect(isSyntheticShaped(SYNTHETIC_PREFIX + 'has spaces in it here')).toBe(false);
  });

  it('hashes exactly as NHI does: HMAC-SHA256(value, pepper)', () => {
    const v = mintSynthetic();
    const expected = createHmac('sha256', PEPPER).update(v).digest();
    expect(hashSynthetic(v, PEPPER).equals(expected)).toBe(true);
    // A different pepper gives a different hash — the pepper is load-bearing.
    expect(hashSynthetic(v, Buffer.alloc(32, 7)).equals(expected)).toBe(false);
  });

  it('compares hashes in constant time, and refuses mismatched lengths', () => {
    const a = hashSynthetic('x', PEPPER);
    expect(syntheticHashesEqual(a, hashSynthetic('x', PEPPER))).toBe(true);
    expect(syntheticHashesEqual(a, hashSynthetic('y', PEPPER))).toBe(false);
    expect(syntheticHashesEqual(a, Buffer.alloc(8))).toBe(false);
  });
});

/* ------------------------- sources: local three ----------------------- */

describe('sources — env / file / exec work with nothing installed', () => {
  it("env resolves from the RECORDER's environment", async () => {
    const s = makeSource({ type: 'env', var: 'TOK' }, seams({ env: { TOK: REAL } }));
    await expect(s.resolve()).resolves.toEqual({ value: REAL });
  });

  it('env denies source_empty when unset or empty', async () => {
    const s = makeSource({ type: 'env', var: 'TOK' }, seams({ env: {} }));
    await expect(s.resolve()).rejects.toMatchObject({ code: 'source_empty' });
    const e = makeSource({ type: 'env', var: 'TOK' }, seams({ env: { TOK: '' } }));
    await expect(e.resolve()).rejects.toMatchObject({ code: 'source_empty' });
  });

  it('file strips the trailing newline `echo >` adds, and can keep it', async () => {
    const file = { content: `${REAL}\n`, mode: 0o100600, uid: 501 };
    const strict = makeSource({ type: 'file', path: '/x' }, seams({ readSecretFile: () => Promise.resolve(file) }));
    await expect(strict.resolve()).resolves.toEqual({ value: REAL });
    const keep = makeSource(
      { type: 'file', path: '/x', keep_trailing_newline: true },
      seams({ readSecretFile: () => Promise.resolve(file) }),
    );
    await expect(keep.resolve()).resolves.toEqual({ value: `${REAL}\n` });
  });

  it.skipIf(!FILE_MODE_CHECK_APPLIES)('file REFUSES a world-readable secret and says which mode', async () => {
    const s = makeSource(
      { type: 'file', path: '/x' },
      seams({ readSecretFile: () => Promise.resolve({ content: REAL, mode: 0o100644, uid: 501 }) }),
    );
    await expect(s.resolve()).rejects.toMatchObject({ code: 'source_file_mode_too_open' });
    await s.resolve().catch((err: CredentialSourceError) => {
      expect(err.detail).toContain('world-readable');
      expect(err.detail).toContain('644');
      // The detail is for the operator; the CODE is all a caller ever sees.
      expect(err.code).toBe('source_file_mode_too_open');
    });
  });

  it.skipIf(!FILE_MODE_CHECK_APPLIES)('file refuses group-readable unless the operator opted in', async () => {
    const read = () => Promise.resolve({ content: REAL, mode: 0o100640, uid: 501 });
    await expect(
      makeSource({ type: 'file', path: '/x' }, seams({ readSecretFile: read })).resolve(),
    ).rejects.toMatchObject({ code: 'source_file_mode_too_open' });
    await expect(
      makeSource(
        { type: 'file', path: '/x', allow_group_readable: true },
        seams({ readSecretFile: read }),
      ).resolve(),
    ).resolves.toEqual({ value: REAL });
  });

  it.skipIf(!FILE_MODE_CHECK_APPLIES)('file reads a REAL file through the default seam, mode check included', async () => {
    // The seam is faked everywhere else; this proves the default one stats the
    // descriptor it reads. Skipped on Windows, where mode bits are a fiction
    // and `FILE_MODE_CHECK_APPLIES` turns the check off for that reason.
    const dir = await mkdtemp(join(tmpdir(), 'broker-file-'));
    try {
      const good = join(dir, 'ok');
      await writeFile(good, `${REAL}\n`, { mode: 0o600 });
      await chmod(good, 0o600);
      const { defaultSeams } = await import('../src/broker/sources.js');
      await expect(makeSource({ type: 'file', path: good }, defaultSeams({})).resolve()).resolves.toEqual({
        value: REAL,
      });

      const bad = join(dir, 'open');
      await writeFile(bad, REAL, { mode: 0o644 });
      await chmod(bad, 0o644);
      await expect(
        makeSource({ type: 'file', path: bad }, defaultSeams({})).resolve(),
      ).rejects.toMatchObject({ code: 'source_file_mode_too_open' });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('exec takes stdout whole, or one field of a credential_process JSON', async () => {
    const plain = makeSource(
      { type: 'exec', command: 'helper' },
      seams({ exec: () => Promise.resolve({ code: 0, stdout: `${REAL}\n`, stderr: '' }) }),
    );
    await expect(plain.resolve()).resolves.toEqual({ value: REAL });

    const json = JSON.stringify({
      Version: 1,
      AccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      SessionToken: REAL,
      Expiration: '2023-11-14T22:13:20.000Z',
    });
    const field = makeSource(
      {
        type: 'exec',
        command: 'aws-helper',
        json_field: 'SessionToken',
        json_expiry_field: 'Expiration',
      },
      seams({ exec: () => Promise.resolve({ code: 0, stdout: json, stderr: '' }) }),
    );
    await expect(field.resolve()).resolves.toEqual({
      value: REAL,
      expiresAtMs: Date.parse('2023-11-14T22:13:20.000Z'),
    });
  });

  it('exec really spawns, with no shell, through the default seam', async () => {
    // `process.execPath` is node itself, so this needs nothing installed and
    // behaves the same on every platform the recorder supports. It proves the
    // default seam (spawn, collect stdout, wait for close) works, which the
    // faked-seam tests above deliberately do not.
    const { defaultSeams } = await import('../src/broker/sources.js');
    const ok = makeSource(
      {
        type: 'exec',
        command: process.execPath,
        args: ['-e', `process.stdout.write(${JSON.stringify(REAL)})`],
      },
      defaultSeams({}),
    );
    await expect(ok.resolve()).resolves.toEqual({ value: REAL });

    const fails = makeSource(
      { type: 'exec', command: process.execPath, args: ['-e', 'process.exit(7)'] },
      defaultSeams({}),
    );
    await expect(fails.resolve()).rejects.toMatchObject({ code: 'source_exec_failed' });

    // A command that does not exist is a code, not an uncaught spawn error.
    const missing = makeSource(
      { type: 'exec', command: 'mcp-recorder-no-such-credential-helper' },
      defaultSeams({}),
    );
    await expect(missing.resolve()).rejects.toMatchObject({ code: 'source_exec_failed' });
  }, 15_000);

  it('exec keeps stderr out of the code and passes the args from CONFIG only', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const s = makeSource(
      { type: 'exec', command: 'helper', args: ['--profile', 'ci'] },
      seams({
        exec: (command, args) => {
          calls.push({ command, args });
          return Promise.resolve({ code: 3, stdout: '', stderr: `failed with ${REAL}` });
        },
      }),
    );
    await expect(s.resolve()).rejects.toMatchObject({ code: 'source_exec_failed' });
    expect(calls).toEqual([{ command: 'helper', args: ['--profile', 'ci'] }]);
  });
});

/* -------------------- sources: the four with a seam ------------------- */

describe('sources — github-app mints an installation token', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

  it('signs a real RS256 JWT and returns the token with its expiry', async () => {
    const sent: HttpSeamRequest[] = [];
    const s = makeSource(
      {
        type: 'github-app',
        app_id: '12345',
        installation_id: '67890',
        private_key: { type: 'env', var: 'APP_PEM' },
        repositories: ['acme/widgets'],
        permissions: { issues: 'write' },
      },
      seams({
        env: { APP_PEM: pem },
        http: (r) => {
          sent.push(r);
          return Promise.resolve({
            status: 201,
            body: JSON.stringify({ token: REAL, expires_at: '2023-11-14T23:00:00Z' }),
          });
        },
      }),
    );

    await expect(s.resolve()).resolves.toEqual({
      value: REAL,
      expiresAtMs: Date.parse('2023-11-14T23:00:00Z'),
    });

    const call = sent[0]!;
    expect(call.url).toBe('https://api.github.com/app/installations/67890/access_tokens');
    // The narrowing is what makes this source worth preferring over a PAT.
    expect(JSON.parse(call.body!)).toEqual({
      repositories: ['acme/widgets'],
      permissions: { issues: 'write' },
    });

    const jwt = call.headers.authorization!.replace(/^Bearer /, '');
    const [h, p, sig] = jwt.split('.');
    expect(JSON.parse(Buffer.from(h!, 'base64url').toString())).toEqual({ alg: 'RS256', typ: 'JWT' });
    const payload = JSON.parse(Buffer.from(p!, 'base64url').toString()) as Record<string, number | string>;
    expect(payload.iss).toBe('12345');
    // iat is backdated 60s for clock skew; exp is inside GitHub's 10-minute cap.
    expect(Number(payload.exp) - Number(payload.iat)).toBe(600);
    expect(
      cryptoVerify(
        'RSA-SHA256',
        Buffer.from(`${h!}.${p!}`),
        publicKey,
        Buffer.from(sig!, 'base64url'),
      ),
    ).toBe(true);
  });

  it('denies github_app_rejected without echoing the response body', async () => {
    const s = makeSource(
      {
        type: 'github-app',
        app_id: '1',
        installation_id: '2',
        private_key: { type: 'env', var: 'APP_PEM' },
      },
      seams({
        env: { APP_PEM: pem },
        http: () => Promise.resolve({ status: 401, body: `{"message":"bad jwt ${REAL}"}` }),
      }),
    );
    const err = (await s.resolve().catch((e: unknown) => e)) as CredentialSourceError;
    expect(err.code).toBe('github_app_rejected');
    expect(err.code).not.toContain(REAL);
  });

  it('surfaces an unusable private key as a code, not a crypto stack trace', async () => {
    const s = makeSource(
      {
        type: 'github-app',
        app_id: '1',
        installation_id: '2',
        private_key: { type: 'env', var: 'APP_PEM' },
      },
      seams({ env: { APP_PEM: 'not a pem' }, http: () => Promise.resolve({ status: 201, body: '{}' }) }),
    );
    await expect(s.resolve()).rejects.toMatchObject({ code: 'github_app_rejected' });
  });
});

describe('sources — aws-sts assumes a role', () => {
  const stsBody = (token: string): string =>
    `<AssumeRoleResponse><AssumeRoleResult><Credentials>` +
    `<AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>` +
    `<SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>` +
    `<SessionToken>${token}</SessionToken>` +
    `<Expiration>2023-11-14T22:30:00Z</Expiration>` +
    `</Credentials></AssumeRoleResult></AssumeRoleResponse>`;

  const spec: CredentialSourceSpec = {
    type: 'aws-sts',
    role_arn: 'arn:aws:iam::123456789012:role/mcp-recorder',
    region: 'eu-west-1',
    access_key_id: { type: 'env', var: 'AWS_ACCESS_KEY_ID' },
    secret_access_key: { type: 'env', var: 'AWS_SECRET_ACCESS_KEY' },
  };
  const env = {
    AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
    AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  };

  it('emits the credential_process JSON by default and signs with SigV4', async () => {
    const sent: HttpSeamRequest[] = [];
    const s = makeSource(
      spec,
      seams({
        env,
        http: (r) => {
          sent.push(r);
          return Promise.resolve({ status: 200, body: stsBody(REAL) });
        },
      }),
    );
    const out = await s.resolve();
    expect(JSON.parse(out.value)).toEqual({
      Version: 1,
      AccessKeyId: 'ASIAIOSFODNN7EXAMPLE',
      SecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      SessionToken: REAL,
      Expiration: '2023-11-14T22:30:00Z',
    });
    expect(out.expiresAtMs).toBe(Date.parse('2023-11-14T22:30:00Z'));

    const call = sent[0]!;
    expect(call.url).toBe('https://sts.eu-west-1.amazonaws.com/');
    expect(call.body).toContain('Action=AssumeRole');
    expect(call.headers.authorization).toMatch(
      /^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/\d{8}\/eu-west-1\/sts\/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=[0-9a-f]{64}$/,
    );
  });

  it('emits only the session token when asked, and includes the security token header', async () => {
    const sent: HttpSeamRequest[] = [];
    const s = makeSource(
      { ...spec, emit: 'session_token', session_token: { type: 'env', var: 'AWS_SESSION_TOKEN' } },
      seams({
        env: { ...env, AWS_SESSION_TOKEN: 'root-session' },
        http: (r) => {
          sent.push(r);
          return Promise.resolve({ status: 200, body: stsBody(REAL) });
        },
      }),
    );
    await expect(s.resolve()).resolves.toMatchObject({ value: REAL });
    expect(sent[0]!.headers['x-amz-security-token']).toBe('root-session');
    expect(sent[0]!.headers.authorization).toContain('x-amz-security-token');
  });

  it('denies aws_sts_rejected on a non-200 and on an incomplete body', async () => {
    const bad = makeSource(spec, seams({ env, http: () => Promise.resolve({ status: 403, body: '<Error/>' }) }));
    await expect(bad.resolve()).rejects.toMatchObject({ code: 'aws_sts_rejected' });
    const partial = makeSource(
      spec,
      seams({ env, http: () => Promise.resolve({ status: 200, body: '<AssumeRoleResponse/>' }) }),
    );
    await expect(partial.resolve()).rejects.toMatchObject({ code: 'aws_sts_rejected' });
  });

  it('signs the documented SigV4 example deterministically', () => {
    // Same inputs twice must give the same signature, and a changed body must
    // change it — the two properties a hand-written signer gets wrong.
    const base = {
      method: 'POST' as const,
      url: new URL('https://sts.us-east-1.amazonaws.com/'),
      region: 'us-east-1',
      service: 'sts',
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      body: 'Action=AssumeRole&Version=2011-06-15',
      nowMs: Date.parse('2015-08-30T12:36:00Z'),
    };
    const a = sigv4Headers(base);
    const b = sigv4Headers(base);
    const c = sigv4Headers({ ...base, body: 'Action=GetCallerIdentity' });
    expect(a.authorization).toBe(b.authorization);
    expect(a.authorization).not.toBe(c.authorization);
    expect(a['x-amz-date']).toBe('20150830T123600Z');
  });

  it('xmlTag reads a leaf and ignores a missing one', () => {
    expect(xmlTag('<a><B>x</B></a>', 'B')).toBe('x');
    expect(xmlTag('<a></a>', 'B')).toBeUndefined();
  });
});

describe('sources — vault (OpenBao) and clickup', () => {
  const kv = (blob: Record<string, unknown>): string => JSON.stringify({ data: { data: blob } });

  it('reads KV v2 with the token header and the default `token` field', async () => {
    const sent: HttpSeamRequest[] = [];
    const s = makeSource(
      { type: 'vault', addr: 'https://bao.internal:8200/', path: '/github/ci', token: { type: 'env', var: 'BAO' } },
      seams({
        env: { BAO: 'hvs.rootish' },
        http: (r) => {
          sent.push(r);
          return Promise.resolve({ status: 200, body: kv({ token: REAL }) });
        },
      }),
    );
    await expect(s.resolve()).resolves.toEqual({ value: REAL });
    expect(sent[0]!.url).toBe('https://bao.internal:8200/v1/secret/data/github/ci');
    expect(sent[0]!.headers['x-vault-token']).toBe('hvs.rootish');
  });

  it("answers NHI's own vault_missing_token when the blob has no field", async () => {
    const s = makeSource(
      { type: 'vault', addr: 'https://bao', path: 'p', token: { type: 'env', var: 'BAO' } },
      seams({ env: { BAO: 't' }, http: () => Promise.resolve({ status: 200, body: kv({ other: 'x' }) }) }),
    );
    await expect(s.resolve()).rejects.toMatchObject({ code: 'vault_missing_token' });
  });

  it('answers vault_unreachable on a non-200 and on a transport failure', async () => {
    const s404 = makeSource(
      { type: 'vault', addr: 'https://bao', path: 'p', token: { type: 'env', var: 'BAO' } },
      seams({ env: { BAO: 't' }, http: () => Promise.resolve({ status: 404, body: '{}' }) }),
    );
    await expect(s404.resolve()).rejects.toMatchObject({ code: 'vault_unreachable' });
    const dead = makeSource(
      { type: 'vault', addr: 'https://bao', path: 'p', token: { type: 'env', var: 'BAO' } },
      seams({ env: { BAO: 't' }, http: () => Promise.reject(new Error('ECONNREFUSED 10.0.0.1:8200')) }),
    );
    await expect(dead.resolve()).rejects.toMatchObject({ code: 'vault_unreachable' });
  });

  it('clickup passes the token through, and verifies it only when asked', async () => {
    let calls = 0;
    const quiet = makeSource(
      { type: 'clickup', token: { type: 'env', var: 'CU' } },
      seams({
        env: { CU: REAL },
        http: () => {
          calls++;
          return Promise.resolve({ status: 200, body: '{}' });
        },
      }),
    );
    await expect(quiet.resolve()).resolves.toEqual({ value: REAL });
    expect(calls).toBe(0);

    const verified = makeSource(
      { type: 'clickup', token: { type: 'env', var: 'CU' }, verify: true },
      seams({
        env: { CU: REAL },
        http: () => {
          calls++;
          return Promise.resolve({ status: 401, body: '{"err":"Token invalid"}' });
        },
      }),
    );
    await expect(verified.resolve()).rejects.toMatchObject({ code: 'clickup_token_rejected' });
    expect(calls).toBe(1);
  });

  it('sourceKinds walks nested root credentials', () => {
    expect(
      sourceKinds({
        type: 'vault',
        addr: 'https://bao',
        path: 'p',
        token: { type: 'file', path: '/root/.bao-token' },
      }),
    ).toEqual(['vault', 'file']);
    expect(
      sourceKinds({
        type: 'aws-sts',
        role_arn: 'r',
        access_key_id: { type: 'env', var: 'A' },
        secret_access_key: { type: 'exec', command: 'helper' },
      }),
    ).toEqual(['aws-sts', 'env', 'exec']);
  });
});

/* ---------------------------- config trust ---------------------------- */

describe('assessConfigTrust', () => {
  const statAs = (mode: number, uid: number, gid: number): Stats => ({ mode, uid, gid }) as unknown as Stats;

  it('says writable when the running uid owns a writable config', async () => {
    const out = await assessConfigTrust(['/etc/policy.yaml'], {
      uid: 501,
      gids: [20],
      statFile: () => Promise.resolve(statAs(0o100644, 501, 20)),
    });
    expect(out.writableByUs).toBe(true);
    expect(out.reasons[0]).toContain('owned and writable');
  });

  it('says NOT writable for a root-owned 0644 config read by a non-root uid', async () => {
    const out = await assessConfigTrust(['/etc/policy.yaml'], {
      uid: 501,
      gids: [20],
      statFile: () => Promise.resolve(statAs(0o100644, 0, 0)),
    });
    expect(out.writableByUs).toBe(false);
    expect(out.reasons).toEqual([]);
  });

  it('treats an unreadable config, a group-writable one and root as writable', async () => {
    const missing = await assessConfigTrust(['/nope'], {
      uid: 501,
      gids: [],
      statFile: () => Promise.reject(new Error('ENOENT')),
    });
    expect(missing.writableByUs).toBe(true);

    const group = await assessConfigTrust(['/p'], {
      uid: 501,
      gids: [20],
      statFile: () => Promise.resolve(statAs(0o100664, 0, 20)),
    });
    expect(group.writableByUs).toBe(true);

    const asRoot = await assessConfigTrust(['/p'], {
      uid: 0,
      gids: [0],
      statFile: () => Promise.resolve(statAs(0o100400, 0, 0)),
    });
    expect(asRoot.writableByUs).toBe(true);
  });
});

/* ---------------------------- validation ------------------------------ */

describe('validation — a swap site with no host constraint is an ERROR', () => {
  it('refuses an allow rule without a host', () => {
    const problems = validateCredentialEntry(
      entry({ synthetic: mintSynthetic(), allow: [{ host: [] }] }),
    );
    expect(problems.join('\n')).toContain('no host constraint');
  });

  it('refuses a host glob that constrains nothing', () => {
    for (const host of ['*', '**']) {
      const problems = validateCredentialEntry(entry({ synthetic: mintSynthetic(), allow: [{ host: [host] }] }));
      expect(problems.join('\n')).toContain('constrains nothing');
    }
  });

  it('refuses a site with no host_from, and an argument binding with no arg', () => {
    const noBinding = validateCredentialEntry(
      entry({
        synthetic: mintSynthetic(),
        sites: [{ server: ['s'], tool: ['t'], arg: 'token' } as never],
      }),
    );
    expect(noBinding.join('\n')).toContain('must declare host_from');

    const emptyArg = validateCredentialEntry(
      entry({
        synthetic: mintSynthetic(),
        sites: [{ server: ['s'], tool: ['t'], arg: 'token', host_from: { kind: 'argument', arg: '' } }],
      }),
    );
    expect(emptyArg.join('\n')).toContain('host_from.kind=argument with no arg');
  });

  it('refuses a broker built from an invalid config rather than denying at runtime', () => {
    expect(
      () =>
        new LocalBroker({
          credentials: [entry({ synthetic: mintSynthetic(), allow: [] })],
          pepper: PEPPER,
          seams: seams(),
          warn: () => {},
        }),
    ).toThrow(/invalid broker credentials/);
  });

  it('refuses two credentials behind one synthetic', () => {
    const synthetic = mintSynthetic();
    const hash = hashSynthetic(synthetic, PEPPER).toString('hex');
    expect(
      () =>
        new LocalBroker({
          credentials: [
            { ...entry({ id: 'a' }), synthetic_hash: hash },
            { ...entry({ id: 'b' }), synthetic_hash: hash },
          ],
          pepper: PEPPER,
          seams: seams(),
          warn: () => {},
        }),
    ).toThrow(/share one synthetic/);
  });

  it('hands out COPIES of the swap sites, not the config objects', () => {
    const { broker } = build();
    const first = broker.sites();
    first[0]!.site.tool.push('**');
    expect(broker.sites()[0]!.site.tool).toEqual(['create_issue']);
  });

  it('hashes the config for the chain WITHOUT the raw synthetic in the input', () => {
    const s1 = mintSynthetic();
    const s2 = mintSynthetic();
    expect(credentialsConfigHash([entry({ synthetic: s1 })])).toBe(
      credentialsConfigHash([entry({ synthetic: s2 })]),
    );
    // But a change that matters — a widened host — moves the hash.
    expect(credentialsConfigHash([entry({ synthetic: s1 })])).not.toBe(
      credentialsConfigHash([entry({ synthetic: s1, allow: [{ host: ['attacker.example'] }] })]),
    );
  });
});

/* --------------------------- LocalBroker ------------------------------ */

describe("LocalBroker — the happy path answers NHI's 200 body", () => {
  it('returns real_token + ttl_seconds + decision_id and records the decision', async () => {
    const { broker, decisions, synthetic } = build();
    const out = await broker.exchange(req({}, synthetic), { site_id: 'github/create_issue#token', host_binding: 'server' });
    expect(out).toEqual({
      real_token: REAL,
      ttl_seconds: BROKER_DEFAULT_TTL_SECONDS,
      decision_id: expect.stringMatching(/^[0-9a-f-]{36}$/),
    });
    expect(out.denied).toBeUndefined();

    const d = decisions[0]!;
    expect(d).toMatchObject({
      allowed: true,
      credential_id: 'github-ci',
      provider: 'github',
      scopes: ['issues:write'],
      source_kind: 'env',
      site_id: 'github/create_issue#token',
      host_binding: 'server',
      cache: 'miss',
      policy_hash: 'policy-hash',
    });
    expect(d.config_hash).toMatch(/^[0-9a-f]{64}$/);
    // Invariant 4: an id and a decision id, never the value and never the synthetic.
    expect(JSON.stringify(d)).not.toContain(REAL);
    expect(JSON.stringify(d)).not.toContain(synthetic);
  });

  it('registers the resolved value so nothing can fingerprint it', async () => {
    const { broker, synthetic } = build();
    expect(isBrokeredSecret(REAL)).toBe(false);
    await broker.exchange(req({}, synthetic));
    expect(isBrokeredSecret(REAL)).toBe(true);
  });

  it("caps the TTL at the entry's own ttl_seconds and at the provider's expiry", async () => {
    const short = build({ entries: [entry({ ttl_seconds: 5 })] });
    const a = await short.broker.exchange(req({}, short.synthetic));
    expect(a.ttl_seconds).toBe(5);

    const expiring = build({
      makeSource: () => ({
        kind: 'env' as const,
        resolve: () => Promise.resolve({ value: REAL, expiresAtMs: 1_700_000_000_000 + 3_000 }),
      }),
    });
    const b = await expiring.broker.exchange(req({}, expiring.synthetic));
    expect(b.ttl_seconds).toBe(3);
  });
});

describe('LocalBroker — deny paths never carry a token', () => {
  it('denies unknown_synthetic for both an unknown value and a malformed one', async () => {
    const { broker } = build();
    for (const value of [mintSynthetic(), 'ghp_not_a_synthetic', '']) {
      const out = await broker.exchange(req({}, value));
      expect(out.deny_reason).toBe('unknown_synthetic');
      expect(out.denied).toBe(true);
      expect(out.real_token).toBeUndefined();
      expect(out.ttl_seconds).toBe(0);
    }
  });

  it('denies a revoked or disabled synthetic', async () => {
    const revoked = build({ entries: [entry({ status: 'revoked' })] });
    const a = await revoked.broker.exchange(req({}, revoked.synthetic));
    expect(a).toMatchObject({ denied: true, deny_reason: 'synthetic_revoked' });
    expect(a.real_token).toBeUndefined();

    const disabled = build({ entries: [entry({ status: 'disabled' })] });
    const b = await disabled.broker.exchange(req({}, disabled.synthetic));
    expect(b).toMatchObject({ denied: true, deny_reason: 'synthetic_disabled' });
  });

  it('DENIES A DESTINATION THE POLICY DID NOT NAME — the attacker.example case', async () => {
    // The whole point of carrying `host` separately: a credential allowed for
    // api.github.com must not ride an `http_post` to somewhere the agent picked.
    const { broker, decisions, synthetic } = build({
      entries: [
        entry({
          sites: [
            {
              server: ['corp-notes'],
              tool: ['http_post'],
              arg: 'headers.Authorization',
              host_from: { kind: 'argument', arg: 'url' },
            },
          ],
          allow: [{ host: ['api.github.com'] }],
        }),
      ],
    });
    const out = await broker.exchange(
      req({ host: 'attacker.example', path_template: 'http_post' }, synthetic),
      { host_binding: 'argument' },
    );
    expect(out).toMatchObject({ denied: true, deny_reason: 'host_not_permitted', ttl_seconds: 0 });
    expect(out.real_token).toBeUndefined();
    expect(decisions[0]!.host_binding).toBe('argument');
  });

  it('constrains method and path_template too', async () => {
    const { broker, synthetic } = build({
      entries: [entry({ allow: [{ method: ['tools/call'], host: ['api.github.com'], path_template: ['create_issue'] }] })],
    });
    await expect(broker.exchange(req({ method: 'resources/read' }, synthetic))).resolves.toMatchObject({
      deny_reason: 'method_not_permitted',
    });
    await expect(broker.exchange(req({ path_template: 'delete_repo' }, synthetic))).resolves.toMatchObject({
      deny_reason: 'path_not_permitted',
    });
  });

  it('denies no_host_constraint if a host-less rule ever reaches the matcher', () => {
    // The validator refuses this at load, so this is the defence in depth:
    // a rule built by hand must deny rather than default to permissive.
    expect(matchRules([{ host: [] }], { method: 'tools/call', host: 'anywhere', path_template: 't' })).toBe(
      'no_host_constraint',
    );
    expect(matchRules([], { method: 'tools/call', host: 'anywhere', path_template: 't' })).toBe(
      'denied_by_policy',
    );
  });

  it('honours host globs with the "." delimiter the egress policy already uses', () => {
    const rules = [{ host: ['*.github.com'] }];
    expect(matchRules(rules, { method: 'tools/call', host: 'api.github.com', path_template: 't' })).toBeUndefined();
    // "*" does not cross the delimiter, so a deeper label does not match.
    expect(matchRules(rules, { method: 'tools/call', host: 'evil.api.github.com', path_template: 't' })).toBe(
      'host_not_permitted',
    );
    expect(matchRules(rules, { method: 'tools/call', host: 'github.com.evil.example', path_template: 't' })).toBe(
      'host_not_permitted',
    );
  });

  it('denies, never forwards, when the source fails — and keeps the detail out of the code', async () => {
    const { broker, decisions, warnings, synthetic } = build({ env: {} });
    const out = await broker.exchange(req({}, synthetic));
    expect(out).toMatchObject({ denied: true, deny_reason: 'source_empty' });
    expect(out.real_token).toBeUndefined();
    expect(decisions[0]!.allowed).toBe(false);
    // The operator gets the detail; the caller got a code.
    expect(warnings.join('\n')).toContain('GITHUB_TOKEN');
    expect(JSON.stringify(out)).not.toContain('GITHUB_TOKEN');
  });

  it('denies broker_error rather than throwing when a source misbehaves', async () => {
    const { broker, synthetic } = build({
      makeSource: () => ({
        kind: 'env' as const,
        resolve: () => {
          throw new TypeError('not a CredentialSourceError');
        },
      }),
    });
    const out = await broker.exchange(req({}, synthetic));
    expect(out.denied).toBe(true);
    expect(out.real_token).toBeUndefined();
  });
});

describe('LocalBroker — the cache is keyed on the whole tuple', () => {
  function counting(): { source: CredentialSource; calls: () => number } {
    let calls = 0;
    return {
      source: {
        kind: 'env' as const,
        resolve: () => {
          calls++;
          return Promise.resolve({ value: REAL });
        },
      },
      calls: () => calls,
    };
  }

  it('reuses a resolution for the SAME tuple', async () => {
    const c = counting();
    const { broker, synthetic, decisions } = build({ makeSource: () => c.source });
    await broker.exchange(req({}, synthetic));
    await broker.exchange(req({}, synthetic));
    expect(c.calls()).toBe(1);
    expect(decisions.map((d) => d.cache)).toEqual(['miss', 'hit']);
  });

  it('does NOT turn an allow for one tool into an allow for another', async () => {
    // The sharp version of the cache bug: 30 s of `create_issue` must not be
    // 30 s of `delete_repo`.
    const c = counting();
    const { broker, synthetic } = build({
      entries: [entry({ allow: [{ host: ['api.github.com'], path_template: ['create_issue'] }] })],
      makeSource: () => c.source,
    });
    await expect(broker.exchange(req({}, synthetic))).resolves.toMatchObject({ real_token: REAL });
    const out = await broker.exchange(req({ path_template: 'delete_repo' }, synthetic));
    expect(out).toMatchObject({ denied: true, deny_reason: 'path_not_permitted' });
    expect(out.real_token).toBeUndefined();
    expect(c.calls()).toBe(1);
  });

  it('keys on the TUPLE, not the synthetic: two allowed destinations resolve twice', async () => {
    // Both calls are allowed, so the policy check cannot be what separates
    // them — only the cache key can. A key of "the synthetic" would serve the
    // second destination out of the first's slot, which is the bug this
    // asserts against; the observable is the resolve count.
    const c = counting();
    const { broker, synthetic } = build({
      entries: [entry({ allow: [{ host: ['api.github.com', 'api.clickup.com'] }] })],
      makeSource: () => c.source,
    });
    await expect(broker.exchange(req({}, synthetic))).resolves.toMatchObject({ real_token: REAL });
    await expect(
      broker.exchange(req({ host: 'api.clickup.com' }, synthetic)),
    ).resolves.toMatchObject({ real_token: REAL });
    expect(c.calls()).toBe(2);
    // ... and each destination then has its own slot.
    await broker.exchange(req({}, synthetic));
    await broker.exchange(req({ host: 'api.clickup.com' }, synthetic));
    expect(c.calls()).toBe(2);
  });

  it('bounds the cache, because the agent writes the host a glob allows', async () => {
    const c = counting();
    const { broker, synthetic } = build({
      entries: [entry({ allow: [{ host: ['*.github.com'] }] })],
      makeSource: () => c.source,
    });
    // Every one of these is policy-legitimate under `*.github.com`, so the
    // cap is the only thing between an allowed loop and an unbounded map of
    // live tokens.
    for (let i = 0; i < MAX_DECISION_CACHE + 20; i++) {
      await expect(
        broker.exchange(req({ host: `host${String(i)}.github.com` }, synthetic)),
      ).resolves.toMatchObject({ real_token: REAL });
    }
    // The earliest destination has been evicted, so it re-resolves rather
    // than being served from a slot that no longer exists.
    const before = c.calls();
    await broker.exchange(req({ host: 'host0.github.com' }, synthetic));
    expect(c.calls()).toBe(before + 1);
  });

  it('re-resolves after the TTL, and on invalidate()', async () => {
    const c = counting();
    const { broker, synthetic, clock } = build({ makeSource: () => c.source });
    await broker.exchange(req({}, synthetic));
    clock.ms += BROKER_DEFAULT_TTL_SECONDS * 1000 + 1;
    await broker.exchange(req({}, synthetic));
    expect(c.calls()).toBe(2);
    broker.invalidate();
    await broker.exchange(req({}, synthetic));
    expect(c.calls()).toBe(3);
  });

  it('re-evaluates the policy on a cache HIT, so a revocation is not outrun', async () => {
    const c = counting();
    const entries = [entry()];
    const { broker, synthetic } = build({ entries, makeSource: () => c.source });
    await broker.exchange(req({}, synthetic));
    // Same tuple, but the host is now somewhere else: the cached value must
    // not short-circuit the destination check.
    const out = await broker.exchange(req({ host: 'attacker.example' }, synthetic));
    expect(out).toMatchObject({ denied: true, deny_reason: 'host_not_permitted' });
  });
});

describe('LocalBroker — deadlines and the unhealthy window', () => {
  it('denies source_timeout, then denies immediately until the window passes', async () => {
    let resolves = 0;
    const { broker, synthetic, clock } = build({
      makeSource: () => ({
        kind: 'env' as const,
        resolve: () => {
          resolves++;
          // Never settles: the deadline is what ends this call.
          return new Promise<never>(() => {});
        },
      }),
    });

    const first = await broker.exchange(req({}, synthetic));
    expect(first).toMatchObject({ denied: true, deny_reason: 'source_timeout' });
    expect(first.real_token).toBeUndefined();

    // Marked unhealthy: the next call must not pay the deadline again.
    const second = await broker.exchange(req({}, synthetic));
    expect(second).toMatchObject({ denied: true, deny_reason: 'source_unhealthy' });
    expect(resolves).toBe(1);

    clock.ms += SOURCE_UNHEALTHY_MS + 1;
    const third = await broker.exchange(req({}, synthetic));
    expect(third).toMatchObject({ denied: true, deny_reason: 'source_timeout' });
    expect(resolves).toBe(2);
  }, 10_000);
});

describe('LocalBroker — exec under a writable config', () => {
  const execEntry = entry({ source: { type: 'exec', command: '/usr/local/bin/get-token' } });

  it('refuses an exec source when the config is writable by this uid', async () => {
    const { broker, synthetic, warnings } = build({
      entries: [execEntry],
      trust: { configWritableByUs: true },
      seams: { exec: () => Promise.resolve({ code: 0, stdout: REAL, stderr: '' }) },
    });
    const out = await broker.exchange(req({}, synthetic));
    expect(out).toMatchObject({ denied: true, deny_reason: 'source_untrusted_config' });
    expect(out.real_token).toBeUndefined();
    expect(warnings.join('\n')).toContain('refusing it');
    // And the operator is told what the deployment does and does not give them.
    expect(warnings.join('\n')).toContain('not a confidentiality one');
  });

  it('allows it with an explicit opt-in, and when the config is not writable', async () => {
    const opted = build({
      entries: [execEntry],
      trust: { configWritableByUs: true, allowExecFromWritableConfig: true },
      seams: { exec: () => Promise.resolve({ code: 0, stdout: REAL, stderr: '' }) },
    });
    await expect(opted.broker.exchange(req({}, opted.synthetic))).resolves.toMatchObject({ real_token: REAL });

    const rootOwned = build({
      entries: [execEntry],
      trust: { configWritableByUs: false },
      seams: { exec: () => Promise.resolve({ code: 0, stdout: REAL, stderr: '' }) },
    });
    await expect(rootOwned.broker.exchange(req({}, rootOwned.synthetic))).resolves.toMatchObject({
      real_token: REAL,
    });
  });

  it("refuses an exec nested inside another source's root credential", async () => {
    const nested = build({
      entries: [
        entry({
          source: {
            type: 'vault',
            addr: 'https://bao',
            path: 'p',
            token: { type: 'exec', command: 'print-bao-token' },
          },
        }),
      ],
      trust: { configWritableByUs: true },
    });
    await expect(nested.broker.exchange(req({}, nested.synthetic))).resolves.toMatchObject({
      deny_reason: 'source_untrusted_config',
    });
  });
});

describe('LocalBroker — recording is fail-open, enforcement is fail-closed', () => {
  it('a decision sink that throws does not turn an allow into a deny', async () => {
    const synthetic = mintSynthetic();
    const warnings: string[] = [];
    const broker = new LocalBroker({
      credentials: [{ ...entry(), synthetic_hash: hashSynthetic(synthetic, PEPPER).toString('hex') }],
      pepper: PEPPER,
      seams: seams({ env: { GITHUB_TOKEN: REAL } }),
      configTrust: { configWritableByUs: false },
      onDecision: () => {
        throw new Error('store is full');
      },
      warn: (l) => warnings.push(l),
    });
    await expect(broker.exchange(req({}, synthetic))).resolves.toMatchObject({ real_token: REAL });
    expect(warnings.join('\n')).toContain('decision sink threw');
  });

  it('exposes the declared sites so the gateway can bind the swap to one', () => {
    const { broker } = build();
    expect(broker.sites()).toEqual([
      {
        credential_id: 'github-ci',
        site: {
          server: ['github'],
          tool: ['create_issue'],
          arg: 'token',
          host_from: { kind: 'server' },
        },
      },
    ]);
  });
});

/* --------------------------- RemoteBroker ----------------------------- */

describe("RemoteBroker — the Go client's behaviour, in TypeScript", () => {
  const base = { baseUrl: 'https://api.cresec.test/', dataPlaneInstanceId: 'dp-1', warn: () => {} };

  it("POSTs NHI's exact snake_case body to /broker/exchange", async () => {
    const sent: Array<{ url: string; body: string; headers: Record<string, string> }> = [];
    const broker = new RemoteBroker({
      ...base,
      authToken: 'sink-token',
      fetch: (r) => {
        sent.push({ url: r.url, body: r.body, headers: r.headers });
        return Promise.resolve({
          status: 200,
          body: JSON.stringify({ real_token: REAL, ttl_seconds: 30, decision_id: 'd-1' }),
        });
      },
    });

    const out = await broker.exchange({
      synthetic: 'cresec_synth_v1_abcdefghijklmnop',
      // Deliberately wrong: the broker must use ITS configured instance id.
      data_plane_instance_id: 'attacker-chosen',
      request: { method: 'tools/call', host: 'api.github.com', path_template: 'create_issue', user_agent: 'claude/1' },
    });
    expect(out).toEqual({ real_token: REAL, ttl_seconds: 30, decision_id: 'd-1' });

    expect(sent[0]!.url).toBe('https://api.cresec.test/broker/exchange');
    expect(JSON.parse(sent[0]!.body)).toEqual({
      synthetic: 'cresec_synth_v1_abcdefghijklmnop',
      data_plane_instance_id: 'dp-1',
      request: {
        method: 'tools/call',
        host: 'api.github.com',
        path_template: 'create_issue',
        user_agent: 'claude/1',
      },
    });
    expect(sent[0]!.headers.authorization).toBe('Bearer sink-token');
  });

  it("treats the STATUS as the source of truth, as the Go client does", async () => {
    const broker = new RemoteBroker({
      ...base,
      // A 403 whose body claims otherwise is still a denial.
      fetch: () =>
        Promise.resolve({
          status: 403,
          body: JSON.stringify({ denied: false, deny_reason: 'unknown_synthetic', decision_id: 'd-2', real_token: REAL }),
        }),
    });
    const out = await broker.exchange(req({}, 'cresec_synth_v1_abcdefghijklmnop'));
    expect(out).toEqual({ decision_id: 'd-2', ttl_seconds: 0, denied: true, deny_reason: 'unknown_synthetic' });
    expect(out.real_token).toBeUndefined();
  });

  it('fails CLOSED on transport failure, an odd status, a bad body and a 200 with no token', async () => {
    const cases: Array<[() => Promise<{ status: number; body: string }>, string]> = [
      [() => Promise.reject(new Error('ECONNRESET')), 'broker_unreachable'],
      [() => Promise.resolve({ status: 500, body: 'oops' }), 'broker_error'],
      [() => Promise.resolve({ status: 200, body: 'not json' }), 'broker_error'],
      [() => Promise.resolve({ status: 200, body: '{"ttl_seconds":30,"decision_id":"d"}' }), 'broker_error'],
      [() => Promise.resolve({ status: 200, body: `{"real_token":"${REAL}","ttl_seconds":0,"decision_id":"d"}` }), 'broker_error'],
    ];
    for (const [fetch, reason] of cases) {
      const broker = new RemoteBroker({ ...base, fetch });
      const out = await broker.exchange(req({}, 'cresec_synth_v1_abcdefghijklmnop'));
      expect(out.deny_reason).toBe(reason);
      expect(out.denied).toBe(true);
      expect(out.real_token).toBeUndefined();
    }
  });
});

/* ------------------------------ THE CANARY ---------------------------- */

describe('invariant 3 — a brokered secret never reaches the evidence chain', () => {
  it('excludes the value from every fingerprinting surface in the redactor', async () => {
    const canaryRef = sha256Ref(REAL);
    const redactor = new Redactor();

    // Before brokering, the recorder behaves exactly as it always has — this
    // half of the test is what proves the exclusion is doing the work below.
    expect(collectEnvCredentialFingerprints({ GITHUB_TOKEN: REAL }, redactor)).toEqual([
      { name: 'GITHUB_TOKEN', ref: canaryRef },
    ]);

    const { broker, synthetic } = build();
    await expect(broker.exchange(req({}, synthetic))).resolves.toMatchObject({ real_token: REAL });

    // 1. env fingerprints — `env: GITHUB_TOKEN` is exactly CREDENTIAL_NAME_RE.
    expect(collectEnvCredentialFingerprints({ GITHUB_TOKEN: REAL }, redactor)).toEqual([]);

    // 2. the wrapped server's argv, both shapes.
    const argv = scrubArgv(['server', '--token', REAL, `GITHUB_TOKEN=${REAL}`], redactor);
    expect(argv.fingerprints).toEqual([]);
    expect(argv.command).not.toContain(REAL);
    expect(argv.command).not.toContain(canaryRef);
    expect(argv.command).toContain(BROKERED_REF);

    // 3. a whole leaf that IS the token.
    const leaf = redactor.scrub({ token: REAL }) as { token: RedactedRef };
    expect(leaf.token.ref).toBe(BROKERED_REF);
    expect(leaf.token.secret_refs).toBeUndefined();

    // 4. a leaf that CONTAINS it — `Bearer <token>`, whose hash is just as
    //    recoverable because the prefix is known.
    const header = redactor.scrub({ headers: { authorization: `Bearer ${REAL}` } });
    expect(JSON.stringify(header)).not.toContain(canaryRef);
    expect(JSON.stringify(header)).not.toContain(sha256Ref(`Bearer ${REAL}`));
    expect(JSON.stringify(header)).toContain(BROKERED_REF);

    // 5. tool arguments, where NOTHING passes in any mode.
    const args = scrubToolArguments(redactor, { headers: { Authorization: `Bearer ${REAL}` } });
    expect(JSON.stringify(args)).not.toContain(canaryRef);
    expect(JSON.stringify(args)).not.toContain(REAL);

    // 6. and the value itself is nowhere in any of it.
    const everything = JSON.stringify([argv, leaf, header, args]);
    expect(everything).not.toContain(REAL);
    expect(everything).not.toContain(canaryRef);
  });

  it('the placeholder ref is a genuine sha256 of a public literal', () => {
    expect(BROKERED_REF).toBe(sha256Ref(BROKERED_PLACEHOLDER));
    expect(BROKERED_REF).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('does not blank short or unrelated values', () => {
    registerBrokeredSecret('short');
    const redactor = new Redactor();
    // Under the containment floor: exact exclusion only, so an unrelated leaf
    // that merely contains "short" is untouched.
    const out = redactor.scrub({ note: 'a short sentence' }) as { note: RedactedRef };
    expect(out.note.ref).toBe(sha256Ref('a short sentence'));
    expect(containsBrokeredSecret('a short sentence')).toBe(false);
    expect(isBrokeredSecret('short')).toBe(true);
  });

  it('DENIES rather than hands over a value it could not register', async () => {
    // Fill the exclusion set, then broker one more. A full set must never
    // degrade to "return the token and fingerprint it".
    for (let i = 0; i < MAX_BROKERED_SECRETS; i++) registerBrokeredSecret(`filler-${String(i)}-${'x'.repeat(20)}`);
    expect(brokeredSecretCount()).toBe(MAX_BROKERED_SECRETS);

    const { broker, synthetic, warnings } = build();
    const out = await broker.exchange(req({}, synthetic));
    expect(out).toMatchObject({ denied: true, deny_reason: 'exclusion_capacity' });
    expect(out.real_token).toBeUndefined();
    expect(warnings.join('\n')).toContain('exclusion set is full');
  });
});

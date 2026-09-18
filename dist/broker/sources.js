/**
 * Credential sources — where a real token actually comes from.
 *
 * One interface, seven implementations, and a single rule that shapes all of
 * them: EVERY escape from this process (a file read, a spawn, an HTTPS call)
 * goes through an injected seam. Not for tidiness — for the test suite. A
 * credential source that reaches the network in a unit test is a test that
 * fails in CI for reasons unrelated to the code, so `github-app`, `aws-sts`,
 * `vault` and `clickup` are exercised against a fake `http` seam that returns
 * the provider's real response bodies, and `env`, `file` and `exec` work for
 * real with nothing installed.
 *
 * WHAT A SOURCE IS AND IS NOT. It is the resolution half of a brokered
 * credential: given a spec from the CONFIG (never from the call — see
 * `LocalBroker`), hand back one string and, where the provider says so, when
 * it expires. It is not an authorisation decision, it does not cache, and it
 * does not know what the token is for. It fails by throwing a
 * {@link CredentialSourceError} carrying a deny CODE, because the code is the
 * only part of a failure that may travel back to the caller.
 *
 * WHAT NONE OF THIS BUYS. The real credential is resolved on the same machine
 * as the agent, from a source the agent's own uid can usually read: `env` is
 * this process's environment, `file` is a path with the same permissions,
 * `exec` is a command the agent can run itself. `vault`, `aws-sts` and
 * `github-app` do not change that on their own — their ROOT credential (the
 * OpenBao token, the AWS keys, the app private key) sits in the same env or
 * the same file, so an agent that wants a token mints its own rather than
 * stealing a brokered one. What they do buy is duration: an installation
 * token lives an hour, an STS session as long as you asked for, a KV read can
 * be rotated behind you. That shrinks the window, not the readership. The
 * confidentiality boundary only exists when the resolver runs as a principal
 * the agent is not — a root-owned config with a root-owned resolver, or the
 * hosted control plane. Say that, do not say "the agent never sees your
 * credentials".
 */
import { Buffer } from 'node:buffer';
import { spawn } from 'node:child_process';
import { createSign, createHash } from 'node:crypto';
import { createHmac } from 'node:crypto';
import { open, stat } from 'node:fs/promises';
import { sinkFetch } from '../sink/http.js';
/* -------------------------------------------------------------------- */
/* errors                                                                */
/* -------------------------------------------------------------------- */
/**
 * A resolution failure, reduced to a code.
 *
 * `detail` exists for the operator's stderr and is NEVER returned from an
 * exchange: it can hold a vault path, an exec command line, or an upstream
 * error body that quotes the token. The broker logs it through its `warn`
 * seam (which the operator controls) and answers the caller with `code`.
 */
export class CredentialSourceError extends Error {
    code;
    detail;
    constructor(code, detail) {
        super(code);
        this.name = 'CredentialSourceError';
        this.code = code;
        this.detail = detail;
    }
}
/** Cap on a resolved credential, and on what a source will read at all. */
export const MAX_CREDENTIAL_BYTES = 64 * 1024;
/**
 * The real seams: node builtins plus the sink's HTTP transport.
 *
 * `sinkFetch` is reused rather than reimplemented because it already carries
 * the two things a corporate or cloud environment needs and `node:https` does
 * not do by itself — HTTPS_PROXY/NO_PROXY CONNECT tunnelling and split
 * connect/total timeouts — with certificate verification never disabled. A
 * broker that could not reach OpenBao through the same proxy the shipper uses
 * would fail closed on every call, which is a correctness problem, not a
 * convenience one.
 */
export function defaultSeams(env = process.env) {
    return {
        env,
        now: () => Date.now(),
        async readSecretFile(path) {
            // Open FIRST, then fstat the descriptor we are about to read. A
            // `stat(path)` followed by `readFile(path)` checks the permissions of
            // one inode and reads another if the path is swapped in between, which
            // is exactly the trick a mode check is supposed to stop.
            const fh = await open(path, 'r');
            try {
                const st = await fh.stat();
                const buf = Buffer.alloc(Math.min(Number(st.size), MAX_CREDENTIAL_BYTES));
                const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
                return {
                    content: buf.subarray(0, bytesRead).toString('utf8'),
                    mode: st.mode,
                    uid: st.uid,
                };
            }
            finally {
                await fh.close();
            }
        },
        async exec(command, args, timeoutMs) {
            return await new Promise((resolve, reject) => {
                // No shell, ever. `shell: true` would make the command string in the
                // config an injection surface for anything that can influence it, and
                // the config is already the most dangerous file in this design.
                const child = spawn(command, args, {
                    shell: false,
                    stdio: ['ignore', 'pipe', 'pipe'],
                });
                let stdout = '';
                let stderr = '';
                let settled = false;
                const timer = setTimeout(() => {
                    if (settled)
                        return;
                    settled = true;
                    child.kill('SIGKILL');
                    reject(new CredentialSourceError('source_timeout', `${command} exceeded ${String(timeoutMs)}ms`));
                }, timeoutMs);
                timer.unref?.();
                child.stdout.on('data', (c) => {
                    if (stdout.length < MAX_CREDENTIAL_BYTES)
                        stdout += c.toString('utf8');
                });
                child.stderr.on('data', (c) => {
                    if (stderr.length < 8192)
                        stderr += c.toString('utf8');
                });
                child.on('error', (err) => {
                    if (settled)
                        return;
                    settled = true;
                    clearTimeout(timer);
                    reject(new CredentialSourceError('source_exec_failed', err.message));
                });
                child.on('close', (code) => {
                    if (settled)
                        return;
                    settled = true;
                    clearTimeout(timer);
                    resolve({ code, stdout, stderr });
                });
            });
        },
        async http(req) {
            const res = await sinkFetch({
                method: req.method,
                url: req.url,
                headers: req.headers,
                ...(req.body !== undefined ? { body: Buffer.from(req.body, 'utf8') } : {}),
                totalTimeoutMs: req.timeoutMs,
            }, env);
            return { status: res.status, body: res.body.toString('utf8') };
        },
    };
}
/**
 * Per-kind resolution deadlines, in ms.
 *
 * These bound the stall a brokered call can impose on the proxy thread the
 * client is waiting on, which is the whole reason they exist: a resolution
 * sits on the forwarding path of every declared-site `tools/call`, and a
 * hung OpenBao must become a refusal, not a hung MCP server. Measured on this
 * repo's CI-class hardware (Node 22): `env` resolves in ~0.2 us and `file` in
 * ~215 us warm, that being a real open + fstat + read + close rather than a
 * cached string. The 250 ms local budget is therefore three orders of
 * magnitude of headroom over the slower of the two, and fires only on
 * something pathological — an NFS mount gone away, a FUSE filesystem that
 * never answers. `exec` gets 2 s because a credential helper may itself do a
 * network call, and the network sources get 5 s, which is the budget the
 * sink's own transport defaults to.
 *
 * Overrunning does not merely fail the call: the source is marked unhealthy
 * (see `LocalBroker`) so the NEXT call denies immediately instead of paying
 * the timeout again.
 */
export const SOURCE_DEADLINE_MS = {
    env: 250,
    file: 250,
    exec: 2_000,
    'github-app': 5_000,
    'aws-sts': 5_000,
    vault: 5_000,
    clickup: 5_000,
};
/* -------------------------------------------------------------------- */
/* factory                                                               */
/* -------------------------------------------------------------------- */
/** Build the source described by `spec`. Pure — no I/O until `resolve()`. */
export function makeSource(spec, seams) {
    switch (spec.type) {
        case 'env':
            return new EnvSource(spec, seams);
        case 'file':
            return new FileSource(spec, seams);
        case 'exec':
            return new ExecSource(spec, seams);
        case 'github-app':
            return new GithubAppSource(spec, seams);
        case 'aws-sts':
            return new AwsStsSource(spec, seams);
        case 'vault':
            return new VaultSource(spec, seams);
        case 'clickup':
            return new ClickupSource(spec, seams);
    }
}
/** Every source kind named anywhere in `spec`, including nested root credentials. */
export function sourceKinds(spec) {
    const out = [spec.type];
    const nested = spec.type === 'github-app'
        ? [spec.private_key]
        : spec.type === 'aws-sts'
            ? [spec.access_key_id, spec.secret_access_key, ...(spec.session_token ? [spec.session_token] : [])]
            : spec.type === 'vault'
                ? [spec.token]
                : spec.type === 'clickup'
                    ? [spec.token]
                    : [];
    for (const n of nested)
        out.push(...sourceKinds(n));
    return out;
}
/* -------------------------------------------------------------------- */
/* env / file / exec — the three that work with nothing installed        */
/* -------------------------------------------------------------------- */
class EnvSource {
    kind = 'env';
    #spec;
    #seams;
    constructor(spec, seams) {
        this.#spec = spec;
        this.#seams = seams;
    }
    resolve() {
        const value = this.#seams.env[this.#spec.var];
        if (value === undefined || value === '') {
            // The variable NAME is in the config, so naming it in `detail` tells the
            // operator nothing the config does not — but it still never reaches the
            // caller, which is the rule.
            return Promise.reject(new CredentialSourceError('source_empty', `env ${this.#spec.var} is unset`));
        }
        return Promise.resolve({ value });
    }
}
/** Mode bits that make a secret file readable by somebody who is not its owner. */
const MODE_GROUP_READ = 0o040;
const MODE_OTHER_READ = 0o004;
/**
 * Whether the mode check below means anything on this platform.
 *
 * It does not on Windows: access there is decided by ACLs, node's `Stats.mode`
 * reports a synthesized 0o666/0o444 that reflects only the read-only
 * attribute, and refusing on it would reject EVERY `file` source on Windows
 * while checking nothing. So the check is skipped there — stated plainly
 * rather than hidden, because it is a real gap: on Windows a `file` source
 * gets no permission check at all, and an operator who wants one has to set
 * the ACL themselves. Exported so the tests can say which platform they are
 * asserting about instead of guessing.
 */
export const FILE_MODE_CHECK_APPLIES = process.platform !== 'win32';
class FileSource {
    kind = 'file';
    #spec;
    #seams;
    constructor(spec, seams) {
        this.#spec = spec;
        this.#seams = seams;
    }
    async resolve() {
        let file;
        try {
            file = await this.#seams.readSecretFile(this.#spec.path);
        }
        catch (err) {
            if (err instanceof CredentialSourceError)
                throw err;
            throw new CredentialSourceError('source_unavailable', errText(err));
        }
        // A world-readable secret file is refused outright, and a group-readable
        // one unless the operator opted in. This is a small check with a specific
        // job: the broker's claim is that a use of the credential is recorded and
        // policy-checked, and a file every account on the box can read makes even
        // THAT claim thin — the next reader never comes past the broker at all.
        // It is not a confidentiality control against the agent, which shares the
        // owner's uid; see the header.
        const perms = file.mode & 0o777;
        if (FILE_MODE_CHECK_APPLIES && (perms & MODE_OTHER_READ) !== 0) {
            throw new CredentialSourceError('source_file_mode_too_open', `${this.#spec.path} is world-readable (mode ${perms.toString(8)}); chmod 600 it`);
        }
        if (FILE_MODE_CHECK_APPLIES &&
            (perms & MODE_GROUP_READ) !== 0 &&
            this.#spec.allow_group_readable !== true) {
            throw new CredentialSourceError('source_file_mode_too_open', `${this.#spec.path} is group-readable (mode ${perms.toString(8)}); chmod 600 it or set allow_group_readable`);
        }
        const value = this.#spec.keep_trailing_newline === true ? file.content : file.content.replace(/\r?\n$/, '');
        if (value === '') {
            throw new CredentialSourceError('source_empty', `${this.#spec.path} is empty`);
        }
        return { value };
    }
}
class ExecSource {
    kind = 'exec';
    #spec;
    #seams;
    constructor(spec, seams) {
        this.#spec = spec;
        this.#seams = seams;
    }
    async resolve() {
        const timeoutMs = this.#spec.timeout_ms ?? SOURCE_DEADLINE_MS.exec;
        let out;
        try {
            out = await this.#seams.exec(this.#spec.command, this.#spec.args ?? [], timeoutMs);
        }
        catch (err) {
            if (err instanceof CredentialSourceError)
                throw err;
            throw new CredentialSourceError('source_exec_failed', errText(err));
        }
        if (out.code !== 0) {
            // stderr goes to `detail`, never to the caller: a credential helper
            // routinely echoes the command line it failed on, and an `aws` CLI
            // failure has been seen to print the profile's keys.
            throw new CredentialSourceError('source_exec_failed', `${this.#spec.command} exited ${String(out.code)}: ${out.stderr.slice(0, 500)}`);
        }
        if (this.#spec.json_field === undefined) {
            const value = out.stdout.replace(/\r?\n$/, '');
            if (value === '')
                throw new CredentialSourceError('source_empty', `${this.#spec.command} printed nothing`);
            return { value };
        }
        const parsed = parseJsonObject(out.stdout, 'source_exec_failed', `${this.#spec.command} stdout is not JSON`);
        const value = parsed[this.#spec.json_field];
        if (typeof value !== 'string' || value === '') {
            throw new CredentialSourceError('source_empty', `${this.#spec.command} JSON has no string ${this.#spec.json_field}`);
        }
        const expiresAtMs = this.#spec.json_expiry_field
            ? parseRfc3339(parsed[this.#spec.json_expiry_field])
            : undefined;
        return expiresAtMs === undefined ? { value } : { value, expiresAtMs };
    }
}
/* -------------------------------------------------------------------- */
/* github-app                                                            */
/* -------------------------------------------------------------------- */
/**
 * Mint an installation access token.
 *
 * This is the source to prefer over `env: GITHUB_TOKEN` even on a laptop, and
 * the reason is duration and scope rather than secrecy: the token GitHub
 * returns lives one hour and carries only the `repositories`/`permissions`
 * asked for, where a PAT in the environment is long-lived and carries
 * everything its owner can do. The app private key is still a file on the
 * same machine — an agent that can read it can mint its own token, so the
 * gain is that a LEAKED brokered token expires, not that it cannot be
 * obtained.
 */
class GithubAppSource {
    kind = 'github-app';
    #spec;
    #seams;
    constructor(spec, seams) {
        this.#spec = spec;
        this.#seams = seams;
    }
    async resolve() {
        const pem = (await makeSource(this.#spec.private_key, this.#seams).resolve()).value;
        const now = Math.floor(this.#seams.now() / 1000);
        // GitHub rejects an `iat` in its future; 60 s back absorbs clock skew,
        // and the 9-minute `exp` is under GitHub's 10-minute ceiling.
        const jwt = signRs256Jwt({ alg: 'RS256', typ: 'JWT' }, { iat: now - 60, exp: now + 540, iss: this.#spec.app_id }, pem);
        const base = (this.#spec.api_base ?? 'https://api.github.com').replace(/\/+$/, '');
        const body = {};
        if (this.#spec.repositories)
            body.repositories = this.#spec.repositories;
        if (this.#spec.permissions)
            body.permissions = this.#spec.permissions;
        const res = await this.#seams.http({
            method: 'POST',
            url: `${base}/app/installations/${encodeURIComponent(this.#spec.installation_id)}/access_tokens`,
            headers: {
                authorization: `Bearer ${jwt}`,
                accept: 'application/vnd.github+json',
                'x-github-api-version': '2022-11-28',
                'content-type': 'application/json',
                'user-agent': 'mcp-recorder-broker',
            },
            body: JSON.stringify(body),
            timeoutMs: this.#spec.timeout_ms ?? SOURCE_DEADLINE_MS['github-app'],
        });
        if (res.status !== 201 && res.status !== 200) {
            // The response body can quote the JWT back; it stays in `detail`.
            throw new CredentialSourceError('github_app_rejected', `status ${String(res.status)}: ${res.body.slice(0, 300)}`);
        }
        const parsed = parseJsonObject(res.body, 'github_app_rejected', 'installation token response is not JSON');
        const token = parsed.token;
        if (typeof token !== 'string' || token === '') {
            throw new CredentialSourceError('github_app_rejected', 'installation token response has no token');
        }
        const expiresAtMs = parseRfc3339(parsed.expires_at);
        return expiresAtMs === undefined ? { value: token } : { value: token, expiresAtMs };
    }
}
/** `base64url(header).base64url(payload).base64url(RS256 signature)`. */
function signRs256Jwt(header, payload, privateKeyPem) {
    const seg = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
    const signingInput = `${seg(header)}.${seg(payload)}`;
    let signature;
    try {
        const signer = createSign('RSA-SHA256');
        signer.update(signingInput);
        signature = signer.sign(privateKeyPem);
    }
    catch (err) {
        throw new CredentialSourceError('github_app_rejected', `private key unusable: ${errText(err)}`);
    }
    return `${signingInput}.${signature.toString('base64url')}`;
}
/* -------------------------------------------------------------------- */
/* aws-sts                                                               */
/* -------------------------------------------------------------------- */
/**
 * AssumeRole, signed with SigV4 from a root credential that is itself in env,
 * a file or an exec helper.
 *
 * Same honest framing as `github-app`: the win is a session that expires and
 * a role that may be narrower than the caller's own identity, not that the
 * root keys are out of reach — they are in the same environment the agent's
 * shell inherits.
 */
class AwsStsSource {
    kind = 'aws-sts';
    #spec;
    #seams;
    constructor(spec, seams) {
        this.#spec = spec;
        this.#seams = seams;
    }
    async resolve() {
        const region = this.#spec.region ?? 'us-east-1';
        const accessKeyId = (await makeSource(this.#spec.access_key_id, this.#seams).resolve()).value;
        const secretAccessKey = (await makeSource(this.#spec.secret_access_key, this.#seams).resolve()).value;
        const sessionToken = this.#spec.session_token
            ? (await makeSource(this.#spec.session_token, this.#seams).resolve()).value
            : undefined;
        const endpoint = this.#spec.endpoint ?? `https://sts.${region}.amazonaws.com/`;
        const url = new URL(endpoint);
        const form = new URLSearchParams({
            Action: 'AssumeRole',
            Version: '2011-06-15',
            RoleArn: this.#spec.role_arn,
            RoleSessionName: this.#spec.session_name ?? 'mcp-recorder-broker',
            DurationSeconds: String(this.#spec.duration_seconds ?? 900),
        }).toString();
        const headers = sigv4Headers({
            method: 'POST',
            url,
            region,
            service: 'sts',
            accessKeyId,
            secretAccessKey,
            sessionToken,
            body: form,
            nowMs: this.#seams.now(),
        });
        const res = await this.#seams.http({
            method: 'POST',
            url: url.toString(),
            headers,
            body: form,
            timeoutMs: this.#spec.timeout_ms ?? SOURCE_DEADLINE_MS['aws-sts'],
        });
        if (res.status !== 200) {
            throw new CredentialSourceError('aws_sts_rejected', `status ${String(res.status)}: ${res.body.slice(0, 300)}`);
        }
        const accessKey = xmlTag(res.body, 'AccessKeyId');
        const secret = xmlTag(res.body, 'SecretAccessKey');
        const token = xmlTag(res.body, 'SessionToken');
        const expiration = xmlTag(res.body, 'Expiration');
        if (accessKey === undefined || secret === undefined || token === undefined) {
            throw new CredentialSourceError('aws_sts_rejected', 'AssumeRole response is missing credential fields');
        }
        const expiresAtMs = parseRfc3339(expiration);
        const value = (this.#spec.emit ?? 'json') === 'session_token'
            ? token
            : JSON.stringify({
                Version: 1,
                AccessKeyId: accessKey,
                SecretAccessKey: secret,
                SessionToken: token,
                ...(expiration !== undefined ? { Expiration: expiration } : {}),
            });
        return expiresAtMs === undefined ? { value } : { value, expiresAtMs };
    }
}
/**
 * SigV4 for the one request shape this file makes: a form-encoded POST with
 * no query string. Written out rather than pulled in, because the repo's rule
 * is node builtins over dependencies and the alternative is the AWS SDK.
 */
export function sigv4Headers(input) {
    const amzDate = new Date(input.nowMs).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
    const dateStamp = amzDate.slice(0, 8);
    const host = input.url.host;
    const contentType = 'application/x-www-form-urlencoded; charset=utf-8';
    const payloadHash = sha256Hex(input.body);
    const signed = [
        ['content-type', contentType],
        ['host', host],
        ['x-amz-date', amzDate],
    ];
    if (input.sessionToken !== undefined)
        signed.push(['x-amz-security-token', input.sessionToken]);
    signed.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const canonicalHeaders = signed.map(([k, v]) => `${k}:${v.trim()}\n`).join('');
    const signedHeaders = signed.map(([k]) => k).join(';');
    const canonicalRequest = [
        input.method,
        input.url.pathname === '' ? '/' : input.url.pathname,
        '',
        canonicalHeaders,
        signedHeaders,
        payloadHash,
    ].join('\n');
    const scope = `${dateStamp}/${input.region}/${input.service}/aws4_request`;
    const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256Hex(canonicalRequest)].join('\n');
    let key = createHmac('sha256', `AWS4${input.secretAccessKey}`).update(dateStamp).digest();
    for (const part of [input.region, input.service, 'aws4_request']) {
        key = createHmac('sha256', key).update(part).digest();
    }
    const signature = createHmac('sha256', key).update(stringToSign).digest('hex');
    const headers = {
        'content-type': contentType,
        'x-amz-date': amzDate,
        authorization: `AWS4-HMAC-SHA256 Credential=${input.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    };
    if (input.sessionToken !== undefined)
        headers['x-amz-security-token'] = input.sessionToken;
    return headers;
}
function sha256Hex(s) {
    return createHash('sha256').update(s, 'utf8').digest('hex');
}
/**
 * First `<tag>…</tag>` in an XML document.
 *
 * A regex, not a parser: the AssumeRole response is a fixed, flat shape from
 * a service we are already trusting for the credential itself, and the four
 * fields we read are leaf text. The alternative is an XML dependency on a
 * path that must never gain one. The pattern is anchored to a literal tag
 * name and matches lazily up to the first close tag, so there is nothing to
 * backtrack over.
 */
export function xmlTag(doc, tag) {
    const m = new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(doc);
    return m?.[1];
}
/* -------------------------------------------------------------------- */
/* vault (OpenBao) / clickup                                             */
/* -------------------------------------------------------------------- */
class VaultSource {
    kind = 'vault';
    #spec;
    #seams;
    constructor(spec, seams) {
        this.#spec = spec;
        this.#seams = seams;
    }
    async resolve() {
        const token = (await makeSource(this.#spec.token, this.#seams).resolve()).value;
        const addr = this.#spec.addr.replace(/\/+$/, '');
        const mount = this.#spec.mount ?? 'secret';
        const path = this.#spec.path.replace(/^\/+/, '');
        const headers = { 'x-vault-token': token, accept: 'application/json' };
        if (this.#spec.namespace !== undefined)
            headers['x-vault-namespace'] = this.#spec.namespace;
        let res;
        try {
            res = await this.#seams.http({
                method: 'GET',
                url: `${addr}/v1/${mount}/data/${path}`,
                headers,
                timeoutMs: this.#spec.timeout_ms ?? SOURCE_DEADLINE_MS.vault,
            });
        }
        catch (err) {
            if (err instanceof CredentialSourceError)
                throw err;
            throw new CredentialSourceError('vault_unreachable', errText(err));
        }
        if (res.status !== 200) {
            throw new CredentialSourceError('vault_unreachable', `status ${String(res.status)}`);
        }
        const parsed = parseJsonObject(res.body, 'vault_unreachable', 'KV read is not JSON');
        // KV v2 nests the blob at data.data; NHI's VaultClient reads the same shape.
        const outer = parsed.data;
        const blob = isPlainObject(outer) ? outer.data : undefined;
        const field = this.#spec.field ?? 'token';
        const value = isPlainObject(blob) ? blob[field] : undefined;
        if (typeof value !== 'string' || value === '') {
            // NHI's exchange.ts answers exactly this code when the blob has no
            // token; keeping the spelling means a policy or a dashboard written
            // against the control plane reads the local broker's denials unchanged.
            throw new CredentialSourceError('vault_missing_token', `${mount}/${path} has no string ${field}`);
        }
        return { value };
    }
}
class ClickupSource {
    kind = 'clickup';
    #spec;
    #seams;
    constructor(spec, seams) {
        this.#spec = spec;
        this.#seams = seams;
    }
    async resolve() {
        const token = (await makeSource(this.#spec.token, this.#seams).resolve()).value;
        if (this.#spec.verify !== true)
            return { value: token };
        const base = (this.#spec.api_base ?? 'https://api.clickup.com/api').replace(/\/+$/, '');
        let res;
        try {
            res = await this.#seams.http({
                method: 'GET',
                url: `${base}/v2/user`,
                headers: { authorization: token, accept: 'application/json' },
                timeoutMs: this.#spec.timeout_ms ?? SOURCE_DEADLINE_MS.clickup,
            });
        }
        catch (err) {
            if (err instanceof CredentialSourceError)
                throw err;
            throw new CredentialSourceError('source_unavailable', errText(err));
        }
        if (res.status === 401 || res.status === 403) {
            throw new CredentialSourceError('clickup_token_rejected', `status ${String(res.status)}`);
        }
        if (res.status !== 200) {
            throw new CredentialSourceError('source_unavailable', `status ${String(res.status)}`);
        }
        return { value: token };
    }
}
/**
 * Can the uid this process runs as rewrite the files that name the credential
 * sources?
 *
 * This is the check behind the `exec` refusal in `LocalBroker`. An attacker
 * (or an agent following a poisoned instruction) who can edit the broker
 * config does not need an exploit: `exec` is arbitrary code execution BY
 * CONFIGURATION, run as the recorder, on every brokered call — and short of
 * that, they can point a swap site at a host they control and have the
 * credential handed to it legitimately. On a single-uid developer laptop this
 * check says "yes, writable" and the honest answer is that the control is
 * advisory: what protects the operator there is that both config hashes are
 * stamped on every decision, so a mid-session edit is EVIDENT in a
 * tamper-evident chain. It is not prevented. Only an OS boundary — a
 * root-owned config and a resolver running as somebody the agent is not — or
 * the hosted control plane makes it tamper-RESISTANT.
 */
export async function assessConfigTrust(paths, opts = {}) {
    const uid = opts.uid ?? (typeof process.getuid === 'function' ? process.getuid() : -1);
    const gids = opts.gids ?? (typeof process.getgid === 'function' ? [process.getgid()] : []);
    const statFile = opts.statFile ?? ((p) => stat(p));
    const reasons = [];
    let writableByUs = false;
    for (const p of paths) {
        let st;
        try {
            st = await statFile(p);
        }
        catch {
            // A config that cannot be stat'ed is not a config we can vouch for.
            reasons.push(`${p}: not readable`);
            writableByUs = true;
            continue;
        }
        const perms = st.mode & 0o777;
        // root (uid 0) can write anything, so the answer there is always yes —
        // which is correct: a broker running as root has no boundary against a
        // root agent either.
        if (uid === 0) {
            writableByUs = true;
            reasons.push(`${p}: running as root`);
            continue;
        }
        if (st.uid === uid && (perms & 0o200) !== 0) {
            writableByUs = true;
            reasons.push(`${p}: owned and writable by uid ${String(uid)} (mode ${perms.toString(8)})`);
            continue;
        }
        if (gids.includes(st.gid) && (perms & 0o020) !== 0) {
            writableByUs = true;
            reasons.push(`${p}: group-writable by a group this process is in (mode ${perms.toString(8)})`);
            continue;
        }
        if ((perms & 0o002) !== 0) {
            writableByUs = true;
            reasons.push(`${p}: world-writable (mode ${perms.toString(8)})`);
        }
    }
    return { paths, writableByUs, reasons };
}
/* -------------------------------------------------------------------- */
/* small shared helpers                                                  */
/* -------------------------------------------------------------------- */
function isPlainObject(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function parseJsonObject(text, code, detail) {
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        throw new CredentialSourceError(code, detail);
    }
    if (!isPlainObject(parsed))
        throw new CredentialSourceError(code, detail);
    return parsed;
}
/** RFC 3339 -> unix ms, or undefined for anything unparseable. */
function parseRfc3339(value) {
    if (typeof value !== 'string' || value === '')
        return undefined;
    const ms = Date.parse(value);
    return Number.isNaN(ms) ? undefined : ms;
}
/** Error text for the OPERATOR's eyes only (see CredentialSourceError.detail). */
function errText(err) {
    return err instanceof Error ? err.message : String(err);
}
//# sourceMappingURL=sources.js.map
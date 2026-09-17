#!/usr/bin/env node
/**
 * CLI for the reference receiver.
 *
 *   npm run receiver -- serve  [--data-dir DIR] [--port N] [--host H]
 *   npm run receiver -- status [--data-dir DIR]
 *   npm run receiver -- verify --chain <chain_id> [--data-dir DIR]
 *   npm run receiver -- export --chain <chain_id> --out DIR [--zip FILE]
 *   npm run receiver -- ack-key --tenant T --key <64hex> [--data-dir DIR]
 *
 * `status` and `verify` read the data dir directly, so they work against a
 * receiver that is running, stopped, or on a disk you copied somewhere else.
 */

import { resolve } from 'node:path';
import { GENESIS_HASH } from '../src/chain/hash.js';
import { verifyRecords } from '../src/verify/verify.js';
import { VERSION } from '../src/version.js';
import { ReceiverStore } from './store.js';
import { loadAuthConfig } from './auth.js';
import { serveReceiver } from './server.js';
import { exportReceivedChain } from './export.js';
import { HEX64 } from './protocol.js';

interface Flags {
  [name: string]: string | boolean | undefined;
}

function parseArgs(argv: string[]): { command: string; flags: Flags } {
  const flags: Flags = {};
  let command = 'serve';
  let i = 0;
  if (argv[0] !== undefined && !argv[0].startsWith('-')) {
    command = argv[0];
    i = 1;
  }
  for (; i < argv.length; i++) {
    const arg = argv[i]!;
    if (!arg.startsWith('--')) continue;
    const eq = arg.indexOf('=');
    if (eq !== -1) {
      flags[arg.slice(2, eq)] = arg.slice(eq + 1);
      continue;
    }
    const name = arg.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      flags[name] = true;
    } else {
      flags[name] = next;
      i++;
    }
  }
  return { command, flags };
}

function str(flags: Flags, name: string): string | undefined {
  const value = flags[name];
  return typeof value === 'string' ? value : undefined;
}

function num(flags: Flags, name: string): number | undefined {
  const value = str(flags, name);
  if (value === undefined) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function dataDirOf(flags: Flags): string {
  return resolve(str(flags, 'data-dir') ?? process.env.MCPR_RECEIVER_DATA_DIR ?? './receiver-data');
}

const USAGE = `mcp-recorder reference receiver v${VERSION}

  serve    [--data-dir DIR] [--host H] [--port N] [--heartbeat-interval S]
           [--silence-after N] [--require-range-header] [--tls-cert F --tls-key F]
  status   [--data-dir DIR]
  verify   --chain <chain_id> [--data-dir DIR]
  export   --chain <chain_id> --out DIR [--zip FILE] [--data-dir DIR]
  ack-key  --tenant T --key <64hex> [--data-dir DIR]

This is a REFERENCE receiver: not multi-tenant hardened, not the hosted
service. See receiver/README.md before pointing anything real at it.
`;

async function main(argv: string[]): Promise<number> {
  const { command, flags } = parseArgs(argv);
  if (flags.help === true || command === 'help') {
    process.stdout.write(USAGE);
    return 0;
  }
  const dataDir = dataDirOf(flags);

  if (command === 'serve') {
    const handle = await serveReceiver({
      dataDir,
      ...(str(flags, 'host') !== undefined ? { host: str(flags, 'host')! } : {}),
      ...(num(flags, 'port') !== undefined ? { port: num(flags, 'port')! } : {}),
      ...(num(flags, 'heartbeat-interval') !== undefined
        ? { heartbeatIntervalS: num(flags, 'heartbeat-interval')! }
        : {}),
      ...(num(flags, 'silence-after') !== undefined
        ? { silenceAfterIntervals: num(flags, 'silence-after')! }
        : {}),
      ...(flags['require-range-header'] === true ? { requireRangeHeader: true } : {}),
      ...(str(flags, 'tls-cert') !== undefined ? { tlsCert: str(flags, 'tls-cert')! } : {}),
      ...(str(flags, 'tls-key') !== undefined ? { tlsKey: str(flags, 'tls-key')! } : {}),
    });
    const auth = handle.receiver.auth;
    process.stdout.write(
      `mcp-recorder reference receiver v${VERSION}\n` +
        `  listening    ${handle.url}\n` +
        `  data dir     ${dataDir}\n` +
        `  ingest auth  ${auth.tokens.length} token(s) from ${auth.source}\n` +
        `  operator     Authorization: Bearer ${handle.operatorToken}\n` +
        (handle.url.startsWith('http://') && !/\/\/(127\.|\[::1\]|localhost)/.test(handle.url)
          ? '  WARNING      serving plain HTTP on a non-loopback address; put a TLS terminator in front\n'
          : '') +
        (auth.source === 'none'
          ? '  WARNING      no ingest tokens configured — every POST will be answered 401.\n' +
            `               Write ${dataDir}/tokens.json, or set MCPR_RECEIVER_TOKEN.\n`
          : ''),
    );
    await new Promise<void>(() => {
      /* serve until signalled */
    });
    return 0;
  }

  if (command === 'status') {
    const store = new ReceiverStore(dataDir);
    const auth = loadAuthConfig(dataDir);
    const chains = store.listChains();
    process.stdout.write(
      `receiver data dir : ${dataDir}\n` +
        `ingest tokens     : ${auth.tokens.length} (${auth.source})\n` +
        `chains            : ${chains.length}\n\n`,
    );
    if (chains.length === 0) {
      process.stdout.write('no chains have reported to this receiver yet.\n');
    }
    for (const chain of chains) {
      const ack = store.enrolledKey(chain.tenant, chain.key)?.acknowledged ?? false;
      const undelivered = Math.max(0, chain.claimed_head_seq - (chain.next_seq - 1));
      process.stdout.write(
        `chain ${chain.chain_id}\n` +
          `  key            ${chain.key}${ack ? '' : '   (NOT acknowledged — new_identity)'}\n` +
          `  tenant/status  ${chain.tenant} / ${chain.status}` +
          `${chain.chain_id_verified ? '' : ' (chain_id unverified: seq 1 not yet received)'}\n` +
          `  held           ${chain.records_held} record(s), next_seq ${chain.next_seq}\n` +
          `  head_hash      ${chain.head_hash}\n` +
          `  attested       seq ${chain.attested_seq}${chain.attested_at === null ? '' : ` at ${chain.attested_at}`}\n` +
          `  claimed head   seq ${chain.claimed_head_seq}  ->  ${undelivered} record(s) sealed but NOT delivered\n` +
          `  last seen      ${chain.last_seen_at}\n`,
      );
    }
    const alerts = store.alerts(10);
    if (alerts.length > 0) {
      process.stdout.write(`\nlast ${alerts.length} alert(s):\n`);
      for (const alert of alerts) {
        process.stdout.write(`  ${alert.at}  ${alert.kind}  ${alert.detail}\n`);
      }
    }
    const rejections = store.rejections(10);
    if (rejections.length > 0) {
      process.stdout.write(`\nlast ${rejections.length} rejection(s):\n`);
      for (const rej of rejections) {
        process.stdout.write(
          `  ${rej.received_at}  ${rej.status} ${rej.error}  ${rej.chain_id.slice(0, 16)}…  ${rej.detail}\n`,
        );
      }
    }
    return 0;
  }

  if (command === 'verify') {
    const chainId = str(flags, 'chain');
    if (chainId === undefined || !HEX64.test(chainId)) {
      process.stderr.write('verify needs --chain <64-hex chain_id>\n');
      return 2;
    }
    const store = new ReceiverStore(dataDir);
    const state = store.chain(chainId);
    if (state === undefined) {
      process.stderr.write(`no chain ${chainId} on this receiver\n`);
      return 2;
    }
    const records = store.records(chainId).map((r) => r.record);
    const signatures = store.signatures(chainId).map((s) => s.signature);
    const result = await verifyRecords(records, signatures, {
      baseHash: GENESIS_HASH,
      expectedPublicKeyHex: state.key,
      // The replica's tail is legitimately unsigned between flushes; that is
      // the sender's pace, not a problem with what we hold.
      allowUnsigned: true,
    });
    process.stdout.write(
      `${result.ok ? 'PASS' : 'FAIL'}: ${result.checked_events} record(s), head seq ${result.head.seq}\n` +
        `  chain_id verified : ${state.chain_id_verified}\n` +
        `  attested through  : seq ${state.attested_seq}\n` +
        `  sender claimed    : seq ${state.claimed_head_seq}\n`,
    );
    for (const problem of result.problems) {
      process.stdout.write(
        `  ${problem.warning === true ? 'warn' : 'FAIL'} ${problem.type} @${problem.seq}: ${problem.detail}\n`,
      );
    }
    return result.ok ? 0 : 1;
  }

  if (command === 'export') {
    const chainId = str(flags, 'chain');
    const out = str(flags, 'out');
    if (chainId === undefined || !HEX64.test(chainId)) {
      process.stderr.write('export needs --chain <64-hex chain_id>\n');
      return 2;
    }
    if (out === undefined && str(flags, 'zip') === undefined) {
      process.stderr.write('export needs --out <dir> and/or --zip <file>\n');
      return 2;
    }
    const store = new ReceiverStore(dataDir);
    const result = await exportReceivedChain({
      store,
      chainId,
      toolVersion: VERSION,
      ...(out !== undefined ? { dirPath: resolve(out) } : {}),
      ...(str(flags, 'zip') !== undefined ? { zipPath: resolve(str(flags, 'zip')!) } : {}),
    });
    process.stdout.write(
      `exported seq ${result.manifest.range.from_seq}..${result.manifest.range.to_seq} ` +
        `(${result.manifest.event_count} record(s))\n` +
        `  signed by       ${result.manifest.signature.public_key}\n` +
        `  NOT in bundle   ${result.unattested_records} held record(s) past the attested head\n` +
        `  sender claimed  seq ${result.claimed_head_seq}\n` +
        '  verify with     node verify.cjs   (inside the bundle)\n',
    );
    return 0;
  }

  if (command === 'ack-key') {
    const tenant = str(flags, 'tenant');
    const key = str(flags, 'key')?.toLowerCase();
    if (tenant === undefined || key === undefined || !HEX64.test(key)) {
      process.stderr.write('ack-key needs --tenant <t> --key <64hex>\n');
      return 2;
    }
    const store = new ReceiverStore(dataDir);
    if (!store.acknowledgeKey(tenant, key)) {
      process.stderr.write(`tenant ${tenant} has never been seen with key ${key}\n`);
      return 2;
    }
    process.stdout.write(`acknowledged ${key} for tenant ${tenant}; its chains now count as attested\n`);
    return 0;
  }

  process.stderr.write(`unknown command '${command}'\n\n${USAGE}`);
  return 2;
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });

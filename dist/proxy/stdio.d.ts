/**
 * Transparent stdio passthrough proxy (M0) + capture tap (M1).
 *
 * FORWARDING IS SACRED: client<->server bytes flow through plain .pipe()
 * with backpressure and are never mutated, delayed, or filtered. The tap
 * attaches separate 'data' listeners feeding a LineScanner; everything the
 * tap does is wrapped fail-open — a recorder/tap failure is logged once to
 * stderr and traffic continues.
 */
import type { Readable, Writable } from 'node:stream';
import type { RecorderLike, RedactorLike } from '../types.js';
export interface StdioProxyOpts {
    /** argv of the wrapped server, e.g. ['npx','@modelcontextprotocol/server-foo']. */
    command: string[];
    recorder: RecorderLike;
    redactor: RedactorLike;
    serverName?: string;
    identityLabel?: string;
    proxyVersion: string;
    stdin?: Readable;
    stdout?: Writable;
    stderr?: Writable;
    env?: NodeJS.ProcessEnv;
}
export declare function runStdioProxy(opts: StdioProxyOpts): Promise<number>;

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
import type { Stats } from 'node:fs';
import type { DenyReason } from './protocol.js';
/**
 * A resolution failure, reduced to a code.
 *
 * `detail` exists for the operator's stderr and is NEVER returned from an
 * exchange: it can hold a vault path, an exec command line, or an upstream
 * error body that quotes the token. The broker logs it through its `warn`
 * seam (which the operator controls) and answers the caller with `code`.
 */
export declare class CredentialSourceError extends Error {
    readonly code: DenyReason;
    readonly detail?: string;
    constructor(code: DenyReason, detail?: string);
}
export interface HttpSeamRequest {
    method: 'GET' | 'POST';
    url: string;
    headers: Record<string, string>;
    body?: string;
    timeoutMs: number;
}
export interface HttpSeamResponse {
    status: number;
    body: string;
}
export interface ExecSeamResult {
    code: number | null;
    stdout: string;
    stderr: string;
}
/** A secret file, read and stat'ed through the SAME descriptor (see `defaultSeams`). */
export interface SecretFile {
    content: string;
    /** `Stats.mode` — the permission bits are what `file` refuses on. */
    mode: number;
    uid: number;
}
export interface SourceSeams {
    env: NodeJS.ProcessEnv;
    now(): number;
    readSecretFile(path: string): Promise<SecretFile>;
    exec(command: string, args: string[], timeoutMs: number): Promise<ExecSeamResult>;
    http(req: HttpSeamRequest): Promise<HttpSeamResponse>;
}
/** Cap on a resolved credential, and on what a source will read at all. */
export declare const MAX_CREDENTIAL_BYTES: number;
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
export declare function defaultSeams(env?: NodeJS.ProcessEnv): SourceSeams;
export type CredentialSourceKind = 'env' | 'file' | 'exec' | 'github-app' | 'aws-sts' | 'vault' | 'clickup';
export interface EnvSourceSpec {
    type: 'env';
    /** Variable name. Read from the recorder's OWN environment, never the call's. */
    var: string;
}
export interface FileSourceSpec {
    type: 'file';
    path: string;
    /** Keep the file's trailing newline. Off by default: `echo tok > f` adds one. */
    keep_trailing_newline?: boolean;
    /** Opt in to a group-readable file (a shared CI runner, a deploy group). */
    allow_group_readable?: boolean;
}
export interface ExecSourceSpec {
    type: 'exec';
    /** Absolute path or PATH-resolvable command. No shell is used. */
    command: string;
    args?: string[];
    /**
     * Read this field out of the command's JSON stdout instead of taking the
     * whole of it — the `credential_process` / git-credential convention, e.g.
     * `SessionToken` from an AWS credential helper.
     */
    json_field?: string;
    /** Field holding an RFC 3339 expiry, when the helper reports one. */
    json_expiry_field?: string;
    timeout_ms?: number;
}
export interface GithubAppSourceSpec {
    type: 'github-app';
    app_id: string;
    installation_id: string;
    /** Where the PEM private key lives. Usually `file`; never inline. */
    private_key: CredentialSourceSpec;
    api_base?: string;
    /** Narrow the minted token, the reason to prefer this source over `env`. */
    repositories?: string[];
    permissions?: Record<string, string>;
    timeout_ms?: number;
}
export interface AwsStsSourceSpec {
    type: 'aws-sts';
    role_arn: string;
    region?: string;
    session_name?: string;
    duration_seconds?: number;
    access_key_id: CredentialSourceSpec;
    secret_access_key: CredentialSourceSpec;
    session_token?: CredentialSourceSpec;
    /**
     * What the single wire-shaped string contains. An AWS caller needs the
     * triple, not one token, so the default is the `credential_process` JSON
     * object every AWS SDK already understands; `session_token` is for a
     * consumer that genuinely wants the one field.
     */
    emit?: 'json' | 'session_token';
    endpoint?: string;
    timeout_ms?: number;
}
export interface VaultSourceSpec {
    type: 'vault';
    /** OpenBao/Vault address, e.g. `https://bao.internal:8200`. */
    addr: string;
    /** KV v2 mount. Default `secret`. */
    mount?: string;
    /** Path under the mount, e.g. `github/ci`. */
    path: string;
    /** Field within the KV blob. Default `token`, as NHI's vault blobs use. */
    field?: string;
    /** The OpenBao token itself — which lives in env or a file like everything else. */
    token: CredentialSourceSpec;
    namespace?: string;
    timeout_ms?: number;
}
export interface ClickupSourceSpec {
    type: 'clickup';
    token: CredentialSourceSpec;
    api_base?: string;
    /**
     * Check the token against `GET /v2/user` before handing it over. Off by
     * default: it is a network round trip on the forwarding path, and a
     * ClickUp personal token is long-lived, so the check tells you the token
     * still works — it does not make it short-lived or narrowly scoped.
     */
    verify?: boolean;
    timeout_ms?: number;
}
export type CredentialSourceSpec = EnvSourceSpec | FileSourceSpec | ExecSourceSpec | GithubAppSourceSpec | AwsStsSourceSpec | VaultSourceSpec | ClickupSourceSpec;
export interface ResolvedCredential {
    value: string;
    /** Unix ms at which the provider says the value stops working, when it says. */
    expiresAtMs?: number;
}
export interface CredentialSource {
    readonly kind: CredentialSourceKind;
    /** Resolve, or throw a {@link CredentialSourceError}. Never returns an empty value. */
    resolve(): Promise<ResolvedCredential>;
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
export declare const SOURCE_DEADLINE_MS: Record<CredentialSourceKind, number>;
/** Build the source described by `spec`. Pure — no I/O until `resolve()`. */
export declare function makeSource(spec: CredentialSourceSpec, seams: SourceSeams): CredentialSource;
/** Every source kind named anywhere in `spec`, including nested root credentials. */
export declare function sourceKinds(spec: CredentialSourceSpec): CredentialSourceKind[];
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
export declare const FILE_MODE_CHECK_APPLIES: boolean;
interface Sigv4Input {
    method: 'GET' | 'POST';
    url: URL;
    region: string;
    service: string;
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
    body: string;
    nowMs: number;
}
/**
 * SigV4 for the one request shape this file makes: a form-encoded POST with
 * no query string. Written out rather than pulled in, because the repo's rule
 * is node builtins over dependencies and the alternative is the AWS SDK.
 */
export declare function sigv4Headers(input: Sigv4Input): Record<string, string>;
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
export declare function xmlTag(doc: string, tag: string): string | undefined;
export interface ConfigTrustReport {
    /** Files inspected (policy, broker config). */
    paths: string[];
    /** True when the running uid can rewrite at least one of them. */
    writableByUs: boolean;
    /** Human-readable reasons, for the operator's stderr — never for a caller. */
    reasons: string[];
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
export declare function assessConfigTrust(paths: string[], opts?: {
    uid?: number;
    gids?: number[];
    statFile?: (p: string) => Promise<Stats>;
}): Promise<ConfigTrustReport>;
export {};

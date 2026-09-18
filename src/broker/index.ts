/**
 * Credential brokering — the barrel the rest of the recorder imports.
 *
 * WHAT BROKERING IS AND IS NOT, in one place, because every claim about it
 * has to survive an adversary who reads the source:
 *
 *   IT IS. The real credential is absent from the model's context and from
 *   the transcript — the agent composes a call carrying a synthetic and the
 *   swap happens after the tap, at a declared site. Every use of the real
 *   credential is a policy-checked decision, recorded under a decision id
 *   with the credential's id, its provider and its scopes, and revocable by
 *   editing one config entry (live within `BROKER_DEFAULT_TTL_SECONDS`, 30 s,
 *   not instantly).
 *
 *   IT IS NOT confidentiality against the agent on a single-uid developer
 *   machine. The agent can read the env var, the file or the exec command the
 *   broker reads, and it can read the config that names them; at rest the
 *   secret is in env/file/keychain and at use it is in this process's heap
 *   and in the upstream server's. Brokering becomes a confidentiality control
 *   only when the resolver runs as a principal the agent is not — a
 *   root-owned config with a root-owned resolver, or the hosted control
 *   plane. Prefer `github-app` / `aws-sts` even locally: they mint
 *   short-lived, narrowly-scoped tokens, which shrinks the window rather than
 *   the readership.
 *
 *   IT DOES NOT STOP prompt injection from CAUSING a use of the credential.
 *   Destination-bound swapping stops the token being exfiltrated through a
 *   reflecting tool; it does not stop an injected instruction asking for an
 *   authorised, policy-permitted call. The gain is that the use is recorded
 *   and bounded, not prevented.
 */

export {
  SYNTHETIC_PREFIX,
  BROKER_DEFAULT_TTL_SECONDS,
  mintSynthetic,
  mintPepper,
  isSyntheticShaped,
  hashSynthetic,
  syntheticHashesEqual,
  denyResponse,
  newDecisionId,
} from './protocol.js';
export type {
  Broker,
  BrokerExchangeRequest,
  BrokerExchangeResponse,
  DenyReason,
} from './protocol.js';

export {
  CredentialSourceError,
  FILE_MODE_CHECK_APPLIES,
  MAX_CREDENTIAL_BYTES,
  SOURCE_DEADLINE_MS,
  assessConfigTrust,
  defaultSeams,
  makeSource,
  sigv4Headers,
  sourceKinds,
  xmlTag,
} from './sources.js';
export type {
  AwsStsSourceSpec,
  ClickupSourceSpec,
  ConfigTrustReport,
  CredentialSource,
  CredentialSourceKind,
  CredentialSourceSpec,
  EnvSourceSpec,
  ExecSeamResult,
  ExecSourceSpec,
  FileSourceSpec,
  GithubAppSourceSpec,
  HttpSeamRequest,
  HttpSeamResponse,
  ResolvedCredential,
  SecretFile,
  SourceSeams,
  VaultSourceSpec,
} from './sources.js';

export {
  LocalBroker,
  MAX_DECISION_CACHE,
  SOURCE_UNHEALTHY_MS,
  credentialsConfigHash,
  matchRules,
  validateCredentialEntry,
  validateCredentials,
} from './local.js';
export type {
  BrokerDecisionRecord,
  ConfigTrust,
  CredentialEntry,
  CredentialRule,
  CredentialSwapSite,
  ExchangeContext,
  FieldBinding,
  LocalBrokerOptions,
} from './local.js';

export { RemoteBroker, REMOTE_TIMEOUT_MS } from './remote.js';
export type { RemoteBrokerOptions } from './remote.js';

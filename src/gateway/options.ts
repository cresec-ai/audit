/**
 * Gateway mode wiring contract between the CLI and the stdio proxy.
 *
 * `runStdioProxy` receives a `GatewayOptions` ONLY when the operator passed
 * `--policy` (or MCP_RECORDER_POLICY); when the field is absent the proxy is
 * the plain byte-for-byte, fail-open recorder. Kept in its own module so the
 * CLI, the proxy and the tests share one definition without importing each
 * other's internals.
 */

import type { LoadedPolicy } from '../policy/load.js';
import type { CredentialSwap } from './credentials.js';
import type { HoldStore } from './holds.js';

export interface GatewayOptions {
  /** The validated, normalized policy plus the hash/name stamped on events. */
  policy: LoadedPolicy;
  /** Where held calls are parked for `mcp-recorder approve|deny`. */
  holdStore: HoldStore;
  /** Poll interval for hold decisions (tests shrink it); default 200 ms. */
  pollMs?: number;
  /**
   * Additive: present ONLY when the policy declares a `credentials` section
   * AND a broker was configured. Absent = no call is ever rewritten and the
   * proxy behaves exactly as it did before credential brokering existed.
   * See ./credentials.ts for what the swap is and is not.
   */
  credentials?: CredentialSwap;
}

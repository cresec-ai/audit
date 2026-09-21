/**
 * The actor claim as every event carries it: a fresh copy per event, so a
 * later mutation of one event can never reach another (the same reason
 * `currentIdentity()` copies `credential_fingerprints`). The verified flag
 * rides beside the claim (`identity.actor_verified`), never inside it: the
 * claim itself stays ADR 012's shape byte for byte.
 */

import type { ActorClaim, IdentityContext } from '../schema/events.js';

/** What a proxy or the hook is started with: the claim and whether its signature was checked. */
export interface ActorStamp {
  actor: ActorClaim;
  verified: boolean;
}

export function cloneActor(actor: ActorClaim): ActorClaim {
  return {
    user: { ...actor.user },
    tool: { ...actor.tool },
    host: { ...actor.host },
    run_as: actor.run_as,
  };
}

/** Stamp `actor` and `actor_verified` on one event's identity block. */
export function stampActor(identity: IdentityContext, stamp: ActorStamp): void {
  identity.actor = cloneActor(stamp.actor);
  identity.actor_verified = stamp.verified;
}

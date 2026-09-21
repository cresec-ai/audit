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
export declare function cloneActor(actor: ActorClaim): ActorClaim;
/** Stamp `actor` and `actor_verified` on one event's identity block. */
export declare function stampActor(identity: IdentityContext, stamp: ActorStamp): void;

/**
 * The actor claim as every event carries it: a fresh copy per event, so a
 * later mutation of one event can never reach another (the same reason
 * `currentIdentity()` copies `credential_fingerprints`). The verified flag
 * rides beside the claim (`identity.actor_verified`), never inside it: the
 * claim itself stays ADR 012's shape byte for byte.
 */
export function cloneActor(actor) {
    return {
        user: { ...actor.user },
        tool: { ...actor.tool },
        host: { ...actor.host },
        run_as: actor.run_as,
    };
}
/** Stamp `actor` and `actor_verified` on one event's identity block. */
export function stampActor(identity, stamp) {
    identity.actor = cloneActor(stamp.actor);
    identity.actor_verified = stamp.verified;
}
//# sourceMappingURL=stamp.js.map
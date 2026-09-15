/**
 * FROZEN EVENT SCHEMA — v1
 * ========================
 * This is the contract between capture (M1), the tamper-evident store (M2),
 * and replay/query/export (M3). Treat every shipped field as frozen:
 * additive changes only; breaking changes require a new `SCHEMA` id.
 *
 * Field naming aligns with OpenTelemetry GenAI / RPC semantic conventions
 * where one exists (`gen_ai.*`, `rpc.*`, `error.*`, `mcp.*`) — see
 * docs/event-schema.md for the full mapping.
 *
 * Privacy posture: payloads never land in the store readable. String values
 * are replaced at the edge by `RedactedRef`s — a SHA-256 of the exact value
 * plus its length. Hashes are deliberately unsalted so a blast-radius query
 * can match a known probe value by hashing it the same way.
 */
export const SCHEMA = 'edut.mcp-recorder.event.v1';
//# sourceMappingURL=events.js.map
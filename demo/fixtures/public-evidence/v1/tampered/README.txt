This is a signed evidence bundle from @edut/mcp-recorder: 2 redacted MCP event(s), seq 1..2 of the full event chain, sealed in a SHA-256 hash chain.
How to verify (needs only Node.js, no packages):  node verify.cjs
PASS checks the present records against the declared range, hash chain and signed head under the bundled ed25519 public key. It does not prove all real activity was recorded or who controls that key.
Obtain the signer public key and expected head/range independently for stronger assurance; use node verify.cjs --public-key <hex-or-path> to pin the key. A never-recorded action or a self-consistent earlier history need not be detected.
Recording can drop events after failed appends; durable coverage/reconciliation is not complete. Enforcement applies only to mediated calls in explicitly selected gateway mode, never from a valid chain alone.
The generation time and tool version below are unsigned informational metadata, not a trusted timestamp.
Generated 2026-09-25T16:10:24.019Z by @edut/mcp-recorder v0.1.0; details in manifest.json.

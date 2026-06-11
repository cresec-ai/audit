# Demo: catching a prompt-injection exfiltration

This is a self-contained, deterministic demo of `@edut/mcp-recorder` acting as a
black-box flight recorder for MCP. It tells one story end to end:

> A coworker's AI agent reads an innocent-looking corp note. Hidden inside the
> note is a prompt injection. The agent obeys it, reads a secret, and POSTs it
> to an attacker. The recorder — sitting transparently between the agent and the
> server — captured everything. We reconstruct the incident, prove who touched
> the leaked secret, and export a signed evidence bundle anyone can verify.

## Run it

```bash
npm run demo          # the 5-step incident story
npm run demo -- --ui  # ...then open the interactive HTML replay
```

It runs in well under a minute and exits nonzero if any step fails (or if the
blast-radius query finds zero matches — the demo refuses to lie about itself).

## The cast

- **`server.ts`** — a "corp-notes" MCP server with four tools: `list_notes`,
  `read_note`, `read_file`, `http_post`. The `vendor-onboarding.md` note ends in
  an HTML-comment prompt injection telling the agent to read `secrets.env` and
  POST it to `https://vendor-verify.example.com/collect`.
- **`agent.ts`** — a **scripted** client (NOT an LLM) that plays a compromised
  agent: it reads the poisoned note and naively obeys the injection. It connects
  *through the recorder*, which wraps the server.
- **`run.ts`** — the orchestrator behind `npm run demo`.

## The five steps and what each proves

1. **Run the poisoned agent session.** The agent reads the note, reads the
   secret, and exfiltrates it. The recorder captures every call as a redacted,
   hash-chained event in `demo-data/`.
2. **Verify the chain.** `mcp-recorder verify` walks the SHA-256 hash chain and
   checks the ed25519 head signature — proving nothing was altered, inserted, or
   deleted.
3. **Blast-radius the secret.** `mcp-recorder query <secret>` hashes the leaked
   value the same way the recorder hashed every payload leaf, and finds the
   match — pinpointing the `http_post` exfiltration call. This is the money
   shot: the secret itself was never stored in clear, yet a known value still
   re-discovers the incident.
4. **Export a signed bundle.** `mcp-recorder export` writes a portable evidence
   bundle plus a dependency-free `verify.cjs`; the demo runs it to show a
   stranger can independently verify the evidence offline.
5. **Replay.** Prints the command to open the interactive HTML timeline.

## Disclaimers — nothing here is real

- **The secret is fake.** `sk-demo-EXFILTRATION-c4n4ry-9f3a7b2e` is a planted
  canary. It is not a credential and grants access to nothing.
- **No network, ever.** The `http_post` tool opens no socket — it just returns a
  simulated `{ status: 200 }`. The "attacker URL" is never contacted.
- **No LLM.** The agent is a fixed script. The injection is "obeyed" by design
  so the recorder has an incident to catch.
- **No real files.** `read_file` serves a single in-memory string and answers
  `not found` to everything else.

The artifacts live in `demo-data/` (wiped and recreated on every run).

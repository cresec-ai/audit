# Public evidence sample: what verification actually proves

This is a **synthetic educational fixture**, not a production workflow or a
recording of live customer activity. Two fictional MCP observations (a summary
read and a draft creation) pass through the real redactor, recorder, chain store
and exporter. No tool server, remote service, credential broker or enterprise
login is called. The fixture does not prove enforcement or workflow execution.

The checked-in [v1 sample](../demo/fixtures/public-evidence/v1/) contains two
ordinary `edut.mcp-recorder.bundle.v1` directories and a separate display
contract. No new evidence format or verifier is introduced. The generator
creates a fresh temporary signing key, exports only the public key, then removes
the temporary store and private key. Do not use the sample key as a production
trust anchor.

## Verify the published sample offline

From a checkout of this repository, with Node.js installed:

```sh
node demo/fixtures/public-evidence/v1/intact/verify.cjs
node demo/fixtures/public-evidence/v1/tampered/verify.cjs
```

The first exits **0 / PASS**. The second intentionally exits **1 / FAIL** with
`hash mismatch at seq 1`. Only `event.tool` in the first record was changed;
the chain hashes, manifest and signature were left untouched. Both copies run
the exact standalone `verify.cjs` supplied by the existing exporter. No npm
dependencies or network are required to run these two commands.

These checks trust the bundled public key only. If you have independently
obtained the expected signer key, run the existing verifier with
`--public-key <64-hex-or-PEM-path>`. Copying a key out of the bundle and passing
it back does **not** independently establish who signed it.

## Generate a fresh sample

In a development checkout, run the repository bootstrap once, then choose a new
output directory whose parent exists:

```sh
sh scripts/bootstrap.sh
npm run demo:sample -- --out /tmp/cresec-public-sample
node /tmp/cresec-public-sample/intact/verify.cjs
node /tmp/cresec-public-sample/tampered/verify.cjs
```

Bootstrap installs dependencies and can use the network. Sample generation and
verification themselves use no network. The generator refuses to overwrite an
existing destination. It asserts both expected outcomes before writing
`display.json`. Each run uses a fresh key and real generation timestamp, so
reproducibility means the same procedure and verdicts, **not identical artifact
bytes**. Fictional event timestamps are fixed and are not measured execution
times.

`display.json` records the fixture version, package version, source base commit,
generation time, Node version, raw-public-key fingerprint and every bundle
artifact's SHA-256. Source provenance is captured **before generation writes any
output**. `source_state` says whether the checkout is clean or dirty;
`source_changes` lists every tracked working-tree change relative to the base
commit and every nonignored untracked file. It hashes current working-tree bytes
even when an earlier version is staged, records deletions explicitly, and records
symlink-target hashes and filesystem modes. The `source_sha256` map is a lookup
over these changes, not a handpicked runtime-import list. For a clean checkout,
the base commit identifies repository source and the change list is empty.

This includes changes to store/schema modules and new local dependencies without
requiring a maintainer to update a file list. Keep source unchanged during
generation. Ignored files (including installed `node_modules`), dependency
installation integrity and the execution environment are **not attested**;
reproduce from the identified repository state with the committed lockfile.
These provenance fields and recorded verifier output are **unsigned informational
metadata**. The bundle's signature covers the chain head, not the display JSON,
generation date or package version. Do not treat a source hash as the source
contents or as proof that an installed dependency matches the lockfile.

## Four different questions

| Question | What this sample demonstrates | What it does not establish |
| --- | --- | --- |
| Integrity | The present records reproduce the declared chain and signed head under the supplied key; changing one event is rejected. | Who supplied the observations, whether they describe reality, or a trusted timestamp. |
| Coverage | Exactly two present records occupy the declared range. | Every real action being recorded. Failed appends can cause drops; durable spool/replay/reconciliation is not complete. |
| Enforcement | Nothing: the fixture models observation mode and has no policy decisions. | A policy having blocked a call, or coverage of unmediated tools. Explicit gateway mode governs only the mediated surface. |
| Signer and anchors | Internal consistency against the bundled key. | Independent signer identity or a known complete/latest history without separately trusted keys and head/range anchors. |

A never-recorded action cannot be recovered by verifying a chain. A
self-consistent earlier history or re-signed replacement is not guaranteed to
be detected without independently trusted expectations. Identity is
**unattributed**: the fingerprint is synthetic, no `identity.actor` or
`identity.actor_verified` claim is added. The local broker's ability to keep a
credential out of model context is not proof that no credential exists on the
agent's machine; this fixture exercises neither broker mode.

## Display contract for websites and other consumers

Read [display.json](../demo/fixtures/public-evidence/v1/display.json), pin a
reviewed repository revision when distributing it, and keep these fields together:

| Field | Display requirement |
| --- | --- |
| `sample`, `scenario`, `mode`, `actor_status` | Say “Synthetic sample · observation mode · unattributed”. Do not present it as the visitor's own run. |
| `safe_records`, `event_count`, `range` | Show structural tool names, IDs and illustrative timestamps only. Business prose belongs in a separately labeled simulation. |
| `verification.kind`, `observed_at`, `package_version` | Say “Sample verified on [date] with [version]”. This is a precomputed result, not a browser verification. |
| `verification.intact`, `verification.tampered` | Link each artifact and reproduction command. Display expected PASS and expected tamper FAIL without running a fake verification animation. |
| `signer`, `head_hash`, `artifact_sha256`, `generator` | Make provenance inspectable; bundled-key consistency is not independent signer trust. Hashes here are unsigned and require a trusted source for comparison. |
| `limitations` | Place the integrity, coverage, enforcement and trust limitations beside the result, not behind only a footnote. |

A consumer that executes the real verifier may show its fresh observed result
and timestamp. Otherwise its button should say **“View verification evidence”**
or **“Reproduce locally”**, never “Verify now” followed by an invented pass badge.
Do not imply the site's separate role-based business simulation produced these
records. Keep the original artifact bytes; changing readable payload into a new
presentation inside `events.jsonl` invalidates its signature.

The existing [scripted MCP demo](../demo/README.md) additionally exercises a fake
server through the proxy, including an opt-in enforcing policy. The
[event schema](event-schema.md), [security model](../README.md#security-model-the-honest-version)
and [connector coverage](connector-coverage.md) describe the wider boundaries.

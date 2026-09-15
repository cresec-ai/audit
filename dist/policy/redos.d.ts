/**
 * Catastrophic-backtracking (ReDoS) shapes in `match.args` regexes.
 *
 * Everything in the policy regex subset is linear-time under RE2 (the
 * compiled Rego runs there), but the local engine matches with V8's
 * backtracking `RegExp`, where a repeated group that can match the same text
 * in more than one way is exponential: `^(a+)+$` against 29 non-matching
 * characters takes ~14 s and, on the proxy thread, freezes every other
 * request behind it.
 *
 * Two layers defend against that. `regex-guard.ts` is the RUNTIME guarantee
 * (a hard deadline off the main thread); this module is the VALIDATION-TIME
 * one, rejecting the shapes that are clearly exponential before a policy is
 * ever loaded. It is deliberately a structural check, not a proof: it names
 * the shape it saw so the author can rewrite the pattern, and it is also what
 * the runtime guard consults when it has to fall back to in-thread matching.
 *
 * A group repeated by `*`, `+`, `{n,}`, `{n,m}` (m > 1) or `{n}` (n > 1) — a
 * trailing `?` is not a repetition — is rejected when its body:
 *
 *   1. contains a top-level alternation:  `(a|aa)+`, `(?:x|y)*`
 *   2. ends with a quantified atom:       `(a+)+`, `(\w+[ ]?)*`, `(ab?)*`
 *   3. ends with characters the repeated part can also match: `(.*a)*`
 *
 * Shape 3 is what separates `(.*a)*` (the `.*` swallows the trailing `a`, so
 * every iteration boundary is ambiguous) from `([a-z0-9-]+\.)*`, which stays
 * allowed: `.` is outside the repeated class, so it anchors every iteration
 * and the match is linear. An atom that can match the empty string (`x?`,
 * `x{0,3}`) never anchors, and a group never does either — the analysis
 * cannot see inside it, and a nested repeated group is the shape this module
 * exists to catch.
 */
/**
 * Why `pattern` has a clearly exponential shape under a backtracking engine,
 * or undefined when it does not. Never throws: an unparseable pattern (a
 * dangling `(`, a stray `)`) is somebody else's error and simply yields
 * undefined here.
 */
export declare function checkCatastrophicShape(pattern: string): string | undefined;

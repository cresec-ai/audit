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
 * the shape it saw so the author can rewrite the pattern.
 *
 * Two families are refused. First, a group repeated by `*`, `+`, `{n,}`,
 * `{n,m}` (m > 1) or `{n}` (n > 1) — a trailing `?` is not a repetition —
 * whose body:
 *
 *   1. contains a top-level alternation:  `(a|aa)+`, `(?:x|y)*`
 *   2. ends with a quantified atom:       `(a+)+`, `(\w+[ ]?)*`, `(ab?)*`
 *   3. ends with characters the repeated part can also match: `(.*a)*`
 *
 * A body whose last atom is itself a GROUP is re-analysed as if the outer
 * quantifier were written on the inner group: `((a+))+` is `(a+)+` wearing a
 * redundant wrapper, and `((a|aa))+`, `((?:a+))+`, `((a{1,2}))+` and
 * `(([a-z]+))+` are the same trick. Without that recursion the wrapper hides
 * the shape from the check and `^((a+))+$` takes 38 s at 30 characters.
 *
 * Shape 3 is what separates `(.*a)*` (the `.*` swallows the trailing `a`, so
 * every iteration boundary is ambiguous) from `([a-z0-9-]+\.)*`, which stays
 * allowed: `.` is outside the repeated class, so it anchors every iteration
 * and the match is linear. An atom that can match the empty string (`x?`,
 * `x{0,3}`) never anchors, and a group never does either — the analysis
 * cannot see inside it, and a nested repeated group is the shape this module
 * exists to catch.
 *
 * Second, ADJACENT repeated atoms that can match the same characters, at any
 * nesting level and with no group involved at all: `[a-z]*[a-z]*[a-z]*x`,
 * `\w+\w+`, `a+a*`. Every way of splitting the input between them is tried,
 * which is polynomial in the number of such atoms — `^[a-z]*[a-z]*[a-z]*x$`
 * against a 4096-character value (the `REGEX_VALUE_CAP` a single argument can
 * reach) takes 8.6 s here, where RE2 answers instantly.
 *
 * {@link checkProvablyLinear} is the stricter, POSITIVE form of the same
 * analysis: it is what the runtime guard consults when it has no worker
 * thread and has to decide whether a pattern may be run on the proxy thread
 * at all. Absence of a known-bad shape is not enough there, so that check
 * additionally refuses every repeated group, more than
 * {@link MAX_LINEAR_REPEATS} repeated atoms and more than
 * {@link MAX_LINEAR_BRANCHES} alternation branches.
 */
/** Max repeated (`*`, `+`, `{n,m}`) atoms a pattern may have to stay in-thread runnable. */
export declare const MAX_LINEAR_REPEATS = 2;
/** Max product of alternation branch counts a pattern may have to stay in-thread runnable. */
export declare const MAX_LINEAR_BRANCHES = 64;
/**
 * Why `pattern` has a clearly exponential (or badly polynomial) shape under a
 * backtracking engine, or undefined when it does not. Never throws: an
 * unparseable pattern (a dangling `(`, a stray `)`) is somebody else's error
 * and simply yields undefined here.
 */
export declare function checkCatastrophicShape(pattern: string): string | undefined;
/**
 * Why `pattern` may NOT be matched on the proxy thread, or undefined when it
 * provably runs in (at worst low-degree polynomial) bounded time.
 *
 * This is the fail-closed twin of {@link checkCatastrophicShape}: there,
 * absence of a known-bad shape is enough to load a policy, because at run
 * time the worker's hard deadline is what actually bounds the match. With no
 * worker there is nothing to abandon a runaway match, so a pattern gets to
 * run in-thread only if it is positively cleared here:
 *
 * - it parses, and has none of the catastrophic shapes;
 * - no group carries a repeating quantifier at all (`(...)+` is the whole
 *   exponential family; a wrapper cannot hide one from this rule);
 * - at most {@link MAX_LINEAR_REPEATS} repeated atoms in the entire pattern,
 *   so the worst case stays quadratic in the value length (~8 ms at the
 *   4096-character `REGEX_VALUE_CAP`, measured);
 * - at most {@link MAX_LINEAR_BRANCHES} alternation paths, so a pattern
 *   cannot multiply its way to an exponential number of them.
 */
export declare function checkProvablyLinear(pattern: string): string | undefined;

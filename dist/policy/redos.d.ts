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
 * That second rule looks THROUGH parentheses that are pure concatenation. A
 * group carrying no quantifier and no top-level alternation means exactly what
 * its body means — `([a-z]+)([a-z]+)([a-z]+)x` IS `[a-z]+[a-z]+[a-z]+x`, and
 * the same 4096-character value takes 8.2 s against the first spelling and
 * 8.6 s against the second (measured; with a fourth group, 22 s at 512
 * characters alone). Such a group is therefore inlined into its parent branch
 * before the adjacency scan, so the two spellings of one regex get one answer
 * instead of the group form slipping through as "opaque". Parentheses that are
 * repeated (`([a-z0-9-]+\.)*`) or that alternate (`(^|/)`) are NOT pure
 * concatenation and stay opaque here; the first family above is what looks
 * inside those.
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
 * Work an in-thread match may cost before it is refused instead.
 *
 * {@link MAX_LINEAR_REPEATS} repeated atoms cost about `valueLength` to that
 * power: two of them over a 4096-character value is 16.7 million steps —
 * certified as linear, run on the proxy's only thread, with no deadline that
 * can interrupt it, blocking every concurrent call until it finishes. It is
 * polynomial rather than exponential, which is why it is not a shape
 * problem, but "not exponential" is not the same as "safe to run
 * uninterruptibly".
 *
 * The number is deliberately far inside the deadline rather than level with
 * it. A step costs 0.5-1 ns here — `^.{0,4096}a.{0,4096}b$` at the value cap
 * measured 13 ms for its 16.7 million — but that constant moves with the
 * pattern, the machine and the load, and the whole point of this path is
 * that nothing can interrupt a bad guess. 400k steps is two orders of
 * magnitude under a 25 ms deadline on this hardware, which is the margin
 * that buys.
 *
 * It bounds cost that grows with the value, not absolute time: one repeated
 * atom over a big enough value still overruns, which is why the deadline
 * check after the match stays.
 *
 * Only the no-worker fallback consults it, and a value it refuses denies —
 * the same fail-closed answer that path already gives a pattern it cannot
 * prove linear.
 */
export declare const MAX_IN_THREAD_STEPS = 400000;
/**
 * Why `pattern` has a clearly exponential (or badly polynomial) shape under a
 * backtracking engine, or undefined when it does not. Never throws: an
 * unparseable pattern (a dangling `(`, a stray `)`) is somebody else's error
 * and simply yields undefined here.
 */
export declare function checkCatastrophicShape(pattern: string): string | undefined;
export declare function checkProvablyLinear(pattern: string, valueLength?: number): string | undefined;

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
/** How deep {@link shapeProblem} re-enters trailing groups before giving up and refusing. */
const MAX_WRAPPER_DEPTH = 32;
/** Max repeated (`*`, `+`, `{n,m}`) atoms a pattern may have to stay in-thread runnable. */
export const MAX_LINEAR_REPEATS = 2;
/** Max product of alternation branch counts a pattern may have to stay in-thread runnable. */
export const MAX_LINEAR_BRANCHES = 64;
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
export const MAX_IN_THREAD_STEPS = 400_000;
/**
 * Characters the overlap test probes: all of ASCII plus representative
 * non-ASCII ones. Two of the five non-ASCII probes used to be plain ASCII
 * spaces — a non-breaking and an ideographic space that had been normalized
 * away at some point — so the Latin-1 band had no probe at all and
 * `[\xa0-\xa5]` overlapped with nothing.
 */
const PROBE_CHARS = (() => {
    const chars = [];
    for (let c = 0; c < 128; c++)
        chars.push(String.fromCharCode(c));
    const nonAscii = [
        '\u00a0', // NO-BREAK SPACE: the start of the Latin-1 supplement
        '\u00a3', // POUND SIGN: Latin-1 punctuation
        '\u00e9', // é: a Latin-1 letter
        '\u0301', // COMBINING ACUTE ACCENT: a mark
        '\u0430', // а: Cyrillic
        '\u2028', // LINE SEPARATOR: a line terminator the two engines argue about
        '\u3000', // IDEOGRAPHIC SPACE
        '\u4e2d', // 中: CJK
        '\ud83d\ude00', // an astral code point, as its surrogate pair
    ];
    return [...chars, ...nonAscii];
})();
/** `{2}`, `{2,}`, `{2,5}` starting at `at` (a `{`), or undefined when it is a literal brace. */
function braceQuantifier(pattern, at) {
    const close = pattern.indexOf('}', at);
    if (close === -1)
        return undefined;
    const body = pattern.slice(at + 1, close);
    const m = /^([0-9]+)(,([0-9]*)?)?$/.exec(body);
    if (m === null)
        return undefined;
    const min = Number(m[1]);
    const max = m[2] === undefined ? min : m[3] === undefined || m[3] === '' ? Infinity : Number(m[3]);
    return { text: pattern.slice(at, close + 1), min, max };
}
/** True when the quantifier can run its atom more than once (`?` and `{0,1}` cannot). */
function repeats(quant) {
    if (quant.startsWith('*') || quant.startsWith('+'))
        return true;
    if (quant.startsWith('?'))
        return false;
    const parsed = braceQuantifier(quant, 0);
    return parsed !== undefined && parsed.max > 1;
}
/** True when the quantifier lets its atom match the empty string. */
function optional(quant) {
    if (quant.startsWith('*') || quant.startsWith('?'))
        return true;
    if (quant.startsWith('+'))
        return false;
    const parsed = braceQuantifier(quant, 0);
    return parsed !== undefined && parsed.min === 0;
}
/** True when this atom is run more than once by its own quantifier. */
function isRepeated(atom) {
    return atom.quant !== undefined && repeats(atom.quant);
}
/** Length of the escape sequence starting at `at` (a backslash). */
function escapeLength(pattern, at) {
    if (pattern[at + 1] === 'x' && /^[0-9A-Fa-f]{2}$/.test(pattern.slice(at + 2, at + 4)))
        return 4;
    return pattern[at + 1] === undefined ? 1 : 2;
}
/** Index just past the `]` that closes the class opened at `at`, or the end of the pattern. */
function classEnd(pattern, at) {
    let i = at + 1;
    if (pattern[i] === '^')
        i++;
    if (pattern[i] === ']')
        i++; // a leading "]" is a literal in RE2 (the subset check rejects it separately)
    for (; i < pattern.length; i++) {
        if (pattern[i] === '\\') {
            i += escapeLength(pattern, i) - 1;
            continue;
        }
        if (pattern[i] === ']')
            return i + 1;
    }
    return pattern.length;
}
/** Length of a group's opening punctuation: `(`, `(?:`, `(?<name>`, ... */
function groupPrefixLength(pattern, at) {
    if (pattern[at + 1] !== '?')
        return 1;
    const third = pattern[at + 2];
    if (third === '<' && pattern[at + 3] !== '=' && pattern[at + 3] !== '!') {
        const close = pattern.indexOf('>', at + 3);
        return close === -1 ? 3 : close - at + 1;
    }
    return third === undefined ? 2 : 3;
}
/** Attach the quantifier written at `at` to `atom`, returning its length (0 when there is none). */
function readQuantifier(pattern, at) {
    const ch = pattern[at];
    if (ch === '*' || ch === '+' || ch === '?') {
        return pattern[at + 1] === '?' ? `${ch}?` : ch;
    }
    if (ch === '{') {
        const brace = braceQuantifier(pattern, at);
        if (brace === undefined)
            return undefined;
        return pattern[at + brace.text.length] === '?' ? `${brace.text}?` : brace.text;
    }
    return undefined;
}
/** Can `text` (one atom, verbatim) match the single character `ch`? Undefined when it cannot be compiled. */
function matcher(text) {
    try {
        const re = new RegExp(`^(?:${text})$`);
        return (ch) => re.test(ch);
    }
    catch {
        return undefined;
    }
}
/** True when `anchor` provably matches no character `repeated` matches — then it anchors each iteration. */
function anchors(repeated, anchor) {
    if (anchor.group || anchor.zeroWidth)
        return false;
    if (anchor.quant !== undefined && optional(anchor.quant))
        return false;
    if (repeated.group)
        return false; // an opaque body: assume it can swallow the anchor
    const repeatedMatches = matcher(repeated.text);
    const anchorMatches = matcher(anchor.text);
    if (repeatedMatches === undefined || anchorMatches === undefined)
        return false;
    let anchorMatchedSomething = false;
    for (const ch of PROBE_CHARS) {
        if (!anchorMatches(ch))
            continue;
        anchorMatchedSomething = true;
        if (repeatedMatches(ch))
            return false;
    }
    return anchorMatchedSomething;
}
/** True when the two atoms can match the same character (assumed when either cannot be compiled). */
function overlap(a, b) {
    const am = matcher(a.text);
    const bm = matcher(b.text);
    if (am === undefined || bm === undefined)
        return true; // cannot tell: assume the worst
    let sawA = false;
    let sawB = false;
    for (const ch of PROBE_CHARS) {
        const inA = am(ch);
        const inB = bm(ch);
        if (inA && inB)
            return true;
        sawA ||= inA;
        sawB ||= inB;
    }
    // No probe landed in one of the sets, so the probes say nothing about it.
    // Reading that as "disjoint" is what let `[\xa0-\xa5]*[\xa0-\xa5]*` past
    // the adjacent-atom rule; it is an absence of evidence, so assume overlap.
    return !sawA || !sawB;
}
/**
 * True when two branches of an alternation can match the same input, which
 * makes a repetition around it ambiguous: the engine has more than one way
 * to consume the same characters, and on a non-matching tail it tries all of
 * them. `(?:b|b)`, `(?:[b]|b)`, `(?:a[bc]|a[cd])` and `(?:ab|a)` are all
 * ambiguous; `(?:b|c)` is not, which is why a trailing alternation is not
 * rejected outright.
 *
 * The rules split by WHERE the ambiguity leaves the engine, because that is
 * what decides whether the alternation's position in the body matters:
 *
 * - SAME-SPAN ambiguity — the branches can match the same text, so the
 *   engine has two ways to consume one span and the atoms after it see the
 *   same position either way. Two branches are same-span ambiguous when they
 *   are written identically, or when they have the same number of atoms and
 *   every atom can match a character its opposite can. This holds wherever
 *   the alternation sits.
 * - PREFIX ambiguity — one branch is the start of the other, so the two ways
 *   differ in how much they consume. That is only exponential when the next
 *   thing along can pick up the difference, which is the case when the
 *   alternation ENDS the repeated body and the next iteration follows it. In
 *   the middle of a body the following atoms pin the boundary and the match
 *   is deterministic: `(?:(?:a|ab)c)+` has one way to match each iteration.
 *
 * `sameSpanOnly` asks for the first kind alone, for an alternation somewhere
 * inside the body rather than at the end of it.
 */
function ambiguousAlternation(frame, sameSpanOnly = false) {
    const branches = frame.branches.map((b) => b.filter((a) => !a.zeroWidth));
    const key = (branch) => branch.map(atomText).join('\u0000');
    for (let i = 0; i < branches.length; i++) {
        for (let j = i + 1; j < branches.length; j++) {
            const a = branches[i];
            const b = branches[j];
            if (a.length === 0 || b.length === 0)
                continue; // an empty branch is `?`, not ambiguity
            if (key(a) === key(b))
                return true;
            // Atom for atom, each can match a character the other can: the two
            // branches can consume the same span. Testing this only when both
            // branches were a SINGLE atom left `(?:a[bc]|a[cd])` — same defect,
            // one atom wider — accepted, at 56 ms on 61 characters.
            if (a.length === b.length && a.every((atom, k) => overlap(atom, b[k])))
                return true;
            if (sameSpanOnly)
                continue;
            const short = a.length <= b.length ? a : b;
            const long = a.length <= b.length ? b : a;
            if (short.every((atom, k) => atomText(atom) === atomText(long[k])))
                return true;
        }
    }
    return false;
}
/**
 * Every alternation frame strictly inside `frame`, innermost last. The body
 * of a repeated group is ambiguous wherever one of these is, not only when
 * one ends it.
 */
function innerAlternations(frame) {
    const out = [];
    const walk = (f) => {
        for (const branch of f.branches) {
            for (const atom of branch) {
                if (atom.frame === undefined)
                    continue;
                if (atom.frame.branches.length > 1)
                    out.push(atom.frame);
                walk(atom.frame);
            }
        }
    };
    walk(frame);
    return out;
}
const ADVICE = 'JavaScript backtracks exponentially on a non-matching input, where RE2 (the compiled Rego) stays linear;' +
    ' end each repetition with something the repeated part cannot match, e.g. "([a-z0-9-]+\\.)*"';
const ADJACENT_ADVICE = 'JavaScript tries every way of splitting the input between them, where RE2 (the compiled Rego) stays linear;' +
    ' make the character sets disjoint or drop one of the quantifiers, e.g. "[a-z]+[0-9]*"';
/** Source text of one atom including its quantifier. */
function atomText(a) {
    return `${a.text}${a.quant ?? ''}`;
}
/** How an atom is named in a message: the group it was the whole of, when it had one. */
function shownText(a) {
    return a.written ?? atomText(a);
}
/**
 * Why the group whose body is `frame`, repeated by the quantifier that makes
 * `label` (the group source plus that quantifier), is exponential — or
 * undefined. `depth` counts the redundant wrappers already seen through.
 */
function shapeProblem(frame, label, depth) {
    const group = JSON.stringify(label);
    if (depth > MAX_WRAPPER_DEPTH) {
        return `regex shape ${group} nests repeated groups too deeply to analyse: ${ADVICE}`;
    }
    if (frame.branches.length > 1) {
        return `regex shape ${group} repeats a group whose body contains an alternation (like "(a|aa)+"): ${ADVICE}`;
    }
    const atoms = frame.branches[0].filter((a) => !a.zeroWidth);
    if (atoms.length === 0)
        return undefined;
    const last = atoms[atoms.length - 1];
    if (last.quant !== undefined) {
        return (`regex shape ${group} repeats a group whose body ends with the quantified atom ` +
            `${JSON.stringify(atomText(last))} (like "(a+)+"): ${ADVICE}`);
    }
    if (last.group && last.frame !== undefined) {
        // A group that IS the body is a redundant wrapper around the real
        // repetition: `((a+))+` is `(a+)+` and `((a|aa))+` is `(a|aa)+`.
        // Re-analyse it as if the outer quantifier had been written on it.
        if (atoms.length === 1)
            return shapeProblem(last.frame, label, depth + 1);
        // A trailing group with no alternation of its own is plain concatenation,
        // so splice its atoms into the body: `(b(.*a))*` is `(b.*a)*`. With an
        // alternation inside it that is not true in general — the branches are
        // anchored by what precedes them — so `(?:a(?:b|c))+` stays allowed and
        // the group stays opaque. UNLESS the branches can match the same text:
        // `(?:a(?:b|b))+` then has two ways to consume every iteration and
        // backtracks exponentially on a non-matching tail, which is the same
        // defect as `(a|aa)+` one level down.
        const inner = last.frame.branches[0];
        if (last.frame.branches.length === 1) {
            const spliced = { branches: [[...atoms.slice(0, -1), ...inner]], openedAt: frame.openedAt };
            return shapeProblem(spliced, label, depth + 1);
        }
        if (ambiguousAlternation(last.frame)) {
            return (`regex shape ${group} repeats a group ending in an alternation whose branches can match the same ` +
                `text (like "(?:a(?:b|b))+"): ${ADVICE}`);
        }
    }
    // An ambiguous alternation ANYWHERE in the body makes the body ambiguous,
    // not only one that ends it. The check above reaches an alternation only
    // as the body's last atom, so a single trailing character re-hid the
    // shape: `(?:a(?:b|b))+` was rejected and `(?:a(?:b|b)c)+` — the same two
    // ways to match every iteration — was accepted, at 55 ms on 61 characters
    // and doubling every three.
    for (const inner of innerAlternations(frame)) {
        if (!ambiguousAlternation(inner, true))
            continue;
        return (`regex shape ${group} repeats a group containing an alternation whose branches can match the same ` +
            `text (like "(?:a(?:b|b)c)+"): ${ADVICE}`);
    }
    let repeatedAt = -1;
    for (let i = atoms.length - 1; i >= 0; i--) {
        if (isRepeated(atoms[i])) {
            repeatedAt = i;
            break;
        }
    }
    if (repeatedAt === -1)
        return undefined;
    const repeated = atoms[repeatedAt];
    for (let i = repeatedAt + 1; i < atoms.length; i++) {
        if (anchors(repeated, atoms[i]))
            return undefined;
    }
    const tail = atoms.slice(repeatedAt + 1).map(atomText).join('');
    return (`regex shape ${group} repeats a group whose trailing ${JSON.stringify(tail)} can also be matched by ` +
        `${JSON.stringify(atomText(repeated))} in front of it (like "(.*a)*"): ${ADVICE}`);
}
/**
 * `branch` with every PLAIN group — one that carries no quantifier and has no
 * top-level alternation — replaced by the atoms of its body, recursively.
 *
 * Such parentheses are pure concatenation: `(a)(b)` matches exactly what `ab`
 * matches, and `([a-z]+)([a-z]+)x` exactly what `[a-z]+[a-z]+x` matches. The
 * adjacency rule below therefore has to see through them, or the identical
 * regex is judged twice over — rejected written with bare atoms, accepted
 * written with a pair of redundant parentheses around each one.
 *
 * A group with a quantifier is left alone: inlining `(ab)?` or `(ab)*` would
 * change what the branch matches, and a REPEATED group is {@link shapeProblem}'s
 * business. A group with a top-level alternation is left alone too: its
 * branches are alternatives, not a concatenation, so there is no single list of
 * atoms to splice in. When the inlined body is a single atom the group source
 * rides along in {@link Atom.written} so the message can quote the pattern as
 * the author typed it.
 */
function inlinePlainGroups(branch, depth) {
    const out = [];
    for (const atom of branch) {
        const frame = atom.frame;
        const plain = atom.group && atom.quant === undefined && frame !== undefined && frame.branches.length === 1;
        if (!plain || frame === undefined || depth >= MAX_WRAPPER_DEPTH) {
            out.push(atom);
            continue;
        }
        const inner = inlinePlainGroups(frame.branches[0], depth + 1);
        const consuming = inner.filter((a) => !a.zeroWidth);
        // `([a-z]+)` is one atom wearing parentheses: keep the source for the message.
        if (consuming.length === 1)
            out.push({ ...consuming[0], written: atom.text });
        else
            out.push(...inner);
    }
    return out;
}
/**
 * Why one alternation branch has two repeated atoms that can match the same
 * characters, with nothing in between that has to be consumed — or undefined.
 * `[a-z]*[a-z]*x` is the shape; `[a-z]+\.` and `.*secret.*` are not (the
 * second atom of each pair is anchored by text the first cannot swallow, or
 * separated by a literal that must be consumed).
 *
 * Call it on a branch that has been through {@link inlinePlainGroups}, so that
 * `([a-z]+)([a-z]+)x` is seen as the `[a-z]+[a-z]+x` it is.
 */
function adjacentProblem(branch) {
    for (let i = 0; i < branch.length; i++) {
        const first = branch[i];
        if (first.zeroWidth || first.group || !isRepeated(first))
            continue;
        for (let j = i + 1; j < branch.length; j++) {
            const next = branch[j];
            if (next.zeroWidth)
                continue;
            if (next.group)
                break; // opaque: `shapeProblem` is what looks inside groups
            if (isRepeated(next) && overlap(first, next)) {
                return (`regex shape ${JSON.stringify(shownText(first) + shownText(next))} repeats two adjacent atoms that can match ` +
                    `the same characters (like "\\w+\\w+" or "([a-z]+)([a-z]+)x"): ${ADJACENT_ADVICE}`);
            }
            if (next.quant !== undefined && optional(next.quant))
                continue; // can be skipped entirely
            break;
        }
    }
    return undefined;
}
/**
 * Parse `pattern` into frames. `balanced` is false when the parentheses do
 * not match (a stray `)`, an unclosed `(`): somebody else's error to report,
 * and never a reason to claim a pattern is safe.
 */
function parsePattern(pattern) {
    const root = { branches: [[]], openedAt: 0 };
    const stack = [root];
    let problem;
    let i = 0;
    while (i < pattern.length) {
        const frame = stack[stack.length - 1];
        const branch = frame.branches[frame.branches.length - 1];
        const ch = pattern[i];
        let atom;
        let next = i + 1;
        if (ch === '\\') {
            const len = escapeLength(pattern, i);
            const letter = pattern[i + 1];
            atom = { text: pattern.slice(i, i + len), group: false, zeroWidth: letter === 'b' || letter === 'B' };
            next = i + len;
        }
        else if (ch === '[') {
            const end = classEnd(pattern, i);
            atom = { text: pattern.slice(i, end), group: false, zeroWidth: false };
            next = end;
        }
        else if (ch === '(') {
            stack.push({ branches: [[]], openedAt: i });
            i += groupPrefixLength(pattern, i);
            continue;
        }
        else if (ch === ')') {
            if (stack.length === 1)
                return { root, balanced: false, ...(problem === undefined ? {} : { problem }) }; // stray ")"
            const closed = stack.pop();
            const parent = stack[stack.length - 1];
            const parentBranch = parent.branches[parent.branches.length - 1];
            const quant = readQuantifier(pattern, i + 1);
            atom = { text: pattern.slice(closed.openedAt, i + 1), group: true, zeroWidth: false, frame: closed };
            if (quant !== undefined) {
                atom.quant = quant;
                if (repeats(quant) && problem === undefined) {
                    problem = shapeProblem(closed, `${atom.text}${quant}`, 0);
                }
            }
            parentBranch.push(atom);
            i = i + 1 + (quant?.length ?? 0);
            continue;
        }
        else if (ch === '|') {
            frame.branches.push([]);
            i++;
            continue;
        }
        else if (ch === '*' || ch === '+' || ch === '?' || ch === '{') {
            // A quantifier with nothing to quantify (or a literal `{`): treat it as a plain character.
            const quant = readQuantifier(pattern, i);
            const target = branch[branch.length - 1];
            if (quant !== undefined && target !== undefined && target.quant === undefined) {
                target.quant = quant;
                i += quant.length;
                continue;
            }
            atom = { text: ch, group: false, zeroWidth: false };
            next = i + 1;
        }
        else {
            atom = { text: ch, group: false, zeroWidth: ch === '^' || ch === '$' };
            next = i + 1;
        }
        branch.push(atom);
        i = next;
    }
    const balanced = stack.length === 1;
    return { root, balanced, ...(problem === undefined ? {} : { problem }) };
}
/** Every frame of a parse, outermost first. */
function allFrames(root) {
    return framesWithOwners(root).map((f) => f.frame);
}
/** Every frame of a parse with the atom that owns it (undefined for the root). */
function framesWithOwners(root) {
    const out = [];
    const walk = (frame, owner) => {
        out.push(owner === undefined ? { frame } : { frame, owner });
        for (const branch of frame.branches) {
            for (const atom of branch)
                if (atom.frame !== undefined)
                    walk(atom.frame, atom);
        }
    };
    walk(root);
    return out;
}
/**
 * Why `pattern` has a clearly exponential (or badly polynomial) shape under a
 * backtracking engine, or undefined when it does not. Never throws: an
 * unparseable pattern (a dangling `(`, a stray `)`) is somebody else's error
 * and simply yields undefined here.
 */
export function checkCatastrophicShape(pattern) {
    const parsed = parsePattern(pattern);
    if (parsed.problem !== undefined)
        return parsed.problem;
    if (!parsed.balanced)
        return undefined;
    for (const frame of allFrames(parsed.root)) {
        for (const branch of frame.branches) {
            const why = adjacentProblem(inlinePlainGroups(branch, 0));
            if (why !== undefined)
                return why;
        }
    }
    return undefined;
}
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
/**
 * True when every match must start at offset 0, so the engine runs the
 * pattern once rather than once per starting position.
 *
 * Conservative on purpose: a top-level alternation is not anchored even when
 * one branch is (`^a|b` can start anywhere), so only a single-branch pattern
 * beginning with `^` counts.
 */
function startsAnchored(root) {
    if (root.branches.length !== 1)
        return false;
    const first = root.branches[0][0];
    return first !== undefined && first.zeroWidth && first.text === '^';
}
export function checkProvablyLinear(pattern, valueLength) {
    const parsed = parsePattern(pattern);
    const shape = checkCatastrophicShape(pattern);
    if (shape !== undefined)
        return shape;
    if (!parsed.balanced)
        return 'the pattern could not be parsed for a linearity proof';
    let repeatedAtoms = 0;
    let branches = 1;
    for (const { frame, owner } of framesWithOwners(parsed.root)) {
        // An OPTIONAL group has one more path than it has branches: skipping it
        // entirely. `(?:a|a)?` is three ways to read the same input, not two,
        // and six of them chained are 729 paths where this counted 64.
        const skippable = owner?.quant !== undefined && optional(owner.quant);
        branches *= frame.branches.length + (skippable ? 1 : 0);
        if (branches > MAX_LINEAR_BRANCHES) {
            return `the pattern has more than ${MAX_LINEAR_BRANCHES} alternation paths, which cannot be proved linear`;
        }
        for (const branch of frame.branches) {
            for (const atom of branch) {
                if (!isRepeated(atom))
                    continue;
                if (atom.group) {
                    return `the repeated group ${JSON.stringify(atomText(atom))} cannot be proved linear`;
                }
                repeatedAtoms++;
            }
        }
    }
    if (repeatedAtoms > MAX_LINEAR_REPEATS) {
        return `the pattern has ${repeatedAtoms} repeated quantifiers (more than ${MAX_LINEAR_REPEATS}), which cannot be proved linear`;
    }
    // Linear in the pattern is not the same as cheap on THIS value: see
    // MAX_IN_THREAD_STEPS. Asked without a value this stays the pure shape
    // question, which is what `policy validate` wants.
    //
    // An UNANCHORED pattern is also run once per starting position, and that
    // loop multiplies whatever the repeats cost — it is not free just because
    // it is implicit. `a.*b` has one repeat and is quadratic: measured 0.47 ms
    // at 1000 characters, 2 ms at 2000, 7 ms at 4000, while the anchored
    // `^a.*b$` stays at 0.00 ms throughout. Charging only the repeats
    // certified the first as linear. The loop costs a factor only when there
    // is a repeat inside it to multiply; a fixed-width pattern scanned at
    // every position is linear in the value.
    const exponent = repeatedAtoms === 0 ? 1 : repeatedAtoms + (startsAnchored(parsed.root) ? 0 : 1);
    if (valueLength !== undefined && exponent > 1 && valueLength > 1) {
        const steps = Math.pow(valueLength, exponent);
        if (steps > MAX_IN_THREAD_STEPS) {
            const why = exponent > repeatedAtoms
                ? `${repeatedAtoms} repeated quantifier${repeatedAtoms === 1 ? '' : 's'} and no \`^\` anchor`
                : `${repeatedAtoms} repeated quantifiers`;
            return (`the pattern's ${why} cost up to ${valueLength}^${exponent} steps on a ` +
                `${valueLength}-character value, over the ${MAX_IN_THREAD_STEPS} an uninterruptible match may take`);
        }
    }
    return undefined;
}
//# sourceMappingURL=redos.js.map
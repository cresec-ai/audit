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
/** Characters the overlap test probes: all of ASCII plus a few representative non-ASCII ones. */
const PROBE_CHARS = (() => {
    const chars = [];
    for (let c = 0; c < 128; c++)
        chars.push(String.fromCharCode(c));
    return [...chars, ' ', 'é', 'а', ' ', '中'];
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
const ADVICE = 'JavaScript backtracks exponentially on a non-matching input, where RE2 (the compiled Rego) stays linear;' +
    ' end each repetition with something the repeated part cannot match, e.g. "([a-z0-9-]+\\.)*"';
/** Why the group closed at `frame` and repeated by `quant` is exponential, or undefined. */
function shapeProblem(frame, pattern, closeAt, quant) {
    const group = `${pattern.slice(frame.openedAt, closeAt + 1)}${quant}`;
    if (frame.alternation) {
        return `regex shape ${JSON.stringify(group)} repeats a group whose body contains an alternation (like "(a|aa)+"): ${ADVICE}`;
    }
    const atoms = frame.atoms.filter((a) => !a.zeroWidth);
    if (atoms.length === 0)
        return undefined;
    const last = atoms[atoms.length - 1];
    if (last.quant !== undefined) {
        return (`regex shape ${JSON.stringify(group)} repeats a group whose body ends with the quantified atom ` +
            `${JSON.stringify(`${last.text}${last.quant}`)} (like "(a+)+"): ${ADVICE}`);
    }
    let repeatedAt = -1;
    for (let i = atoms.length - 1; i >= 0; i--) {
        const q = atoms[i].quant;
        if (q !== undefined && repeats(q)) {
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
    const tail = atoms
        .slice(repeatedAt + 1)
        .map((a) => `${a.text}${a.quant ?? ''}`)
        .join('');
    return (`regex shape ${JSON.stringify(group)} repeats a group whose trailing ${JSON.stringify(tail)} can also be matched by ` +
        `${JSON.stringify(`${repeated.text}${repeated.quant ?? ''}`)} in front of it (like "(.*a)*"): ${ADVICE}`);
}
/**
 * Why `pattern` has a clearly exponential shape under a backtracking engine,
 * or undefined when it does not. Never throws: an unparseable pattern (a
 * dangling `(`, a stray `)`) is somebody else's error and simply yields
 * undefined here.
 */
export function checkCatastrophicShape(pattern) {
    const root = { atoms: [], alternation: false, openedAt: 0 };
    const stack = [root];
    let i = 0;
    while (i < pattern.length) {
        const frame = stack[stack.length - 1];
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
            stack.push({ atoms: [], alternation: false, openedAt: i });
            i += groupPrefixLength(pattern, i);
            continue;
        }
        else if (ch === ')') {
            if (stack.length === 1)
                return undefined; // unbalanced: not our error to report
            const closed = stack.pop();
            const parent = stack[stack.length - 1];
            const quant = readQuantifier(pattern, i + 1);
            atom = { text: pattern.slice(closed.openedAt, i + 1), group: true, zeroWidth: false };
            if (quant !== undefined) {
                atom.quant = quant;
                if (repeats(quant)) {
                    const why = shapeProblem(closed, pattern, i, quant);
                    if (why !== undefined)
                        return why;
                }
            }
            parent.atoms.push(atom);
            i = i + 1 + (quant?.length ?? 0);
            continue;
        }
        else if (ch === '|') {
            frame.alternation = true;
            i++;
            continue;
        }
        else if (ch === '*' || ch === '+' || ch === '?' || ch === '{') {
            // A quantifier with nothing to quantify (or a literal `{`): treat it as a plain character.
            const quant = readQuantifier(pattern, i);
            const target = frame.atoms[frame.atoms.length - 1];
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
        frame.atoms.push(atom);
        i = next;
    }
    return undefined;
}
//# sourceMappingURL=redos.js.map
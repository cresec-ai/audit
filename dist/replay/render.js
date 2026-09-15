/**
 * Replay timeline renderer — one self-contained, dark-theme HTML page.
 *
 * Zero external requests: all CSS and JS are inline, and the blast-radius
 * search hashes its input client-side with crypto.subtle, so a saved page
 * works fully offline. XSS hygiene: every interpolated string is HTML-escaped
 * (tool names, methods, paths are attacker-influenced), and the embedded JSON
 * blob escapes '<' as < so a payload can never close the script tag.
 */
/** Hard cap on events embedded in one page (static mode renders every session). */
export const MAX_EMBED_EVENTS = 5000;
/* ------------------------------ escaping ------------------------------ */
function escapeHtml(s) {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
/** JSON for a <script type="application/json"> block: '<' can never appear raw. */
function escapeJsonForScript(json) {
    return json
        .replace(/</g, '\\u003c')
        .replace(/\u2028/g, '\\u2028')
        .replace(/\u2029/g, '\\u2029');
}
/**
 * Escape a value the TYPE SYSTEM says is a number (seq, duration_ms,
 * bytes_len, ...) before interpolating it into HTML. TypeScript's types are
 * not a runtime guarantee: a tampered/crafted store is read back with
 * JSON.parse and cast, so a malicious store could put an HTML-shaped string
 * where a number is expected. String(n) is a no-op for a real number, but
 * this still escapes it defensively so that path can never inject markup.
 */
function num(n) {
    return escapeHtml(String(n));
}
function isRedactedRef(value) {
    return (typeof value === 'object' &&
        value !== null &&
        !Array.isArray(value) &&
        value.redacted === true &&
        typeof value.ref === 'string' &&
        typeof value.len === 'number');
}
/** 'sha256:ab12cd34…' — short display form of a sha256:<hex> ref. */
function shortRef(ref) {
    const hex = ref.startsWith('sha256:') ? ref.slice('sha256:'.length) : ref;
    return 'sha256:' + hex.slice(0, 8) + '…';
}
/** First 16 chars of the hex part — for identity fingerprints / pubkeys. */
function shortHex(value, n = 16) {
    const hex = value.startsWith('sha256:') ? value.slice('sha256:'.length) : value;
    return hex.slice(0, n) + '…';
}
/* ----------------------------- scrubbed tree ---------------------------- */
/** sha256:<64 hex> — matches a hashed object key (P1 key redaction). */
const SHA256_REF_RE = /^sha256:[0-9a-fA-F]{64}$/;
/**
 * Lock chip for a RedactedRef: short ref visible, full ref in the title.
 * secret_refs (tokens matched INSIDE this leaf, e.g. an AWS key embedded in
 * a larger string) are exposed as a space-separated data-secret-refs
 * attribute so the client-side blast-radius search — a CSS `~=` selector,
 * which matches one whitespace-separated token exactly — can find them too.
 */
function lockChip(ref) {
    const secretRefsAttr = ref.secret_refs !== undefined && ref.secret_refs.length > 0
        ? ` data-secret-refs="${escapeHtml(ref.secret_refs.join(' '))}"`
        : '';
    return (`<span class="lock" data-ref="${escapeHtml(ref.ref)}"${secretRefsAttr}` +
        ` title="${escapeHtml(ref.ref)} (len ${num(ref.len)})">` +
        `\u{1F512} ${escapeHtml(shortRef(ref.ref))} <span class="len">(len ${num(ref.len)})</span></span>`);
}
/**
 * Render an object key: a hashed key (P1 — object keys are redacted too)
 * gets the same lock-chip treatment as a value, with data-ref set so the
 * blast-radius search finds a needle that was used as a KEY, not just a
 * value leaf.
 */
function renderKey(k) {
    if (SHA256_REF_RE.test(k)) {
        return (`<span class="key lock" data-ref="${escapeHtml(k)}" title="${escapeHtml(k)} (hashed key)">` +
            `\u{1F512} ${escapeHtml(JSON.stringify(shortRef(k)))}</span>`);
    }
    return `<span class="key">${escapeHtml(JSON.stringify(k))}</span>`;
}
/** Render a Scrubbed tree as pretty-printed JSON HTML with lock chips. */
function renderTree(value, indent = 0) {
    if (isRedactedRef(value))
        return lockChip(value);
    if (value === null)
        return '<span class="lit">null</span>';
    if (typeof value === 'string') {
        return `<span class="str">${escapeHtml(JSON.stringify(value))}</span>`;
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
        return `<span class="lit">${escapeHtml(String(value))}</span>`;
    }
    const pad = '  '.repeat(indent);
    const inner = '  '.repeat(indent + 1);
    if (Array.isArray(value)) {
        if (value.length === 0)
            return '[]';
        const items = value.map((el) => inner + renderTree(el, indent + 1));
        return '[\n' + items.join(',\n') + '\n' + pad + ']';
    }
    const keys = Object.keys(value);
    if (keys.length === 0)
        return '{}';
    const items = keys.map((k) => inner + renderKey(k) + ': ' + renderTree(value[k], indent + 1));
    return '{\n' + items.join(',\n') + '\n' + pad + '}';
}
/* ------------------------------- cards -------------------------------- */
function timeTag(timestamp) {
    return `<time datetime="${escapeHtml(timestamp)}">${escapeHtml(timestamp)}</time>`;
}
function credentialChips(fingerprints) {
    if (fingerprints === undefined || fingerprints.length === 0)
        return 'none fingerprinted';
    const chips = fingerprints
        .map((cf) => `<span class="lock" data-ref="${escapeHtml(cf.ref)}" title="${escapeHtml(cf.ref)}">` +
        `\u{1F512} ${escapeHtml(cf.name)} ${escapeHtml(shortRef(cf.ref))}</span>`)
        .join(' ');
    return `${fingerprints.length} fingerprinted ${chips}`;
}
function renderSessionStart(seq, e) {
    const id = e.identity;
    const who = [
        id.os_user !== undefined && id.hostname !== undefined
            ? `${id.os_user}@${id.hostname}`
            : (id.os_user ?? id.hostname ?? ''),
        id.client_name !== undefined
            ? `client ${id.client_name}${id.client_version !== undefined ? ' ' + id.client_version : ''}`
            : '',
        id.label !== undefined ? `label ${id.label}` : '',
    ]
        .filter((s) => s !== '')
        .map(escapeHtml)
        .join(' · ');
    return `<article class="event card start" data-seq="${num(seq)}">
  <div class="card-head"><span class="kind tag-start">SESSION START</span>${timeTag(e.timestamp)}</div>
  <dl>
    <dt>command</dt><dd><code>${escapeHtml(e.server.command)}</code> <span class="dim">(${escapeHtml(e.server.transport)})</span></dd>
    <dt>identity</dt><dd>${who !== '' ? who + ' · ' : ''}fingerprint <code title="${escapeHtml(id.fingerprint)}">${escapeHtml(shortHex(id.fingerprint))}</code></dd>
    <dt>credentials</dt><dd>${credentialChips(id.credential_fingerprints)}</dd>
    <dt>redaction</dt><dd>${escapeHtml(e.redaction_mode)} <span class="dim">· proxy v${escapeHtml(e.proxy_version)} · cwd ${escapeHtml(e.cwd)}</span></dd>
  </dl>
</article>`;
}
function renderInitialize(seq, e) {
    const client = `${e.client_name ?? 'unknown client'}${e.client_version !== undefined ? ' ' + e.client_version : ''}`;
    const server = `${e.server_name ?? 'unknown server'}${e.server_version !== undefined ? ' ' + e.server_version : ''}`;
    return `<article class="event card see" data-seq="${num(seq)}">
  <div class="card-head"><span class="kind tag-see">SEE</span> handshake ${timeTag(e.timestamp)}</div>
  <div class="body">${escapeHtml(client)} ⇄ ${escapeHtml(server)}${e.protocol_version !== undefined
        ? ` <span class="dim">· protocol ${escapeHtml(e.protocol_version)}</span>`
        : ''} <span class="dim">· ${num(e.duration_ms)} ms</span></div>
</article>`;
}
/* ------------------------- gateway mode (additive) ------------------------ */
/** CSS class for a gateway decision badge; anything off-schema falls back to the hold style. */
function gatewayBadgeClass(decision) {
    return decision === 'allow' ? 'gw-allow' : decision === 'deny' ? 'gw-deny' : 'gw-hold';
}
/**
 * "redacted 2 secrets · flagged 1 injection marker" — a one-line summary of
 * what the boundary filter did to a tool result. Every count goes through
 * num() (a tampered store may put markup where a number belongs).
 */
function boundarySummary(boundary) {
    if (boundary === undefined)
        return '';
    if (!boundary.scanned) {
        const why = boundary.error !== undefined ? `error ${escapeHtml(boundary.error)}` : 'oversize';
        return `not scanned (${why})` + (boundary.action === 'block' ? ' · blocked' : '');
    }
    const bits = [];
    const verb = boundary.action === 'redact'
        ? 'redacted'
        : boundary.action === 'block'
            ? 'blocked'
            : boundary.action === 'flag'
                ? 'flagged'
                : 'found';
    const secrets = Number(boundary.secrets_found);
    const injections = Number(boundary.injection_found);
    if (secrets > 0)
        bits.push(`${verb} ${num(boundary.secrets_found)} secret${secrets === 1 ? '' : 's'}`);
    if (injections > 0) {
        bits.push(`${verb} ${num(boundary.injection_found)} injection marker${injections === 1 ? '' : 's'}`);
    }
    if (bits.length === 0)
        return 'scanned clean';
    return bits.join(' · ');
}
/**
 * Badge(s) on a tool_call card recorded in gateway mode: the decision
 * (gw-allow / gw-hold / gw-deny), the hold outcome when there is one, and
 * the boundary-filter summary. secret_refs are exposed as data-secret-refs
 * so the client-side blast-radius search finds a value the filter scrubbed
 * before the model ever saw it.
 */
function gatewayBadges(gw) {
    if (gw === undefined)
        return '';
    const cls = gatewayBadgeClass(gw.decision);
    const label = gw.outcome !== undefined ? `${escapeHtml(String(gw.decision))} · ${escapeHtml(String(gw.outcome))}` : escapeHtml(String(gw.decision));
    const title = [];
    if (gw.rule_id !== undefined)
        title.push(`rule ${gw.rule_id}`);
    if (gw.approval_id !== undefined)
        title.push(`hold ${gw.approval_id}`);
    if (gw.waited_ms !== undefined)
        title.push(`waited ${String(gw.waited_ms)} ms`);
    const titleAttr = title.length > 0 ? ` title="${escapeHtml(title.join(' · '))}"` : '';
    let html = `<span class="badge gw ${cls}"${titleAttr}>gateway ${label}</span>`;
    const b = gw.boundary;
    if (b !== undefined) {
        const refs = Array.isArray(b.secret_refs) && b.secret_refs.length > 0
            ? ` data-secret-refs="${escapeHtml(b.secret_refs.map(String).join(' '))}"`
            : '';
        const delivered = b.delivered_result_hash !== undefined
            ? ` title="delivered result ${escapeHtml(String(b.delivered_result_hash))}"`
            : '';
        html += ` <span class="badge boundary${b.action === 'block' ? ' gw-deny' : ''}"${refs}${delivered}>${boundarySummary(b)}</span>`;
    }
    return html;
}
function renderPolicyDecision(seq, e) {
    const cls = gatewayBadgeClass(e.decision);
    const bits = [`request ${escapeHtml(String(e.request_id))}`];
    bits.push(e.rule_id !== undefined ? `rule ${escapeHtml(e.rule_id)}` : 'policy default');
    if (e.outcome !== undefined)
        bits.push(`outcome ${escapeHtml(String(e.outcome))}`);
    if (e.waited_ms !== undefined)
        bits.push(`waited ${num(e.waited_ms)} ms`);
    if (e.approval_id !== undefined)
        bits.push(`hold <code>${escapeHtml(String(e.approval_id))}</code>`);
    if (e.approver !== undefined)
        bits.push(`by ${escapeHtml(String(e.approver))}`);
    const argsHash = typeof e.args_hash === 'string'
        ? ` · args <code class="rh" data-ref="${escapeHtml(e.args_hash)}" title="${escapeHtml(e.args_hash)}">${escapeHtml(shortRef(e.args_hash))}</code>`
        : '';
    return `<article class="event row policy ${cls}" data-seq="${num(seq)}">
  <span class="kind tag-policy">POLICY</span> <span class="tool">${escapeHtml(e.tool)}</span>
  <span class="badge gw ${cls}">${escapeHtml(String(e.decision))}</span>
  <span class="dim">· ${bits.join(' · ')}${argsHash} · policy <code title="${escapeHtml(String(e.policy_hash))}">${escapeHtml(shortRef(String(e.policy_hash)))}</code></span>
  ${timeTag(e.timestamp)}
</article>`;
}
function renderToolCall(seq, e) {
    const hasGenAi = Object.keys(e.attributes).some((k) => k.startsWith('gen_ai.'));
    const genAiBadge = hasGenAi ? '<span class="badge genai">gen_ai</span>' : '';
    const errorBadge = e.is_error ? '<span class="badge err">error</span>' : '';
    const gwBadges = gatewayBadges(e.gateway);
    let errorInfo = '';
    if (e.error !== undefined) {
        const bits = [];
        if (e.error.code !== undefined)
            bits.push(`code ${num(e.error.code)}`);
        if (e.error.type !== undefined)
            bits.push(escapeHtml(e.error.type));
        if (e.error.message_ref !== undefined) {
            bits.push(`message <code class="rh" data-ref="${escapeHtml(e.error.message_ref)}" title="${escapeHtml(e.error.message_ref)}">${escapeHtml(shortRef(e.error.message_ref))}</code>`);
        }
        errorInfo = ` <span class="err-info">${bits.join(' · ')}</span>`;
    }
    return `<article class="event card act" data-seq="${num(seq)}" data-result-hash="${escapeHtml(e.result_hash)}">
  <div class="card-head act-head">
    <span class="kind tag-act">ACT</span>
    <span class="tool">${escapeHtml(e.tool)}</span>
    ${genAiBadge}${errorBadge}${gwBadges}
    <span class="dur">${num(e.duration_ms)} ms</span>
    ${timeTag(e.timestamp)}
  </div>
  <div class="sub">args <span class="dim">· request ${escapeHtml(String(e.request_id))}</span></div>
  <pre class="tree">${renderTree(e.args)}</pre>
  <div class="card-foot effect-head">
    <span class="kind tag-effect">EFFECT</span>
    <span class="rh">result_hash <code title="${escapeHtml(e.result_hash)}">${escapeHtml(shortRef(e.result_hash))}</code></span>${errorInfo}
  </div>
  <pre class="tree">${renderTree(e.result)}</pre>
</article>`;
}
function renderRpc(seq, e) {
    const errorBadge = e.is_error ? ' <span class="badge err">error</span>' : '';
    return `<article class="event row rpc" data-seq="${num(seq)}" data-result-hash="${escapeHtml(e.result_hash)}">
  <span class="kind tag-rpc">RPC</span> <code>${escapeHtml(e.method)}</code>
  <span class="dim">· request ${escapeHtml(String(e.request_id))} · ${num(e.duration_ms)} ms · result <code title="${escapeHtml(e.result_hash)}">${escapeHtml(shortRef(e.result_hash))}</code></span>${errorBadge}
  ${timeTag(e.timestamp)}
  <pre class="tree">${renderTree(e.params)}</pre>
</article>`;
}
function renderNotification(seq, e) {
    const arrow = e.direction === 'client_to_server' ? '→' : '←';
    return `<article class="event row notif" data-seq="${num(seq)}">
  <span class="kind tag-notif">NOTIFY</span> ${arrow} <code>${escapeHtml(e.method)}</code>
  ${timeTag(e.timestamp)}
  <pre class="tree">${renderTree(e.params)}</pre>
</article>`;
}
function renderProtocolError(seq, e) {
    return `<article class="event row proto" data-seq="${num(seq)}">
  <span class="kind tag-proto">PROTOCOL</span> ${escapeHtml(e.reason)}
  <span class="dim">· ${escapeHtml(e.direction)} · ${num(e.bytes_len)} bytes · line <code title="${escapeHtml(e.line_hash)}">${escapeHtml(shortRef(e.line_hash))}</code></span>
  ${timeTag(e.timestamp)}
</article>`;
}
function renderSessionEnd(seq, e) {
    const exit = e.child_exit_code === undefined || e.child_exit_code === null
        ? ''
        : ` · exit ${num(e.child_exit_code)}`;
    return `<article class="event card end" data-seq="${num(seq)}">
  <div class="card-head"><span class="kind tag-end">SESSION END</span>${timeTag(e.timestamp)}</div>
  <div class="body">reason ${escapeHtml(e.reason)}${exit} · recorded ${num(e.events_recorded)} · dropped ${num(e.events_dropped)}</div>
</article>`;
}
function renderEvent(record) {
    const e = record.event;
    switch (e.kind) {
        case 'session_start':
            return renderSessionStart(record.seq, e);
        case 'initialize':
            return renderInitialize(record.seq, e);
        case 'tool_call':
            return renderToolCall(record.seq, e);
        case 'rpc':
            return renderRpc(record.seq, e);
        case 'notification':
            return renderNotification(record.seq, e);
        case 'protocol_error':
            return renderProtocolError(record.seq, e);
        case 'session_end':
            return renderSessionEnd(record.seq, e);
        case 'policy_decision':
            return renderPolicyDecision(record.seq, e);
        default:
            // Future kinds: render an inert row rather than dropping evidence.
            return `<article class="event row" data-seq="${num(record.seq)}"><span class="kind">${escapeHtml(e.kind)}</span> ${timeTag(e.timestamp)}</article>`;
    }
}
/* ----------------------------- page sections ---------------------------- */
function integrityBanner(verify) {
    if (verify.ok) {
        const sig = verify.verified_signature;
        const signed = sig !== undefined
            ? `head signed <code title="${escapeHtml(sig.public_key)}">${escapeHtml(shortHex(sig.public_key))}</code> at ${escapeHtml(sig.signed_at)}`
            : 'head unsigned';
        return `<div class="banner ok">✔ chain intact, ${num(verify.checked_events)} events, ${signed}</div>`;
    }
    const items = verify.problems
        .map((p) => `<li><code>${escapeHtml(p.type)}</code> at seq ${num(p.seq)}: ${escapeHtml(p.detail)}${p.warning === true ? ' <span class="dim">(warning)</span>' : ''}</li>`)
        .join('\n');
    return `<div class="banner bad">✘ integrity check FAILED — ${num(verify.problems.length)} problem(s)
<ul>${items}</ul></div>`;
}
function sessionPicker(sessions) {
    if (sessions.length === 0)
        return '<p class="dim">No sessions recorded.</p>';
    const rows = sessions
        .map((s) => {
        const href = '?session=' + encodeURIComponent(s.session_id);
        return `<tr>
  <td><a href="${escapeHtml(href)}"><code>${escapeHtml(s.session_id)}</code></a></td>
  <td>${escapeHtml(s.started_at)}</td>
  <td>${escapeHtml(s.server_name)}</td>
  <td><code title="${escapeHtml(s.identity_fingerprint)}">${escapeHtml(shortHex(s.identity_fingerprint))}</code></td>
  <td class="num">${num(s.event_count)}</td>
  <td class="num">${num(s.tool_call_count)}</td>
  <td class="num${s.error_count > 0 ? ' has-errors' : ''}">${num(s.error_count)}</td>
</tr>`;
    })
        .join('\n');
    return `<section class="picker">
<h2>sessions</h2>
<table>
<thead><tr><th>session</th><th>started</th><th>server</th><th>identity</th><th>events</th><th>tool calls</th><th>errors</th></tr></thead>
<tbody>
${rows}
</tbody>
</table>
</section>`;
}
function sessionTimeline(sessionId, records) {
    const cards = records.map(renderEvent).join('\n');
    return `<section class="session">
<h2>session <code>${escapeHtml(sessionId)}</code></h2>
<div class="timeline">
${cards}
</div>
</section>`;
}
const PAGE_CSS = `
:root {
  --bg: #0e1116; --panel: #161b24; --panel2: #1c2330; --border: #2a3342;
  --fg: #d7dee8; --dim: #8b96a5; --accent: #5ab0f7; --act: #b48ef0;
  --effect: #58c89b; --warn: #e0a93f; --bad: #e06c75; --ok: #4fc380;
  --lock-bg: #232b3a; --hit: #f2c14e;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 1.25rem 1.5rem 4rem; background: var(--bg); color: var(--fg);
  font: 14px/1.5 ui-sans-serif, system-ui, "Segoe UI", sans-serif;
}
code, pre, .lock { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; }
h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
h2 { font-size: 1rem; margin: 1.5rem 0 .5rem; color: var(--accent); font-weight: 600; }
a { color: var(--accent); }
header .meta { color: var(--dim); }
header .meta code { color: var(--fg); }
.dim { color: var(--dim); }
.banner { margin: .75rem 0; padding: .5rem .75rem; border-radius: 6px; font-weight: 600; }
.banner.ok { background: rgba(79,195,128,.12); border: 1px solid var(--ok); color: var(--ok); }
.banner.bad { background: rgba(224,108,117,.12); border: 1px solid var(--bad); color: var(--bad); }
.banner ul { margin: .5rem 0 0; font-weight: 400; color: var(--fg); }
.blast { margin: 1rem 0; padding: .75rem; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; }
.blast form { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
.blast label { font-weight: 600; }
.blast input { flex: 1 1 18rem; padding: .4rem .6rem; background: var(--bg); color: var(--fg);
  border: 1px solid var(--border); border-radius: 6px; font-family: inherit; }
.blast button { padding: .4rem .9rem; background: var(--accent); color: #08121d; border: 0;
  border-radius: 6px; font-weight: 700; cursor: pointer; }
.blast .hint { flex-basis: 100%; color: var(--dim); font-size: .85em; }
#blast-count { font-weight: 600; color: var(--hit); }
.picker table { border-collapse: collapse; width: 100%; background: var(--panel);
  border: 1px solid var(--border); border-radius: 8px; }
.picker th, .picker td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid var(--border); }
.picker th { color: var(--dim); font-weight: 600; }
.picker td.num { text-align: right; font-variant-numeric: tabular-nums; }
.picker td.has-errors { color: var(--bad); font-weight: 700; }
.timeline { display: flex; flex-direction: column; gap: .6rem; border-left: 2px solid var(--border);
  padding-left: 1rem; margin-left: .25rem; }
.event { border-radius: 8px; }
.event.card { background: var(--panel); border: 1px solid var(--border); padding: .6rem .8rem; }
.event.row { background: var(--panel); border: 1px solid var(--border); padding: .35rem .8rem;
  font-size: .92em; }
.event.row.proto { background: rgba(224,169,63,.10); border-color: var(--warn); }
.card-head, .card-foot { display: flex; gap: .6rem; align-items: baseline; flex-wrap: wrap; }
.card-head time, .event.row time { margin-left: auto; color: var(--dim); font-size: .85em; }
.kind { font-weight: 800; font-size: .75em; letter-spacing: .08em; padding: .1rem .45rem;
  border-radius: 4px; background: var(--panel2); color: var(--dim); }
.tag-act { background: rgba(180,142,240,.18); color: var(--act); }
.tag-effect { background: rgba(88,200,155,.18); color: var(--effect); }
.tag-see { background: rgba(90,176,247,.18); color: var(--accent); }
.tag-proto { background: rgba(224,169,63,.2); color: var(--warn); }
.tag-start, .tag-end { background: var(--panel2); color: var(--fg); }
.event.card.act { border-color: #3b3354; }
.card-foot.effect-head { border-top: 1px solid var(--border); margin-top: .5rem; padding-top: .5rem; }
.tool { font-weight: 700; }
.badge { font-size: .72em; font-weight: 700; padding: .05rem .4rem; border-radius: 999px; }
.badge.genai { background: rgba(90,176,247,.15); color: var(--accent); border: 1px solid var(--accent); }
.badge.err { background: rgba(224,108,117,.15); color: var(--bad); border: 1px solid var(--bad); }
.badge.gw-allow { background: rgba(79,195,128,.15); color: var(--ok); border: 1px solid var(--ok); }
.badge.gw-hold { background: rgba(224,169,63,.15); color: var(--warn); border: 1px solid var(--warn); }
.badge.gw-deny { background: rgba(224,108,117,.15); color: var(--bad); border: 1px solid var(--bad); }
.badge.boundary { background: var(--panel2); color: var(--dim); border: 1px solid var(--border); }
.tag-policy { background: rgba(224,169,63,.2); color: var(--warn); }
.event.row.policy.gw-deny { background: rgba(224,108,117,.08); border-color: var(--bad); }
.event.row.policy.gw-hold { background: rgba(224,169,63,.08); border-color: var(--warn); }
.dur { color: var(--dim); font-size: .85em; }
.sub { color: var(--dim); font-size: .85em; margin-top: .4rem; }
pre.tree { margin: .35rem 0 0; padding: .5rem .65rem; background: var(--bg);
  border: 1px solid var(--border); border-radius: 6px; overflow-x: auto; font-size: .9em; }
pre.tree .key { color: var(--accent); }
pre.tree .str { color: #98c379; }
pre.tree .lit { color: #d19a66; }
.lock { display: inline-block; background: var(--lock-bg); border: 1px solid var(--border);
  border-radius: 999px; padding: 0 .5rem; font-size: .85em; white-space: nowrap; }
.lock .len { color: var(--dim); }
.rh code, .event.row code { color: var(--fg); }
.err-info { color: var(--bad); }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .15rem .8rem; margin: .5rem 0 0; }
dt { color: var(--dim); }
dd { margin: 0; }
.truncated { margin: 1rem 0; padding: .5rem .75rem; border: 1px solid var(--warn);
  color: var(--warn); border-radius: 6px; font-weight: 600; }
.blast-hit { outline: 2px solid var(--hit); box-shadow: 0 0 0 3px rgba(242,193,78,.25); }
span.lock.blast-hit { background: rgba(242,193,78,.25); color: var(--hit); }
`;
/**
 * Client-side blast radius: SHA-256 the probe with crypto.subtle, then
 * highlight every lock chip / result hash carrying the matching ref.
 * Plain ES5-ish on purpose; no external requests, works offline.
 */
const PAGE_JS = `
(function () {
  'use strict';
  var dataEl = document.getElementById('evidence-data');
  if (dataEl) {
    try { window.__evidence = JSON.parse(dataEl.textContent); } catch (err) { window.__evidence = null; }
  }
  var form = document.getElementById('blast-form');
  var input = document.getElementById('blast-input');
  var count = document.getElementById('blast-count');
  if (!form || !input || !count) return;
  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var prior = document.querySelectorAll('.blast-hit');
    for (var i = 0; i < prior.length; i++) prior[i].classList.remove('blast-hit');
    var value = input.value;
    if (!value) { count.textContent = ''; return; }
    var bytes = new TextEncoder().encode(value);
    crypto.subtle.digest('SHA-256', bytes).then(function (buf) {
      var arr = new Uint8Array(buf);
      var hex = '';
      for (var i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, '0');
      var ref = 'sha256:' + hex;
      var sel = '[data-ref="' + ref + '"], [data-result-hash="' + ref + '"], [data-secret-refs~="' + ref + '"]';
      var hits = document.querySelectorAll(sel);
      var seen = {};
      var events = 0;
      for (var j = 0; j < hits.length; j++) {
        hits[j].classList.add('blast-hit');
        var card = hits[j].closest('[data-seq]');
        if (card) {
          card.classList.add('blast-hit');
          var seq = card.getAttribute('data-seq');
          if (!seen[seq]) { seen[seq] = true; events++; }
        }
      }
      count.textContent = events === 0 ? 'no events touched' : events + ' event(s) touched';
      var first = document.querySelector('[data-seq].blast-hit');
      if (first && first.scrollIntoView) first.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, function () {
      count.textContent = 'hashing unavailable (crypto.subtle)';
    });
  });
})();
`;
/* ------------------------------ entry point ----------------------------- */
/**
 * Render the evidence replay page. With `sessionId` only that session's
 * timeline is shown; without it, the session picker plus every session's
 * timeline stacked (static mode), capped at MAX_EMBED_EVENTS events.
 */
export function renderTimelineHtml(store, opts = {}) {
    const allSessions = store.sessions();
    const selected = opts.sessionId;
    const records = [];
    let truncated = false;
    const iterateOpts = selected !== undefined ? { sessionId: selected } : {};
    for (const record of store.iterate(iterateOpts)) {
        if (records.length >= MAX_EMBED_EVENTS) {
            truncated = true;
            break;
        }
        records.push(record);
    }
    // Group by session, preserving chain (seq) order within and across sessions.
    const bySession = new Map();
    for (const record of records) {
        const list = bySession.get(record.event.session_id);
        if (list === undefined)
            bySession.set(record.event.session_id, [record]);
        else
            list.push(record);
    }
    const visibleSessions = selected !== undefined ? allSessions.filter((s) => s.session_id === selected) : allSessions;
    const timelines = [];
    for (const [sessionId, sessionRecords] of bySession) {
        timelines.push(sessionTimeline(sessionId, sessionRecords));
    }
    if (selected !== undefined && records.length === 0) {
        timelines.push(`<p class="dim">No events recorded for session <code>${escapeHtml(selected)}</code>.</p>`);
    }
    const embedded = escapeJsonForScript(JSON.stringify({
        schema: 'edut.mcp-recorder.replay.v1',
        backend: store.backend,
        path: store.path,
        session_id: selected ?? null,
        truncated,
        sessions: visibleSessions,
        events: records,
    }));
    const titleSuffix = selected !== undefined ? ` — session ${escapeHtml(selected)}` : '';
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>mcp-recorder — evidence replay</title>
<style>${PAGE_CSS}</style>
</head>
<body>
<header>
<h1>mcp-recorder — evidence replay${titleSuffix}</h1>
<div class="meta">store: <code>${escapeHtml(store.backend)}</code> · <code>${escapeHtml(store.path)}</code></div>
${opts.verify !== undefined ? integrityBanner(opts.verify) : ''}
</header>
<section class="blast">
<form id="blast-form" autocomplete="off">
<label for="blast-input">blast radius</label>
<input id="blast-input" type="text" placeholder="paste a value (key, email, token) to trace" spellcheck="false">
<button type="submit">trace</button>
<span id="blast-count"></span>
<span class="hint">hashed locally with crypto.subtle — the value never leaves this page</span>
</form>
</section>
${selected === undefined ? sessionPicker(allSessions) : `<p><a href="?">← all sessions</a></p>`}
${truncated ? `<div class="truncated">⚠ truncated: showing the first ${MAX_EMBED_EVENTS} events only</div>` : ''}
${timelines.join('\n')}
<script type="application/json" id="evidence-data">${embedded}</script>
<script>${PAGE_JS}</script>
</body>
</html>
`;
}
//# sourceMappingURL=render.js.map
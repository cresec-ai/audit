#!/usr/bin/env node
/**
 * A fake Cresec control plane serving ONE endpoint, `POST /v1/broker/user-token`,
 * exactly as cresec-ai/nhi docs/internal/contracts/user-token.md specifies —
 * the endpoint `RemoteBroker` calls behind `credentials[].broker: { kind:
 * remote }`. Every request is journaled (headers + body) to
 * `E2E_CP_JOURNAL`, so the test asserts the wire shape from the control
 * plane's side, never from the recorder's.
 *
 * Environment:
 *   E2E_CP_JOURNAL         append-only request journal (required)
 *   E2E_CP_INTERNAL_TOKEN  the internal bearer it expects (401 otherwise)
 *   E2E_CP_TENANT          the X-Cresec-Tenant it expects (404 otherwise)
 *   E2E_CP_ACCESS_TOKEN    the per-user access token it hands out on allow
 *   E2E_CP_DENY_HOSTS      comma-separated target hosts answered 403 grant_required
 *   E2E_CP_MODE            "allow" (default) | "503": every request answers
 *                          503 { error: "vault_unavailable" } | "down": the
 *                          socket is destroyed without a response
 *
 * Prints `listening http://127.0.0.1:<port>` on stdout once bound.
 */
'use strict';

const fs = require('node:fs');
const http = require('node:http');
const { randomUUID } = require('node:crypto');

const JOURNAL = process.env.E2E_CP_JOURNAL;
const INTERNAL = process.env.E2E_CP_INTERNAL_TOKEN || '';
const TENANT = process.env.E2E_CP_TENANT || '';
const ACCESS = process.env.E2E_CP_ACCESS_TOKEN || '';
const DENY_HOSTS = (process.env.E2E_CP_DENY_HOSTS || '').split(',').filter((h) => h !== '');
const MODE = process.env.E2E_CP_MODE || 'allow';

const ACTOR = {
  user: { id: '3c9f2d0e-4b1a-4f7e-9d21-6a0b1c2d3e4f', email: 'dana@cresec.ai', idp: 'okta', idp_sub: '00u1abcXYZ' },
  tool: { id: '9e1d7c3a-2f4b-4c6d-8e0f-1a2b3c4d5e6f', name: 'outreach-tool', version: '3' },
  host: { origin: 'https://tool.staging.cresec.ai', kind: 'vercel' },
  run_as: 'user',
};

function journal(entry) {
  if (JOURNAL === undefined || JOURNAL === '') return;
  fs.appendFileSync(JOURNAL, JSON.stringify(entry) + '\n');
}

function send(res, status, body, decisionId) {
  const out = JSON.stringify(body);
  const headers = { 'content-type': 'application/json', 'content-length': Buffer.byteLength(out) };
  if (decisionId) headers['x-cresec-decision'] = decisionId;
  res.writeHead(status, headers);
  res.end(out);
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    journal({ method: req.method, url: req.url, headers: req.headers, body: raw });
    if (MODE === 'down') {
      req.socket.destroy();
      return;
    }
    if (req.method !== 'POST' || req.url !== '/v1/broker/user-token') {
      send(res, 404, { error: 'not_found' });
      return;
    }
    const auth = req.headers.authorization || '';
    if (auth !== `Bearer ${INTERNAL}`) {
      send(res, 401, { error: 'unauthenticated', reason: 'internal_token_invalid' });
      return;
    }
    if ((req.headers['x-cresec-tenant'] || '') !== TENANT) {
      send(res, 404, { error: 'tenant_not_found' });
      return;
    }
    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      send(res, 400, { error: 'invalid_request', message: 'body is not JSON' });
      return;
    }
    const decisionId = randomUUID();
    if (MODE === '503') {
      send(res, 503, { error: 'vault_unavailable', decision_id: decisionId, reason: 'vault_unavailable', action_class: body.action_class }, decisionId);
      return;
    }
    const host = body.target && body.target.host;
    if (DENY_HOSTS.includes(host)) {
      send(res, 403, { error: 'policy_denied', decision_id: decisionId, decision: 'deny', reason: 'grant_required', action_class: body.action_class, actor: ACTOR }, decisionId);
      return;
    }
    send(
      res,
      200,
      {
        decision_id: decisionId,
        decision: 'allow',
        reason: 'ok',
        token: { access_token: ACCESS, token_type: 'Bearer', api_base: 'http://localhost:9010', expires_at: new Date(Date.now() + 3_600_000).toISOString() },
        ttl_ms: 300000,
        actor: ACTOR,
      },
      decisionId,
    );
  });
});

server.listen(0, '127.0.0.1', () => {
  process.stdout.write(`listening http://127.0.0.1:${server.address().port}\n`);
});

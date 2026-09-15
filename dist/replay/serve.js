/**
 * Local replay UI server — node:http only, loopback only, read only.
 *
 * Routes:
 *   GET /                → session picker (or the default session when one
 *                          was passed to serveUi)
 *   GET /?session=<id>   → that session's timeline
 *   GET /healthz         → 200 'ok'
 *
 * Binds 127.0.0.1 exclusively and exposes no write endpoint of any kind.
 */
import { createServer } from 'node:http';
import { renderTimelineHtml } from './render.js';
const TEXT = { 'content-type': 'text/plain; charset=utf-8' };
const HTML = { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' };
export async function serveUi(opts) {
    const handler = (req, res) => {
        try {
            const method = req.method ?? 'GET';
            if (method !== 'GET' && method !== 'HEAD') {
                res.writeHead(405, { ...TEXT, allow: 'GET, HEAD' });
                res.end('method not allowed');
                return;
            }
            const url = new URL(req.url ?? '/', 'http://127.0.0.1');
            if (url.pathname === '/healthz') {
                res.writeHead(200, TEXT);
                res.end('ok');
                return;
            }
            if (url.pathname === '/') {
                const session = url.searchParams.get('session') ?? opts.sessionId;
                const renderOpts = {};
                if (session !== undefined && session !== '')
                    renderOpts.sessionId = session;
                if (opts.verify !== undefined)
                    renderOpts.verify = opts.verify;
                const html = renderTimelineHtml(opts.store, renderOpts);
                res.writeHead(200, HTML);
                res.end(method === 'HEAD' ? undefined : html);
                return;
            }
            res.writeHead(404, TEXT);
            res.end('not found');
        }
        catch (err) {
            process.stderr.write(`[mcp-recorder] replay ui error: ${err instanceof Error ? err.message : String(err)}\n`);
            if (!res.headersSent)
                res.writeHead(500, TEXT);
            res.end('internal error');
        }
    };
    const server = createServer(handler);
    server.unref(); // never keep a process alive just for the viewer
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(opts.port ?? 0, '127.0.0.1', () => {
            server.removeListener('error', reject);
            resolve();
        });
    });
    const address = server.address();
    const port = typeof address === 'object' && address !== null ? address.port : (opts.port ?? 0);
    return {
        url: `http://127.0.0.1:${port}/`,
        port,
        close: () => new Promise((resolve, reject) => {
            server.close((err) => (err !== undefined && err !== null ? reject(err) : resolve()));
            // Sever keep-alive connections so close() resolves promptly.
            server.closeAllConnections();
        }),
    };
}
//# sourceMappingURL=serve.js.map
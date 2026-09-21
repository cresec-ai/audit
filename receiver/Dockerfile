# The reference evidence receiver (receiver/README.md), as one image.
#
#   docker build -f receiver/Dockerfile -t cresec/receiver .
#   docker run --rm -p 8787:8787 \
#     -v receiver-data:/data \
#     -v /path/to/tls:/tls:ro \
#     -e MCPR_RECEIVER_TOKEN=... -e MCPR_RECEIVER_ENROLMENT=pinned -e MCPR_RECEIVER_KEYS=<64hex> \
#     cresec/receiver
#
# The receiver is TypeScript run through tsx (`npm run receiver`), which is a
# devDependency, so the image installs the full lockfile. `dist/` is committed
# and ships as-is; nothing is compiled here (AGENTS.md: no build/prepare
# scripts). node:20 is the `engines` floor in package.json.
#
# Ingest and operator tokens come from the environment or from
# /data/tokens.json (receiver/auth.ts) — never baked into the image. TLS is
# terminated here only when a certificate and key are mounted at /tls; the
# receiver refuses to bind a non-loopback address over plain HTTP without a
# terminator in front, and the sender refuses a non-loopback http:// sink.
FROM node:20-alpine

WORKDIR /app

# The lockfile first, so the dependency layer caches across source changes.
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund

# The receiver imports `../src/*.ts`; dist/ is what `mcp-recorder` itself is.
COPY src ./src
COPY dist ./dist
COPY receiver ./receiver
COPY LICENSE README.md ./

RUN mkdir -p /data /tls && chown -R node:node /data /app
USER node
VOLUME ["/data"]

# receiver/server.ts binds 0.0.0.0 only when asked; inside a container that
# is the only address anything can reach.
ENV MCPR_RECEIVER_DATA_DIR=/data
EXPOSE 8787

ENTRYPOINT ["npx", "--no-install", "tsx", "receiver/main.ts", "serve", "--data-dir", "/data", "--host", "0.0.0.0", "--port", "8787"]
# Override CMD to drop TLS when a terminator sits in front (`docker run ... cresec/receiver ""` is not
# needed: pass any flags you want instead, e.g. `--require-range-header`).
CMD ["--tls-cert", "/tls/tls.crt", "--tls-key", "/tls/tls.key"]

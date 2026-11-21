# TypeSafe Guardrail Studio — demo image.
#
# Runs the same thing `./start.sh` runs: the Express policy server with Vite in
# middleware mode (vite.config.ts as-is), served on port 8080. Dev-mode on purpose:
# this is a demo, not a production build.
#
#   docker build -t jev-cvs .
#   docker run --rm -p 8080:8080 --env-file .env jev-cvs
#
# TYPESAFE_API_KEY is read from the environment at runtime; it is never baked in.
FROM node:22-slim

ENV NODE_ENV=development \
    PORT=8080 \
    DISABLE_HMR=true

WORKDIR /app

# Dependencies first so the layer is cached across source edits. Installed with bun from
# bun.lock (same resolution as the dev machine; npm trips on an esbuild/vite peer range),
# run with node + tsx (bun refuses the evaluator.test.ts import outside its test runner).
COPY package.json bun.lock ./
RUN npm install -g bun --no-audit --no-fund \
 && bun install --frozen-lockfile

# Everything else (see .dockerignore: no node_modules, .env, dist, .git).
COPY . .

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://localhost:8080/api/typesafe-status').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["npx", "tsx", "server.ts"]

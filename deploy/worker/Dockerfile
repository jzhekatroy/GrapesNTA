# syntax=docker/dockerfile:1
# grapes-worker: observations (Node) + traffic/ASN rollups (Python cron).

FROM node:22-bookworm-slim AS deps
WORKDIR /app/analytics
COPY deploy/analytics/package.json deploy/analytics/package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-bookworm-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV GRAPES_ANALYTICS_WORKER=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    python3 \
    ca-certificates \
    curl \
    util-linux \
  && curl -fsSL -o /usr/local/bin/supercronic \
    https://github.com/aptible/supercronic/releases/download/v0.2.33/supercronic-linux-amd64 \
  && chmod +x /usr/local/bin/supercronic \
  && rm -rf /var/lib/apt/lists/*
# Native clickhouse-client deb often SIGILL on older CPUs; use HTTP shim instead.

RUN groupadd --gid 1001 app \
  && useradd --uid 1001 --gid app --shell /bin/sh --create-home app

COPY --from=deps /app/analytics/node_modules /app/analytics/node_modules
COPY deploy/analytics/package.json /app/analytics/
COPY deploy/analytics/server /app/analytics/server
COPY scripts/traffic_rollup_async.py scripts/traffic_rollup_jobs.py /app/scripts/
COPY deploy/worker/bin /app/bin
COPY deploy/worker/rollups.crontab /etc/grapesnta/rollups.crontab
COPY deploy/worker/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh /app/bin/*.sh /app/bin/*.js \
  && ln -sf /app/bin/clickhouse-client-http.sh /usr/local/bin/clickhouse-client \
  && mkdir -p /app/analytics/server/data/observation_runs /var/log/grapesnta \
  && chown -R app:app /app/analytics/server/data /var/log/grapesnta

USER app

CMD ["/app/entrypoint.sh"]

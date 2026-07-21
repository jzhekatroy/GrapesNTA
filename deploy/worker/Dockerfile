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
    gnupg \
    apt-transport-https \
    util-linux \
  && curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
    | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg \
  && echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main" \
    > /etc/apt/sources.list.d/clickhouse.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends clickhouse-client \
  && curl -fsSL -o /usr/local/bin/supercronic \
    https://github.com/aptible/supercronic/releases/download/v0.2.33/supercronic-linux-amd64 \
  && chmod +x /usr/local/bin/supercronic \
  && rm -rf /var/lib/apt/lists/*

RUN addgroup -g 1001 -S app && adduser -u 1001 -S -G app app

COPY --from=deps /app/analytics/node_modules /app/analytics/node_modules
COPY deploy/analytics/package.json /app/analytics/
COPY deploy/analytics/server /app/analytics/server
COPY scripts/traffic_rollup_async.py scripts/traffic_rollup_jobs.py /app/scripts/
COPY deploy/worker/bin /app/bin
COPY deploy/worker/rollups.crontab /etc/grapesnta/rollups.crontab
COPY deploy/worker/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh /app/bin/*.sh \
  && mkdir -p /app/analytics/server/data/observation_runs /var/log/grapesnta \
  && chown -R app:app /app/analytics/server/data /var/log/grapesnta

USER app

CMD ["/app/entrypoint.sh"]

# syntax=docker/dockerfile:1
# Grapes detection worker — attack/anomaly detector (no UI).
# Build context is this directory (server/ snapshot from NTAdmin).

FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-alpine AS runtime
WORKDIR /app

ARG BUILD_DATE

ENV NODE_ENV=production
ENV GRAPES_DETECTION_WORKER=1

RUN addgroup -g 1001 -S app && adduser -u 1001 -S -G app app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY server ./server

RUN set -e; \
    TS="${BUILD_DATE:-}"; \
    if [ -z "$TS" ] || [ "$TS" = "unknown" ]; then TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; fi; \
    printf '{"buildDate":"%s"}\n' "$TS" > server/build-info.json \
  && mkdir -p server/data \
  && chmod -R a+rX /app \
  && chown -R app:app server/data server/build-info.json

# server/*.js перезаписывает sync-ui-from-ntadmin.sh, поэтому версию печатает CMD.
ARG GRAPES_VERSION=unknown
ENV GRAPES_VERSION=${GRAPES_VERSION}

USER app

CMD ["sh", "-c", "echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) detection version ${GRAPES_VERSION} dated ${GRAPES_VERSION_DATE:-unknown}\"; exec node server/detection-worker.js loop"]

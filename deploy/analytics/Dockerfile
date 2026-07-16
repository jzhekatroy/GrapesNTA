# syntax=docker/dockerfile:1
# Self-contained observations analytics worker (lives in GrapesNTA).

FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV GRAPES_ANALYTICS_WORKER=1

RUN addgroup -g 1001 -S app && adduser -u 1001 -S -G app app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY server ./server

RUN mkdir -p server/data server/data/observation_runs && chown -R app:app server/data

USER app

CMD ["node", "server/analytics.js", "loop"]

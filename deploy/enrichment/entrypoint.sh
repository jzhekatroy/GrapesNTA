#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

mkdir -p /var/lib/geoloaderd/cache /var/log/grapesnta

echo "grapes-enrichment: starting supercronic"
exec supercronic /etc/grapesnta/enrichment.crontab

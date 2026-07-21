# syntax=docker/dockerfile:1
# grapes-enrichment: geo/RIR, bgp-origin, asn-names (external sources).

FROM python:3.12-bookworm-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
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

COPY scripts/load_rir_geo.py scripts/rebuild_bgp_origin_asn.py scripts/load_asn_names.py /app/scripts/
COPY deploy/enrichment/bin /app/bin
COPY deploy/enrichment/enrichment.crontab /etc/grapesnta/enrichment.crontab
COPY deploy/enrichment/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh /app/bin/*.sh \
  && mkdir -p /var/lib/geoloaderd/cache /var/log/grapesnta

CMD ["/app/entrypoint.sh"]

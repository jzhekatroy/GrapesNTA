# syntax=docker/dockerfile:1
# grapes-enrichment: geo/RIR, bgp-origin, asn-names (external sources).

FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    util-linux \
    snmp \
  && rm -rf /var/lib/apt/lists/*

COPY scripts/load_rir_geo.py scripts/rebuild_bgp_origin_asn.py scripts/load_asn_names.py scripts/snmp_iface_sync.py /app/scripts/
COPY deploy/enrichment/bin /app/bin
COPY deploy/enrichment/scheduler.py /app/scheduler.py
COPY deploy/enrichment/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh /app/bin/*.sh /app/bin/report_job_status.py /app/scheduler.py \
  && ln -sf /app/bin/clickhouse-client-http.sh /usr/local/bin/clickhouse-client \
  && mkdir -p /var/lib/geoloaderd/cache /var/log/grapesnta

CMD ["/app/entrypoint.sh"]

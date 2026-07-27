const {
  col,
  flowCol,
  flowsRawTableRef,
  netInterfacesCurrentRef,
  interfaceRolesEffectiveViewRef,
} = require('./clickhouse');
const { flowSamplerIpExpr, sflowIfIndexExpr } = require('./queries');
const { fetchDirectionSettings, portDirectionSql } = require('./net-interface-roles');

const DEFAULT_LOOKBACK_HOURS = 1;
const MAX_LOOKBACK_HOURS = 24;

/** Порог «много автономных систем за портом» для подсказки о стороне сети. */
const DEFAULT_ASN_HINT_THRESHOLD = 50;

/** Полный скан flows_raw дорогой, поэтому окно по умолчанию короткое. */
function parseLookbackHours(value) {
  const hours = Number(value);
  if (!Number.isFinite(hours) || hours <= 0) return DEFAULT_LOOKBACK_HOURS;
  return Math.min(Math.round(hours), MAX_LOOKBACK_HOURS);
}

function apiError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function requireFlowColumns() {
  const samplerCol = flowCol('samplerAddress');
  const inIfCol = flowCol('inIf');
  const outIfCol = flowCol('outIf');
  if (!samplerCol || !inIfCol || !outIfCol) {
    throw apiError('В flows_raw не настроены колонки sampler_address / in_if / out_if', 501);
  }
  return {
    samplerCol,
    inIfCol,
    outIfCol,
    directionCol: flowCol('direction'),
    timeCol: col('time'),
    bytesCol: col('bytes'),
    srcAsnCol: col('srcAsn'),
  };
}

/**
 * Шаг 0: заполняют ли экспортёры интерфейсы.
 * Формат sFlow важен: только 0 несёт один ifIndex, 1 — причина отбрасывания,
 * 2 — «несколько выходных интерфейсов» (флуд, multicast), и как порт непригоден.
 */
function getInterfaceFieldCoverage({ hours } = {}) {
  const c = requireFlowColumns();
  const lookbackHours = parseLookbackHours(hours);
  const inIdx = sflowIfIndexExpr(`f.${c.inIfCol}`);
  const outIdx = sflowIfIndexExpr(`f.${c.outIfCol}`);

  return {
    sql: `
      SELECT
        count() AS flows,
        sum(f.${c.bytesCol}) AS bytes,
        countIf(${inIdx} > 0) AS flows_with_in_if,
        countIf(${outIdx} > 0) AS flows_with_out_if,
        countIf(${inIdx} > 0 AND ${outIdx} > 0) AS flows_with_both,
        sumIf(f.${c.bytesCol}, ${inIdx} > 0 AND ${outIdx} > 0) AS bytes_with_both,
        countIf(${inIdx} > 0 OR ${outIdx} > 0) AS flows_with_any,
        sumIf(f.${c.bytesCol}, ${inIdx} > 0 OR ${outIdx} > 0) AS bytes_with_any,
        countIf(f.${c.inIfCol} > 0 AND ${inIdx} = 0) AS flows_in_if_other_format,
        countIf(f.${c.outIfCol} > 0 AND ${outIdx} = 0) AS flows_out_if_other_format,
        uniqExact(${flowSamplerIpExpr(`f.${c.samplerCol}`)}) AS switches
      FROM ${flowsRawTableRef()} AS f
      WHERE f.${c.timeCol} >= now() - INTERVAL {hours:UInt32} HOUR
    `,
    params: { hours: lookbackHours },
    map(rows) {
      const r = rows[0] || {};
      const flows = Number(r.flows) || 0;
      const bytes = Number(r.bytes) || 0;
      const pct = (part, total) => (total ? Math.round((part * 10000) / total) / 100 : 0);
      const flowsWithBoth = Number(r.flows_with_both) || 0;
      const flowsWithAny = Number(r.flows_with_any) || 0;
      return {
        lookbackHours,
        flows,
        bytes,
        switches: Number(r.switches) || 0,
        flowsWithInIf: Number(r.flows_with_in_if) || 0,
        flowsWithOutIf: Number(r.flows_with_out_if) || 0,
        flowsWithBoth,
        flowsWithBothPercent: pct(flowsWithBoth, flows),
        bytesWithBothPercent: pct(Number(r.bytes_with_both) || 0, bytes),
        flowsWithAny,
        flowsWithAnyPercent: pct(flowsWithAny, flows),
        bytesWithAnyPercent: pct(Number(r.bytes_with_any) || 0, bytes),
        flowsInIfOtherFormat: Number(r.flows_in_if_other_format) || 0,
        flowsOutIfOtherFormat: Number(r.flows_out_if_other_format) || 0,
      };
    },
  };
}

/** JOIN к разметке для входного и выходного порта. */
function boundaryJoinSql(c) {
  const switchIpExpr = flowSamplerIpExpr(`f.${c.samplerCol}`);
  const rolesRef = interfaceRolesEffectiveViewRef();
  return `
      FROM ${flowsRawTableRef()} AS f
      LEFT JOIN ${rolesRef} AS side_in
        ON side_in.switch_ip = ${switchIpExpr}
        AND side_in.if_index = ${sflowIfIndexExpr(`f.${c.inIfCol}`)}
      LEFT JOIN ${rolesRef} AS side_out
        ON side_out.switch_ip = ${switchIpExpr}
        AND side_out.if_index = ${sflowIfIndexExpr(`f.${c.outIfCol}`)}`;
}

/**
 * Матрица «направление по портам» × «текущее direction из flows_raw».
 * Показывает, совпали бы модели при переключении определения направления.
 */
async function compareDirectionModels({ hours, oneSided } = {}) {
  const c = requireFlowColumns();
  if (!c.directionCol) throw apiError('В flows_raw не настроена колонка direction', 501);
  const lookbackHours = parseLookbackHours(hours);
  const settings = await fetchDirectionSettings();
  const policy = oneSided === 'strict' || oneSided === 'infer' ? oneSided : settings.oneSided;
  const inBoundary = `if(side_in.boundary = '', 'unknown', side_in.boundary)`;
  const outBoundary = `if(side_out.boundary = '', 'unknown', side_out.boundary)`;

  return {
    sql: `
      SELECT
        ${portDirectionSql('in_boundary', 'out_boundary', { oneSided: policy })} AS port_direction,
        ch_direction,
        sum(bytes) AS bytes,
        sum(flows) AS flows
      FROM (
        SELECT
          ${inBoundary} AS in_boundary,
          ${outBoundary} AS out_boundary,
          f.${c.directionCol} AS ch_direction,
          sum(f.${c.bytesCol}) AS bytes,
          count() AS flows
        ${boundaryJoinSql(c)}
        WHERE f.${c.timeCol} >= now() - INTERVAL {hours:UInt32} HOUR
        GROUP BY in_boundary, out_boundary, ch_direction
      )
      GROUP BY port_direction, ch_direction
      ORDER BY bytes DESC
    `,
    params: { hours: lookbackHours },
    meta: { oneSided: policy, defaultBoundary: settings.defaultBoundary },
    map(rows) {
      const cells = rows.map((r) => ({
        portDirection: String(r.port_direction ?? 'unknown'),
        chDirection: String(r.ch_direction ?? 'unknown'),
        bytes: Number(r.bytes) || 0,
        flows: Number(r.flows) || 0,
      }));
      const totalBytes = cells.reduce((s, x) => s + x.bytes, 0);
      const agreeBytes = cells
        .filter((x) => x.portDirection === x.chDirection)
        .reduce((s, x) => s + x.bytes, 0);
      const undecidedBytes = cells
        .filter((x) => x.portDirection === 'unknown')
        .reduce((s, x) => s + x.bytes, 0);
      const pct = (part) => (totalBytes ? Math.round((part * 10000) / totalBytes) / 100 : 0);
      return {
        lookbackHours,
        oneSided: policy,
        totalBytes,
        agreeBytes,
        agreePercent: pct(agreeBytes),
        undecidedBytes,
        undecidedPercent: pct(undecidedBytes),
        cells: cells.sort((a, b) => b.bytes - a.bytes),
      };
    },
  };
}

/**
 * Порты с трафиком, их разметка и подсказки для оператора.
 *
 * Число автономных систем за портом — универсальный признак: за клиентским
 * или участниковым портом их единицы, за аплинком и магистралью — сотни.
 * Это подсказка человеку, а не автоматическая разметка.
 */
function listInterfacesByTraffic({
  hours,
  limit,
  onlyUnmarked = false,
  asnThreshold = DEFAULT_ASN_HINT_THRESHOLD,
} = {}) {
  const c = requireFlowColumns();
  const lookbackHours = parseLookbackHours(hours);
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 500);
  const threshold = Math.min(Math.max(Number(asnThreshold) || DEFAULT_ASN_HINT_THRESHOLD, 1), 100000);
  const switchIpExpr = flowSamplerIpExpr(`f.${c.samplerCol}`);
  const filterSql = onlyUnmarked ? `WHERE boundary = 'unknown'` : '';

  return {
    sql: `
      SELECT *
      FROM (
        SELECT
          t.switch_ip AS switch_ip,
          t.if_index AS if_index,
          t.ingress_bytes AS ingress_bytes,
          t.egress_bytes AS egress_bytes,
          t.ingress_bytes + t.egress_bytes AS bytes,
          t.flows AS flows,
          t.ingress_asn_count AS ingress_asn_count,
          if(eff.boundary = '', 'unknown', eff.boundary) AS boundary,
          eff.boundary_source AS boundary_source,
          eff.connectivity AS connectivity,
          iface.if_name AS if_name,
          iface.if_alias AS if_alias,
          iface.if_descr AS if_descr,
          if(iface.if_high_speed_mbps > 0,
             iface.if_high_speed_mbps,
             toUInt32(iface.if_speed_bps / 1000000)) AS speed_mbps,
          iface.if_index > 0 AS in_catalog,
          if(t.ingress_asn_count >= {asn_threshold:UInt32}, 'external', 'internal') AS suggested_boundary
        FROM (
          SELECT
            switch_ip,
            tupleElement(port, 1) AS if_index,
            sumIf(bytes, tupleElement(port, 2) = 'in') AS ingress_bytes,
            sumIf(bytes, tupleElement(port, 2) = 'out') AS egress_bytes,
            count() AS flows,
            uniqCombinedIf(src_asn, tupleElement(port, 2) = 'in') AS ingress_asn_count
          FROM (
            SELECT
              ${switchIpExpr} AS switch_ip,
              arrayJoin(arrayFilter(x -> tupleElement(x, 1) > 0, [
                (${sflowIfIndexExpr(`f.${c.inIfCol}`)}, 'in'),
                (${sflowIfIndexExpr(`f.${c.outIfCol}`)}, 'out')
              ])) AS port,
              f.${c.bytesCol} AS bytes,
              f.${c.srcAsnCol} AS src_asn
            FROM ${flowsRawTableRef()} AS f
            WHERE f.${c.timeCol} >= now() - INTERVAL {hours:UInt32} HOUR
          )
          GROUP BY switch_ip, if_index
        ) AS t
        LEFT JOIN ${interfaceRolesEffectiveViewRef()} AS eff
          ON eff.switch_ip = t.switch_ip AND eff.if_index = t.if_index
        LEFT JOIN ${netInterfacesCurrentRef()} AS iface
          ON iface.switch_ip = t.switch_ip AND iface.if_index = t.if_index
      )
      ${filterSql}
      ORDER BY bytes DESC
      LIMIT {limit:UInt32}
    `,
    params: { hours: lookbackHours, limit: lim, asn_threshold: threshold },
    meta: { lookbackHours, asnThreshold: threshold },
    map(rows) {
      return rows.map((r) => ({
        switchIp: String(r.switch_ip ?? ''),
        ifIndex: Number(r.if_index) || 0,
        ifName: String(r.if_name ?? ''),
        ifAlias: String(r.if_alias ?? ''),
        ifDescr: String(r.if_descr ?? ''),
        speedMbps: Number(r.speed_mbps) || 0,
        inCatalog: Number(r.in_catalog) === 1,
        boundary: String(r.boundary ?? 'unknown'),
        boundarySource: String(r.boundary_source ?? 'default'),
        connectivity: String(r.connectivity ?? ''),
        bytes: Number(r.bytes) || 0,
        ingressBytes: Number(r.ingress_bytes) || 0,
        egressBytes: Number(r.egress_bytes) || 0,
        flows: Number(r.flows) || 0,
        ingressAsnCount: Number(r.ingress_asn_count) || 0,
        suggestedBoundary: String(r.suggested_boundary ?? ''),
      }));
    },
  };
}

module.exports = {
  DEFAULT_LOOKBACK_HOURS,
  MAX_LOOKBACK_HOURS,
  DEFAULT_ASN_HINT_THRESHOLD,
  getInterfaceFieldCoverage,
  compareDirectionModels,
  listInterfacesByTraffic,
};

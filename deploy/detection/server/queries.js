'use strict';

const { flowCol } = require('./clickhouse');

function flowIpExpr(ipCol) {
  const etype = flowCol('etype');
  if (!etype) return `IPv6NumToString(${ipCol})`;
  const etypeRef = ipCol.includes('.')
    ? `${ipCol.split('.')[0]}.${etype}`
    : etype;
  return `if(
        ${etypeRef} = 2048,
        toString(toIPv4(reinterpretAsUInt32(reverse(substring(${ipCol}, 1, 4))))),
        IPv6NumToString(${ipCol})
      )`;
}

module.exports = { flowIpExpr };

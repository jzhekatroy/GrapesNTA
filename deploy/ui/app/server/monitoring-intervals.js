const PARAMETERS = {
  broadband_total: {
    id: 'broadband_total',
    label: 'Суммарный трафик ШПД',
    unit: 'Гбит/мин',
    featureName: 'total_bytes',
    boundsConfigKey: 'intervals',
  },
  broadband_in_ru: {
    id: 'broadband_in_ru',
    label: 'Входящий трафик ШПД из России',
    unit: 'Гбит/мин',
    featureName: 'country_ru',
    boundsConfigKey: 'intervals_country_ru',
  },
  broadband_in_foreign: {
    id: 'broadband_in_foreign',
    label: 'Входящий трафик ШПД из-за рубежа',
    unit: 'Гбит/мин',
    featureName: 'country_F',
    boundsConfigKey: 'intervals_country_F',
  },
  protocol_in_tcp: {
    id: 'protocol_in_tcp',
    label: 'Входящий трафик ШПД по протоколу TCP',
    unit: 'Гбит/мин',
    featureName: 'protocol_tcp',
    boundsConfigKey: 'intervals_protocols_tcp',
    protocolFilter: 'tcp',
  },
  protocol_in_udp: {
    id: 'protocol_in_udp',
    label: 'Входящий трафик ШПД по протоколу UDP',
    unit: 'Гбит/мин',
    featureName: 'protocol_udp',
    boundsConfigKey: 'intervals_protocols_udp',
    protocolFilter: 'udp',
  },
  protocol_in_other: {
    id: 'protocol_in_other',
    label: 'Входящий трафик ШПД по протоколу другие',
    unit: 'Гбит/мин',
    featureName: 'protocol_oth',
    boundsConfigKey: 'intervals_protocols_oth',
    protocolFilter: 'other',
    boundsRequiresCiMinimum: false,
  },
};

const FEATURE_LABELS = Object.fromEntries(
  Object.values(PARAMETERS).map((item) => [item.featureName, item.label]),
);

function getParameter(id) {
  return PARAMETERS[id] || null;
}

function getParameterLabel(featureName) {
  return FEATURE_LABELS[String(featureName || '')] || String(featureName || '—');
}

function listParameterIds() {
  return Object.keys(PARAMETERS);
}

module.exports = {
  PARAMETERS,
  FEATURE_LABELS,
  getParameter,
  getParameterLabel,
  listParameterIds,
};

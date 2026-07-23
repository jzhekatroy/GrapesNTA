#!/bin/sh
# Dictionary SOURCE(CLICKHOUSE(...)) is opened by the ClickHouse *server*
# process, not by this container. It must use the server's loopback native
# endpoint (almost always 127.0.0.1:9000).
#
# Client vars (*_CH_HOST / *_CH_PORT) may point at a remote mirror
# (e.g. 95.x.x.x:6124 + HTTP :6123). Copying those into *_DICT_SOURCE_*
# makes SYSTEM RELOAD DICTIONARY hang with ALL_CONNECTION_TRIES_FAILED.
#
# Usage: fix_dict_source PREFIX   # e.g. fix_dict_source BGPORIGIN

fix_dict_source() {
  prefix="$1"
  if [ -z "$prefix" ]; then
    echo "fix_dict_source: PREFIX required" >&2
    return 2
  fi

  eval "ch_host=\${${prefix}_CH_HOST:-}"
  eval "dict_host=\${${prefix}_DICT_SOURCE_HOST:-}"
  eval "dict_port=\${${prefix}_DICT_SOURCE_PORT:-}"

  case "$dict_host" in
    ""|127.0.0.1|localhost|::1)
      if [ -z "$dict_host" ]; then
        eval "export ${prefix}_DICT_SOURCE_HOST=127.0.0.1"
        echo "${prefix}: DICT_SOURCE_HOST unset → 127.0.0.1 (CH server loopback)" >&2
      fi
      if [ -z "$dict_port" ]; then
        eval "export ${prefix}_DICT_SOURCE_PORT=9000"
        echo "${prefix}: DICT_SOURCE_PORT unset → 9000 (CH native)" >&2
      fi
      return 0
      ;;
  esac

  # Non-loopback dict host that matches the client CH endpoint → almost always a
  # mistaken copy from *_CH_HOST on remote-CH installs. Rewrite to loopback.
  if [ -n "$ch_host" ] && [ "$dict_host" = "$ch_host" ]; then
    echo "${prefix}: DICT_SOURCE_HOST=$dict_host equals ${prefix}_CH_HOST (client endpoint); using 127.0.0.1:9000 for dictionary SOURCE" >&2
    eval "export ${prefix}_DICT_SOURCE_HOST=127.0.0.1"
    eval "export ${prefix}_DICT_SOURCE_PORT=9000"
    return 0
  fi

  # Non-loopback and different from CH_HOST — leave as-is (rare deliberate setup).
  return 0
}

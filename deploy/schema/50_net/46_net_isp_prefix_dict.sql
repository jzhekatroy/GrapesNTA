-- Провайдер ШПД по адресу назначения.
--
-- Префиксы с ролью provider_public не привязаны к клиенту: детекция смотрела
-- только первую /24 каждого префикса и не видела удар, размазанный по сети.
-- Словарь отдаёт entity_id (isp:verolayn и т. п.) за одно обращение. При
-- вложенных префиксах побеждает более точный, как у словаря клиентов.

CREATE OR REPLACE VIEW default.net_isp_prefix_dict_src AS
SELECT
    prefix,
    min(entity_id) AS entity_id
FROM default.net_l3_prefixes_enabled
WHERE family = 4
  AND role = 'provider_public'
  AND prefix != ''
  AND entity_id != ''
GROUP BY prefix;

-- Срок жизни короткий: новые префиксы подхватываются без SYSTEM RELOAD,
-- которого у пользователя интерфейса нет.
CREATE DICTIONARY IF NOT EXISTS default.net_isp_prefix_dict
(
    `prefix` String,
    `entity_id` String
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(HOST '${CH_DICT_HOST}' PORT ${CH_DICT_PORT} USER '${CH_DICT_USER}' PASSWORD '${CH_DICT_PASSWORD}' DB 'default' TABLE 'net_isp_prefix_dict_src' CONNECT_TIMEOUT 10 SEND_RECEIVE_TIMEOUT 30))
LIFETIME(MIN 30 MAX 90)
LAYOUT(IP_TRIE);

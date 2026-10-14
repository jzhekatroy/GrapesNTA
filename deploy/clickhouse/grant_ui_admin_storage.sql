-- Страница «Хранение данных» читает system.parts и system.disks от ui_admin.
-- bootstrap_users.sql на уже живой базе повторно не выполняется.
-- На части установок нет даже GRANT SELECT ON system.*, и ClickHouse 24
-- отвечает ACCESS_DENIED на system.parts и system.disks.
-- Грант выдаёт каждый ./deploy/deploy.sh ui|detection|schema|full.
GRANT SELECT ON system.* TO ui_admin;
GRANT SELECT ON system.parts TO ui_admin;
GRANT SELECT ON system.disks TO ui_admin;

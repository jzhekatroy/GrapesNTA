-- ui_read читает словарь провайдера в запросах детекции.
-- bootstrap_users.sql на уже живой базе повторно не выполняется,
-- поэтому этот грант выдаёт каждый ./deploy/deploy.sh ui|detection|schema|full.
GRANT dictGet ON default.net_isp_prefix_dict TO ui_read;

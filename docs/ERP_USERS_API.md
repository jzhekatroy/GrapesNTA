# ERP ↔ NTA: API управления пользователями NTA — план и контракт

Статус: контракт согласован (ревью по коду ERP, 2026-10-20), правки внесены.
Контракт диктует NTA, ERP подстраивается.
Дата: 2026-10-20. Ветка разработки (NTA): `v.revenko-api-for-crud-clients`.

Документ самодостаточен — его можно целиком перенести в проект ERP.
Разделы 1–3 и 6–7 нужны обеим командам; раздел 4 — реализация в NTA; раздел 5 —
реализация в ERP (Laravel).

---

## 1. Контекст задачи

У одного клиента (лицевой счёт, ЛС) может быть **до 5 пользователей NTA** с ролью
`Client`. Управляет ими техподдержка из ERP по заявкам клиентов; NTA предоставляет
REST API (JSON, авторизация Bearer-токеном).

**PiterIX и Трансроут — разные инсталяции NTA** (разные серверы, базы и URL).
Код и контракт API идентичны на всех инсталяциях, отличается только base URL и
учётные данные (client_id/client_secret). Какая инсталяция обслуживает какой ЛС —
знает ERP по группе ЛС: **710 = PiterIX, 726 = Трансроут**.

### Флоу работы техподдержки

1. Клиент присылает письмо в техподдержку PiterIX с просьбой добавить
   пользователя в NTA → создаётся заявка (тикет).
2. Техподдержка выясняет, **на какой контакт** добавить пользователя; если
   контакта нет в ERP — создаёт контакт.
3. На странице клиента (вкладка «Контактная информация») у каждого контакта
   выпадающее меню рядом с «Удалить»/«Редактировать»:
   - пользователя NTA нет → пункт **«Создать пользователя NTA»**;
   - пользователь есть → пункты **«Сбросить пароль»** и **«Удалить»**.
4. «Создать» открывает модалку: выбираем тикет → «Создать» → **синхронный**
   запрос в NTA → ERP получает логин и пароль.
5. Комментарий в транзакцию тикета — синхронно. Текст комментария и тему
   письма готовит сотрудник техподдержки — **интеграции с ИИ в коде нет**
   (при необходимости текст составляют с помощью ИИ вручную, вне системы).
6. Отправка письма — через очередь. Адресат (`To`) — почта ЛС, копия (`Cc`) —
   почта создаваемого пользователя NTA (из данных клиента, контакты).
   Если у клиента в доп. контактах не заполнен email — ошибка
   «Пожалуйста, заполните email».
7. Все запросы в NTA — **синхронные**; при ошибке ERP показывает ошибку
   пользователю.
8. Лимит: не более 5 пользователей на ЛС. При исчерпании — подсказка при
   наведении на кнопку: «Все 5 контактов созданы, удалите старый, чтобы
   добавить новый».

Пункты 3–8 — работа на стороне ERP. Со стороны NTA реализуется только API
(раздел 4).

---

## 2. Что уже есть в NTA

- **Ночная синхронизация ERP → NTA** уже работает: NTA раз в сутки тянет из ERP
  клиентов категории `piter_ix` в свою таблицу `net_clients`; поле ERP
  `basic_account` = `net_clients.client_id` (= номер ЛС). ЛС, созданный в ERP
  днём, появляется в NTA после ночного прогона (либо после ручного запуска
  синхронизации из админки NTA).
- Пользователи NTA с ролью `Client` привязываются к `client_id`; **лимит 5
  пользователей на ЛС уже действует** в коде NTA (константа
  `MAX_USERS_PER_CLIENT = 5`).
- Внутренний CRUD пользователей для админки NTA существует, но работает под
  cookie-сессиями. Для ERP нужен отдельный внешний Bearer-API — его и строим.

Следствие: ЛС, которого ещё нет в NTA (не синхронизирован), при вызове API
вернёт `404 account_not_found`. Текст ошибки уточним по ходу эксплуатации;
автоподгрузка ЛС при 404 — кандидат в v2 (см. раздел 6).

---

## 3. Контракт API v1 (фиксирует NTA)

Base URL — свой на каждой инсталяции (`https://<nta-piterix>`,
`https://<nta-transroute>`); пути одинаковы. Все тела — JSON (кроме получения
токена — там form-urlencoded или JSON).

### 3.1. Получение токена

`client_id`/`client_secret` выдаются на стороне NTA (один раз, см. 3.8) и
хранятся в справочнике ERP. Токен живёт `expires_in` секунд — **кэшировать его
на стороне ERP** и переиспользовать, а не запрашивать на каждый вызов. При
получении 401 — один раз перевыпустить токен и повторить запрос.

```http
POST /api/v1/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=<id>&client_secret=<secret>
```

```json
{
  "token_type": "Bearer",
  "expires_in": 3600,
  "access_token": "..."
}
```

Ошибка — `401 {"error": "Неверные учётные данные клиента", "code": "invalid_client"}`.

### 3.2. Список пользователей ЛС

Нужен ERP, чтобы решить, какие кнопки показывать (Создать vs Сбросить/Удалить),
и для счётчика лимита. Пароли не отдаёт никогда.

```http
GET /api/v1/clients/users?account=123456
Authorization: Bearer <token>
```

```json
{
  "data": [
    { "login": "ivan@corp.ru", "fullName": "Иван Иванов", "createdAt": "2026-10-20 12:00:00", "active": true }
  ],
  "meta": { "limit": 5, "used": 1, "remaining": 4 }
}
```

### 3.3. Создание пользователя

```http
POST /api/v1/clients/users
Authorization: Bearer <token>
Content-Type: application/json

{ "account": "123456", "login": "ivan@corp.ru", "fullName": "Иван Иванов" }
```

- `account` — номер ЛС (обязателен);
- `login` — email из контакта ERP (обязателен; проверяется формат email);
- `fullName` — **необязателен**: передаём из ERP, если у контакта заполнено ФИО;
  если пусто/нет — NTA запишет в ФИО логин (email), поправить можно будет
  руками в админке NTA.

Ответ `201`:

```json
{ "account": "123456", "login": "ivan@corp.ru", "password": "<сгенерирован>" }
```

Пароль генерирует NTA (14 символов: буквы, цифры, спецсимволы). Возвращается
**один раз**; хранится только bcrypt-хэш. При создании и после сброса у
пользователя обязательная смена пароля при первом входе.

### 3.4. Сброс пароля

```http
POST /api/v1/clients/users/password-reset
Authorization: Bearer <token>
Content-Type: application/json

{ "account": "123456", "login": "ivan@corp.ru" }
```

Ответ `200`:

```json
{ "account": "123456", "login": "ivan@corp.ru", "password": "<новый>" }
```

Старый пароль перестаёт действовать, активные сессии пользователя отзываются.

### 3.5. Удаление

Основной вариант — JSON-тело (единый стиль «данные в JSON» с остальными
методами). **Дополнительно принимаются те же поля как query-параметры** —
запасной вариант на случай ограничений HTTP-клиента (нюанс Laravel — в 5.2).

```http
DELETE /api/v1/clients/users
Authorization: Bearer <token>
Content-Type: application/json

{ "account": "123456", "login": "ivan@corp.ru" }
```

— равнозначно —

```http
DELETE /api/v1/clients/users?account=123456&login=ivan@corp.ru
Authorization: Bearer <token>
```

Ответ: `200 { "ok": true }`. Активные сессии удалённого пользователя отзываются.

### 3.6. Формат ошибок

Везде одинаковый: `{"error": "<текст, можно показать пользователю ERP>", "code": "<машиночитаемый код>"}`.

| HTTP | code | Когда |
|------|------|-------|
| 400 | `validation_failed` | пустые поля, `login` не похож на email |
| 401 | `invalid_client` | неверные client_id/client_secret на `/oauth/token` |
| 401 | `unauthorized` | нет/просрочен Bearer-токен |
| 404 | `account_not_found` | ЛС не найден в NTA (ещё не синхронизирован) |
| 404 | `user_not_found` | пара ЛС+логин не найдена (сброс/удаление) |
| 409 | `login_taken` | логин уже занят (уникален глобально по всем ЛС) |
| 409 | `client_users_limit_reached` | на ЛС уже 5 пользователей |

Тексты ошибок — рабочие, финализируются по ходу эксплуатации (текст
`account_not_found` особенно).

### 3.7. Правила

- Лимит: 5 пользователей на ЛС (`client_users_limit_reached`).
- Логин глобально уникален среди всех пользователей NTA (`login_taken`).
- Создаваемый ЛС должен уже существовать в NTA (см. раздел 2). Если нет —
  `404 account_not_found`; техподдержка запускает синхронизацию в NTA и
  повторяет.
- Все операции выполняются от имени учётной записи клиента `client_id = account`
  с ролью `Client`.

### 3.8. Выдача client_id / client_secret

На **каждой** инсталяции NTA администратор один раз создаёт API-клиента
(CLI-команда на сервере NTA) и передаёт полученные `client_id`/`client_secret`
в ERP — они заносятся в справочник ERP (раздел 5.1) консольной командой.
Секрет показывается при создании один раз и хранится в NTA только в виде
bcrypt-хэша; при утере — перевыпуск.

---

## 4. Реализация на стороне NTA (этот репозиторий)

Приложение NTA — Node.js/Express, вендорено в `deploy/ui/app` (репо NTAdmin).
Go-коллекторы задачей не затрагиваются. План:

1. **`server/api-clients.js`** — справочник API-клиентов: ClickHouse-таблица
   `app_api_clients` (`client_id`, `client_name`, `secret_hash` bcrypt,
   `is_active`, `created_at`, `updated_at`; ReplacingMergeTree) по образцу
   `server/erp-piterix-settings.js`. Клиентов мало (PiterIX ERP, Трансроут ERP),
   справочник плоский.
2. **`server/api-tokens.js`** — выдача/проверка opaque-токенов с TTL в SQLite
   по образцу `server/sessions.js` + middleware `requireBearerToken`
   (проверка `Authorization: Bearer`, TTL, отзыв).
3. **`server/api-v1-routes.js`** — роутер: `POST /oauth/token` + эндпоинты
   3.2–3.5. Внутри — тонкая адаптация поверх существующего `server/users.js`:
   - создание → `createUser({ username: login, fullName, password:
     generatePassword(), roleId: 'Client', clientId: account,
     forcePasswordChange: true })`;
   - список → `listUsers({ clientId: account })` (уже возвращает
     `meta.limit/used/remaining`);
   - сброс → `resetUserPassword(id)` (уже ставит `force_password_change=1`);
   - удаление → `deleteUser(id)` + отзыв сессий
     `sessions.revokeClientSessions({ userIds: [id] })`;
   - проверка ЛС → `getEnabledClient(account)`
     (`server/cabinet/clients-lookup.js`); нет → `404 account_not_found`.
   - DELETE: читать `account`/`login` из тела, а если тела нет — из
     query-параметров.
4. **Монтаж в `server/index.js` до `app.use('/api', requireSession)`** (примерно
   строка 706, по аналогии с `/api/auth/login`): иначе сессионный гард заблокирует
   bearer-запросы.
5. **Аудит**: каждое действие писать через `writeAuditEvent`
   (`server/audit-log.js`) с синтетическим актёром
   (`actorUsername: "api:PiterIX"`), чтобы действия ERP были видны в журнале NTA.
6. **CLI**: `deploy/ui/app/scripts/api-client-create.js` — создаёт запись в
   `app_api_clients`, печатает `client_id`/`client_secret` один раз. Каталога
   `scripts/` в вендоренной копии сейчас нет — создать. Запуск на сервере через
   `docker exec` (см. `deploy/erp-piterix/run.sh`).
7. **Тесты**: `node --test`, по образцу соседних `*.test.js`: выдача/протухание
   токена, маппинг `account+login` → 404/409, лимит 5, fallback query у DELETE.
8. **Деплой**: код одинаков на всех инсталяциях; на каждой создаётся свой
   API-клиент (п. 3.8).

Фронтенд NTA не меняется (управление API-клиентами — CLI; UI-страница —
опционально позже).

---

## 5. Реализация на стороне ERP (Laravel)

### 5.1. Справочник интеграций

Таблица/модель «справочник инсталяций NTA», связанная со справочником компаний
ERP: `company_id`, `base_url`, `client_id`, `client_secret`. Заполнение —
консольной командой (по аналогии с интеграциями Сбера и др.):

```bash
php artisan nta:register --company="PiterIX" --url="https://nta-piterix.example" \
    --client-id=... --client-secret=...
```

Креды берутся у администратора NTA (см. 3.8). Выбор строки справочника — по
группе ЛС: 710 → PiterIX, 726 → Трансроут.

### 5.2. HTTP-клиент

Обычный `Http::` (Guzzle). Passport/Scout для этого не нужны — это вызов
стороннего API, токен кэшируется в cache/store по ключу инсталяции.

```php
// Токен — один раз, дальше из кэша до expires_in
$res = Http::asForm()->post("{$base}/api/v1/oauth/token", [
    'grant_type' => 'client_credentials',
    'client_id' => $clientId,
    'client_secret' => $clientSecret,
])->throw()->json();
$token = $res['access_token'];

// Создание (синхронно; при ошибке — показать её пользователю)
$res = Http::withToken($token)
    ->post("{$base}/api/v1/clients/users", [
        'account' => $account,
        'login'   => $contactEmail,
        'fullName' => $contact->full_name, // может быть null — NTA подставит логин
    ]);
if ($res->status() === 409 && $res->json('code') === 'client_users_limit_reached') {
    // тултип: «Все 5 контактов созданы, удалите старый, чтобы добавить новый»
}

// Сброс пароля
Http::withToken($token)->post("{$base}/api/v1/clients/users/password-reset", [
    'account' => $account, 'login' => $login,
]);

// Удаление — JSON-телом. Проверено по коду ERP (Laravel 10): там
// Http::delete($url, $data) отправляет $data телом (bodyFormat=json
// по умолчанию, PendingRequest.php) — самый простой вариант уже правильный
Http::withToken($token)->delete("{$base}/api/v1/clients/users", [
    'account' => $account, 'login' => $login,
]);

// Удаление — query-параметрами (второй вариант, поддерживаемый NTA)
Http::withToken($token)->delete("{$base}/api/v1/clients/users?" .
    http_build_query(['account' => $account, 'login' => $login]));
```

**Про DELETE и версии Laravel**: поведение `Http::delete($url, $data)` в старых
версиях отличалось (данные уходили в query). Поэтому NTA принимает оба варианта
(3.5) — какой бы ни был Laravel, рабочий найдётся.

### 5.3. UI и логика

- Вкладка «Контактная информация» — Blade + jQuery (не Vue): кнопки
  «Редактировать»/«Удалить» у контакта уже есть в `contact.blade.php`; меню
  «Создать пользователя NTA / Сбросить пароль / Удалить» добавлять в этот же
  Blade-партиал. Показывать только для ЛС групп 710/726 (`Group::PITER_IX` /
  `Group::TRANSROUTE` — константы в `app/Clients/Group.php`).
- Состояние «есть пользователь / нет» и счётчик `used/limit` — из
  `GET /api/v1/clients/users` (3.2) при открытии страницы/меню.
- Модалка создания: выбор тикета → «Создать» → синхронный вызов → экран с
  логином и паролем. Готового пикера тикетов нет — модалка новая
  (Blade-модалки через `data-modal="{{ route(...) }}"`).
- Комментарий в транзакцию тикета — синхронно, через
  `TicketStateChanger::addComment()` (транзакцию открывает вызывающий код).
  **Автор комментария — сотрудник, нажавший кнопку** (не `bot()`).
- Тема и текст письма — сотрудник готовит вручную; интеграции с ИИ в коде нет.
- Письмо — в очередь (job по образцу `SendMailToClient`), отправка с ящика
  очереди тикета (TicketMailer/OngoingMail, тема с `[PREFIX#uid]`) — чтобы
  письмо попало в почтовый тред тикета. Схема адресации — по образцу
  `SendingMail`: `To` = email ЛС (`users.email` биллинга), `Cc` = email
  создаваемого пользователя (доп. контакты клиента). Пустой email → ошибка
  «Пожалуйста, заполните email» до отправки запроса в NTA.
- Все ошибки NTA (`error` из ответа) показывать пользователю как есть.
- **Пароль NTA попадает в комментарий тикета открытым текстом** — осознанное
  решение (так диктует флоу). Риск ограничен: пароль одноразовый, NTA требует
  смену при первом входе. С паролями ERP он никак не связан.
- **Связка контакт ↔ логин** (у контакта может быть несколько email — массив в
  `clients_contacts_data`):
  - при создании логином становится выбранный в модалке email (или первый у
    контакта);
  - «у контакта есть пользователь NTA» — матч логина из списка NTA (3.2) по
    **любому** из email контакта;
  - на сброс/удаление слать именно тот `login`, что вернул NTA в списке, а не
    текущий email контакта — иначе после смены email в ERP словим
    `404 user_not_found`.

### 5.4. Готовые кирпичи в коде ERP (проверено ревью 2026-10-20)

- Справочник компаний `digest_companies`: у компании есть поле `groups` (JSON
  id групп) и готовый `ClientCompanyService::getCompanyByGroupId()` — связка
  «инсталяция NTA ↔ компания ↔ группа 710/726» строится на нём.
- Кэш токена — образец `ZabbixAuthService` (`Cache::remember` до TTL);
  шифрование секретов — `Crypt::encrypt` (паттерн Сбера); artisan-команды —
  `app/Console/Commands/` с автозагрузкой.
- По CLAUDE.md ERP новый код — Clean Architecture: домен `app/Nta/` с
  `Infrastructure/External/`.

---

## 6. Открытые вопросы и отложенное (v2)

Решено (2026-10-20):

- **Генерация текста ИИ** — интеграции нет и не планируется: текст
  комментария/письма сотрудник готовит вручную (при необходимости с помощью ИИ
  вне системы). В коде ERP/NTA работы нет.
- **Пароль NTA в комментарии тикета открытым текстом** — осознанно принято
  (см. 5.3): пароль одноразовый, NTA требует смену при первом входе.

Открыто (ERP-фаза, разработку API на стороне NTA не блокирует):

1. **Клиент в обеих группах сразу (710 + 726)** — в какую инсталяцию создавать
   пользователя. Варианты: выбор инсталяции в модалке (когда групп две) или
   правило «по основной группе». Лимит 5 считается в каждой инсталяции
   отдельно — это нормально. Решить при реализации ERP-части.
2. **Автоподгрузка ЛС при 404** (`account_not_found`): вариант — NTA при
   создании дергает API ERP для этого одного ЛС и апсертит его. Сейчас ERP
   отдаёт клиентов только категорией с курсором
   (`/api/v1/clients/by-category/...`), эндпоинта «один ЛС» нет — потребуется
   расширение на стороне ERP. v2: ручной запуск синхронизации в NTA + ночной
   прогон кейс закрывают.
3. **Текст ошибки** `account_not_found` — финализировать по ходу эксплуатации.
4. Опционально: UI-страница управления API-клиентами в админке NTA вместо CLI.

---

## 7. Ручная проверка контракта (curl)

```bash
BASE=http://localhost:3000

# 1. Токен
TOKEN=$(curl -s -X POST "$BASE/api/v1/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=<id>&client_secret=<secret>' \
  | jq -r .access_token)

# 2. Список пользователей ЛС
curl -s "$BASE/api/v1/clients/users?account=123456" -H "Authorization: Bearer $TOKEN"

# 3. Создать
curl -s -X POST "$BASE/api/v1/clients/users" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"account":"123456","login":"ivan@corp.ru","fullName":"Иван Иванов"}'

# 4. Сбросить пароль
curl -s -X POST "$BASE/api/v1/clients/users/password-reset" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"account":"123456","login":"ivan@corp.ru"}'

# 5. Удалить (тело JSON; работает и через ?account=...&login=...)
curl -s -X DELETE "$BASE/api/v1/clients/users" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"account":"123456","login":"ivan@corp.ru"}'
```

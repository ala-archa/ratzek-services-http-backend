# Shaper byte-quota reset — runbook

## Что это и зачем

На хосте «ограничение скорости» для гостей — это **байтовая квота на iptables**, а не
per-client tc-полиса:

```
# на КАЖДЫЙ форвардящийся пакет ядро добавляет/обновляет запись клиента в set:
-A FORWARD -i eth0 -j SET --add-set shaper src      (+ o eth0 dst, + wlan1 src/dst)
# при накоплении > 1 ГБ — mark 333 -> tc режет скорость:
-A FORWARD -m set --match-set shaper src --bytes-gt 1073741824 -j MARK --set-xmark 0x14d
```

Сет `shaper` = `bitmap:ip range 10.11.5.50-255 timeout 10800 counters`. Для `bitmap:ip`
таргет `SET --add-set` на каждом пакете **сбрасывает timeout обратно на 3 ч** и копит
счётчик. Значит запись истекает (а счётчик обнуляется) **только после 3 ч полной тишины**.
Устройство с фоновым трафиком (пуши/синхронизация телефона) касается сети чаще, чем раз в
3 ч → счётчик > 1 ГБ держится вечно → клиент throttled бессрочно, даже когда им не
пользуются. Отдельного периодического сброса квоты в системе раньше не было.

## Что делает джоб

`src/shaper_quota.rs` — планировщик-задача в backend (по образцу `live_traffic`), тик ~60 с. У
неё **два триггера сброса** (оба через `ipset del shaper <ip>` — запись пересоздаётся с нуля первым
же пакетом, разрыва связи нет, метка throttle 333 снимается сразу):

1. **Time-window.** Через `period_secs` (3 ч) после того как IP впервые замечен в сете (и далее
   каждые 3 ч) счётчик сбрасывается — персональное окно на клиента.
2. **Смена MAC (фикс наследования).** Счётчик `shaper` привязан к IP (`bitmap:ip`); при переезде
   DHCP-лизы на **нового** арендатора того же IP тот наследует счётчик предыдущего и мгновенно
   попадает под throttle. Каждый тик джоб читает dnsmasq-лизы (ip→mac) и, если сохранённый MAC для
   IP отличается от текущего лизы-MAC, сбрасывает счётчик. MAC авторитетный (из лизы, не из запроса),
   подмены нет; тот же клиент (тот же MAC, напр. heavy-юзер на перелогине) **не** сбрасывается — это
   намеренный анти-абуз, свежую квоту он получает только по триггеру #1.

Свойства:
- **`window_start` в памяти; owning-MAC durable (0.1.38).** Персональное окно (`window_start`) живёт
  только в памяти — при рестарте пересевается `now − rand(period)` (clock-agnostic, безопасный сброс
  time-window). А **owning-MAC** каждого IP пишется на диск ОТДЕЛЬНЫМ джобом в `owner_state_path`,
  чтобы триггер смены MAC переживал рестарты (иначе стор пересевался бы из НОВОЙ лизы и хэндовер, что
  случился в downtime, не детектился — ровно этот баг чинит 0.1.38). Ребут обнуляет ipset → MAC для
  IP, которого больше нет в сете, естественно выпадает (наследовать нечего). Пустой `owner_state_path`
  = персистенция выключена (чистый in-memory, как до 0.1.38) — kill-switch для флаки-SSD.
- **Персист декуплен от reset-прохода.** Запись на диск делает отдельный scheduled-job (свой
  overlap-guard, ~2 мин); reset-проход диск НЕ трогает. Поэтому зависший `fsync` на USB-SSD тормозит
  ТОЛЬКО persist-job (durability деградирует к in-memory/time-window backstop), но НЕ сбросы. Ловится
  метрикой `owner_persist_age_seconds` (см. §Метрики).
- **Сбой чтения лиз безопасен.** Не прочитались лизы в тик — mac-логика **полностью пропускается**
  (ноль сбросов от неё), работает только time-window. Отсутствующая/битая лиза для IP из сета =
  «неизвестно», НИКОГДА не смена MAC. Порваный/упавший read не может массово разлочить всех.
- **Сброс на смену MAC И на None-learn наследование (0.1.39).** Кроме `(old→new)` (триггер #2), джоб
  сбрасывает и `(None→new)`, если счётчик IP уже `> quota/4` (256 МиБ при квоте 1 ГиБ): владелец был
  неизвестен, а такой счётчик только что «выученный» арендатор заработать не мог (на ~15 Мбит за 60с-тик
  ≤ ~107 МиБ) → унаследовал. Порог **derived** (`quota_bytes/4`), не конфиг → нельзя занизить в рантайме.
  `mac=None` с МАЛЫМ счётчиком по-прежнему просто усваивается без сброса. `window_start` двигается только
  при фактическом сбросе.
- **Clock-safe.** Нет RTC; прыжок часов назад (`now < window_start`) → time-expired → сброс
  (безопасное направление). Смена MAC — сравнение строк, от времени не зависит.
- **Anti-herd.** Новое окно засевается в `now − rand(0..period)`.

**iptables/ipset НЕ меняются**: порог 1 ГБ и `timeout 10800` остаются как есть. Тот же `ipset del`,
что и ручной эндпоинт `POST /api/v1/admin/devices/{mac}/reset-shaper-counter`.

> **История.** В 0.1.35 фикс наследования делался при регистрации (`note_registration` из
> `client_register`, `POST /api/v1/client`). Он оказался мёртв — **0 сбросов на 60 регистраций**:
> джоб засевал `mac=None` раньше, чем клиент дожимал портал (трафик добавляет IP в `shaper` до
> POST), плюс переиспользование IP приходит после ~3ч (лиза=таймаут), когда старая запись уже выпала
> из стора. Так что «смена MAC» на регистрации не встречалась. В 0.1.36 триггер перенесён в джоб
> (детект по лизам), регистрационный путь удалён.

## Остаточные (приняты; самолечатся ≤ одно `period` через time-window)

Все промахи ниже падают в сторону **un-throttle** (доступность), не throttle:
- **None-learn наследование — закрыто в 0.1.39 (существующие окна) + 0.1.40 (seed нового члена)** (было
  главным остаточным: `(None→new)` с живым чужим счётчиком молча учился без сброса; ловил только 3ч-окно).
  Теперь сбрасывается при счётчике `> quota/4` — и в ветке `(None, Some)` существующего окна, и в seed
  нового члена (0.1.40 закрыл дыру, где IP не было в windows/owner-файле → сеялся владельцем напрямую).
- **Наследование малого счётчика (< quota/4)** через None-learn → не сбрасывается сразу (порог), чистит
  3ч-окно. Не троттлит (ниже квоты), в портале виден лишь неточный «израсходовано».
- **Массовый ложный un-throttle тяжёлых при bare-restart, когда owner-файл нечитаем, А LEASES ЧИТАЮТСЯ.**
  Точное условие (0.1.40): seed нового члена сбрасывает только под `Some(lease)`, поэтому пачка возникает,
  если owner-файл не загрузился (пустой стор → все in-set IP = новые члены), НО leases в тот же тик
  прочитались. Если owner-файл и leases на одном заклинившем USB-SSD — **падают вместе → `leases=None` →
  seed сеет `None`, сброса НЕТ** (безопасно); массовый сброс возможен лишь при расхождении их доступности.
  **Ребут по питанию обнуляет ipset (счётчики 0 → сбрасывать нечего)** → касается только редкого
  bare-restart. Un-throttle-safe, self-heal ≤ одно окно. **Runbook:** пачка `ipset del` идёт немедленно
  (не джиттерована, в отличие от time-window) → кратковременный всплеск нагрузки на слабом LTE + ожидаемый
  одиночный `RatzekShaperQuotaInheritanceResetSpike`. При таком алерте сразу после рестарта — проверь
  `shaper-quota: loaded N persisted IP owners` в логе: если N мал/строки нет, owner-файл не прочитался.
- **Легитимный тяжёлый юзер с затяжным `None`** (лизы недоступны несколько тиков на слабом LTE, а он
  льёт трафик > quota/4) → один ложный сброс при возврате лизы (un-throttle, безобиден; после сброса
  mac выучен → не ре-файрит).
- **Битый-но-валидный YAML owner-файла** → максимум один лишний сброс (un-throttle); нормализация отсекает мусор.
- **Crash между `del` и записью окна:** следующий тик пере-`del`-ит отсутствующий элемент (1× `errors`/warn).
- **Регистрация без лиза (0.1.42).** Портал пускает клиента, известного только по ARP-таблице
  (`src/client_mac.rs`, см. `doc/captive-portal.md`). Пока лиза нет, джоб видит его с `mac: None`, а
  device-metrics/live-traffic не атрибутируют его трафик. Когда лиз появится, может сработать None-learn
  сброс, если счётчик уже `> quota/4` — это un-throttle, безопасно.

## КРИТИЧЕСКИЙ инвариант (проверить перед выкатом)

Механика «`ipset del` не рвёт связь» держится на том, что правило `SET --add-set shaper`
стоит в цепочке FORWARD **ПЕРЕД** accept-правилами (`--match-set shaper … -j ACCEPT`) — тогда
тот же пакет, что застаёт запись удалённой, сам её пересоздаёт и проходит accept. Форвардинг-
гейт — сет `acl` (его джоб не трогает), не `shaper`.

Зафиксировать снимок перед выкатом:
```
ssh root@www.ratzek 'iptables -S FORWARD' > /tmp/forward-before.txt
```
Убедиться, что нет правила, которое **дропает** трафик клиента при отсутствии его в `shaper`.

## Конфиг

Секция `shaper_quota_reset` в `/etc/ala-archa-http-backend.yaml` (см.
`etc/ala-archa-http-backend.example.yaml`):
```yaml
shaper_quota_reset:
  enabled: true
  crontab: "0 * * * * *"     # каждые 60с
  period_secs: 10800         # 3ч, matching ipset timeout
  quota_bytes: 1073741824    # зеркало iptables --bytes-gt (только для метрики over-quota)
  # Durable owning-MAC store (default показан). Отдельный джоб пишет его ~раз в 2 мин, чтобы
  # mac-change/наследование переживало рестарты. "" ВЫКЛючает персист (чистый in-memory,
  # kill-switch для флаки-SSD). Непустой — absolute и ОТЛИЧЕН от всех прочих state-файлов
  # (persistent_state / unlimited-clients / blacklist / history.db / device-metrics.db) —
  # config validate() это проверяет.
  owner_state_path: /var/lib/ala-archa-http-backend/shaper-quota-owners.yaml
```
Отсутствие секции или `enabled: false` — джоб не стартует, поведение как раньше. Owner-файл — 0600
(содержит mac↔ip, PII), лежит на диске рядом с прочими state-файлами, самоочищается (пишется только
пруненая проекция текущих членов сета).

## Метрики (`/metrics`) и алерт

- `ratzek_shaper_quota_enabled` (1/0)
- `ratzek_shaper_quota_age_seconds` — секунд с последнего успешного прохода (**ключевой сигнал**:
  тихая смерть джоба = «снова throttled навсегда»)
- `ratzek_shaper_quota_resets_total` (time-window), `ratzek_shaper_quota_errors_total`
- `ratzek_shaper_clients_over_quota` — сколько клиентов за квотой на последнем проходе
- `ratzek_shaper_quota_mac_change_resets_total` — сбросы по смене арендатора IP (лиза-MAC изменился).
  Резкий рост = churn или **битый/недочитанный lease-файл → массовый false-reset** (см. алерт ниже).
  MAC — только в логах (`info: shaper-quota mac-change reset: ip=… old->new`), не в labels (PII).
  **NB (rename):** в 0.1.35 называлась `ratzek_shaper_quota_register_resets_total` (мертва, всегда 0)
  — переименована; старой больше нет.
- `ratzek_shaper_quota_inheritance_resets_total` (0.1.39) — сбросы по None-learn наследованию (владелец
  IP был неизвестен, счётчик `> quota/4`). Отдельный счётчик от mac-change → свой spike-алерт. Резкий
  рост = масс-наследование или двойной IO-отказ после рестарта. Эффективный порог (`quota/4`) виден в
  `GET /api/v1/admin/shaper-quota` (`inherit_threshold_bytes`).
- `ratzek_shaper_quota_leases_read_failures_total` — тики, где lease-файл не прочитался (mac-детект
  пропущен, работает только time-window). Хронический рост = mac-триггер молча выключен.
- `ratzek_shaper_quota_owner_persist_failures_total` — fail-fast ошибки записи owner-файла (ENOSPC /
  RO / EACCES). Рост = durability деградирует, наследование вернётся после следующего рестарта.
- `ratzek_shaper_quota_owners_persisted` — сколько owning-MAC сейчас на диске (gauge).
- `ratzek_shaper_quota_owner_persist_age_seconds` — секунд с последнего ЗДОРОВОГО прохода персиста
  (запись ИЛИ no-op). Эмитится ТОЛЬКО когда персист включён и был ≥1 здоровый проход → отсутствие
  серии само гасит Stalled-алерт при выключенной/невыполненной персистенции. Растущий age = зависший
  писатель (D-state fsync, который counter выше НЕ ловит — он не возвращает ошибку).

Алерты (`doc/ratzek-site.rules` → `/etc/prometheus/rules/ratzek-site.rules`):
- `RatzekShaperQuotaStalled` — `age_seconds > 600` for 5m (сам reset-джоб завис).
- `RatzekShaperQuotaMacResetSpike` — `rate(mac_change_resets_total[10m]) > 0.05` (всплеск/битые лизы).
- `RatzekShaperQuotaInheritanceResetSpike` — `rate(inheritance_resets_total[10m]) > 0.05` (масс-наследование
  / двойной IO-отказ после рестарта).
- `RatzekShaperQuotaLeasesUnreadable` — `rate(leases_read_failures_total[10m]) > 0` (лизы не читаются).
- `RatzekShaperQuotaOwnerPersistFailing` — `rate(owner_persist_failures_total[10m]) > 0` for 15m
  (запись owner-файла падает fail-fast).
- `RatzekShaperQuotaOwnerPersistStalled` — `owner_persist_age_seconds > 600` for 15m (persist-писатель
  завис в D-state на SSD).

## Деплой (фазовый — сайт доступен только через тот самый LTE-канал, авто-отката нет)

**Фаза A — бинарь 0.1.38 с ВЫКЛЮЧЕННОЙ персистенцией** (свап бинаря отделён от включения SSD-записи):
1. Зафиксировать `iptables -S FORWARD` (см. инвариант выше).
2. `scripts/deploy.sh root@www.ratzek` с `shaper_quota_reset.owner_state_path: ""` (reset-джоб работает
   как 0.1.37, персист-джоб НЕ стартует, диск не трогается).
3. Проверить живость + новый эндпоинт:
   `curl -s --cookie <admin> 127.0.0.1:8888/api/v1/admin/shaper-quota` (снимок), и
   `curl -s 127.0.0.1:8888/metrics | grep owner_persist` → `owner_persist_failures_total 0`,
   age-серии НЕТ (персист выкл).

**Фаза B — включение персистенции + короткий период:**
4. Прописать `owner_state_path: /var/lib/ala-archa-http-backend/shaper-quota-owners.yaml` и
   `period_secs: 120` → `systemctl restart ratzek-services-http-backend`.
5. На хосте выбрать активного клиента и убедиться:
   - `ipset list shaper` — его счётчик обнуляется ~каждые 2 мин;
   - `ping` у клиента **без разрывов** за ≥3 цикла;
   - если был >1 ГБ — метка снимается (`iptables -vnL FORWARD | grep 0x14d` перестаёт расти);
   - `curl -s 127.0.0.1:8888/metrics | grep shaper_quota` — `age_seconds` свежий, `resets_total` растёт,
     `owners_persisted` > 0, `owner_persist_failures_total 0`, `owner_persist_age_seconds` свежий;
   - owner-файл создан `0600`: `ls -l /var/lib/ala-archa-http-backend/shaper-quota-owners.yaml`.
6. **Durable-тест:** снять снимок эндпоинта → `systemctl restart` → снова снимок: stored-MAC уцелели
   (не пересеялись текущими лизами).
7. Вернуть `period_secs: 10800` → `systemctl restart`.
8. Задеплоить правила Prometheus: обновить `/etc/prometheus/rules/ratzek-site.rules` из
   `doc/ratzek-site.rules` → `promtool check rules` → `systemctl reload prometheus`.

## Rollback

- **Отключить только персистенцию** (напр. SSD залип, `RatzekShaperQuotaOwnerPersist*` стреляет):
  `owner_state_path: ""` → `systemctl restart` — reset-джоб продолжает работать, диск не трогается
  (поведение 0.1.37). Owner-файл можно удалить (стор пересоздастся).
- **Отключить джоб целиком:** `enabled: false` → `systemctl restart` (конфиг читается только на старте,
  live-reload нет). iptables/ipset не менялись, откатывать нечего.
- **Полный откат бинаря:** редеплой предыдущего из `/usr/bin/ratzek-services-http-backend.bak-*`.
- Экстренно вернуть клиента: `POST /api/v1/admin/devices/{mac}/reset-shaper-counter` или
  `ipset del shaper <ip>`.

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
- **In-memory / ephemeral.** Окна живут только в памяти (как `live_traffic`), НЕ на флешке. Любой
  ребут обнуляет ipset (наследовать нечего); на голом рестарте процесса стор пересевается из текущих
  лиз (см. §Остаточные). Диск не трогаем (защита от UAS-стопора SSD).
- **Сбой чтения лиз безопасен.** Не прочитались лизы в тик — mac-логика **полностью пропускается**
  (ноль сбросов от неё), работает только time-window. Отсутствующая/битая лиза для IP из сета =
  «неизвестно», НИКОГДА не смена MAC. Порваный/упавший read не может массово разлочить всех.
- **Сброс только на известно-другой MAC.** `mac=None` (не выучен / нет active-лизы) усваивается без
  сброса; `window_start` двигается только при фактическом сбросе (нет регресса «throttled forever»).
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
- **Handover через голый рестарт процесса** (ipset жив, стор пересевается из НОВОЙ лизы, в т.ч.
  rollback `enabled:false`+restart) → смена MAC не видна; чистит 3ч-окно. Ребут по питанию обнуляет
  ipset — там нечего наследовать.
- **None-learn при пропаже лизы:** IP с живым счётчиком, но без active-лизы на момент seed (лиза
  отвалилась на слабом LTE), затем новый тенант → learn `None→new` без сброса; чистит 3ч-окно.
- **Crash между `del` и записью окна:** следующий тик пере-`del`-ит уже отсутствующий элемент
  (1× `errors_total`/warn), самолечится.

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
```
Отсутствие секции или `enabled: false` — джоб не стартует, поведение как раньше.

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
- `ratzek_shaper_quota_leases_read_failures_total` — тики, где lease-файл не прочитался (mac-детект
  пропущен, работает только time-window). Хронический рост = mac-триггер молча выключен.

Алерты `RatzekShaperQuotaStalled`, `RatzekShaperQuotaMacResetSpike`
(`rate(mac_change_resets_total[10m]) > 0.05` — всплеск/битые лизы) и `RatzekShaperQuotaLeasesUnreadable`
(`rate(leases_read_failures_total[10m]) > 0` — обратная беда: лизы не читаются, mac-детект off)
(`doc/ratzek-site.rules`, деплой в
`/etc/prometheus/rules/ratzek-site.rules`): `age_seconds > 600` for 5m.

## Деплой (фазовый — сайт доступен только через тот самый LTE-канал, авто-отката нет)

**Фаза A — бинарь с выключенной фичей:**
1. Зафиксировать `iptables -S FORWARD` (см. инвариант выше).
2. `scripts/deploy.sh root@www.ratzek` с конфигом БЕЗ секции `shaper_quota_reset`
   (или `enabled: false`). Поведение идентично текущему.
3. Проверить живость: `systemctl is-active ratzek-services-http-backend` +
   `curl -s 127.0.0.1:8888/metrics | head`.

**Фаза B — включение и проверка на коротком периоде:**
4. Добавить секцию с `period_secs: 120` → `systemctl restart ratzek-services-http-backend`.
5. На хосте выбрать активного клиента и убедиться:
   - `ipset list shaper` — его счётчик обнуляется ~каждые 2 мин;
   - `ping` у клиента **без разрывов** за ≥3 цикла;
   - если был >1 ГБ — метка снимается: считать пакеты на правиле `--bytes-gt`
     `iptables -vnL FORWARD | grep -A0 0x14d` (счётчик перестаёт расти после сброса);
   - `curl -s 127.0.0.1:8888/metrics | grep shaper_quota` — `age_seconds` свежий, `resets_total` растёт.
6. Вернуть `period_secs: 10800` → `systemctl restart`.
7. Задеплоить правило Prometheus: обновить `/etc/prometheus/rules/ratzek-site.rules` из
   `doc/ratzek-site.rules` → `promtool check rules` → `systemctl reload prometheus`.

## Rollback

`enabled: false` в `/etc/ala-archa-http-backend.yaml` → `systemctl restart ratzek-services-http-backend`
(по ssh, без пересборки — конфиг читается только на старте, live-reload нет). iptables/ipset не
менялись, откатывать нечего. Экстренно вернуть клиента: ручной
`POST /api/v1/admin/devices/{mac}/reset-shaper-counter` или `ipset del shaper <ip>`.

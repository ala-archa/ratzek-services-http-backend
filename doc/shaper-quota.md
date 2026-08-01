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

`src/shaper_quota.rs` — планировщик-задача в backend (по образцу `live_traffic`). Каждые
~60 с даёт каждому клиенту **персональное окно**: через `period_secs` (3 ч) после того как
IP впервые замечен в сете (и далее каждые 3 ч) его счётчик сбрасывается через
`ipset del shaper <ip>`. Запись пересоздаётся с нуля первым же пакетом клиента, поэтому
разрыва связи нет, а метка throttle (333) снимается сразу. Это ровно тот `ipset del`,
который уже в проде использует ручной эндпоинт `POST /api/v1/admin/devices/{mac}/reset-shaper-counter`.

Свойства:
- **In-memory / ephemeral.** Окна живут только в памяти (как `live_traffic`), НЕ на флешке.
  При рестарте пересоздаются — worst case сброс отложится на ≤одно окно; любой ребут и так
  обнуляет ipset. Диск не трогаем (защита от UAS-стопора SSD).
- **Только по времени.** Решение о сбросе не зависит от MAC (MAC из лизов спуфится на
  captive-portal → обход квоты; сбой чтения лизов → false-reset всех). Наследование чужого
  счётчика при смене арендатора IP ограничено 3ч-окном в любом случае.
- **Clock-safe.** На хосте нет RTC. Прыжок часов назад (`now < window_start`) трактуется как
  «истекло → сбросить» (безопасное направление — снимаем throttle), а не как вечный не-сброс.
- **Anti-herd.** Новое окно засевается в `now − rand(0..period)`, поэтому клиенты, что были в
  сете на момент старта, истекают вразнобой, а не все в один тик.

**iptables/ipset НЕ меняются**: порог 1 ГБ и `timeout 10800` остаются как есть (timeout теперь
— лишь уборка реально ушедших клиентов; квоту двигает джоб).

## Сброс при регистрации (наследование счётчика новым арендатором IP) — 0.1.35

Счётчик `shaper` привязан к IP (`bitmap:ip`). Когда DHCP-лиза переезжает на нового клиента,
`client_register` (`POST /api/v1/client`) делает `ipset add -exist` — обновляет timeout, но
**сохраняет счётчик предыдущего арендатора**. Новый клиент проходит портал и сразу видит чужой
~1 ГБ → мгновенный throttle.

Фикс: при регистрации, если MAC на этом IP **известно сменился**, счётчик сбрасывается
(`ipset del`, запись пересоздаётся с нуля последующим `add`). Реализовано вторым триггером в
`src/shaper_quota.rs` (`note_registration`), под тем же feature-флагом `shaper_quota_reset.enabled`.

Ключевые свойства:
- **Сброс только на известно-другой MAC.** Тот же клиент (та же лиза-MAC) при повторном
  `POST /api/v1/client` счётчик НЕ обнуляет — иначе открытый эндпоинт давал бы тривиальный обход
  квоты. Неизвестный предыдущий MAC (`None`: посев джобом / после рестарта процесса, когда ipset
  жив, а стор пуст) — усваивается без сброса; остаточное наследование самолечится ≤3ч периодическим
  окном.
- **Безопасность держится на источнике MAC.** MAC берётся сервером из dhcpd-лизы по source-IP
  (`with_client` → `Dhcp::of_ip`), **не** из тела запроса — подменить его через API нельзя. Смена
  реального NIC-MAC даёт новую лизу и обычно новый IP со своим счётчиком, т.е. дешёвого сброса того
  же IP нет. (Поэтому registration-MAC приемлем, хотя периодический джоб намеренно НЕ читает лизы:
  там сбой чтения лизов мог бы false-reset всех, а тут MAC привязан к конкретному аутентифицируемому
  IP.)
- **Реанкор окна только при фактическом сбросе** (`window_start = now`), поэтому повторная
  регистрация тем же MAC окно не двигает (нет регресса «throttled forever»).
- **Best-effort:** reset-`del` никогда не роняет регистрацию (при ошибке — `warn`, `add` всё равно
  выполняется).

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
- `ratzek_shaper_quota_resets_total`, `ratzek_shaper_quota_errors_total`
- `ratzek_shaper_clients_over_quota` — сколько клиентов за квотой на последнем проходе
- `ratzek_shaper_quota_register_resets_total` — сбросы счётчика при регистрации (смена MAC на IP);
  резкий рост = churn/смена арендаторов IP

Алерт `RatzekShaperQuotaStalled` (`doc/ratzek-site.rules`, деплой в
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

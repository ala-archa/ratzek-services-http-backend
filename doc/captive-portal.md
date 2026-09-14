# Captive-portal redirect — runbook (0.1.37)

## Проблема

Часть гостевых клиентов не перебрасывало на портал при подключении к WiFi. Причины: перехват был
**только для HTTP порт 80** (`nat PREROUTING … --dport 80 ! --match-set acl src -j DNAT → 10.11.5.1:81`,
nginx `:81` → `return 302 http://www.ratzek`); HTTPS-first клиенты упирались в тихий `FORWARD DROP`
443 (302 внутрь TLS не вставить); не было RFC 8910 DHCP option 114 → современные ОС полагались на
хрупкий HTTP-пробинг. DNS = BIND (реальные IP, без hijack); IPv6 выключен (не вектор обхода).

## Три слоя (порт-80 DNAT остаётся фолбэком)

### 1. RFC 8908 Captive Portal API (backend)
`GET /api/v1/captive-portal` (публичный, без auth; nginx уже проксирует `/api/` → `127.0.0.1:8888`).
Отвечает `Content-Type: application/captive+json`:
```json
{ "captive": true, "user-portal-url": "http://www.ratzek/" }
```
`captive = !(source-IP ∈ acl)` (через `IPSet::test`); после авторизации → `captive:false` → ОС **сама
закрывает** портал. Fail-safe: неизвестный IP / ошибка ipset → `captive:true` (показать портал).
`user-portal-url` — из конфига `captive_portal.user_portal_url` (дефолт `http://www.ratzek/`).

### 2. RFC 8910 DHCP option 114 (dnsmasq, host)
Гостям (`tag:ieth0`, НЕ приватному `iwlan1`) выдаётся URI API-эндпоинта → iOS 14+/Android 11+
открывают портал сразу, без пробинга. **IP-based** (не имя) — не зависит от DNS (BIND на слабом LTE
таймаутит).
```
# /etc/ratzek-dnsmasq.conf, рядом с dhcp-option tag:ieth0:
dhcp-option=tag:ieth0,114,http://10.11.5.1/api/v1/captive-portal
```
Применение: `dnsmasq --test -C /etc/ratzek-dnsmasq.conf` → `systemctl restart dnsmasq-ratzek`
(dhcp-option требует restart, не SIGHUP; активные лизы не рвутся). Caveat: RFC 8908 рекомендует HTTPS
user-portal-url; локальный http допустим (iOS может мелко пометить «не защищено»).

### 3. REJECT 443 для не-acl (iptables, host)
Быстрый TCP-RST вместо тихого таймаута → OS-детект/повтор срабатывает сразу. Вставить **ПЕРЕД**
`FORWARD … ! acl -j DROP`:
```
iptables -I FORWARD <поз-перед-DROP> -s 10.11.5.0/24 -p tcp -m tcp --dport 443 \
  -m set ! --match-set acl src -j REJECT --reject-with tcp-reset \
  -m comment --comment "Captive: fast-fail HTTPS pre-auth"
```
Персист: дописать эту строку в `/var/lib/iptables/rules-save` ПЕРЕД строкой
`-A FORWARD -s 10.11.5.0/24 -m set ! --match-set acl src -j DROP` (крон сохраняет только ipset'ы, не
правила). Авторизованные (acl) и приватная сеть 10.11.4.0/24 не затронуты.

## Деплой

1. **Backend:** `scripts/deploy.sh root@10.11.5.1` (0.1.37). Проверка:
   `curl -si http://10.11.5.1/api/v1/captive-portal` → `application/captive+json`, `captive` по
   acl-статусу источника.
2. **dnsmasq:** бэкап конфига → добавить option 114 → `dnsmasq --test` → restart.
3. **iptables:** бэкап `cp -a /var/lib/iptables/rules-save{,.bak-$(date +%F-%H%M)}` → live `iptables
   -I` → дописать в rules-save → **проверить SSH/админ-доступ**.

## Verification
- `dnsmasq --test` SUCCESS; option 114 в DHCP-offer (`tcpdump -i eth0 port 67 or 68`).
- Unauth клиент `curl -m5 https://example.com` → мгновенный «Connection reset» (не таймаут);
  счётчик REJECT в `iptables -vnL FORWARD` растёт.
- Реальные iOS 14+ / Android 11+ → портал всплывает автоматически и **сам закрывается** после входа.

## Rollback
- iptables: `iptables-restore < /var/lib/iptables/rules-save.bak-*` (или `iptables -D FORWARD …` для
  REJECT-правила).
- dnsmasq: восстановить конфиг из бэкапа → `dnsmasq --test` → restart.
- backend: редеплой предыдущего бинаря из `/usr/bin/ratzek-services-http-backend.bak-*`.

## Определение MAC клиента (0.1.42)

### Проблема
`GET/POST /api/v1/client` искал MAC клиента только в лизах dnsmasq и при промахе отдавал **500**
(пользователи называли это «505»). За 14 дней — 39× 500, все из `DHCP lease not found`:
- **Устаревший IP до DHCP.** Телефон возвращается с закэшированным (истёкшим) IP, особенно после
  перезагрузки хоста, и открывает портал раньше, чем делает DHCP. В 5 из 7 эпизодов DHCP был через
  6–34 с, в 2 из 7 — через 27 мин и через 16 ч.
- **Гонка с файлом лизов.** dnsmasq переписывает файл на месте (`rewind` + `ftruncate`), и чтение
  может увидеть пустой или обрезанный файл.
- **VPN (`10.8.0.1`).** Лиза нет никогда.

### Как теперь (`src/client_mac.rs`)
1. **ARP-таблица ядра (`/proc/net/arp`) — первой.** Запрос пришёл по установленному TCP от L2-соседа,
   значит Pi уже разрезолвил MAC отправителя. Берутся только записи с флагом `ATF_COM` (`0x2`):
   FAILED-записи хранят **старый** MAC с `0x0`.
2. **Активный лиз** (`dhcp::active_ip_to_mac`) — фолбэк и сверка.
3. **Повтор чтения лизов через 50 мс** — только если ARP и лиз пусты И чтение лизов похоже на гонку
   (ошибка или ноль активных лизов). Иначе без задержки.
4. Никто не знает клиента → **503 + `Retry-After: 5`** (фронтенд показывает «Подключаем вас к сети…»,
   через ~1 мин — «Не удаётся определить устройство»).

| ARP | лиз | MAC | `result` |
|---|---|---|---|
| есть | тот же | ARP | `agree` |
| есть | другой | **ARP** | `mismatch` |
| есть | нет | ARP | `arp_only` |
| нет | есть | лиз | `lease_only` |
| — | найден при повторе | лиз | `lease_retry` |
| нет | нет | — | `not_found` → 503 |

Парсер лизов (`dhcp::parse_dnsmasq`) дополнительно отбрасывает незавершённую последнюю строку, строки
короче 5 полей и не-IPv4, чтобы обрезанный файл не давал ложное попадание с чужим MAC.

Заблокированный клиент при регистрации теперь получает **403** (было 500).

### Метрики
- `ratzek_client_mac_lookup_total{result="agree|arp_only|mismatch|lease_only|lease_retry|whitelist|not_found"}`
- `ratzek_client_mac_lookup_errors_total{stage="leases|arp|join"}` — сбои чтения источников.

Логи: `client-mac: ip=… result=… arp_mac=… lease_mac=…` на warn — при смене результата для IP или не
чаще раза в 10 минут, иначе debug. Алерта пока нет; панель — `doc/grafana/network-health.json`.

### Принятые ограничения
- **Регистрация без лиза.** Клиент, известный только по ARP (в том числе устройство со статическим IP
  вне DHCP), может зарегистрироваться. Доступ и так выдаётся по IP, блэклист остаётся «мягким»
  (по MAC). Это осознанное расширение модели угроз.
- **Блэклист судит по MAC из ARP**, если он расходится с лизом.
- **VPN/L3-клиенты** (нет ARP-записи, нет лиза) получают 503.
- Пока у клиента нет лиза, shaper-quota и device-metrics его MAC не видят (см. `doc/shaper-quota.md`).

### Деплой
0. Baseline: `zcat -f /var/log/nginx/access.log* | awk '$7 ~ "^/api/v1/client" {print $9}' | sort | uniq -c`.
1. `scripts/deploy.sh` (0.1.42) → бэкап `/usr/bin/ratzek-services-http-backend.bak-<ts>`.
2. Фронтенд: `make dry-run` → `make deploy` (в `ratzek-services-frontend`). Совместим со старым
   бэкендом; старый фронтенд обрабатывает 503 как 500 (`connection_error`).

### Verification
- `curl -s 127.0.0.1:8888/metrics | grep client_mac_lookup` — счётчики есть, `agree` растёт.
- ARP-only: взять IP с флагом `0x2` из `/proc/net/arp`, которого нет в `dnsmasq.leases`;
  `curl -si -H 'X-Real-IP: <ip>' http://127.0.0.1:8888/api/v1/client` → 200 (`Inactive`/`Connected`),
  в журнале `result=arp_only`. **Только GET** — не регистрировать чужое устройство.
- Через nginx: `curl -si -H 'Host: www.ratzek' http://127.0.0.1/api/v1/client` (X-Real-IP 127.0.0.1,
  ARP-записи нет) → **503 + `Retry-After: 5`**.
- После ближайшей перезагрузки: warn `arp_only`/`mismatch` для вернувшихся телефонов, 500 на
  `/api/v1/client` нет.
- 7 дней против baseline: 500 → 0; доля 503 и `not_found` ≈ только VPN; `errors_total` → 0.

### Rollback
- backend: `install -m0755 /usr/bin/ratzek-services-http-backend.bak-<ts> /usr/bin/ratzek-services-http-backend && systemctl restart ratzek-services-http-backend`.
- frontend: `git revert` + `make deploy`.

## Ротация лога dnsmasq (host, 0.1.42)

`/var/log/ratzek-dnsmasq.log` не ротировался со 2 июля (2,1 ГБ). Конфиг — `doc/logrotate-ratzek-dnsmasq`
→ `/etc/logrotate.d/ratzek-dnsmasq`.

**Первая ротация — вручную, в тихое время** (с `delaycompress` принудительный `logrotate -f` только
переименует файл, а gzip 2,1 ГБ уйдёт на неконтролируемый ночной запуск):
```
df -h /var/log
mv /var/log/ratzek-dnsmasq.log /var/log/ratzek-dnsmasq.log.1
install -m0640 -o nobody -g root /dev/null /var/log/ratzek-dnsmasq.log
systemctl kill --kill-who=main -s USR2 dnsmasq-ratzek.service
# дождаться DHCP-события и убедиться, что новый файл растёт
nice -n19 ionice -c3 gzip /var/log/ratzek-dnsmasq.log.1
```
Затем установить конфиг и проверить `logrotate -d /etc/logrotate.d/ratzek-dnsmasq`.

- `create 0640 nobody root` обязателен: dnsmasq переоткрывает лог по SIGUSR2 уже без root и сам создать
  файл в `/var/log` не может.
- `--kill-who=main` — сигнал только самому dnsmasq; сбой пишется в syslog (`journalctl -t logrotate`).
- Проверка, что dnsmasq не пишет в удалённый файл:
  `ls -l /proc/$(systemctl show -p MainPID --value dnsmasq-ratzek)/fd | grep ratzek-dnsmasq` — без `(deleted)`.
- Окно гонки: если ротация совпадёт с reload резерваций, `dhcp_hosts::scrape_reload_log` прочитает
  пустой хвост и не заметит отклонённую резервацию (fail-open). Редко, принято.
- Rollback: `rm /etc/logrotate.d/ratzek-dnsmasq`.

## Границы / дальше
- Порт-80 DNAT + nginx:81 `302` не тронуты (фолбэк для HTTP-проб).
- Фундаментальный предел: клиент только-HTTPS + без option 114 + без OS-пробы — не заставить.
  Следующий рычаг — DNS-перехват unauth на BIND (отложено; строгий скоупинг по client-IP, общий BIND
  с private+VPN).
- IPv6 держать выключенным; включат — дублировать option 114 (RA-опция) и правила на v6.

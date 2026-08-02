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

## Границы / дальше
- Порт-80 DNAT + nginx:81 `302` не тронуты (фолбэк для HTTP-проб).
- Фундаментальный предел: клиент только-HTTPS + без option 114 + без OS-пробы — не заставить.
  Следующий рычаг — DNS-перехват unauth на BIND (отложено; строгий скоупинг по client-IP, общий BIND
  с private+VPN).
- IPv6 держать выключенным; включат — дублировать option 114 (RA-опция) и правила на v6.

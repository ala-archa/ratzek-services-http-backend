# Миграция DHCP: ISC dhcpd → dnsmasq (DHCP-only) — runbook

Статус на 2026-07-01:
- **Часть A** (код бэкенда) — задеплоена, инертна (`dhcp_flavor: auto` → на проде dnsmasq
  неактивен → детект даёт `Isc` → поведение байт-в-байт как прежде). Соакается в проде.
- **Часть B** (этот документ) — dnsmasq-конфиг + эмпирический pre-flight на dnsmasq **2.85**
  (version-parity с прод-Debian 11). Ansible НЕ используется (морально устарел) — конфиги
  кладутся на хост вручную в окне катовера.
- **Часть C** (катовер) — НЕ выполнять без явного go и зелёного pre-flight.

⚠️ **Инвариант безопасности:** доступ к хосту ТОЛЬКО удалённый (openvpn `vpn-firstvds`
10.8.0.10 → SSH). Наш канал не зависит от клиентского DHCP. Сеть не ломать. dhcpd — горячий
фолбэк (enabled-на-boot весь трейл; ребут → known-good dhcpd).

---

## 1. Эмпирический pre-flight (dnsmasq 2.85, изолированный контейнер)

Три открытых вопроса плана — закрыты эмпирически.

### 1.1 `dnsmasq --test` НЕ валидирует содержимое `dhcp-hostsfile`
Прогон `dnsmasq --test` на битых hostsfile-строках (плохой MAC, плохой IP, дубль IP, мусор) —
**все** дают `syntax check OK`, `exit=0`. `--test` проверяет только основной конфиг.

**Следствие для `apply()` (0.1.26):** шаг `validate = dnsmasq --test` ловит ошибки основного
конфига, но **НЕ** ошибки броней. Значит **post-reload скрейп лога — ОБЯЗАТЕЛЕН**, не опционален.
Единственная реалистичная ошибка от валидированного рендера бэкенда — **дубль IP** (две брони на
один IP), и она в логе фиксируется (см. 1.2).

### 1.2 Реальные error-строки лога (для regex скрейпа)
При старте/`SIGHUP`-reload с битой hostsfile dnsmasq (главный процесс, `dnsmasq[pid]:`) пишет:
```
dnsmasq[725]: duplicate dhcp-host IP address 10.11.5.63 at line 5 of /etc/dnsmasq.d/unlimited-hosts
dnsmasq[725]: bad hex constant at line 4 of /etc/dnsmasq.d/unlimited-hosts
dnsmasq[725]: bad DHCP host name at line 6 of /etc/dnsmasq.d/unlimited-hosts
```
Маркер успешного применения (главный DHCP-процесс, `dnsmasq-dhcp[pid]:`):
```
dnsmasq-dhcp[725]: read /etc/dnsmasq.d/unlimited-hosts
```
Чистый reload = **только** строка `read <hostsfile>`; при ошибке error-строки идут **перед** ней.
Единый суффикс всех ошибок: **`at line <N> of <hostsfile>`**.

**Спека скрейпа для `apply()` (0.1.26):**
- До `SIGHUP` снять курсор журнала (см. 1.4).
- После reload — bounded-poll ~2–3 с журнала от курсора.
- **Граница завершения:** появление `read <hostsfile>` (reload обработан).
- **Regex ошибки (default `error_regex`):** `at line [0-9]+ of <hostsfile>` (ловит все варианты:
  duplicate / bad hex / bad DHCP host name). Экранировать путь hostsfile.
- Найдено совпадение error_regex до/в окне → **полный rollback** (restore прежнего hostsfile +
  повторный SIGHUP), вернуть ошибку.

### 1.3 Формат `dnsmasq.leases` — подтверждён, совпадает с `parse_dnsmasq`
Реальная аренда (клиент через veth/netns), в т.ч. для брони:
```
1782891002 92:bb:56:82:1d:e4 10.11.5.99 reserved-client *
```
Поля: `<expiry_epoch> <mac> <ip> <hostname|resv-name|*> <clientid|*>`. Имя брони уходит в
hostname-колонку, если клиент не прислал своё. `parse_dnsmasq` корректно: `f[0]`=expiry,
`f[1]`=mac, `f[2]`=ip, `f[3]`=hostname (`*`→None), `f[4]`=clientid (игнорируем). IPv6-строки
(`duid …` header + не-dotted адрес) пропускаются. **Правок в парсере не требуется.**

### 1.4 journald-курсор (для скрейпа на проде)
В контейнере лог писался в файл (`log-facility=<path>`) — тогда скрейп просто читает хвост файла.
На проде dnsmasq логирует в syslog→journald. Курсор до старта:
`journalctl -u dnsmasq --show-cursor -n1 -o export | grep -oP '(?<=__CURSOR=).*'` (у `-n0` вывод
пуст → берём `-n1`). Затем после reload: `journalctl -u dnsmasq --after-cursor=<cur> --no-pager`.
Config-поля `apply()`: `log_unit` (journald-юнит) ИЛИ `cursor_file`/файл лога + `error_regex`.

---

## 2. `dnsmasq.conf` (провалидирован `--test` на 2.85)

Кладётся на хост как `/etc/ratzek-dnsmasq.conf` (или `/etc/dnsmasq.conf`). Авторизован из живого
`dhcpd.conf` + `ip -4 addr` (read-only). eth0 dual-subnet: `10.11.3.2/24` WAN + `10.11.5.1/24`
клиент; wlan1 `10.11.4.1/24`.

```conf
# ratzek DHCP — dnsmasq (DHCP-only). Debian 11, dnsmasq 2.85. DNS stays on BIND.
port=0

# eth0 is DUAL-SUBNET (10.11.3.2 WAN + 10.11.5.1 client). bind-dynamic serves the
# 10.11.5 subnet on eth0 and follows address changes. Only a 10.11.5 range is
# declared for eth0 -> no service on 10.11.3 (WAN), exactly as dhcpd behaved.
bind-dynamic
interface=eth0
interface=wlan1
domain=ratzek

# wlan1 -> 10.11.4.0/24
dhcp-range=set:iwlan1,10.11.4.50,10.11.4.255,255.255.255.0,43200s
dhcp-option=tag:iwlan1,option:router,10.11.4.1
dhcp-option=tag:iwlan1,option:dns-server,10.11.4.1
# eth0 -> ONLY 10.11.5.0/24 (never 10.11.3 WAN)
dhcp-range=set:ieth0,10.11.5.50,10.11.5.255,255.255.255.0,43200s
dhcp-option=tag:ieth0,option:router,10.11.5.1
dhcp-option=tag:ieth0,option:dns-server,10.11.5.1

# native static reservations (migrated from dhcpd.conf host{} blocks)
dhcp-host=c8:40:52:83:0f:3c,10.11.5.30,pos-terminal   # PAYMENT terminal — critical
dhcp-host=1c:78:4b:dc:67:c4,10.11.5.123,bms-1
# gateway-NIC reservations (own .1 addrs) — parity; likely vestigial, prune later
dhcp-host=30:de:4b:03:a9:89,10.11.4.1,ratzek-service
dhcp-host=e4:5f:01:ed:d5:56,10.11.5.1,ratzek-service-ether

# backend-owned unlimited-client reservations (the 15), SIGHUP reload, no restart
dhcp-hostsfile=/etc/dnsmasq.d/unlimited-hosts
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
log-dhcp
```

**НЕ трогаем:** BIND (:53), iptables/ipset, маршруты, openvpn, WAN, адреса `.1`.

---

## 3. systemd unit + liveness-пробник

dnsmasq 2.85 собран **БЕЗ** sd_notify → `Type=notify` завис бы; **БЕЗ** `WatchdogSec`.

`/etc/systemd/system/dnsmasq-ratzek.service`:
```ini
[Unit]
Description=dnsmasq DHCP (ratzek)
After=network-online.target time-sync.target
Wants=network-online.target
# нет RTC (fake-hwclock) -> ждём синхронизации времени
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStartPre=/usr/sbin/dnsmasq --test -C /etc/ratzek-dnsmasq.conf
ExecStart=/usr/sbin/dnsmasq --keep-in-foreground -C /etc/ratzek-dnsmasq.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always

[Install]
WantedBy=multi-user.target
```

Внешний liveness-пробник на соак (ловит зависание ЖИВОГО демона, которое `Restart=` не видит):
`/etc/systemd/system/dnsmasq-liveness.service` (oneshot) + `.timer` (每30–60с):
```ini
# dnsmasq-liveness.service
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'ss -ulnp | grep -q ":67 .*dnsmasq" || systemctl restart dnsmasq-ratzek'
```
```ini
# dnsmasq-liveness.timer
[Timer]
OnBootSec=60
OnUnitActiveSec=45
[Install]
WantedBy=timers.target
```

---

## 4. Native брони — таблица решений

| host (dhcpd) | MAC | IP | Решение |
|---|---|---|---|
| pos-terminal | c8:40:52:83:0f:3c | 10.11.5.30 | **Мигрировать** (ПЛАТЁЖНЫЙ — критично) `dhcp-host=` |
| bms-1 | 1c:78:4b:dc:67:c4 | 10.11.5.123 | **Мигрировать** `dhcp-host=` |
| ratzek-service | 30:de:4b:03:a9:89 | 10.11.4.1 | Мигрировать для parity (own .1; вероятно vestigial — prune после проверки) |
| ratzek-service-ether | e4:5f:01:ed:d5:56 | 10.11.5.1 | Мигрировать для parity (own .1; вероятно vestigial) |
| *unlimited-hosts.conf* (15) | — | 10.11.5.* | **backend-managed** → `render-dnsmasq-hostsfile` в `dhcp-hostsfile` |

> Расхождение с ред.4 плана: план предлагал SKIP для ratzek-service/-ether. Здесь — мигрировать
> для полной parity (drop брони риск-нее, чем сохранить: сохранение = текущее поведение dhcpd).
> Решение — за оператором; при подтверждении «vestigial» строки можно убрать.

---

## 5. Осталось в коде (0.1.26, инертно под isc) — по эмпирике §1

- `apply()` dnsmasq-ветка: `validate=dnsmasq --test`; `reload=systemctl reload dnsmasq-ratzek`;
  **после** — курсорный скрейп (§1.2/§1.4): default `error_regex=at line [0-9]+ of <hostsfile>`,
  completion-маркер `read <hostsfile>`; при совпадении — rollback (restore+reload).
- isc-guard: перед `restart isc` проверять `is-active isc` → `Applied::SkippedIscInactive`
  (`warn!`+alarm, без restore).
- Config-блок `dnsmasq{ hostsfile_path, validate_command, reload_command, log_unit, cursor_file,
  error_regex }` (всё опц.; ветка живёт только при flavor=dnsmasq → деплой инертен).
- Тест: `reload=0` + грязный лог → rollback. Bump 0.1.26. Задеплоить (инертно), соакнуть.

---

## 6. Катовер (Часть C) — окно, обратимо. НЕ запускать без go.

Предусловия: pre-flight зелёный; 0.1.26 задеплоен (детект→isc). Заморозить ВСЕ DHCP-мутации.
**Бэкап ISC:** `cp` `dhcpd.leases` + `dhcpd.conf` + `unlimited-hosts.conf` в сторону.

1. Положить `/etc/ratzek-dnsmasq.conf`, unit'ы (§2/§3). `--test` конфига на хосте.
2. **Populate hostsfile ДО старта:** `ratzek-services-http-backend render-dnsmasq-hostsfile
   --out /etc/dnsmasq.d/unlimited-hosts` (15 броней; pos/bms уже статикой в конфиге). → dnsmasq
   стартует с ПОЛНЫМ набором (гонка .30/.89 закрыта).
3. Вооружить dead-man (монотонный, ~15м): `systemd-run --on-active=15min --unit=dhcp-deadman
   <скрипт: flock; stop dnsmasq-ratzek; start isc-dhcp-server; restart backend; || start isc>`.
4. `: > /var/lib/misc/dnsmasq.leases`. `systemctl stop isc-dhcp-server; systemctl start
   dnsmasq-ratzek`.
5. **Быстрый liveness-гейт:** `is-active isc-dhcp-server`=inactive && `ss -ulnp|grep :67`=dnsmasq
   && DHCPACK в `journalctl -u dnsmasq-ratzek` → **отменить dead-man** (`systemctl stop
   dhcp-deadman.timer/…`). Рестарт backend (детект→dnsmasq); force-reconcile; курсорный verify чисто.
6. Длинный функциональный verify (под boot-fallback = dhcpd enabled). Отрепетировать полный откат
   один раз (см. §7), вернуться на dnsmasq.
7. Соак сутки: страховка = dhcpd-boot-fallback + liveness-пробник. Финал (позже): dnsmasq enabled,
   dhcpd disabled, снять ping-check/liveness-костыли; удалить isc-адаптер + `dhcpd_parser` +
   `migrate-unlimited` из бэкенда.

### ABORT-дерево (симптом → действие)
| Симптом | Действие |
|---|---|
| После start dnsmasq нет DHCPACK N мин | dead-man сработает; или вручную: stop dnsmasq; start isc; restart backend |
| pos-terminal(.30) / bms(.123) не держат IP | ABORT → откат (§ниже) |
| .89 (или любой unlimited) ушёл чужому MAC | ABORT → откат |
| Клиенты 10.11.3 (WAN) получают offer/NAK от dnsmasq | ABORT немедленно (dual-subnet утечка) |
| **SSH/openvpn отвалился** (сеть цела?) | last-resort: **power-cycle → ISC** (dhcpd enabled-на-boot) |
| backend не читает leases / reconcile ошибки | не критично для сети; чинить после стабилизации DHCP |

### Откат (репетируется в C.6)
```
systemctl stop dnsmasq-ratzek
systemctl start isc-dhcp-server        # ping-check true на окно -> без коллизий пула
ss -ulnp | grep :67                    # ожидаем dhcpd
systemctl restart ratzek-services-http-backend   # детект→isc, reconcile рефрешит include
```
Last-resort (SSH мёртв): power-cycle → boot → isc-dhcp-server поднимается known-good.

---

## 7. Verification (катовер)
- Пул-аренда: клиент eth0 получает 10.11.5.x, **router=10.11.5.1**; клиент wlan1 → 10.11.4.x,
  router=10.11.4.1. Нет offer/NAK на 10.11.3 (WAN).
- Reserved MAC → fixed IP: pos(.30), bms(.123) держат; unlimited из hostsfile — свои IP.
- **.89 офлайн → его IP НЕ уходит чужому** (главная цель миграции).
- backend читает `dnsmasq.leases`; `/dhcp`, `/admin/status`, disconnect, reset-shaper, captive-portal — ок.
- Наш SSH/openvpn (10.8.0.10) неизменен.
- Метрики `free`/`abandoned` под dnsmasq → обычно 0 (сверить с Prometheus alert-правилами
  `ratzek_dhcp_leases_*` перед окном — не алертить на «0 free»).

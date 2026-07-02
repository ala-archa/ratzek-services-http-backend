# Миграция DHCP: ISC dhcpd → dnsmasq (DHCP-only) — runbook

Статус на 2026-07-01:
- **Часть A** (0.1.25) — задеплоена, инертна. Соакается в проде.
- **0.1.26** (dnsmasq apply-scrape + isc-guard) — задеплоена, **инертна** (обе ручки
  `active_unit`/`reload_log` не заданы → детект→Isc, поведение байт-в-байт как прежде;
  подтверждено: flavor=Isc, reconcile `Unchanged`, dhcpd не тронут). Весь код катовера теперь
  в проде → в окне Части C деплой кода НЕ нужен.
- **Часть B** (этот документ) — dnsmasq-конфиг + эмпирический pre-flight + **репетиция катовера**
  на dnsmasq **2.85** (version-parity с прод-Debian 11), всё в изоляции (netns/Docker, ноль
  прода). Ansible НЕ используется (морально устарел) — конфиги кладутся на хост вручную.
- **Стейджинг prep** (2026-07-02, инертно, на проде): ISC забэкаплен (`/root/dhcp-migration-backup/`);
  `/etc/ratzek-dnsmasq.conf` + пустой `/etc/ratzek-dnsmasq-hosts` + `dnsmasq-ratzek.service`
  (inactive/disabled) разложены; `dnsmasq --test` → OK на реальных интерфейсах; ничего не стартовано
  (isc-dhcpd на :67 active, BIND на :53, backend 0.1.26 active — без изменений). `dnsmasq-base` 2.85
  уже стоит → apt не нужен.
- **Часть C — КАТОВЕР ВЫПОЛНЕН 2026-07-02 ~17:44.** dnsmasq-ratzek обслуживает :67, isc остановлен.
  Верифицировано вживую: резервные клиенты получают брони (bms-1→.123, yura-phone→.224), пул
  работает, **0 DHCPNAK, 0 активности на 10.11.3 WAN** (dual-subnet безопасен в проде), backend
  flavor=Dnsmasq читает dnsmasq-аренды, reconcile Unchanged. Boot-fallback: isc enabled (ребут→ISC),
  dnsmasq-ratzek disabled+active. Соак 24ч.
- **⚠️ КОД-БАГ (для 0.1.27):** `Flavor::detect()` хардкодит имя юнита `dnsmasq`, а прод-юнит —
  `dnsmasq-ratzek` → авто-детект НЕ находит dnsmasq и падает в Isc-фолбэк. **Обход:** явно задан
  `dhcp_flavor: dnsmasq` в конфиге (детект не вызывается). На свитче это проявилось: backend
  стартовал flavor=Isc, отрендерил ISC-`host{}` в dnsmasq-hostsfile → dnsmasq отверг
  (`bad DHCP host name at line 4`) → **apply-scrape поймал и откатил** (защита сработала в бою).
  В 0.1.27: убрать авто-детект (при финализации isc-адаптер уходит) ИЛИ сделать имя юнита конфигом.
- **OS-финализация ВЫПОЛНЕНА 2026-07-02** (соак сокращён — функционально всё зелёное): dnsmasq-ratzek
  **enabled**, isc-dhcp-server **disabled**, liveness-пробник (`dnsmasq-liveness.timer`, 45с) активен.
  Состояние консистентно (runtime=boot=dnsmasq); ребут больше не регрессирует на ISC/.89-баг.
  Довод сокращения: держать лимб (runtime=dnsmasq, boot=isc) на хосте, склонном к ребутам
  (электричество/зависания), опаснее, чем консистентный dnsmasq. **ISC-escape-hatch сохранён**
  (пакет+config+бэкапы + задеплоен 0.1.26 с isc-адаптером → откат `.isc`-конфиг+enable isc возможен).
- **Осталось — код-уборка 0.1.27 (единственный необратимый шаг, ОТЛОЖЕН):** убрать isc-адаптер +
  `dhcpd_parser` + `migrate-unlimited`, починить flavor-detect-баг. Держим как escape-hatch; делать,
  когда пройдёт больше циклов renewal и уверенность в отсутствии отката будет полной. Спешки нет —
  функционального выигрыша от удаления кода нет.

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
dnsmasq[725]: duplicate dhcp-host IP address 10.11.5.63 at line 5 of /etc/ratzek-dnsmasq-hosts
dnsmasq[725]: bad hex constant at line 4 of /etc/ratzek-dnsmasq-hosts
dnsmasq[725]: bad DHCP host name at line 6 of /etc/ratzek-dnsmasq-hosts
```
Маркер успешного применения (главный DHCP-процесс, `dnsmasq-dhcp[pid]:`):
```
dnsmasq-dhcp[725]: read /etc/ratzek-dnsmasq-hosts
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

### 1.4 Реализация скрейпа — файловая (не journald)
Скрейп сделан **файловым** (детерминированно, без journald-курсора): dnsmasq пишет в
`log-facility=/var/log/ratzek-dnsmasq.log`; `apply()` запоминает длину файла ДО reload, после
reload читает только новые байты и полл'ит (bounded ~timeout_secs) до маркера. Скоуп — строки,
содержащие путь hostsfile: `error_contains` (`at line`) → rollback; `success_contains` (`read`)
→ чисто. Config: `dhcp_reservations.reload_log{ file, success_contains, error_contains,
timeout_secs }` (см. §5).

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
dhcp-hostsfile=/etc/ratzek-dnsmasq-hosts
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
# logging -> a FILE the backend apply() scrapes for rejected reservations (§1.2/§5).
log-dhcp
log-facility=/var/log/ratzek-dnsmasq.log
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

### ⚠️ Установка dnsmasq — mind :53 (не сломать BIND!)
**На ratzek apt НЕ нужен (проверено 2026-07-02 read-only):** `dnsmasq-base` **2.85 уже стоит** →
бинарь `/usr/sbin/dnsmasq` есть; полный пакет `dnsmasq` и его авто-юнит `/lib/systemd/system/
dnsmasq.service` **отсутствуют** → нашему `dnsmasq-ratzek.service` (указывает на `/usr/sbin/dnsmasq`)
apt не требуется вовсе. Это **снимает всю гочу для этого хоста** (ни :53-конфликта, ни
dependency-churn). Ниже — что делать, если бы пакета-бинаря не было.

**Гоча (общий случай, подтверждено debian:11 + dnsmasq 2.85):** `apt-get install dnsmasq` **автоматически
enable+start дефолтный `dnsmasq.service`** (postinst: `deb-systemd-helper enable` +
`invoke-rc.d dnsmasq start`), а дефолтный `/etc/dnsmasq.conf` (весь закомментирован) поднимает
**DNS-сервер на 0.0.0.0:53 и [::]:53** → **конфликт с BIND** = сломанный DNS на проде. Наивная
установка ломает прод.

**Безопасная последовательность (mask ДО install):**
```sh
systemctl mask dnsmasq            # symlink /etc/systemd/system/dnsmasq.service -> /dev/null;
                                  # работает даже до установки пакета и шэдоует /lib-юнит
apt-get install -y dnsmasq        # postinst-старт дефолта = no-op (masked)
ss -ulnp | grep ':53'             # ПРОВЕРКА: dnsmasq НЕ должен появиться на :53 (только BIND)
# наш отдельный юнит с port=0 -> только :67 (DHCP), с BIND не конфликтует
systemctl daemon-reload           # после раскладки dnsmasq-ratzek.service (файлы, НЕ старт)
```
Проверено в изоляции: наш `port=0`-конфиг биндит только `:67` (DHCP), `:53` пуст. Дефолтный юнит
остаётся masked весь трейл (в т.ч. чтобы ребут не поднял его на :53). backend-hostsfile —
`/etc/ratzek-dnsmasq-hosts` (НЕ под `/etc/dnsmasq.d/` и без `.conf` → не подхватится conf-dir даже
если дефолт когда-то оживёт).

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

> **Native vs unlimited — взаимоисключающи по IP (подтверждено на соаке).** Нельзя завести
> unlimited-клиента (API) на IP, который уже объявлен нативной `dhcp-host=` в
> `ratzek-dnsmasq.conf`: dnsmasq на reload даст `duplicate dhcp-host IP address <ip>`, apply-scrape
> откатит, create упадёт до записи в store (безопасно). Чтобы перевести native-бронь (напр. bms-1
> .123, pos-terminal .30) в unlimited: сначала удалить её `dhcp-host=`-строку из `ratzek-dnsmasq.conf`
> + `reload`, затем добавить через API. Замечание: native фиксирует только IP (без ipset-доступа);
> unlimited даёт IP + `acl`+`no_shape`.

---

## 5. Код 0.1.26 — РЕАЛИЗОВАНО (инертно под isc), по эмпирике §1

Реализация — через опц. поля на существующем `dhcp_reservations` (без отдельного блока), обе
`None` по умолчанию → текущее ISC-поведение (флейвор в `apply()` не нужен):
- **isc-guard** `dhcp_reservations.active_unit: Option<String>` — если задан, `apply()` проверяет
  `systemctl is-active <unit>` ПЕРЕД reload; inactive → `Applied::SkippedInactive` (warn, без
  restart/restore; изменение pending до следующего reconcile). На окно арминга ставится
  `active_unit: isc-dhcp-server`.
- **скрейп** `dhcp_reservations.reload_log{ file, success_contains="read", error_contains="at line",
  timeout_secs=3 }` — после успешного reload читает новые байты `file` от offset'а (снятого до
  reload), скоуп по строкам с путём hostsfile; `error_contains` → полный rollback (restore+reload),
  `success_contains` → чисто. Таймаут без маркера → чисто + warn.
- **Под dnsmasq** `dhcp_reservations` перенастраивается: `include_path`→hostsfile,
  `validate_command`→`dnsmasq --test -C /etc/ratzek-dnsmasq.conf`, `reload_command`→
  `systemctl reload dnsmasq-ratzek`, `reload_log.file`→`/var/log/ratzek-dnsmasq.log`, `active_unit`
  снят.
- Тесты: guard-skip; scrape error→rollback; scrape success→Changed. Bump 0.1.26.
  Деплой инертен (обе опции None на проде) → соакнуть.

---

## 5a. Репетиция катовера (dry-run, dnsmasq 2.85, netns/Docker — ноль прода)

Прогнаны два самых страшных неизвестных Части C в изоляции (2026-07-01, `debian:11`, dnsmasq
2.85, veth/netns). **Оба закрыты.**

### TEST A — dual-subnet eth0 (пункт №1 ABORT-дерева)
Интерфейс с двумя адресами `10.11.3.2` (WAN) + `10.11.5.1` (клиент), dnsmasq с диапазоном
только 10.11.5, **non-authoritative** (как §2).
- **A1 PASS** — обычный клиент получил `10.11.5.104` (DISCOVER→OFFER→ACK); никаких 10.11.3.
- **A2 PASS** — клиент, просящий чужой `10.11.3.99`, **НЕ получил DHCPNAK**: non-auth dnsmasq
  молча выдал пуловый 10.11.5-адрес. Активной disruption чужих аренд нет.
- **Вывод:** поведение = **паритет с текущим dhcpd** (dhcpd так же отдаёт 10.11.5 любому
  броадкастеру на eth0 — отличить «10.11.3-устройство» от «10.11.5» в момент DISCOVER на общем
  L2 нельзя ни тому, ни другому). dnsmasq **не хуже и не NAK'ает**. Регрессии нет. (Контраст
  «authoritative→NAK» воспроизвести чисто не удалось — `dhclient` свалился в DISCOVER; на вывод
  не влияет: наш конфиг non-auth и A2 прошёл.)

### TEST B — реальный apply-scrape цикл (формат бэкенда + дубль IP)
dnsmasq с `dhcp-hostsfile` в формате `render(Dnsmasq)` (`MAC,IP,name`), `log-facility=<file>`.
- **B1 PASS** — чистый reload → `dnsmasq-dhcp[pid]: read /t/hosts` → совпадает с
  `success_contains="read"`.
- **B2 PASS** — дубль IP → SIGHUP → `dnsmasq[pid]: duplicate dhcp-host IP address 10.11.5.61
  **at line 3 of /t/hosts**` → строка содержит путь + `at line` → скрейп **откатил бы**. Offset
  (снятый до reload) отработал — читались только новые байты.
- **Вывод:** apply-scrape замкнут на реальный dnsmasq 2.85 — дефолты кода (`read`/`at line` +
  путь-скоуп) ловят именно то, что пишет эта связка на битой брони.

### Остаточное (не блокирует Часть C)
Более строгий NAK-контраст (scapy/nmap с чистым INIT-REBOOT REQUEST) — nice-to-have; core-
безопасность (A2, non-auth = no NAK) подтверждена.

---

## 6. Катовер (Часть C) — окно, обратимо. НЕ запускать без go.

Предусловия: pre-flight зелёный; 0.1.26 задеплоен (детект→isc). Заморозить ВСЕ DHCP-мутации.
**Бэкап ISC:** `cp` `dhcpd.leases` + `dhcpd.conf` + `unlimited-hosts.conf` в сторону.

0. **Установить dnsmasq masked** (заранее, вне окна — §3 «Установка»): `systemctl mask dnsmasq;
   apt-get install -y dnsmasq; ss -ulnp|grep :53` (dnsmasq НЕ на :53 — иначе STOP, чинить BIND).
   Арм isc-guard: `active_unit: isc-dhcp-server` в конфиге backend + рестарт (инертно, пока isc жив).
1. Положить `/etc/ratzek-dnsmasq.conf`, unit'ы (§2/§3), `daemon-reload`. `--test` конфига на хосте.
2. **Populate hostsfile ДО старта:** `ratzek-services-http-backend render-dnsmasq-hostsfile
   --out /etc/ratzek-dnsmasq-hosts` (15 броней; pos/bms уже статикой в конфиге). → dnsmasq
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
| dnsmasq шлёт **DHCPNAK** на 10.11.3 ИЛИ offer'ит адрес из 10.11.3-диапазона | ABORT немедленно (см. §5a: NAK — реальный disruptor; 10.11.5-offer WAN-броадкастеру = паритет с dhcpd, НЕ повод для ABORT) |
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

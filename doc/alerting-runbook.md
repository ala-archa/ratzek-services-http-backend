# Alerting: Prometheus → Alertmanager → Telegram — runbook

Статус на 2026-07-10:
- **Фаза 1 — ВЫПОЛНЕНА.** Backend `0.1.29` задеплоен (webhook `POST /alertmanager/webhook`),
  секция `alerting` в `/etc/ala-archa-http-backend.yaml` (доставка в чат «рацек-телеком»
  `-1002436469006`), smoke-тест прошёл (200 + сообщение в группе).
- **Фаза 2 — ВЫПОЛНЕНА.** Alertmanager `0.27.0` установлен (`/usr/local/bin`), `enabled`+`active`
  на `127.0.0.1:9093` (кластер выключен), конфиг `blackhole` (default) — в Telegram пока ничего
  не идёт; `amtool check-config` SUCCESS.
- **Фаза 3 — ВЫПОЛНЕНА.** Prometheus связан с AM (`alerting:` → `127.0.0.1:9093`) + scrape-job
  `alertmanager` (self-monitoring, up). Правила `ansible_managed.rules` не тронуты. В «тихом окне»
  firing только `Watchdog` (объект здоров).
- **Фаза 4 — ВЫПОЛНЕНА. Алертинг ЖИВОЙ.** Маршрут AM: default → `backend-webhook`,
  `Watchdog` → `blackhole`. Доставка AM→backend→Telegram подтверждена (тест-алерт дошёл в чат;
  Watchdog не доставляется; `errors=0`). Реальные алерты (InstanceDown/clock/fs/conntrack) теперь
  идут в чат «рацек-телеком».

- **Каталог алертов Tier 1 — ПРИМЕНЁН (2026-07-10).** 11 правил объекта в
  `/etc/prometheus/rules/ratzek-site.rules` (питание/BMS, PoE, MikroTik-недоступность, WAN,
  само-здоровье алертинга); пороги калиброваны по 7-дневной истории, end-to-end проверено.
  Канонич. копия — `doc/ratzek-site.rules`. Детали — в разделе ниже.

**Отложено (тюнинг, отдельный шаг):** пороги/`for:` node-правил (`ansible_managed.rules`:
InstanceDown 5m, clock 10m) — понаблюдать шум на ребутах; каталог Tier 2 (см. ниже).

Архитектура (алертер целиком на Pi — осознанное решение; при полной потере питания/LTE он
падает вместе с хостом и «объект лёг» сам не сообщит):

```
Prometheus (rules, :9090) --alerting--> Alertmanager (:9093)
  route/group/blackhole
    ├─ alertname=Watchdog -> blackhole      (без внешнего DMS Watchdog бесполезен)
    └─ прочее             -> backend-webhook -> POST 127.0.0.1:8888/alertmanager/webhook
                                                 (Bearer <webhook_token>)
                                                   backend -> persistent Telegram queue
                                                     -> бот (тот же токен) -> группа «алерты»
```

⚠️ **Ansible морально устарел** — при его прогоне `prometheus.yml`/rules будут затёрты, а про
Alertmanager он не знает. До модернизации ansible всё правится **вручную на хосте** (этот рунбук).

## Предпосылки
- **Telegram-группа алертов**: создать, добавить существующего бота, получить `chat_id`
  (не светить bot-token в history):
  ```bash
  read -rs BOT; curl -s "https://api.telegram.org/bot$BOT/getUpdates" | grep -o '"chat":{"id":-\?[0-9]*'
  ```
  → id (для групп отрицательный).
- **Webhook-секрет**: `openssl rand -hex 24` → одно значение в ДВА места: backend
  `alerting.webhook_token` и AM `credentials`. Mismatch → backend 401 (тихо) → проверяется в Фазе 4.

## Фаза 1 — Backend 0.1.29 + конфиг
1. **Деплой** (с dev-хоста): `scripts/deploy.sh ratzek` — кросс-компиляция в Docker, scp,
   атомарный swap с бэкапом (`/usr/bin/ratzek-services-http-backend.bak-<ts>`), restart,
   печать версии/`is-active`. Пока `alerting` в конфиге нет → эндпоинт 404 (норм, обратно
   совместимо).
2. **Конфиг** — дописать в `/etc/ala-archa-http-backend.yaml` (root:0600) рядом с `telegram:`:
   ```yaml
   alerting:
     webhook_token: "<openssl rand -hex 24>"
     telegram_chat_ids: ["-100XXXXXXXXXX"]
     queue_max_size: 1000
   ```
   `systemctl restart ratzek-services-http-backend && systemctl is-active ratzek-services-http-backend`
3. **Проверка backend→Telegram** (токен из env, тело из файла — не в `ps`/history):
   ```bash
   read -rs T
   cat >/tmp/smoke.json <<'JSON'
   {"alerts":[{"status":"firing","labels":{"alertname":"SmokeTest","severity":"info","instance":"manual"},"annotations":{"summary":"pipeline check"}}]}
   JSON
   curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8888/alertmanager/webhook            # 401
   curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $T" \
     -H 'Content-Type: application/json' -d @/tmp/smoke.json http://127.0.0.1:8888/alertmanager/webhook    # 200 + сообщение
   rm -f /tmp/smoke.json
   ```

## Фаза 2 — Alertmanager (сначала всё в `blackhole`, без спама)
1. **Установка** (aarch64):
   ```bash
   V=0.27.0; cd /tmp
   curl -fLO https://github.com/prometheus/alertmanager/releases/download/v$V/alertmanager-$V.linux-arm64.tar.gz
   # сверить sha256 с https://github.com/prometheus/alertmanager/releases
   tar xzf alertmanager-$V.linux-arm64.tar.gz
   install -m0755 alertmanager-$V.linux-arm64/{alertmanager,amtool} /usr/local/bin/
   install -d -o prometheus -g prometheus /var/lib/alertmanager
   install -d /etc/alertmanager
   ```
2. **`/etc/alertmanager/alertmanager.yml`** — receiver назван `blackhole` (НЕ `null`: в YAML это
   зарезервированное значение → «undefined receiver»). На этой фазе default = `blackhole`:
   ```yaml
   route:
     receiver: blackhole
     # Схлопываем шторм ребута: все InstanceDown в ОДНО сообщение. НЕ группируем по instance —
     # у экспортёров он разный (:9100/:9436/…), иначе N сообщений на ребут.
     group_by: [alertname]
     group_wait: 30s
     group_interval: 5m
     repeat_interval: 4h
     routes:
       - matchers: [ 'alertname="Watchdog"' ]
         receiver: blackhole
   receivers:
     - name: blackhole
     - name: backend-webhook
       webhook_configs:
         - url: http://127.0.0.1:8888/alertmanager/webhook
           send_resolved: true
           http_config:
             authorization: { type: Bearer, credentials: '<webhook_token>' }
   # inhibit_rules намеренно нет: на одном хосте нет общего лейбла, а equal:[instance] не связал
   # бы node-down с падением его экспортёров. Против шторма работает group_by.
   ```
   **Права (в файле секрет!):** `chown root:prometheus /etc/alertmanager/alertmanager.yml && chmod 0640 /etc/alertmanager/alertmanager.yml`
   Валидация: `amtool check-config /etc/alertmanager/alertmanager.yml`
3. **systemd** `/etc/systemd/system/alertmanager.service`:
   ```ini
   [Unit]
   Description=Prometheus Alertmanager
   After=network-online.target
   [Service]
   Type=simple
   User=prometheus
   # --cluster.listen-address= (empty) disables HA clustering: a single on-Pi node
   # otherwise opens 0.0.0.0:9094, exposing the cluster port to the client subnets.
   ExecStart=/usr/local/bin/alertmanager --config.file=/etc/alertmanager/alertmanager.yml --storage.path=/var/lib/alertmanager --web.listen-address=127.0.0.1:9093 --cluster.listen-address=
   ExecReload=/bin/kill -HUP $MAINPID
   Restart=on-failure
   RestartSec=5s
   [Install]
   WantedBy=multi-user.target
   ```
   `systemctl daemon-reload && systemctl enable --now alertmanager && systemctl is-active alertmanager`

## Фаза 3 — Провязка Prometheus
1. **Бэкап**: `cp -a /etc/prometheus/prometheus.yml{,.bak-$(date +%F)}` и
   `cp -a /etc/prometheus/rules/ansible_managed.rules{,.bak-$(date +%F)}`.
2. **`/etc/prometheus/prometheus.yml`** — top-level блок (перед `rule_files:`) и scrape-job:
   ```yaml
   alerting:
     alertmanagers:
       - static_configs:
           - targets: ['127.0.0.1:9093']
   ```
   в конец `scrape_configs:`:
   ```yaml
     - job_name: alertmanager
       static_configs:
         - targets: ['127.0.0.1:9093']
   ```
3. (опц.) в `ansible_managed.rules` снизить `for:` у `InstanceDown` и `NodeClockNotSynchronising`
   до `1m` (хост без RTC часто ребутится).
4. `promtool check config /etc/prometheus/prometheus.yml && promtool check rules /etc/prometheus/rules/ansible_managed.rules`
5. `systemctl reload prometheus`
6. **Пост-reload проверка** (SIGHUP при битом конфиге оставляет старый и логирует ошибку):
   `journalctl -u prometheus -n5 --no-pager` (нет `error loading config`);
   `curl -s 127.0.0.1:9090/api/v1/alertmanagers | grep -o '127.0.0.1:9093'` (AM активен).

## Фаза 4 — Включить доставку + наблюдать
1. В `alertmanager.yml` сменить `route.receiver: blackhole` → `backend-webhook` (под-route
   Watchdog оставить `blackhole`). `amtool check-config …` → `systemctl reload alertmanager`.
2. **Живой тест**: `systemctl stop veml7700-prometheus-exporter` → через `for` сработает
   `InstanceDown` → AM → webhook → Telegram; вернуть `systemctl start …` → `RESOLVED`. Убедиться:
   `Watchdog` в Telegram **не** приходит.
3. **Проверка доставки через AM** (ловит рассинхрон токенов AM↔backend): после прошедшего алерта
   `curl -s 127.0.0.1:8888/metrics | grep -E 'ratzek_alert_webhook_(received|errors)_total|ratzek_telegram_queue_len'`
   — `received` вырос, `errors`≈0.
4. Сутки наблюдать шум `InstanceDown`/clock на ребутах, подстроить `for:`/`group_wait`.

## Rollback (по фазам)
- AM: `systemctl disable --now alertmanager`.
- Prometheus: восстановить `.bak` конфига/rules → `systemctl reload prometheus` (пустой
  `alerting:` = алерты никуда не идут).
- Backend: убрать секцию `alerting` из конфига + restart (эндпоинт → 404), либо откат бинаря на
  `/usr/bin/ratzek-services-http-backend.bak-*`.

## Каталог алертов Tier 1 — ПРИМЕНЁН (2026-07-10)

Файл **`/etc/prometheus/rules/ratzek-site.rules`** (host-direct, `root:prometheus 0640`), группа
`ratzek-site`, 11 правил, `promtool` SUCCESS, на reload все `inactive` (объект здоров, шторма нет),
end-to-end проверено реальным правилом (Prometheus→AM→backend→Telegram). Пороги калиброваны по
7-дневной истории Prometheus. Маршрут — существующий default→`backend-webhook`.

| Alert | expr | for | sev |
|---|---|---|---|
| RatzekBatteryDeepDischarge | `pack_V * current < -150` (Вт) | 5m | warn |
| RatzekSolarNotChargingDaytime | `veml7700_lux>200 and on() max_over_time(current[6h])<0.5` | 15m | warn |
| RatzekBatterySOCLow | `soc_percent < 35` | 15m | warn |
| RatzekBatterySOCCritical | `soc_percent < 20` | 5m | crit |
| RatzekBatteryVoltageLow | `pack_voltage < 22.5` | 10m | crit |
| RatzekBMSAlarm | `daly_bms_alarm != 0` | 5m | warn |
| RatzekBMSCommsLost | `time()-last_frame_ts > 300` | 5m | warn |
| RatzekPoEPortDown | `mikrotik_poe_current == 0` | 5m | warn |
| RatzekMikrotikUnreachable | `mikrotik_scrape_collector_success == 0` | 5m | warn |
| RatzekWANDown | `ratzek_internet_available == 0` | 10m | crit |
| RatzekAlertingDegraded | `rate(am_notif_failed)>0 or rate(webhook_errors)>0 or queue_len>20` | 10m | warn |

Калибровка (7д): DeepDischarge −150 (min V·I −198.8; <−150 = 3/нед; −200 инертен). VoltageLow 22.5
(pack проседал до 23.6 при SOC≥50% = load-sag; <22.5 = 0 ложных). SOC 35/20 (7д min 50%). Известное:
SOC warning+critical перекрываются при <20 (два сообщения — принято); PoE==0 ловит потерю питания, а
НЕ зависание камеры (детект зависания = возраст снапшота `/var/www/webcam_archive`, метрики нет).
Rollback: `rm /etc/prometheus/rules/ratzek-site.rules && systemctl reload prometheus`.

## Каталог Tier 2 (кандидаты, вне первого батча)
LTE (`mikrotik_lte_interface_session_uptime` сброс / rsrp/sinr деградация), низкий `ratzek_isp_balance`
(флор), `ratzek_device_metrics_age_seconds`>1800, темп Pi (`node_hwmon_temp_celsius`>78) и BMS (заряд
при <0 °C), обвал `ratzek_clients_in_acl`, `mikrotik_interface_link_downs`, mikrotik free-mem/cpu.

# Alerting: Prometheus → Alertmanager → Telegram — runbook

Статус на 2026-07-10:
- **Backend 0.1.29** — реализован webhook-приёмник `POST /alertmanager/webhook`
  (`src/alertmanager.rs`, `src/http.rs`), доставка через устойчивую Telegram-очередь backend.
  Отревьюен, тесты зелёные. **Ещё не задеплоен** (см. Фаза 1).
- **Alertmanager** — на хост НЕ установлен (порт 9093 свободен). Ставится вручную (Фаза 2).
- **Prometheus** (`/usr/local/bin/prometheus`, reload=SIGHUP) — правила `ansible_managed.rules`
  (`Watchdog`, `InstanceDown`, node-fs/clock/conntrack) лежат, но секции `alerting:` нет →
  никуда не маршрутизируются. Провязка — Фаза 3.

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
   ExecStart=/usr/local/bin/alertmanager --config.file=/etc/alertmanager/alertmanager.yml --storage.path=/var/lib/alertmanager --web.listen-address=127.0.0.1:9093
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

## Каталог алертов (вне объёма пайплайна — отдельный шаг)
Кандидаты: питание/BMS (`daly_bms_soc_percent` низко / `daly_bms_current_amperes`<0 разряд —
упреждение до отключения), LTE (`mikrotik_lte_interface_session_uptime` сброс, rsrp низкий),
PoE-порт (`mikrotik_poe_current`==0 — webcam-камера 10.11.3.4), `ratzek_internet_available==0`,
обвал `ratzek_clients_in_acl`, `ratzek_dhcp_leases_free` низко,
`ratzek_device_metrics_age_seconds` высок, диск, температура.

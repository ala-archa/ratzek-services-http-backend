use anyhow::Result;
use serde::{Deserialize, Serialize};
use slog_scope::{error, info};

fn decode_hex_to_ucs2(hex: &str) -> Result<String> {
    // Cut string to fit 4-byte chunks
    let hex = if hex.len() % 4 != 0 {
        let len = hex.len() - hex.len() % 4;
        let mut hex = hex.to_string();
        hex.truncate(len);
        hex
    } else {
        hex.to_string()
    };

    // check if hex string is of 4-byte chunks
    if hex.len() % 4 != 0 {
        return Err(anyhow::anyhow!("Hex string length is not a multiple of 4"));
    }

    // Преобразуем hex-строку в байты
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|err| anyhow::anyhow!("Failed to parse hex string: {err}"))?;

    // Преобразуем UCS-2 в UTF-8
    let utf16_data = bytes
        .chunks(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<u16>>();

    String::from_utf16(&utf16_data)
        .map_err(|err| anyhow::anyhow!("Failed to convert UCS-2 to UTF-8: {err}"))
}

#[derive(Deserialize, Serialize, Clone)]
pub struct MobileProvider {
    pub update_tariff_command: String,
    pub get_balance_command: String,
    #[serde(default)]
    pub get_balance_crontab: Option<String>,
    pub low_balance_threshold: f64,
    pub low_download_speed_threshold: f64,
    #[serde(with = "humantime_serde")]
    pub min_update_tariff_interval: std::time::Duration,
    pub telegram_chat_ids: Vec<String>,
    pub phone_number: String,
    pub get_balance_retry_count: u8,
    #[serde(with = "humantime_serde")]
    pub get_balance_retry_interval: std::time::Duration,
    pub restart_lte_command: String,
}

impl MobileProvider {
    async fn get_balance(&self) -> Result<f64> {
        let output = tokio::process::Command::new("bash")
            .arg("-c")
            .arg(&self.get_balance_command)
            .output()
            .await?;
        let output = String::from_utf8(output.stdout)?;

        slog_scope::info!("Got balance output: {}", output);

        // get line in output, which starts with +CUSD: 0,"
        let line = output
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("+CUSD: 0,\""))
            .ok_or_else(|| anyhow::anyhow!("Failed to find balance in output"))?;
        // split line by double quotes and get second part
        let message = line
            .split("\"")
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("Failed to extract message from line"))?;
        slog_scope::info!("Got encoded balance message: {}", message);
        let message = decode_hex_to_ucs2(message)?;
        slog_scope::info!("Got decoded balance message: {}", message);
        // extract number from message which looks like: Баланс 548.08 с. ...
        let balance = message
            .split_whitespace()
            .nth(2)
            .ok_or_else(|| anyhow::anyhow!("Failed to extract balance from message"))?
            .trim();
        slog_scope::info!("Got balance: {}", balance);

        let balance = balance
            .parse()
            .map_err(|err| anyhow::anyhow!("Failed to parse balance: {err}"))?;

        Ok(balance)
    }

    async fn alert_balance(
        &self,
        persistent_state: &crate::persistent_state::PersistentStateGuard,
        telegram: &crate::telegram::Telegram,
        balance: f64,
    ) -> Result<()> {
        let message = format!(
            "Низкий остаток: {} сом. Необходимо пополнить номер {}. Уведомления приходят, если баланс менее {} сом.",
            balance, self.phone_number, self.low_balance_threshold
        );
        telegram
            .send_message(persistent_state, &self.telegram_chat_ids, &message)
            .await;

        Ok(())
    }

    async fn alert_update_tariff(
        &self,
        persistent_state: &crate::persistent_state::PersistentStateGuard,
        telegram: &crate::telegram::Telegram,
    ) -> Result<()> {
        let message = "Скорость интернета ниже порога. Обновление тарифа...";
        telegram
            .send_message(persistent_state, &self.telegram_chat_ids, message)
            .await;

        Ok(())
    }

    pub async fn get_and_alert_balance(
        &self,
        persistent_state: &crate::persistent_state::PersistentStateGuard,
        telegram: &Option<crate::telegram::Telegram>,
    ) -> Result<f64> {
        let mut balance = None;
        for _ in 0..self.get_balance_retry_count {
            match self.get_balance().await {
                Ok(v) => {
                    balance = Some(v);
                    break;
                }
                Err(err) => {
                    error!("Failed to get balance: {:?}", err);
                }
            }
            tokio::time::sleep(self.get_balance_retry_interval).await;
        }

        // restart LTE after getting balance
        let output = tokio::process::Command::new("bash")
            .arg("-c")
            .arg(&self.restart_lte_command)
            .output()
            .await;
        if let Err(err) = output {
            error!("Failed to restart LTE: {:?}", err);
        }

        let balance = match balance {
            Some(v) => v,
            None => {
                return Err(anyhow::anyhow!("Failed to get balance"));
            }
        };

        if balance < self.low_balance_threshold {
            if let Some(telegram) = telegram {
                if let Err(err) = self
                    .alert_balance(persistent_state, telegram, balance)
                    .await
                {
                    error!("Failed to send balance alert: {:?}", err);
                }
            }
        }
        Ok(balance)
    }

    pub async fn update_tariff(
        &self,
        config: &crate::config::Config,
        persistent_state: &crate::persistent_state::PersistentStateGuard,
    ) {
        let persistent_state_unwrapped = persistent_state.get().await;
        let speedtest = match persistent_state_unwrapped.speedtest {
            None => {
                info!("No speedtest data available, skipping tariff update");
                return;
            }
            Some(v) => v,
        };

        if speedtest.download > self.low_download_speed_threshold {
            info!("Download speed is good, skipping tariff update");
            return;
        }

        if let Some(last_update) = persistent_state_unwrapped.last_tariff_update {
            if chrono::Utc::now() - last_update
                < chrono::TimeDelta::from_std(self.min_update_tariff_interval).unwrap()
            {
                info!("Last tariff update was too recent, skipping");
                return;
            }
        }

        let output = tokio::process::Command::new("bash")
            .arg("-c")
            .arg(&self.update_tariff_command)
            .output()
            .await;

        if let Err(err) = output {
            error!("Failed to update tariff: {:?}", err);
            return;
        }

        if let Some(telegram) = &config.telegram {
            if let Err(err) = self.alert_update_tariff(persistent_state, telegram).await {
                error!("Failed to send tariff update alert: {:?}", err);
            }
        }

        let r = persistent_state
            .update(|state| {
                state.last_tariff_update = Some(chrono::Utc::now());
            })
            .await;
        if let Err(err) = r {
            error!("Failed to update persistent state: {:?}", err);
        }
    }
}

#[test]
fn test_ucs2_decoder() {
    let input = "04110430043b0430043d04410020003500340038002e0030003800200441002e002000310030003000300020043f044104380445043e043b043e04330438044704350441043a0438044500200442043504410442043e04320020002a00330034003100230020003500200441043e043c00200432002004340435043d044c";
    let output = decode_hex_to_ucs2(input).unwrap();
    println!("{}", output);
    assert_eq!(
        output,
        "Баланс 548.08 с. 1000 психологических тестов *341# 5 сом в день"
    );
}

#[test]
fn test_ucs2_decoder_truncated_string() {
    let expected = "Баланс 548.08 с. 1000 психологических тестов *341# 5 сом в ден";

    let input = "04110430043b0430043d04410020003500340038002e0030003800200441002e002000310030003000300020043f044104380445043e043b043e04330438044704350441043a0438044500200442043504410442043e04320020002a00330034003100230020003500200441043e043c00200432002004340435043d044";
    let output = decode_hex_to_ucs2(input).unwrap();
    assert_eq!(output, expected,);

    let input = "04110430043b0430043d04410020003500340038002e0030003800200441002e002000310030003000300020043f044104380445043e043b043e04330438044704350441043a0438044500200442043504410442043e04320020002a00330034003100230020003500200441043e043c00200432002004340435043d04";
    let output = decode_hex_to_ucs2(input).unwrap();
    assert_eq!(output, expected,);

    let input = "04110430043b0430043d04410020003500340038002e0030003800200441002e002000310030003000300020043f044104380445043e043b043e04330438044704350441043a0438044500200442043504410442043e04320020002a00330034003100230020003500200441043e043c00200432002004340435043d0";
    let output = decode_hex_to_ucs2(input).unwrap();
    assert_eq!(output, expected,);
}

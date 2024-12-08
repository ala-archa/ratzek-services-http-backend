use anyhow::Result;
use serde::{Deserialize, Serialize};
use slog_scope::{error, info};

fn decode_ucs2_in_hex(hex: &str) -> Result<String> {
    // Cut string to fit 4-byte chunks
    let hex = if hex.len() % 4 != 0 {
        let len = hex.len() - hex.len() % 4;
        let mut hex = hex.to_string();
        hex.truncate(len);
        hex
    } else {
        hex.to_string()
    };

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

fn decode_utf8_in_hex(hex: &str) -> Result<String> {
    // Cut string to fit 2-byte chunks
    let hex = if hex.len() % 2 != 0 {
        let len = hex.len() - hex.len() % 2;
        let mut hex = hex.to_string();
        hex.truncate(len);
        hex
    } else {
        hex.to_string()
    };

    // Преобразуем hex-строку в байты
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|err| anyhow::anyhow!("Failed to parse hex string: {err}"))?;

    String::from_utf8(bytes).map_err(|err| anyhow::anyhow!("Failed to read UTF-8: {err}"))
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
    async fn get_balance_once(&self) -> Result<f64> {
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
            .find(|line| line.starts_with("+CUSD: "))
            .ok_or_else(|| anyhow::anyhow!("Failed to find balance in output"))?;
        // split line by double quotes and get second part
        let message = line
            .split("\"")
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("Failed to extract message from line"))?;
        slog_scope::info!("Got encoded balance message: {}", message);
        let message_variants = vec![decode_ucs2_in_hex(message), decode_utf8_in_hex(message)]
            .into_iter()
            .filter_map(|result| match result {
                Ok(v) => Some(v),
                Err(err) => {
                    error!("Failed to decode message: {:?}", err);
                    None
                }
            })
            .collect::<Vec<String>>();
        for message in message_variants {
            slog_scope::info!("Got decoded balance message: {}", message);
            // extract number from message which looks like: Баланс 548.08 с. ...
            let balance = if message.starts_with("Баланс ") {
                message
                    .split_whitespace()
                    .nth(1)
                    .ok_or_else(|| anyhow::anyhow!("Failed to extract balance from message"))?
                    .trim()
                // extract number from message which looks like: You have 398.08 som.
            } else if message.starts_with("You have ") {
                message
                    .split_whitespace()
                    .nth(2)
                    .ok_or_else(|| anyhow::anyhow!("Failed to extract balance from message"))?
                    .trim()
            } else {
                error!("Failed to extract balance from message: unexpected message prefix");
                continue;
            };

            slog_scope::info!("Got balance: {}", balance);

            match balance
                .parse()
                .map_err(|err| anyhow::anyhow!("Failed to parse balance: {err}"))
            {
                Ok(v) => return Ok(v),
                Err(err) => {
                    error!("Failed to parse balance: {:?}", err);
                }
            }
        }

        anyhow::bail!("Unable to extract balance from operator response")
    }

    pub async fn get_balance(&self) -> Result<f64> {
        let mut balance = None;
        for _ in 0..self.get_balance_retry_count {
            match self.get_balance_once().await {
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

        balance.ok_or_else(|| anyhow::anyhow!("Failed to get balance"))
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
        let balance = self.get_balance().await?;

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
    let output = decode_ucs2_in_hex(input).unwrap();
    println!("{}", output);
    assert_eq!(
        output,
        "Баланс 548.08 с. 1000 психологических тестов *341# 5 сом в день"
    );
}

// Dec 07 13:20:20 ratzek ratzek-services-http-backend[406]: Got balance output:   output: OK
//                                                                     +CREG: 1, 1ca4, ca8b8, 2
//                                                                     +CGREG: 1,"1ca4","000ca8b8",4,6
//                                                                     +CEREG: 0
//                                                                     +CGREG: 1,"1ca4","000ca8b8",6,6
//                                                                     +CREG: 1, 1ca4, ca8b8, 6
//                                                                     +CUSD: 0,"596f752068617665203339382e303820

#[test]
fn test_utf8_decoder() {
    let input =
        "596f752068617665203339382e303820736f6d2e20546f7020757020796f75722062616c616e63652077697468204f21426f6e75736573";
    let output = decode_utf8_in_hex(input).unwrap();
    println!("{}", output);
    assert_eq!(
        output,
        "You have 398.08 som. Top up your balance with O!Bonuses"
    );
}

#[test]
fn test_ucs2_decoder_truncated_string() {
    let expected = "Баланс 548.08 с. 1000 психологических тестов *341# 5 сом в ден";

    let input = "04110430043b0430043d04410020003500340038002e0030003800200441002e002000310030003000300020043f044104380445043e043b043e04330438044704350441043a0438044500200442043504410442043e04320020002a00330034003100230020003500200441043e043c00200432002004340435043d044";
    let output = decode_ucs2_in_hex(input).unwrap();
    assert_eq!(output, expected,);

    let input = "04110430043b0430043d04410020003500340038002e0030003800200441002e002000310030003000300020043f044104380445043e043b043e04330438044704350441043a0438044500200442043504410442043e04320020002a00330034003100230020003500200441043e043c00200432002004340435043d04";
    let output = decode_ucs2_in_hex(input).unwrap();
    assert_eq!(output, expected,);

    let input = "04110430043b0430043d04410020003500340038002e0030003800200441002e002000310030003000300020043f044104380445043e043b043e04330438044704350441043a0438044500200442043504410442043e04320020002a00330034003100230020003500200441043e043c00200432002004340435043d0";
    let output = decode_ucs2_in_hex(input).unwrap();
    assert_eq!(output, expected,);
}

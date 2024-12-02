use anyhow::Result;
use serde::{Deserialize, Serialize};
use slog_scope::{error, info};

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
    pub telegram_chat_ids: Vec<i64>,
    pub phone_number: String,
}

impl MobileProvider {
    async fn get_balance(&self) -> Result<f64> {
        let output = tokio::process::Command::new("bash")
            .arg("-c")
            .arg(&self.get_balance_command)
            .output()
            .await?;
        // TODO
        let balance = String::from_utf8(output.stdout)?;
        Ok(balance.trim().parse()?)
    }

    async fn alert_balance(
        &self,
        telegram: &crate::telegram::Telegram,
        balance: f64,
    ) -> Result<()> {
        let message = format!(
            "Низкий остаток: {} сом. Необходимо пополнить номер {}",
            balance, self.phone_number
        );
        telegram
            .send_message(&self.telegram_chat_ids, &message)
            .await;

        Ok(())
    }

    pub async fn get_and_alert_balance(&self, telegram: &crate::telegram::Telegram) -> Result<f64> {
        let balance = self.get_balance().await?;
        if balance < self.low_balance_threshold {
            self.alert_balance(telegram, balance).await?;
        }
        Ok(balance)
    }

    pub async fn update_tariff(
        &self,
        config: &crate::config::Config,
        persistent_state: &crate::state::PersistentStateGuard,
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

        let r = persistent_state
            .update(config, |state| {
                state.last_tariff_update = Some(chrono::Utc::now());
            })
            .await;
        if let Err(err) = r {
            error!("Failed to update persistent state: {:?}", err);
        }
    }
}

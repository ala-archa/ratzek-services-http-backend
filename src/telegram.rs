use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use slog_scope::info;

#[derive(Deserialize, Serialize, Clone)]
pub struct Telegram {
    pub bot_token: String,
    #[serde(with = "humantime_serde")]
    pub message_timeout: std::time::Duration,
    pub retry_crontab: String,
}

impl Telegram {
    async fn try_send_message(&self, chat_id: &str, text: &str) -> Result<()> {
        slog_scope::info!("Sending message to telegram chat {}: {}", chat_id, text);
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let client = reqwest::Client::new();
        let r = client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": chat_id,
                "text": text,
            }))
            .send()
            .await;

        let r = match r {
            Ok(r) => r,
            Err(err) => {
                slog_scope::error!("Failed to send message to telegram: {}", err);
                return Err(err.into());
            }
        };

        if !r.status().is_success() {
            let text = r.text().await.unwrap_or_else(|_| "".to_string());
            slog_scope::error!("Failed to send message to telegram: {}", text);
            bail!("Failed to send message to telegram: {}", text);
        }

        Ok(())
    }

    pub async fn send_message(
        &self,
        persistent_state: &crate::persistent_state::PersistentStateGuard,
        chat_ids: &[String],
        text: &str,
    ) {
        for chat_id in chat_ids {
            let r = self.try_send_message(chat_id, text).await;
            if r.is_err() {
                let r = persistent_state
                    .update(|persistent_state| {
                        persistent_state.telegram_queue.push(
                            crate::persistent_state::TelegramMessage {
                                chat_id: chat_id.to_string(),
                                text: text.to_string(),
                                timestamp: chrono::Local::now(),
                            },
                        );
                    })
                    .await;
                if let Err(err) = r {
                    slog_scope::error!("Failed to update persistent state: {}", err);
                }
            }
        }
    }

    pub async fn process_queue(
        &self,
        persistent_state: &crate::persistent_state::PersistentStateGuard,
    ) -> Result<()> {
        info!("Processing telegram queue");
        let mut queue = persistent_state
            .update(|persistent_state| {
                let r = persistent_state.telegram_queue.clone();
                persistent_state.telegram_queue.clear();
                r
            })
            .await?;
        let mut new_queue = Vec::new();
        while let Some(message) = queue.pop() {
            info!("Processing message: {}", message.text);
            if (chrono::Local::now() - message.timestamp).to_std().unwrap() > self.message_timeout {
                info!("Dropping message due to timeout: {}", message.text);
                continue;
            }

            let text = format!(
                "{}\n\nЭто сообщение было отправлено в {}.",
                message.text,
                message.timestamp.format("%Y-%m-%d %H:%M:%S")
            );
            let r = self.try_send_message(&message.chat_id, &text).await;
            if r.is_err() {
                new_queue.push(message);
            }
        }
        persistent_state
            .update(|persistent_state| {
                persistent_state.telegram_queue = new_queue;
            })
            .await?;
        Ok(())
    }
}

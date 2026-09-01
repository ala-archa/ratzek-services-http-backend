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

/// Whether a queued message stamped at `stamped_at` is older than `timeout`.
///
/// A timestamp in the *future* is never expiry. The host has no RTC: after a hard reset
/// fake-hwclock restores the time saved at the last hourly tick, so `now` can be up to an hour
/// behind messages queued just before the reset. Converting that negative age with
/// `Duration::to_std().unwrap()` used to panic, and `process_queue` clears and persists the queue
/// before iterating it — so the panic destroyed every pending alert, precisely the ones describing
/// the outage that caused the reset.
fn is_expired(
    now: chrono::DateTime<chrono::Local>,
    stamped_at: chrono::DateTime<chrono::Local>,
    timeout: std::time::Duration,
) -> bool {
    (now - stamped_at).to_std().is_ok_and(|age| age > timeout)
}

impl Telegram {
    async fn try_send_message(&self, chat_id: &str, text: &str) -> Result<()> {
        slog_scope::info!("Sending message to telegram chat {}: {}", chat_id, text);
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        // Bounded timeout: the uplink is a weak/lossy LTE link, and this runs inside
        // the Alertmanager webhook HTTP handler — an unbounded hang would tie up a
        // worker and stall Alertmanager into a retry. On timeout the message falls
        // back to the persistent retry queue in `send_message`.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
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
            if is_expired(chrono::Local::now(), message.timestamp, self.message_timeout) {
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

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

    fn at(s: &str) -> chrono::DateTime<chrono::Local> {
        use chrono::TimeZone;
        let naive = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
            .expect("valid timestamp");
        chrono::Local
            .from_local_datetime(&naive)
            .single()
            .expect("unambiguous local time")
    }

    #[test]
    fn older_than_timeout_expires() {
        assert!(is_expired(
            at("2026-08-30 13:00:00"),
            at("2026-08-29 12:00:00"),
            TIMEOUT
        ));
    }

    #[test]
    fn within_timeout_is_kept() {
        assert!(!is_expired(
            at("2026-08-30 12:00:00"),
            at("2026-08-30 11:00:00"),
            TIMEOUT
        ));
    }

    #[test]
    fn timestamp_from_the_future_is_kept_not_panicking() {
        // fake-hwclock rolled the clock back an hour after a hard reset.
        assert!(!is_expired(
            at("2026-08-30 12:00:00"),
            at("2026-08-30 13:00:00"),
            TIMEOUT
        ));
    }
}

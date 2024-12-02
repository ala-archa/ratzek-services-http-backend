use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone)]
pub struct Telegram {
    pub bot_token: String,
}

impl Telegram {
    pub async fn send_message(&self, chat_ids: &[i64], text: &str) {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let client = reqwest::Client::new();
        for chat_id in chat_ids {
            let r = client
                .post(&url)
                .json(&serde_json::json!({
                    "chat_id": chat_id,
                    "text": text,
                }))
                .send()
                .await;

            if let Err(err) = r {
                slog_scope::error!("Failed to send message to telegram: {}", err);
            }
        }
    }
}

//! Alertmanager webhook (v4) payload model + plain-text formatting.
//!
//! Alertmanager (running on this host) POSTs this JSON to `/alertmanager/webhook`;
//! the HTTP handler in `src/http.rs` authenticates it, calls [`format_message`],
//! and enqueues the result onto the shared Telegram queue. Output is plain text
//! (the Telegram sender sets no `parse_mode`), so label values need no escaping —
//! a malicious label cannot inject Telegram markup.

use serde::Deserialize;
use std::collections::BTreeMap;

/// The subset of the Alertmanager v4 webhook we consume. Unknown fields
/// (`groupKey`, `externalURL`, `commonLabels`, …) are ignored by serde.
#[derive(Deserialize, Debug, Default)]
pub struct Webhook {
    #[serde(default)]
    pub alerts: Vec<Alert>,
}

#[derive(Deserialize, Debug, Default)]
pub struct Alert {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

impl Alert {
    fn label(&self, key: &str) -> Option<&str> {
        self.labels.get(key).map(String::as_str).filter(|s| !s.is_empty())
    }

    fn annotation(&self, key: &str) -> Option<&str> {
        self.annotations.get(key).map(String::as_str).filter(|s| !s.is_empty())
    }

    /// One plain-text line for this alert, e.g.
    /// `🔴 FIRING: InstanceDown [critical] @127.0.0.1:9100 — target is down`.
    fn render_line(&self) -> String {
        let firing = !self.status.eq_ignore_ascii_case("resolved");
        let head = if firing { "🔴 FIRING" } else { "✅ RESOLVED" };
        let name = self.label("alertname").unwrap_or("alert");

        let mut line = format!("{head}: {name}");
        if let Some(sev) = self.label("severity") {
            line.push_str(&format!(" [{sev}]"));
        }
        if let Some(inst) = self.label("instance").or_else(|| self.label("job")) {
            line.push_str(&format!(" @{inst}"));
        }
        if let Some(text) = self.annotation("summary").or_else(|| self.annotation("description")) {
            line.push_str(&format!(" — {text}"));
        }
        line
    }
}

/// Format a whole webhook batch into a single plain-text Telegram message, or
/// `None` when there is nothing worth sending (no alerts).
pub fn format_message(payload: &Webhook) -> Option<String> {
    if payload.alerts.is_empty() {
        return None;
    }
    let body = payload
        .alerts
        .iter()
        .map(Alert::render_line)
        .collect::<Vec<_>>()
        .join("\n");
    Some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Webhook {
        serde_json::from_str(s).expect("valid webhook json")
    }

    #[test]
    fn firing_with_all_fields() {
        let wh = parse(
            r#"{"version":"4","status":"firing","alerts":[
                {"status":"firing",
                 "labels":{"alertname":"InstanceDown","severity":"critical","instance":"127.0.0.1:9100"},
                 "annotations":{"summary":"target is down"},
                 "startsAt":"2026-07-10T12:00:00Z"}]}"#,
        );
        let msg = format_message(&wh).unwrap();
        assert_eq!(
            msg,
            "🔴 FIRING: InstanceDown [critical] @127.0.0.1:9100 — target is down"
        );
    }

    #[test]
    fn resolved_uses_check_and_description_fallback() {
        let wh = parse(
            r#"{"status":"resolved","alerts":[
                {"status":"resolved",
                 "labels":{"alertname":"DiskFull"},
                 "annotations":{"description":"space recovered"}}]}"#,
        );
        let msg = format_message(&wh).unwrap();
        assert_eq!(msg, "✅ RESOLVED: DiskFull — space recovered");
    }

    #[test]
    fn multiple_alerts_join_with_newline() {
        let wh = parse(
            r#"{"status":"firing","alerts":[
                {"status":"firing","labels":{"alertname":"A"}},
                {"status":"firing","labels":{"alertname":"B"}}]}"#,
        );
        assert_eq!(format_message(&wh).unwrap(), "🔴 FIRING: A\n🔴 FIRING: B");
    }

    #[test]
    fn empty_alerts_is_none() {
        let wh = parse(r#"{"status":"firing","alerts":[]}"#);
        assert!(format_message(&wh).is_none());
    }

    #[test]
    fn missing_optional_fields_are_tolerated() {
        // No severity, no instance, no annotations, unknown extra fields present.
        let wh = parse(
            r#"{"status":"firing","groupKey":"x","externalURL":"http://y","alerts":[
                {"status":"firing","labels":{"alertname":"Bare"},"fingerprint":"abc"}]}"#,
        );
        assert_eq!(format_message(&wh).unwrap(), "🔴 FIRING: Bare");
    }

    #[test]
    fn plain_text_label_is_not_escaped() {
        // We send plain text (no parse_mode); markup chars pass through literally.
        let wh = parse(
            r#"{"status":"firing","alerts":[
                {"status":"firing","labels":{"alertname":"Weird*_`[name"}}]}"#,
        );
        assert_eq!(format_message(&wh).unwrap(), "🔴 FIRING: Weird*_`[name");
    }
}

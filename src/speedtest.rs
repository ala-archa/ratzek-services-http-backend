use serde::{Deserialize, Serialize};
use slog_scope::info;

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct SpeedTest {
    pub download: f64,
    pub upload: f64,
    pub ping: f64,
}

impl SpeedTest {
    pub async fn run(config: &crate::config::SpeedTest) -> anyhow::Result<Self> {
        info!("Running speed test");
        let r = tokio::process::Command::new(&config.speedtest_cli_path)
            .arg("--json")
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&r.stdout);
        let stderr = String::from_utf8_lossy(&r.stderr);
        slog_scope::info!("Speed test STDOUT: {}", stdout);
        slog_scope::info!("Speed test STDERR: {}", stderr);
        let speed_test: SpeedTest = serde_json::from_str(&stdout)?;

        slog_scope::info!("Speed test results: {:?}", speed_test);

        Ok(speed_test)
    }
}

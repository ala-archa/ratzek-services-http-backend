use serde::Deserialize;

#[derive(Deserialize, Default, Debug)]
pub struct SpeedTest {
    pub download: f64,
    pub upload: f64,
    pub ping: f64,
}

impl SpeedTest {
    pub async fn run(config: &crate::config::SpeedTest) -> anyhow::Result<Self> {
        let r = tokio::process::Command::new(&config.speedtest_cli_path)
            .args(["--json", "--server", &config.server])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&r.stdout);
        let speed_test: SpeedTest = serde_json::from_str(&stdout)?;

        slog_scope::info!("Speed test results: {:?}", speed_test);

        Ok(speed_test)
    }
}

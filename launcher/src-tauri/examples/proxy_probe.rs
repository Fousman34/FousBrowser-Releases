//! Manual integration check. Credentials are read only from environment variables.
//! FOUS_PROXY_HOST, FOUS_PROXY_PORT, FOUS_PROXY_SCHEME, FOUS_PROXY_USER, FOUS_PROXY_PASSWORD.
use fousbrowser_launcher_lib::{proxy::Bridge, vault::ProxyConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ProxyConfig {
        scheme: std::env::var("FOUS_PROXY_SCHEME")?.parse()?,
        host: std::env::var("FOUS_PROXY_HOST")?,
        port: std::env::var("FOUS_PROXY_PORT")?.parse()?,
        username: std::env::var("FOUS_PROXY_USER").ok(),
        password: std::env::var("FOUS_PROXY_PASSWORD").ok(),
    };
    fousbrowser_launcher_lib::proxy::check(&config).await?;
    let bridge = Bridge::start(config).await?;
    let address = format!("socks5h://127.0.0.1:{}", bridge.port());
    let result = tokio::task::spawn_blocking(move || {
        std::process::Command::new("curl.exe")
            .args([
                "--proxy",
                &address,
                "--max-time",
                "30",
                "--silent",
                "--show-error",
                "--output",
                "NUL",
                "--write-out",
                "%{http_code}",
                "https://example.com",
            ])
            .output()
    })
    .await??;
    bridge.stop();
    if !result.status.success() || result.stdout != b"200" {
        return Err("end-to-end proxy request failed".into());
    }
    println!("PASS: preflight + local SOCKS5 bridge + upstream + HTTPS response 200");
    Ok(())
}

use reqwest;
use std::time::Duration;
use serde_json::Value;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    let proxies = vec![
        "socks5://184.178.172.18:15303",
        "socks5://98.162.25.23:4145",
        "socks5://72.210.252.134:4145",
    ];

    println!(" Kraken Proxy Scout...");

    for addr in proxies {
        
        
        let proxy = match reqwest::Proxy::all(addr) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(7))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0")
            .build()?;

        match client.get("https://api.ipify.org?format=json").send().await {
            Ok(resp) => {
                let json: Value = resp.json().await?;
                
                
                return Ok(());
            }
            Err(e) => {
                
            }
        }
    }

    
    Ok(())
}

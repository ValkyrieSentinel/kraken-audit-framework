mod entropy;
mod tunnel;
mod pdf_generator;

use aya::maps::HashMap as BpfHashMap;
use aya::programs::{SchedClassifier, TcAttachType, tc};
use aya::{include_bytes_aligned, Bpf};
use colored::*;
use std::convert::{TryFrom, TryInto};
use tokio::time::{timeout, Duration, Instant};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tunnel::TorTunnel;
use rand::Rng;
use std::sync::Arc;
use tokio::sync::Mutex;
use pnet::datalink;
use chrono::Local;


use kraken_common::MAC_MAP_KEY;


struct AuditResult {
    port: u16, 
    entropy: f32, 
    leaks: Vec<String>, 
    response_time_ms: u128,
}


fn get_interface_mac(iface_name: &str) -> [u8; 6] {
    datalink::interfaces().into_iter()
        .find(|iface| iface.name == iface_name)
        .and_then(|iface| iface.mac)
        .map(|mac| [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5])
        .expect("No MAC")
}

fn generate_random_mac() -> [u8; 6] {
    let mut rng = rand::thread_rng();
    let mut mac = [0u8; 6];
    rng.fill(&mut mac);
    mac[0] = (mac[0] & 0xfc) | 0x02; 
    mac
}

async fn perform_audit(target: String) -> Option<AuditResult> {
    let port = target.split(':').last()?.parse().ok()?;
    let start = Instant::now();
    
    
    let mut stream = timeout(Duration::from_secs(10), TorTunnel::connect(&target)).await.ok()?.ok()?;
    let req = "GET / HTTP/1.1\r\nHost: scanme.nmap.org\r\nConnection: close\r\n\r\n";
    
    let _ = stream.write_all(req.as_bytes()).await;
    let mut buffer = [0u8; 1024];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buffer)).await.ok()?.ok()?;
    
    let body = String::from_utf8_lossy(&buffer[..n]).to_string();
    let ent = entropy::calculate_entropy(&body) as f32; // Кастуємо в f32
    let mut leaks = Vec::new();
    if entropy::is_suspicious(&body) { 
        leaks.push("SENSITIVE_DATA_DETECTED".to_string()); 
    }

    Some(AuditResult {
        port, 
        entropy: ent, 
        leaks, 
        response_time_ms: start.elapsed().as_millis(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "===  KRAKEN CORE v4.0 ===".bright_cyan().bold());
    
    let mut report_leaks = Vec::new();
    let iface = "wlo1"; 
    let real_mac = get_interface_mac(iface);
    
    
    let bpf_data = include_bytes_aligned!("../../target/bpfel-unknown-none/release/kraken-ebpf");
    let mut bpf = Bpf::load(bpf_data)?;
    

    let _ = tc::qdisc_add_clsact(iface);
    
    let program: &mut SchedClassifier = bpf.program_mut("kraken_stealth").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, TcAttachType::Egress)?;

    
    let mut real_mac_map: BpfHashMap<_, u32, [u8; 6]> = BpfHashMap::try_from(bpf.map_mut("REAL_MAC_MAP").unwrap())?;
    real_mac_map.insert(MAC_MAP_KEY, real_mac, 0)?;

    let target_ip = ""; 
    let ports = vec![80, 443, 8080];
    let shared_bpf = Arc::new(Mutex::new(bpf));

    for port in ports {
        let new_mac = generate_random_mac();
        {
            let mut bpf_lock = shared_bpf.lock().await;
            let mut mac_map: BpfHashMap<_, u32, [u8; 6]> = BpfHashMap::try_from(bpf_lock.map_mut("MAC_MAP").unwrap())?;
            mac_map.insert(MAC_MAP_KEY, new_mac, 0)?;
        }
        
        println!(" {} {:02x}:{:02x}:{:02x}...", "Stealth MAC Active:".bright_yellow(), new_mac[0], new_mac[1], new_mac[2]);

        let target = format!("{}:{}", target_ip, port);
        if let Some(res) = perform_audit(target).await {
            println!(">> Port: {} | Entropy: {:.2} | Time: {}ms", 
                res.port.to_string().bright_white(), 
                res.entropy, 
                res.response_time_ms);
            
            if !res.leaks.is_empty() || res.entropy > 4.5 {
                report_leaks.push(pdf_generator::LeakEvent {
                    timestamp: Local::now().to_rfc3339(),
                    protocol: format!("TCP/{}", res.port),
                    entropy: res.entropy,
                    data_preview: if res.leaks.is_empty() { "High Entropy payload".into() } else { res.leaks.join(", ") },
                });
            }
        }
        
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    
    if !report_leaks.is_empty() {
        let session_id = format!("KRAKEN_{}", Local::now().format("%Y%m%d_%H%M%S"));
        pdf_generator::generate_pdf_report(&session_id, &report_leaks)?;
        println!(" {} {}.pdf", "Full Audit Report saved:".bright_green(), session_id);
    }

    Ok(())
}
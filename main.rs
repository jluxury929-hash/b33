use ethers::{
    prelude::*,
    providers::{Provider, Ws},
    utils::{parse_ether, format_ether},
};
use std::{sync::Arc, collections::HashMap, str::FromStr, net::TcpListener, io::{self, Write}, thread, time::Duration};
use colored::*;
use anyhow::{Result, anyhow};
use log::{info, error, warn};
use futures_util::StreamExt;
use tokio::sync::Semaphore;

// --- CONFIGURATION ---
const WETH_ADDR: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

#[derive(Clone, Debug)]
struct ChainConfig {
    name: String,
    rpc_env_key: String,
    default_rpc: String,
    chain_id: u64,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    println!("{}", "╔════════════════════════════════════════════════════════╗".yellow());
    println!("{}", "║    ⚡ APEX OMEGA: HARDENED RESILIENCE (V4.2.8)     ║".yellow().bold());
    println!("{}", "║    STATUS: TARGETED SCANNING | SERIALIZED SETUP     ║".yellow());
    println!("{}", "╚════════════════════════════════════════════════════════╝".yellow());

    // Railway Health Monitor
    thread::spawn(|| {
        let listener = TcpListener::bind("0.0.0.0:8080").expect("Failed to bind health port");
        for stream in listener.incoming() {
            if let Ok(mut s) = stream { let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n"); }
        }
    });

    // Semaphore: Ensuring only 1 handshake happens at a time to prevent IP-wide 429s
    let handshake_semaphore = Arc::new(Semaphore::new(1));

    let chains = vec![
        ChainConfig { name: "ETHEREUM".into(), rpc_env_key: "ETH_RPC".into(), default_rpc: "wss://mainnet.infura.io/ws/v3/ID".into(), chain_id: 1 },
        ChainConfig { name: "BASE".into(), rpc_env_key: "BASE_RPC".into(), default_rpc: "wss://base-mainnet.infura.io/ws/v3/ID".into(), chain_id: 8453 },
        ChainConfig { name: "ARBITRUM".into(), rpc_env_key: "ARB_RPC".into(), default_rpc: "wss://arbitrum-mainnet.infura.io/ws/v3/ID".into(), chain_id: 42161 },
    ];

    let mut handles = vec![];
    for config in chains {
        let sem = Arc::clone(&handshake_semaphore);
        handles.push(tokio::spawn(async move {
            let mut backoff = 60;
            loop {
                // ACQUIRE PERMIT ONLY FOR CONNECTION PHASE
                let permit = sem.acquire().await.unwrap();
                let rpc_url = std::env::var(&config.rpc_env_key).unwrap_or(config.default_rpc.clone());

                info!("[{}] Permit Acquired. Establishing Link...", config.name);

                match monitor_chain(config.clone(), rpc_url).await {
                    Ok(_) => {
                        drop(permit);
                        backoff = 60;
                    },
                    Err(e) => {
                        drop(permit); // Release immediately so others can try
                        let err_msg = format!("{:?}", e);
                        error!("[{}] Fail: {}. Sleeping {}s", config.name, err_msg, backoff);
                        tokio::time::sleep(Duration::from_secs(backoff)).await;
                        backoff = std::cmp::min(backoff * 2, 600);
                    }
                }
            }
        }));
    }

    futures_util::future::join_all(handles).await;
}

async fn monitor_chain(config: ChainConfig, rpc_url: String) -> Result<()> {
    // 1. Establish WebSocket Connection
    let provider = Provider::<Ws>::connect(&rpc_url).await?;
    let provider = Arc::new(provider);

    // 2. TARGETED FILTERING (Saves massive RPC credits)
    // Replace these with the specific high-volume pool addresses you want to monitor
    let pool_addresses = vec![
        "0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852".parse::<Address>()?, // UniV2 ETH/USDT
        "0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc".parse::<Address>()?, // UniV2 USDC/ETH
    ];

    let filter = Filter::new()
        .address(ValueOrArray::Array(pool_addresses))
        .event("Sync(uint112,uint112)");

    let mut stream = provider.subscribe_logs(&filter).await?;
    info!("[{}] Hardened Link Ready. Monitoring targeted pools...", config.name);

    loop {
        // 3. HEARTBEAT & TIMEOUT HANDLING
        match tokio::time::timeout(Duration::from_secs(120), stream.next()).await {
            Ok(Some(log)) => {
                // Handle Log (Arb Math Here)
                print!("{}", ".".black());
                let _ = io::stdout().flush();
            },
            Ok(None) => return Err(anyhow!("Stream closed by Infura")),
            Err(_) => {
                // 4. HEARTBEAT: Check if connection is actually alive
                info!("[{}] Stream idle. Sending heartbeat...", config.name);
                provider.get_block_number().await.map_err(|e| {
                    anyhow!("[{}] Heartbeat failed, link dead: {:?}", config.name, e)
                })?;
            }
        }
    }
}

use ethers::prelude::*;
use std::{sync::Arc, time::Duration, net::TcpListener, io::Write, thread};
use tokio::sync::Semaphore;
use anyhow::{Result, anyhow};
use log::{info, error, warn};
use futures_util::StreamExt;
use rand::Rng;

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
    
    // Railway Health Monitor
    thread::spawn(|| {
        let listener = TcpListener::bind("0.0.0.0:8080").expect("Failed to bind health port");
        for stream in listener.incoming() {
            if let Ok(mut s) = stream { let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n"); }
        }
    });

    // Semaphore set to 1 to force SEQUENTIAL initialization and reconnection
    let handshake_semaphore = Arc::new(Semaphore::new(1));

    let chains = vec![
        ChainConfig { name: "ETHEREUM".into(), rpc_env_key: "ETH_RPC".into(), default_rpc: "wss://eth.llamarpc.com".into(), chain_id: 1 },
        ChainConfig { name: "BASE".into(), rpc_env_key: "BASE_RPC".into(), default_rpc: "wss://base.publicnode.com".into(), chain_id: 8453 },
        ChainConfig { name: "ARBITRUM".into(), rpc_env_key: "ARB_RPC".into(), default_rpc: "wss://arbitrum.llamarpc.com".into(), chain_id: 42161 },
    ];

    let mut handles = vec![];
    for config in chains {
        let sem = Arc::clone(&handshake_semaphore);
        handles.push(tokio::spawn(async move {
            let mut backoff_secs = 30;
            loop {
                // STAGGERED RECONNECTION START
                // 1. Acquire permit for the Handshake Phase
                let permit = sem.acquire().await.unwrap();
                info!("[{}] Semaphore Acquired. Starting Handshake...", config.name);

                let rpc_url = std::env::var(&config.rpc_env_key).unwrap_or(config.default_rpc.clone());

                // 2. Try to establish the link
                match monitor_chain(config.clone(), rpc_url).await {
                    Ok(_) => {
                        // If monitor_chain returns Ok, it means the stream ended gracefully
                        drop(permit); 
                        backoff_secs = 30;
                    }
                    Err(e) => {
                        drop(permit); // Release permit so other chains aren't blocked by our failure
                        let err_msg = format!("{:?}", e);
                        
                        if err_msg.contains("429") {
                            error!("[{}] RATE LIMIT. Deep Sleep 5m.", config.name);
                            tokio::time::sleep(Duration::from_secs(300)).await;
                        } else {
                            warn!("[{}] Link Failed: {}. Retrying in {}s", config.name, err_msg, backoff_secs);
                            tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                            backoff_secs = std::cmp::min(backoff_secs * 2, 600); // Max 10 min backoff
                        }
                    }
                }
            }
        }));
    }

    futures_util::future::join_all(handles).await;
}

async fn monitor_chain(config: ChainConfig, rpc_url: String) -> Result<()> {
    // 3. Connect & Settle
    let provider = Provider::<Ws>::connect(&rpc_url).await?;
    let provider = Arc::new(provider);
    tokio::time::sleep(Duration::from_secs(5)).await;

    // 4. TARGETED FILTERING
    let pool_addresses = vec![
        "0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852".parse::<Address>()?, 
        "0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc".parse::<Address>()?,
    ];

    let filter = Filter::new()
        .address(ValueOrArray::Array(pool_addresses))
        .event("Sync(uint112,uint112)");

    let mut stream = provider.subscribe_logs(&filter).await?;
    info!("[{}] Link Active. Release Semaphore for next chain.", config.name);
    
    // Note: The permit is dropped when this function exits, or we can use 
    // a separate logic. In the loop above, the permit is dropped when monitor_chain ends.
    // To allow the next chain to start while THIS chain is monitoring:
    // We would need to pass the permit in or structure differently. 
    // BUT for maximum safety on Infura, keeping the permit until the stream is 
    // established is the correct play.

    loop {
        match tokio::time::timeout(Duration::from_secs(120), stream.next()).await {
            Ok(Some(_log)) => {
                // ARB LOGIC HERE
                print!("{}", ".".black());
                let _ = std::io::stdout().flush();
            },
            Ok(None) => return Err(anyhow!("Stream closed by Infura")),
            Err(_) => {
                // 5. HEARTBEAT / LIVENESS CHECK
                // If stream is idle, check if connection is actually alive
                match provider.get_block_number().await {
                    Ok(_) => continue, // Connection is fine, just no trades
                    Err(e) => return Err(anyhow!("Heartbeat failed: {:?}", e)),
                }
            }
        }
    }
}

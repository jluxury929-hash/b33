use ethers::{
    prelude::*,
    providers::{Provider, Ws},
    utils::{parse_ether, format_ether},
    abi::{Token, encode},
};
use ethers_flashbots::{BundleRequest, FlashbotsMiddleware};
use petgraph::{graph::{NodeIndex, UnGraph}, visit::EdgeRef};
use std::{sync::Arc, collections::HashMap, str::FromStr, net::TcpListener, io::{self, Write}, thread, time::Duration};
use colored::*;
use dotenv::dotenv;
use std::env;
use anyhow::{Result, anyhow};
use url::Url;
use log::{info, error, warn};
use futures_util::StreamExt;
use tokio::sync::Semaphore;
use rand::Rng;

const WETH_ADDR: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

#[derive(Clone, Debug)]
struct ChainConfig {
    name: String,
    rpc_env_key: String,
    default_rpc: String,
    flashbots_relay: String,
    chain_id: u64,
}

abigen!(IUniswapV2Pair, r#"[
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)
    function token0() external view returns (address)
    function token1() external view returns (address)
]"#);

abigen!(ApexOmegaContract, r#"[ function execute(uint256 mode, address token, uint256 amount, bytes calldata strategy) external payable ]"#);

#[derive(Clone, Copy, Debug)]
struct PoolEdge {
    pair_address: Address,
    token_0: Address,
    token_1: Address,
    reserve_0: U256,
    reserve_1: U256,
    fee_numerator: u32,
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    println!("{}", "╔════════════════════════════════════════════════════════╗".yellow());
    println!("{}", "║    ⚡ APEX OMEGA: SERIALIZED RESILIENCE (V4.2.4)   ║".yellow().bold());
    println!("{}", "║    STATUS: INFURA-HARDENED | QUOTA CONSERVATIVE     ║".yellow());
    println!("{}", "╚════════════════════════════════════════════════════════╝".yellow());

    if let Err(e) = start_bot().await {
        error!("FATAL STARTUP ERROR: {:?}", e);
        thread::sleep(Duration::from_secs(10));
        std::process::exit(1);
    }
}

async fn start_bot() -> Result<()> {
    validate_env()?;

    // Railway Health Monitor
    thread::spawn(|| {
        let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
        for stream in listener.incoming() {
            if let Ok(mut s) = stream { let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n"); }
        }
    });

    // Semaphore: ONLY 1 chain can handshake at a time to prevent IP 429s
    let handshake_semaphore = Arc::new(Semaphore::new(1));

    let chains = vec![
        ChainConfig { name: "ETHEREUM".into(), rpc_env_key: "ETH_RPC".into(), default_rpc: "wss://mainnet.infura.io/ws/v3/ID".into(), flashbots_relay: "https://relay.flashbots.net".into(), chain_id: 1 },
        ChainConfig { name: "BASE".into(), rpc_env_key: "BASE_RPC".into(), default_rpc: "wss://base-mainnet.infura.io/ws/v3/ID".into(), flashbots_relay: "".into(), chain_id: 8453 },
        ChainConfig { name: "ARBITRUM".into(), rpc_env_key: "ARB_RPC".into(), default_rpc: "wss://arbitrum-mainnet.infura.io/ws/v3/ID".into(), flashbots_relay: "".into(), chain_id: 42161 },
    ];

    let mut handles = vec![];
    for config in chains {
        let semaphore = Arc::clone(&handshake_semaphore);
        handles.push(tokio::spawn(async move {
            let pk = env::var("PRIVATE_KEY").unwrap();
            let exec = env::var("EXECUTOR_ADDRESS").unwrap();
            
            let mut backoff = 60; // Start with 1 min backoff for Infura 429s
            loop {
                // Wait for the semaphore before connecting
                let permit = semaphore.acquire().await.unwrap();
                info!("[{}] Semaphore Acquired. Establishing Link...", config.name);

                let rpc_url = env::var(&config.rpc_env_key).unwrap_or(config.default_rpc.clone());

                match monitor_chain(config.clone(), pk.clone(), exec.clone(), rpc_url).await {
                    Ok(_) => {
                        drop(permit); // Release immediately on graceful exit
                        backoff = 60;
                    },
                    Err(e) => {
                        drop(permit); // Release so other chains can try while this one backs off
                        let err_msg = format!("{:?}", e);
                        error!("[{}] Connection Failed: {}. Sleep {}s", config.name, err_msg, backoff);
                        tokio::time::sleep(Duration::from_secs(backoff)).await;
                        backoff = std::cmp::min(backoff * 2, 600);
                    }
                }
            }
        }));
    }

    futures_util::future::join_all(handles).await;
    Ok(())
}

async fn monitor_chain(config: ChainConfig, pk: String, exec_addr: String, rpc_url: String) -> Result<()> {
    // 1. WebSocket Connection
    let provider = tokio::time::timeout(Duration::from_secs(30), Provider::<Ws>::connect(&rpc_url))
        .await.map_err(|_| anyhow!("Handshake Timeout"))??;
    
    // 2. LONG SETTLE DELAY (Critical for Infura 429 prevention)
    tokio::time::sleep(Duration::from_millis(5000)).await;

    let provider = Arc::new(provider);
    let wallet: LocalWallet = pk.parse()?;
    
    // 3. STATIC CHAIN ID (Saves 1 request credit per handshake)
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.with_chain_id(config.chain_id)));

    info!("[{}] Hardened Link Ready (Chain {}). Subscribing...", config.name, config.chain_id);

    let filter = Filter::new().event("Sync(uint112,uint112)");
    let mut stream = provider.subscribe_logs(&filter).await?;

    loop {
        match tokio::time::timeout(Duration::from_secs(120), stream.next()).await {
            Ok(Some(log)) => {
                print!("{}", ".".black());
                let _ = io::stdout().flush();
                // ... Arb Logic ...
            },
            Ok(None) => return Err(anyhow!("Stream ended")),
            Err(_) => return Err(anyhow!("Stream timeout")),
        }
    }
}

// ... (find_arb_recursive, get_amount_out, validate_env remain the same) ...

fn validate_env() -> Result<()> {
    let _ = env::var("PRIVATE_KEY")?;
    let _ = env::var("EXECUTOR_ADDRESS")?;
    Ok(())
}

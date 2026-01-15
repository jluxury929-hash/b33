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
    println!("{}", "║    ⚡ APEX OMEGA: PAID-TIER OPTIMIZED (V4.2.7)      ║".yellow().bold());
    println!("{}", "║    STATUS: HIGH-THROUGHPUT | MULTI-KEY READY        ║".yellow());
    println!("{}", "╚════════════════════════════════════════════════════════╝".yellow());

    if let Err(e) = start_bot().await {
        error!("FATAL STARTUP ERROR: {:?}", e);
        thread::sleep(Duration::from_secs(5));
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

    // Semaphore: Set to 3 for Paid Plans (Allows all chains to connect simultaneously)
    let handshake_semaphore = Arc::new(Semaphore::new(3));

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
            
            loop {
                let permit = semaphore.acquire().await.unwrap();
                let rpc_url = env::var(&config.rpc_env_key).unwrap_or(config.default_rpc.clone());

                match monitor_chain(config.clone(), pk.clone(), exec.clone(), rpc_url).await {
                    Ok(_) => { drop(permit); tokio::time::sleep(Duration::from_secs(5)).await; },
                    Err(e) => {
                        drop(permit);
                        error!("[{}] Fail: {:?}. Rotating/Retrying...", config.name, e);
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                }
            }
        }));
    }

    futures_util::future::join_all(handles).await;
    Ok(())
}

async fn monitor_chain(config: ChainConfig, pk: String, exec_addr: String, rpc_url: String) -> Result<()> {
    // 1. WebSocket Handshake (Paid tier is faster)
    let provider = tokio::time::timeout(Duration::from_secs(15), Provider::<Ws>::connect(&rpc_url))
        .await.map_err(|_| anyhow!("Handshake Timeout"))??;
    
    // 2. Micro-Settle Delay (1s instead of 5s)
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let provider = Arc::new(provider);
    let wallet: LocalWallet = pk.parse()?;
    
    // 3. Static Chain ID to save credits
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.with_chain_id(config.chain_id)));

    info!("[{}] Link Live. High-Throughput Mode Active.", config.name);

    let filter = Filter::new().event("Sync(uint112,uint112)");
    let mut stream = provider.subscribe_logs(&filter).await?;

    loop {
        match tokio::time::timeout(Duration::from_secs(60), stream.next()).await {
            Ok(Some(log)) => {
                print!("{}", ".".black());
                let _ = io::stdout().flush();
                
                // MEV MATH GOES HERE
                
                // 4. MICRO-THROTTLE: Prevents 429 during high-volume spikes
                // 10ms delay is enough to keep Infura happy without losing competitive edge
                tokio::time::sleep(Duration::from_millis(10)).await;
            },
            Ok(None) => return Err(anyhow!("Stream end")),
            Err(_) => return Err(anyhow!("Timeout")),
        }
    }
}

fn validate_env() -> Result<()> {
    let _ = env::var("PRIVATE_KEY")?;
    let _ = env::var("EXECUTOR_ADDRESS")?;
    Ok(())
}

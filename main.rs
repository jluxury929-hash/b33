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
use rand::Rng; // Add 'rand = "0.8"' to Cargo.toml

#[derive(Clone, Debug)]
struct ChainConfig {
    name: String,
    rpc_env_key: String,
    default_rpc: String,
    flashbots_relay: String,
}

abigen!(IUniswapV2Pair, r#"[
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)
    function token0() external view returns (address)
    function token1() external view returns (address)
]"#);

abigen!(ApexOmega, r#"[ function execute(uint256 mode, address token, uint256 amount, bytes calldata strategy) external payable ]"#);

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
    println!("{}", "║    ⚡ APEX OMEGA: FINAL BATTLE EDITION (QUAD)       ║".yellow());
    println!("{}", "║    STATUS: STAGGERED START | JITTER RECONNECT ACTIVE   ║".yellow());
    println!("{}", "╚════════════════════════════════════════════════════════╝".yellow());
    let _ = io::stdout().flush();

    if let Err(e) = start_bot().await {
        error!("FATAL STARTUP ERROR: {:?}", e);
        thread::sleep(Duration::from_secs(10));
        std::process::exit(1);
    }
}

async fn start_bot() -> Result<()> {
    validate_env()?;

    thread::spawn(|| {
        let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
        for stream in listener.incoming() {
            if let Ok(mut s) = stream { let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n"); }
        }
    });

    let chains = vec![
        ChainConfig { name: "ETHEREUM".into(), rpc_env_key: "ETH_RPC".into(), default_rpc: "wss://mainnet.infura.io/ws/v3/e601dc0b8ff943619576956539dd3b82".into(), flashbots_relay: "https://relay.flashbots.net".into() },
        ChainConfig { name: "BASE".into(), rpc_env_key: "BASE_RPC".into(), default_rpc: "wss://base-mainnet.infura.io/ws/v3/e601dc0b8ff943619576956539dd3b82".into(), flashbots_relay: "".into() },
        ChainConfig { name: "ARBITRUM".into(), rpc_env_key: "ARB_RPC".into(), default_rpc: "wss://arbitrum-mainnet.infura.io/ws/v3/d266e88fdc0b4626bfa0d22f8fcf04d6".into(), flashbots_relay: "".into() },
    ];

    let mut handles = vec![];
    for config in chains {
        let pk = env::var("PRIVATE_KEY")?;
        let exec = env::var("EXECUTOR_ADDRESS")?;
        
        handles.push(tokio::spawn(async move {
            let mut backoff_secs = 5;
            loop {
                // STAGGERED START: Each chain waits a random offset to prevent thundering herd
                let jitter = rand::thread_rng().gen_range(500..3000);
                tokio::time::sleep(Duration::from_millis(jitter)).await;

                let mut url = env::var(&config.rpc_env_key).unwrap_or(config.default_rpc.clone());
                if url.contains("infura.io") && !url.contains("/ws/") { url = url.replace(".io/v3/", ".io/ws/v3/"); }

                match monitor_chain(config.clone(), pk.clone(), exec.clone(), url).await {
                    Ok(_) => {
                        info!("[{}] Stream ended cleanly. Reconnecting...", config.name);
                        backoff_secs = 5;
                    },
                    Err(e) => {
                        error!("[{}] CRITICAL FAILURE: {:?}. Backing off for {}s", config.name, e, backoff_secs);
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                        // Exponential backoff with a cap of 2 minutes
                        backoff_secs = std::cmp::min(backoff_secs * 2, 120);
                    }
                }
            }
        }));
    }

    futures::future::join_all(handles).await;
    Ok(())
}

async fn monitor_chain(config: ChainConfig, pk: String, exec_addr: String, rpc_url: String) -> Result<()> {
    info!("[{}] Attempting connection...", config.name);
    
    // Handshake Timeout: Don't hang forever if the RPC is lagging
    let provider = tokio::time::timeout(
        Duration::from_secs(10), 
        Provider::<Ws>::connect(&rpc_url)
    ).await.map_err(|_| anyhow!("Connection handshake timed out"))??;
    
    let provider = Arc::new(provider);
    let wallet: LocalWallet = pk.parse()?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.with_chain_id(chain_id)));

    let fb_client = if !config.flashbots_relay.is_empty() {
        let fb_signer: LocalWallet = "0000000000000000000000000000000000000000000000000000000000000001".parse()?;
        Some(Arc::new(FlashbotsMiddleware::new(client.clone(), Url::parse(&config.flashbots_relay)?, fb_signer)))
    } else { None };

    let executor = ApexOmega::new(exec_addr.parse::<Address>()?, client.clone());
    let mut pair_map: HashMap<Address, petgraph::graph::EdgeIndex> = HashMap::new();
    let mut graph = UnGraph::<Address, PoolEdge>::new_undirected();
    let mut node_map: HashMap<Address, NodeIndex> = HashMap::new();

    // Initial Load Logic
    let pool_addr = Address::from_str("0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc")?;
    let pair = IUniswapV2Pair::new(pool_addr, provider.clone());
    if let Ok((r0, r1, _)) = pair.get_reserves().call().await {
        let t0 = pair.token_0().call().await?;
        let t1 = pair.token_1().call().await?;
        let n0 = *node_map.entry(t0).or_insert_with(|| graph.add_node(t0));
        let n1 = *node_map.entry(t1).or_insert_with(|| graph.add_node(t1));
        let idx = graph.add_edge(n0, n1, PoolEdge { pair_address: pool_addr, token_0: t0, token_1: t1, reserve_0: r0.into(), reserve_1: r1.into(), fee_numerator: 997 });
        pair_map.insert(pool_addr, idx);
    }

    info!("[{}] Chain ID {} Verified. Live.", config.name, chain_id);
    let filter = Filter::new().event("Sync(uint112,uint112)");
    let mut stream = provider.subscribe_logs(&filter).await?;

    while let Some(log) = stream.next().await {
        // [Logic for arbitrage search...]
        // Keep this loop as lightweight as possible to avoid 429s on read calls
    }
    
    Ok(())
}

fn validate_env() -> Result<()> {
    let _ = env::var("PRIVATE_KEY")?;
    let _ = env::var("EXECUTOR_ADDRESS")?;
    Ok(())
}

// ... [Include find_arb_recursive, get_amount_out, and build_strategy functions here] ...

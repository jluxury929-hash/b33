use ethers::{
    prelude::*,
    providers::{Provider, Ws},
    utils::{parse_ether, format_ether},
    abi::{Token, encode},
};
use ethers_flashbots::{BundleRequest, FlashbotsMiddleware};
use petgraph::{graph::{NodeIndex, UnGraph}, visit::EdgeRef, Direction};
use std::{sync::Arc, collections::HashMap, str::FromStr, net::TcpListener, io::{self, Write}, thread, time::Duration};
use colored::*;
use dotenv::dotenv;
use std::env;
use anyhow::{Result, anyhow};
use url::Url;
use log::{info, error, warn};
use futures_util::StreamExt;
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
    println!("{}", "║    ⚡ APEX OMEGA: DISTRIBUTED RESILIENCE (V4.2.3)   ║".yellow().bold());
    println!("{}", "║    STATUS: ASYNC HANDSHAKE | GRAPH-ARBITRAGE LIVE   ║".yellow());
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

    let chains = vec![
        ChainConfig { name: "ETHEREUM".into(), rpc_env_key: "ETH_RPC".into(), default_rpc: "wss://eth.llamarpc.com".into(), flashbots_relay: "https://relay.flashbots.net".into(), chain_id: 1 },
        ChainConfig { name: "BASE".into(), rpc_env_key: "BASE_RPC".into(), default_rpc: "wss://base.publicnode.com".into(), flashbots_relay: "".into(), chain_id: 8453 },
        ChainConfig { name: "ARBITRUM".into(), rpc_env_key: "ARB_RPC".into(), default_rpc: "wss://arbitrum.llamarpc.com".into(), flashbots_relay: "".into(), chain_id: 42161 },
    ];

    let mut handles = vec![];
    for config in chains {
        handles.push(tokio::spawn(async move {
            let pk = env::var("PRIVATE_KEY").unwrap();
            let exec = env::var("EXECUTOR_ADDRESS").unwrap();
            
            let mut backoff = 10;
            loop {
                // Per-chain Jitter (No global lock)
                let jitter = rand::thread_rng().gen_range(3000..9000);
                tokio::time::sleep(Duration::from_millis(jitter)).await;

                let rpc_url = env::var(&config.rpc_env_key).unwrap_or(config.default_rpc.clone());

                match monitor_chain(config.clone(), pk.clone(), exec.clone(), rpc_url).await {
                    Ok(_) => backoff = 10,
                    Err(e) => {
                        error!("[{}] Error: {:?}. Reconnecting in {}s", config.name, e, backoff);
                        tokio::time::sleep(Duration::from_secs(backoff)).await;
                        backoff = std::cmp::min(backoff * 2, 300);
                    }
                }
            }
        }));
    }

    futures_util::future::join_all(handles).await;
    Ok(())
}

async fn monitor_chain(config: ChainConfig, pk: String, exec_addr: String, rpc_url: String) -> Result<()> {
    info!("[{}] Establishing Hardened Link...", config.name);
    
    // Hardened WebSocket Handshake
    let provider = tokio::time::timeout(Duration::from_secs(30), Provider::<Ws>::connect(&rpc_url))
        .await.map_err(|_| anyhow!("Handshake Timeout"))??;
    
    // Static Settle Delay
    tokio::time::sleep(Duration::from_millis(2000)).await;

    let provider = Arc::new(provider);
    let wallet: LocalWallet = pk.parse()?;
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.with_chain_id(config.chain_id)));

    let fb_client = if !config.flashbots_relay.is_empty() {
        let fb_signer: LocalWallet = "0000000000000000000000000000000000000000000000000000000000000001".parse()?;
        Some(Arc::new(FlashbotsMiddleware::new(client.clone(), Url::parse(&config.flashbots_relay)?, fb_signer)))
    } else { None };

    let executor = ApexOmegaContract::new(exec_addr.parse::<Address>()?, client.clone());
    let mut pair_map: HashMap<Address, petgraph::graph::EdgeIndex> = HashMap::new();
    let mut graph = UnGraph::<Address, PoolEdge>::new_undirected();
    let mut node_map: HashMap<Address, NodeIndex> = HashMap::new();

    // Init Logic Pulse
    info!("[{}] Chain {} Live. Initializing Graph...", config.name, config.chain_id);

    let filter = Filter::new().event("Sync(uint112,uint112)");
    let mut stream = provider.subscribe_logs(&filter).await?;

    loop {
        match tokio::time::timeout(Duration::from_secs(90), stream.next()).await {
            Ok(Some(log)) => {
                // Heartbeat Pulse
                print!("{}", ".".black());
                let _ = io::stdout().flush();

                // Reserve Update Logic
                if let Some(edge_idx) = pair_map.get(&log.address) {
                    if let Some(edge) = graph.edge_weight_mut(*edge_idx) {
                        if log.data.len() >= 64 {
                            edge.reserve_0 = U256::from_big_endian(&log.data[0..32]);
                            edge.reserve_1 = U256::from_big_endian(&log.data[32..64]);
                        }
                    }
                    
                    // Recursive Search for WETH profit
                    let weth = Address::from_str(if config.chain_id == 137 { "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270" } else { WETH_ADDR })?;
                    if let Some(start_node) = node_map.get(&weth) {
                        if let Some((profit, route)) = find_arb_recursive(&graph, *start_node, *start_node, parse_ether("1.0")?, 4, vec![]) {
                            if profit > parse_ether("0.005")? {
                                info!("[{}] 💰 PROFIT FOUND: {} ETH", config.name, format_ether(profit));
                                // Strike logic here...
                            }
                        }
                    }
                }
            },
            Ok(None) => return Err(anyhow!("Stream disconnect")),
            Err(_) => return Err(anyhow!("Stream timeout")),
        }
    }
}

// --- UTILS & MATH ---
fn get_amount_out(amt_in: U256, edge: &PoolEdge, curr: NodeIndex, graph: &UnGraph<Address, PoolEdge>) -> U256 {
    let addr = graph.node_weight(curr).unwrap();
    let (r_in, r_out) = if *addr == edge.token_0 { (edge.reserve_0, edge.reserve_1) } else { (edge.reserve_1, edge.reserve_0) };
    if r_in.is_zero() || r_out.is_zero() { return U256::zero(); }
    let amt_fee = amt_in * edge.fee_numerator;
    (amt_fee * r_out) / ((r_in * 1000) + amt_fee)
}

fn find_arb_recursive(graph: &UnGraph<Address, PoolEdge>, curr: NodeIndex, start: NodeIndex, amt: U256, depth: u8, path: Vec<(Address, Address)>) -> Option<(U256, Vec<(Address, Address)>)> {
    if curr == start && path.len() > 1 {
        let initial = parse_ether("1.0").unwrap();
        return if amt > initial { Some((amt - initial, path)) } else { None };
    }
    if depth == 0 { return None; }
    for edge in graph.edges(curr) {
        let next = edge.target();
        let out = get_amount_out(amt, edge.weight(), curr, graph);
        if out.is_zero() { continue; }
        let mut next_path = path.clone();
        next_path.push((*graph.node_weight(curr).unwrap(), *graph.node_weight(next).unwrap()));
        if let Some(res) = find_arb_recursive(graph, next, start, out, depth - 1, next_path) { return Some(res); }
    }
    None
}

fn validate_env() -> Result<()> {
    let _ = env::var("PRIVATE_KEY")?;
    let _ = env::var("EXECUTOR_ADDRESS")?;
    Ok(())
}

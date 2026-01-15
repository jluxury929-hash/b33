use ethers::prelude::*;
use std::{sync::Arc, time::Duration, net::TcpListener, io::{self, Write}, thread, collections::HashMap};
use tokio::sync::Semaphore;
use anyhow::{Result, anyhow};
use log::{info, error, warn};
use futures_util::StreamExt;
use colored::Colorize;
use petgraph::{graph::{NodeIndex, UnGraph}, visit::EdgeRef};

// --- CONSTANTS ---
const WETH_ADDR: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

// --- CONTRACT ABIS ---
abigen!(IUniswapV2Pair, r#"[
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)
    function token0() external view returns (address)
    function token1() external view returns (address)
]"#);

abigen!(ApexOmega, r#"[ function execute(uint256 mode, address token, uint256 amount, bytes calldata strategy) external payable ]"#);

#[derive(Clone, Debug)]
struct ChainConfig {
    name: String,
    rpc_env_key: String,
    default_rpc: String,
    chain_id: u64,
}

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
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    println!("{}", "╔════════════════════════════════════════════════════════╗".yellow());
    println!("{}", "║    ⚡ APEX OMEGA: FULL SINGULARITY (V4.2.9)        ║".yellow().bold());
    println!("{}", "║    STATUS: RECURSIVE ENGINE | HARDENED FAILOVER     ║".yellow());
    println!("{}", "╚════════════════════════════════════════════════════════╝".yellow());

    // Railway Health Monitor
    thread::spawn(|| {
        let listener = TcpListener::bind("0.0.0.0:8080").expect("Failed to bind health port");
        for stream in listener.incoming() {
            if let Ok(mut s) = stream { let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n"); }
        }
    });

    let semaphore = Arc::new(Semaphore::new(1));

    let chains = vec![
        ChainConfig { name: "ETHEREUM".into(), rpc_env_key: "ETH_RPC".into(), default_rpc: "wss://mainnet.infura.io/ws/v3/ID".into(), chain_id: 1 },
        ChainConfig { name: "BASE".into(), rpc_env_key: "BASE_RPC".into(), default_rpc: "wss://base-mainnet.infura.io/ws/v3/ID".into(), chain_id: 8453 },
        ChainConfig { name: "ARBITRUM".into(), rpc_env_key: "ARB_RPC".into(), default_rpc: "wss://arbitrum-mainnet.infura.io/ws/v3/ID".into(), chain_id: 42161 },
    ];

    let mut handles = vec![];
    for config in chains {
        let sem = Arc::clone(&semaphore);
        handles.push(tokio::spawn(async move {
            let mut backoff = 60;
            loop {
                let permit = sem.acquire().await.unwrap();
                let rpc_url = std::env::var(&config.rpc_env_key).unwrap_or(config.default_rpc.clone());

                match monitor_chain(config.clone(), rpc_url).await {
                    Ok(_) => { drop(permit); backoff = 60; },
                    Err(e) => {
                        drop(permit);
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
    Ok(())
}

async fn monitor_chain(config: ChainConfig, rpc_url: String) -> Result<()> {
    let provider = Provider::<Ws>::connect(&rpc_url).await?;
    let provider = Arc::new(provider);
    tokio::time::sleep(Duration::from_secs(10)).await;

    // TARGETED FILTER: Only high-volume pairs to save Infura Credits
    let pool_addresses = vec![
        "0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852".parse::<Address>()?, // UniV2 ETH/USDT
        "0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc".parse::<Address>()?, // UniV2 USDC/ETH
    ];

    let filter = Filter::new()
        .address(ValueOrArray::Array(pool_addresses.clone()))
        .event("Sync(uint112,uint112)");

    let mut graph = UnGraph::<Address, PoolEdge>::new_undirected();
    let mut node_map: HashMap<Address, NodeIndex> = HashMap::new();
    let mut pair_map: HashMap<Address, petgraph::graph::EdgeIndex> = HashMap::new();

    // Initial Sync for the targeted pools
    for addr in &pool_addresses {
        let pair = IUniswapV2Pair::new(*addr, provider.clone());
        if let Ok((r0, r1, _)) = pair.get_reserves().call().await {
            let t0 = pair.token_0().call().await?;
            let t1 = pair.token_1().call().await?;
            let n0 = *node_map.entry(t0).or_insert_with(|| graph.add_node(t0));
            let n1 = *node_map.entry(t1).or_insert_with(|| graph.add_node(t1));
            let idx = graph.add_edge(n0, n1, PoolEdge { pair_address: *addr, token_0: t0, token_1: t1, reserve_0: r0.into(), reserve_1: r1.into(), fee_numerator: 997 });
            pair_map.insert(*addr, idx);
        }
    }

    let mut stream = provider.subscribe_logs(&filter).await?;
    info!("[{}] Link Active. Release Permit.", config.name);

    loop {
        match tokio::time::timeout(Duration::from_secs(120), stream.next()).await {
            Ok(Some(log)) => {
                if let Some(edge_idx) = pair_map.get(&log.address) {
                    if let Some(edge) = graph.edge_weight_mut(*edge_idx) {
                        if log.data.len() >= 64 {
                            edge.reserve_0 = U256::from_big_endian(&log.data[0..32]);
                            edge.reserve_1 = U256::from_big_endian(&log.data[32..64]);
                        }
                    }
                    // Run recursive search from WETH
                    let weth = Address::from_str(WETH_ADDR)?;
                    if let Some(start) = node_map.get(&weth) {
                        if let Some((profit, _path)) = find_arb_recursive(&graph, *start, *start, parse_ether("1.0")?, 4, vec![]) {
                            if profit > parse_ether("0.005")? {
                                info!("[{}] 💎 Opportunity Found: {} ETH", config.name, format_ether(profit));
                                // strike logic here...
                            }
                        }
                    }
                }
                print!("{}", ".".black());
                let _ = io::stdout().flush();
            },
            Ok(None) => return Err(anyhow!("Stream end")),
            Err(_) => {
                provider.get_block_number().await.map_err(|e| anyhow!("Link dead: {:?}", e))?;
            }
        }
    }
}

// --- MATH ENGINE ---
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

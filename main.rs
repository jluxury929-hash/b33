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
use rand::Rng;

#[derive(Clone, Debug)]
struct ChainConfig {
    name: String,
    rpc_env_key: String,
    default_rpc: String,
    flashbots_relay: String,
    stagger_delay: u64, // Staggered start to prevent 429s
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
    println!("{}", "║    ⚡ APEX OMEGA: FINAL SINGULARITY (V4.1)          ║".yellow());
    println!("{}", "║    STATUS: ANTI-BAN JITTER ACTIVE | QUAD-CORE       ║".yellow());
    println!("{}", "╚════════════════════════════════════════════════════════╝".yellow());
    let _ = io::stdout().flush();

    if let Err(e) = start_bot().await {
        error!("FATAL STARTUP ERROR: {:?}", e);
        thread::sleep(Duration::from_secs(60));
        std::process::exit(1);
    }
}

async fn start_bot() -> Result<()> {
    validate_env()?;

    // Port 8080 Guard for Railway
    thread::spawn(|| {
        let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
        for stream in listener.incoming() {
            if let Ok(mut s) = stream { let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n"); }
        }
    });

    let chains = vec![
        ChainConfig { name: "ETHEREUM".into(), rpc_env_key: "ETH_RPC".into(), default_rpc: "wss://mainnet.infura.io/ws/v3/PROJECT_ID".into(), flashbots_relay: "https://relay.flashbots.net".into(), stagger_delay: 0 },
        ChainConfig { name: "BASE".into(), rpc_env_key: "BASE_RPC".into(), default_rpc: "wss://base-mainnet.infura.io/ws/v3/PROJECT_ID".into(), flashbots_relay: "".into(), stagger_delay: 20 },
        ChainConfig { name: "ARBITRUM".into(), rpc_env_key: "ARB_RPC".into(), default_rpc: "wss://arbitrum-mainnet.infura.io/ws/v3/PROJECT_ID".into(), flashbots_relay: "".into(), stagger_delay: 40 },
    ];

    let mut handles = vec![];
    for config in chains {
        let pk = env::var("PRIVATE_KEY")?;
        let exec = env::var("EXECUTOR_ADDRESS")?;
        handles.push(tokio::spawn(async move {
            if config.stagger_delay > 0 {
                tokio::time::sleep(Duration::from_secs(config.stagger_delay)).await;
            }
            let mut backoff = 10;
            loop {
                let mut url = env::var(&config.rpc_env_key).unwrap_or(config.default_rpc.clone());
                if url.contains("infura.io") && !url.contains("/ws/") { url = url.replace(".io/v3/", ".io/ws/v3/"); }

                match monitor_chain(config.clone(), pk.clone(), exec.clone(), url).await {
                    Ok(_) => backoff = 10,
                    Err(e) => {
                        let err_msg = format!("{:?}", e);
                        if err_msg.contains("429") || err_msg.contains("-32005") {
                            error!("[{}] BANNED BY INFURA. Entering deep sleep (5m) to clear IP.", config.name);
                            tokio::time::sleep(Duration::from_secs(300)).await;
                        } else {
                            error!("[{}] Error: {}. Backoff {}s", config.name, err_msg, backoff);
                            tokio::time::sleep(Duration::from_secs(backoff)).await;
                            backoff = std::cmp::min(backoff * 2, 60);
                        }
                    }
                }
            }
        }));
    }

    futures::future::join_all(handles).await;
    Ok(())
}

async fn monitor_chain(config: ChainConfig, pk: String, exec_addr: String, rpc_url: String) -> Result<()> {
    info!("[{}] Handshaking...", config.name);
    let provider = Arc::new(Provider::<Ws>::connect(&rpc_url).await?);
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

    // Initial Sync
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

    info!("[{}] Chain {} Live. Hunting...", config.name, chain_id);
    let filter = Filter::new().event("Sync(uint112,uint112)");
    let mut stream = provider.subscribe_logs(&filter).await?;

    while let Some(log) = stream.next().await {
        if let Some(edge_idx) = pair_map.get(&log.address) {
            if let Some(edge) = graph.edge_weight_mut(*edge_idx) {
                if log.data.len() >= 64 {
                    edge.reserve_0 = U256::from_big_endian(&log.data[0..32]);
                    edge.reserve_1 = U256::from_big_endian(&log.data[32..64]);
                }
            }

            let weth = Address::from_str(if chain_id == 137 { "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270" } else { "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" })?;
            if let Some(start) = node_map.get(&weth) {
                if let Some((profit, route)) = find_arb_recursive(&graph, *start, *start, parse_ether("1.0")?, 4, vec![]) {
                    if profit > parse_ether("0.01")? {
                        info!("[{}] 💎 OPPORTUNITY FOUND: {} ETH", config.name, format_ether(profit));
                        let bribe = profit * 90 / 100;
                        let strategy = build_strategy(route, parse_ether("1.0")?, bribe, executor.address(), &graph)?;
                        let mut tx = executor.execute(U256::zero(), weth, parse_ether("1.0")?, strategy).tx;
                        let _ = client.fill_transaction(&mut tx, None).await;

                        if let Ok(sig) = client.signer().sign_transaction(&tx).await {
                            let rlp = tx.rlp_signed(&sig);
                            if let Some(fb) = fb_client.as_ref() {
                                let block = provider.get_block_number().await.unwrap_or_default();
                                let bundle = BundleRequest::new().push_transaction(rlp).set_block(block + 1);
                                let fb_cl = fb.clone();
                                tokio::spawn(async move { let _ = fb_cl.send_bundle(&bundle).await; });
                            } else {
                                let http_url = rpc_url.replace("wss://", "https://").replace("ws://", "http://");
                                saturation_strike(&http_url, rlp).await;
                            }
                        }
                    }
                }
            }
        }
    }
    Err(anyhow!("Stream disconnect"))
}

async fn saturation_strike(rpc_url: &str, signed_rlp: Bytes) {
    let client_http = reqwest::Client::new();
    let rpc = rpc_url.to_string();
    let raw_tx_hex = format!("0x{}", hex::encode(&signed_rlp));
    tokio::spawn(async move {
        let body = serde_json::json!({"jsonrpc": "2.0", "method": "eth_sendRawTransaction", "params": [raw_tx_hex], "id": 1});
        let _ = client_http.post(rpc).json(&body).send().await;
    });
}

fn validate_env() -> Result<()> {
    let _ = env::var("PRIVATE_KEY")?;
    let _ = env::var("EXECUTOR_ADDRESS")?;
    Ok(())
}

fn find_arb_recursive(graph: &UnGraph<Address, PoolEdge>, curr: NodeIndex, start: NodeIndex, amt: U256, depth: u8, path: Vec<(Address, Address)>) -> Option<(U256, Vec<(Address, Address)>)> {
    if curr == start && path.len() > 1 {
        let initial = parse_ether("1.0").unwrap();
        return if amt > initial { Some((amt - initial, path)) } else { None };
    }
    if depth == 0 { return None; }
    for edge in graph.edges(curr) {
        let next = edge.target();
        if path.iter().any(|(a, _)| *a == *graph.node_weight(next).unwrap()) && next != start { continue; }
        let out = get_amount_out(amt, edge.weight(), curr, graph);
        if out.is_zero() { continue; }
        let mut next_path = path.clone();
        next_path.push((*graph.node_weight(curr).unwrap(), *graph.node_weight(next).unwrap()));
        if let Some(res) = find_arb_recursive(graph, next, start, out, depth - 1, next_path) { return Some(res); }
    }
    None
}

fn get_amount_out(amt_in: U256, edge: &PoolEdge, curr: NodeIndex, graph: &UnGraph<Address, PoolEdge>) -> U256 {
    let addr = graph.node_weight(curr).unwrap();
    let (r_in, r_out) = if *addr == edge.token_0 { (edge.reserve_0, edge.reserve_1) } else { (edge.reserve_1, edge.reserve_0) };
    if r_in.is_zero() || r_out.is_zero() { return U256::zero(); }
    let amt_fee = amt_in * edge.fee_numerator;
    (amt_fee * r_out) / ((r_in * 1000) + amt_fee)
}

fn build_strategy(route: Vec<(Address, Address)>, init_amt: U256, bribe: U256, contract: Address, graph: &UnGraph<Address, PoolEdge>) -> Result<Bytes> {
    let mut targets = Vec::new();
    let mut payloads = Vec::new();
    let mut curr_in = init_amt;
    for (i, (tin, tout)) in route.iter().enumerate() {
        let nin = graph.node_indices().find(|n| *graph.node_weight(*n).unwrap() == *tin).unwrap();
        let nout = graph.node_indices().find(|n| *graph.node_weight(*n).unwrap() == *tout).unwrap();
        let edge = &graph[graph.find_edge(nin, nout).unwrap()];
        if i == 0 {
            targets.push(*tin);
            let d = ethers::abi::encode(&[Token::Address(edge.pair_address), Token::Uint(init_amt)]);
            let mut data = vec![0xa9, 0x05, 0x9c, 0xbb]; data.extend(d);
            payloads.push(Bytes::from(data));
        }
        let out = get_amount_out(curr_in, edge, nin, graph);
        let (a0, a1) = if *tin == edge.token_0 { (U256::zero(), out) } else { (out, U256::zero()) };
        let to = if i == route.len() - 1 { contract } else {
            let next_node_out = graph.node_indices().find(|n| *graph.node_weight(*n).unwrap() == route[i+1].1).unwrap();
            graph[graph.find_edge(nout, next_node_out).unwrap()].pair_address
        };
        targets.push(edge.pair_address);
        let d = ethers::abi::encode(&[Token::Uint(a0), Token::Uint(a1), Token::Address(to), Token::Bytes(vec![])]);
        let mut data = vec![0x02, 0x2c, 0x0d, 0x9f]; data.extend(d);
        payloads.push(Bytes::from(data));
        curr_in = out;
    }
    Ok(Bytes::from(encode(&[
        Token::Array(targets.into_iter().map(Token::Address).collect()),
        Token::Array(payloads.into_iter().map(|b| Token::Bytes(b.to_vec())).collect()),
        Token::Uint(bribe),
    ])))
}

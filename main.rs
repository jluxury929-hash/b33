use ethers::{
    prelude::*,
    providers::{Provider, Ws, Http},
    utils::{parse_ether, format_ether},
    abi::{Token, encode},
};
use ethers_flashbots::{BundleRequest, FlashbotsMiddleware};
use petgraph::{graph::{NodeIndex, UnGraph}, visit::EdgeRef};
use std::{sync::Arc, collections::HashMap, str::FromStr, net::TcpListener, io::{self, Write}, thread};
use colored::*;
use dotenv::dotenv;
use std::env;
use anyhow::{Result, anyhow};
use url::Url;
use log::{info, error};

#[derive(Clone, Debug)]
struct ChainConfig {
    name: String,
    rpc_env_key: String,
    default_rpc: String,
    flashbots_relay: String,
}

abigen!(
    IUniswapV2Pair,
    r#"[
        function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)
        function token0() external view returns (address)
        function token1() external view returns (address)
    ]"#
);

abigen!(
    ApexOmega,
    r#"[ function execute(uint256 mode, address token, uint256 amount, bytes calldata strategy) external payable ]"#
);

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
    println!("{}", "║    ⚡ APEX OMEGA: QUAD-NETWORK SINGULARITY           ║".yellow());
    println!("{}", "║    STATUS: STARTING ENGINES...                         ║".yellow());
    println!("{}", "╚════════════════════════════════════════════════════════╝".yellow());
    let _ = io::stdout().flush();

    if let Err(e) = start_bot().await {
        error!("FATAL STARTUP ERROR: {:?}", e);
        thread::sleep(std::time::Duration::from_secs(5));
        std::process::exit(1);
    }
}

async fn start_bot() -> Result<()> {
    validate_env()?;

    // Health Monitor for Railway
    thread::spawn(|| {
        let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
            }
        }
    });

    let chains = vec![
        ChainConfig { name: "ETHEREUM".into(), rpc_env_key: "ETH_RPC".into(), default_rpc: "wss://mainnet.infura.io/ws/v3/YOUR_KEY".into(), flashbots_relay: "https://relay.flashbots.net".into() },
        ChainConfig { name: "BASE".into(), rpc_env_key: "BASE_RPC".into(), default_rpc: "wss://base-mainnet.infura.io/ws/v3/YOUR_KEY".into(), flashbots_relay: "".into() },
    ];

    let mut handles = vec![];
    for config in chains {
        let pk = env::var("PRIVATE_KEY")?;
        let exec = env::var("EXECUTOR_ADDRESS")?;
        handles.push(tokio::spawn(async move {
            if let Err(e) = monitor_chain(config.clone(), pk, exec).await {
                error!("[{}] Chain Died: {:?}", config.name, e);
            }
        }));
    }

    futures::future::join_all(handles).await;
    Ok(())
}

async fn monitor_chain(config: ChainConfig, pk: String, exec_addr: String) -> Result<()> {
    let rpc_url = env::var(&config.rpc_env_key).unwrap_or(config.default_rpc);
    info!("[{}] Connecting to {}...", config.name, rpc_url);
    
    // FIX: Hybrid Connection Handler (Detects WSS vs HTTPS automatically)
    let provider = if rpc_url.starts_with("wss://") || rpc_url.starts_with("ws://") {
        Provider::<Ws>::connect(&rpc_url).await?
    } else {
        Provider::<Http>::try_from(&rpc_url)?
    };

    let provider = Arc::new(provider);
    let wallet: LocalWallet = pk.parse()?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.clone().with_chain_id(chain_id)));

    let fb_client = if !config.flashbots_relay.is_empty() {
        Some(Arc::new(FlashbotsMiddleware::new(client.clone(), Url::parse(&config.flashbots_relay)?, wallet.clone())))
    } else { None };

    let executor = ApexOmega::new(exec_addr.parse::<Address>()?, client.clone());
    let mut graph = UnGraph::<Address, PoolEdge>::new_undirected();
    let mut node_map: HashMap<Address, NodeIndex> = HashMap::new();
    let mut pair_map: HashMap<Address, petgraph::graph::EdgeIndex> = HashMap::new();

    info!("[{}] Armed. Subscribing to Logs...", config.name);
    let filter = Filter::new().event("Sync(uint112,uint112)");
    let mut stream = provider.subscribe_logs(&filter).await?;

    while let Some(log) = stream.next().await {
        if let Some(idx) = pair_map.get(&log.address) {
            if let Some(edge) = graph.edge_weight_mut(*idx) {
                edge.reserve_0 = U256::from_big_endian(&log.data[0..32]);
                edge.reserve_1 = U256::from_big_endian(&log.data[32..64]);
            }

            let weth = if chain_id == 137 { "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270" } else { "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" };
            if let Some(start) = node_map.get(&Address::from_str(weth)?) {
                let amt_in = parse_ether("1.0")?;
                if let Some((profit, route)) = find_arb_recursive(&graph, *start, *start, amt_in, 4, vec![]) {
                    if profit > parse_ether("0.01")? {
                        info!("[{}] 💎 PROFIT: {} ETH", config.name, format_ether(profit));
                        let bribe = profit * 90 / 100;
                        let strategy = build_strategy(route, amt_in, bribe, executor.address(), &graph)?;
                        let mut tx = executor.execute(U256::zero(), Address::from_str(weth)?, amt_in, strategy).tx;
                        
                        client.fill_transaction(&mut tx, None).await.ok();
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
    Ok(())
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
    let _ = env::var("PRIVATE_KEY").map_err(|_| anyhow!("Missing PRIVATE_KEY"))?;
    let _ = env::var("EXECUTOR_ADDRESS").map_err(|_| anyhow!("Missing EXECUTOR_ADDRESS"))?;
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
        if let Some(res) = find_arb_recursive(graph, next, start, out, depth - 1, next_path) {
            return Some(res);
        }
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
            let n_next_out = graph.node_indices().find(|n| *graph.node_weight(*n).unwrap() == route[i+1].1).unwrap();
            graph[graph.find_edge(nout, n_next_out).unwrap()].pair_address
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

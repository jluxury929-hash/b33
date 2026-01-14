use ethers::{
    prelude::*,
    providers::{Provider, Ws},
    utils::parse_ether,
    abi::{Token, encode},
    types::{TransactionRequest, Eip1559TransactionRequest},
};
use ethers_flashbots::{BundleRequest, FlashbotsMiddleware};
use petgraph::{graph::{NodeIndex, UnGraph}, visit::EdgeRef};
use std::{sync::Arc, collections::HashMap, str::FromStr, net::TcpListener, io::Write, thread};
use colored::*;
use dotenv::dotenv;
use std::env;
use anyhow::{Result, anyhow};
use url::Url;
use log::{info, warn, error};

// --- CONFIGURATION STRUCT ---
#[derive(Clone, Debug)]
struct ChainConfig {
    name: String,
    rpc_env_key: String,
    default_rpc: String,
    flashbots_relay: String,
}

// --- ABIGEN INTERFACES ---
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
    // 0. IMMEDIATE LOGGING INIT (Crash Protection)
    dotenv().ok();
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    println!("{}", "╔════════════════════════════════════════════════════════╗".gold());
    println!("{}", "║    ⚡ APEX OMEGA: SINGULARITY (QUAD-NETWORK)         ║".gold());
    println!("{}", "║    STATUS: CLOUD GUARD ACTIVE | ZERO-COPY | FLASHBOTS  ║".gold());
    println!("{}", "╚════════════════════════════════════════════════════════╝".gold());

    // 1. WRAP MAIN LOGIC TO CATCH CRASHES
    if let Err(e) = run().await {
        error!("FATAL CRASH: {:?}", e);
        // Keep process alive for 60s so logs can be read in cloud console
        std::thread::sleep(std::time::Duration::from_secs(60));
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    // 2. HARDENED VALIDATION
    validate_env()?;

    // 3. CLOUD BOOT GUARD (HEALTH MONITOR)
    thread::spawn(|| {
        let listener = TcpListener::bind("0.0.0.0:8080").expect("Failed to bind port 8080");
        info!("Cloud Health Monitor active on Port 8080");
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"HUNTING\",\"version\":\"3.1.0\"}";
                stream.write_all(response.as_bytes()).unwrap_or_default();
            }
        }
    });

    // 4. QUAD-NETWORK CONFIGURATION
    let chains = vec![
        ChainConfig {
            name: "ETHEREUM".to_string(),
            rpc_env_key: "ETH_RPC".to_string(),
            default_rpc: "wss://eth.llamarpc.com".to_string(),
            flashbots_relay: "https://relay.flashbots.net".to_string(),
        },
        ChainConfig {
            name: "BASE".to_string(),
            rpc_env_key: "BASE_RPC".to_string(),
            default_rpc: "wss://base.llamarpc.com".to_string(),
            flashbots_relay: "".to_string(),
        },
        ChainConfig {
            name: "ARBITRUM".to_string(),
            rpc_env_key: "ARB_RPC".to_string(),
            default_rpc: "wss://arbitrum.llamarpc.com".to_string(),
            flashbots_relay: "".to_string(),
        },
        ChainConfig {
            name: "POLYGON".to_string(),
            rpc_env_key: "POLY_RPC".to_string(),
            default_rpc: "wss://polygon-bor.publicnode.com".to_string(),
            flashbots_relay: "".to_string(),
        },
    ];

    let private_key = env::var("PRIVATE_KEY")?;
    let executor_addr = env::var("EXECUTOR_ADDRESS")?;

    // 5. SPAWN CONCURRENT MONITORS
    let mut handles = vec![];

    for config in chains {
        let pk = private_key.clone();
        let exec = executor_addr.clone();
        
        let handle = tokio::spawn(async move {
            if let Err(e) = monitor_chain(config.clone(), pk, exec).await {
                error!("Chain {} Failed: {:?}", config.name, e);
            }
        });
        handles.push(handle);
    }

    // Keep main process alive
    for h in handles {
        let _ = h.await;
    }

    Ok(())
}

// --- CORE CHAIN LOGIC ---
async fn monitor_chain(config: ChainConfig, pk: String, exec_addr: String) -> Result<()> {
    let rpc_url = env::var(&config.rpc_env_key).unwrap_or(config.default_rpc);
    info!("[{}] Connecting to {}...", config.name, rpc_url);
    
    // Setup Provider & Wallet
    let provider = Provider::<Ws>::connect(&rpc_url).await?;
    let provider = Arc::new(provider);
    let wallet: LocalWallet = pk.parse()?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = SignerMiddleware::new(provider.clone(), wallet.clone().with_chain_id(chain_id));
    let client = Arc::new(client);

    // Setup Flashbots
    let fb_client = if !config.flashbots_relay.is_empty() {
        Some(FlashbotsMiddleware::new(
            client.clone(),
            Url::parse(&config.flashbots_relay)?,
            wallet.clone(),
        ))
    } else {
        None
    };

    let executor = ApexOmega::new(exec_addr.parse::<Address>()?, client.clone());

    // Build Graph
    let mut graph = UnGraph::<Address, PoolEdge>::new_undirected();
    let mut node_map: HashMap<Address, NodeIndex> = HashMap::new();
    let mut pair_map: HashMap<Address, petgraph::graph::EdgeIndex> = HashMap::new();

    // WETH Address Logic
    let weth_addr_str = if chain_id == 137 { "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270" } 
                   else if chain_id == 42161 { "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1" } 
                   else { "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" };

    let pools = vec!["0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc"]; 

    info!("[{}] Initializing Graph...", config.name);
    for pool_addr in pools {
        if let Ok(addr) = Address::from_str(pool_addr) {
            let pair = IUniswapV2Pair::new(addr, provider.clone());
            if let Ok((r0, r1, _)) = pair.get_reserves().call().await {
                let t0 = pair.token0().call().await?;
                let t1 = pair.token1().call().await?;

                let n0 = *node_map.entry(t0).or_insert_with(|| graph.add_node(t0));
                let n1 = *node_map.entry(t1).or_insert_with(|| graph.add_node(t1));

                let idx = graph.add_edge(n0, n1, PoolEdge {
                    pair_address: addr, token_0: t0, token_1: t1, reserve_0: r0.into(), reserve_1: r1.into(), fee_numerator: 997,
                });
                pair_map.insert(addr, idx);
            }
        }
    }
    
    info!("[{}] Armed & Hunting.", config.name);

    let filter = Filter::new().event("Sync(uint112,uint112)");
    let mut stream = provider.subscribe_logs(&filter).await?;

    while let Some(log) = stream.next().await {
        if let Some(idx) = pair_map.get(&log.address) {
            if let Some(edge) = graph.edge_weight_mut(*idx) {
                let r0 = U256::from_big_endian(&log.data[0..32]);
                let r1 = U256::from_big_endian(&log.data[32..64]);
                edge.reserve_0 = r0;
                edge.reserve_1 = r1;
            }

            // Infinite Recursive Search
            let weth = Address::from_str(weth_addr_str)?;
            if let Some(start) = node_map.get(&weth) {
                let amt_in = parse_ether("1.0")?; 
                
                if let Some((profit, route)) = find_arb_recursive(&graph, *start, *start, amt_in, 4, vec![]) {
                    if profit > parse_ether("0.01")? { 
                        info!("[{}] 💎 PROFIT: {} ETH", config.name, profit);
                        
                        let bribe = profit * 90 / 100;
                        let strategy_bytes = build_strategy(route, amt_in, bribe, executor.address(), &graph)?;

                        let tx = executor.execute(
                            U256::zero(), 
                            weth,
                            amt_in,
                            strategy_bytes
                        ).tx;

                        if let Some(fb) = fb_client.as_ref() {
                            let block = provider.get_block_number().await?;
                            let bundle = BundleRequest::new()
                                .push_transaction(tx)
                                .set_block(block + 1)
                                .set_simulation_block(block)
                                .set_simulation_timestamp(0);
                            
                            fb.send_bundle(&bundle).await.ok();
                        } else {
                             // Dual Channel Strike for L2s
                             let http_url = rpc_url.replace("wss://", "https://").replace("ws://", "http://");
                             saturation_strike(&client, &http_url, tx).await;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// --- SATURATION STRIKE ---
async fn saturation_strike<M: Middleware + 'static>(client: &Arc<M>, rpc_url: &str, tx: Eip1559TransactionRequest) {
    if let Ok(signed_tx) = client.signer().sign_transaction(&tx.clone().into()).await {
        let raw_tx = signed_tx.rlp();
        let client_http = reqwest::Client::new();
        let rpc = rpc_url.to_string();
        let raw_tx_hex = format!("0x{}", hex::encode(&raw_tx));
        
        // Channel 1: HTTP Raw Post
        tokio::spawn(async move {
            let body = serde_json::json!({
                "jsonrpc": "2.0", "method": "eth_sendRawTransaction", "params": [raw_tx_hex], "id": 1
            });
            let _ = client_http.post(rpc).json(&body).send().await;
        });

        // Channel 2: Standard Provider
        let _ = client.send_transaction(tx, None).await;
        info!("🚀 Saturation Strike Sent");
    }
}

// --- VALIDATION HELPER ---
fn validate_env() -> Result<()> {
    let key = env::var("PRIVATE_KEY").map_err(|_| anyhow!("Missing PRIVATE_KEY"))?;
    if key.len() != 64 && !key.starts_with("0x") { return Err(anyhow!("Invalid Private Key Length (Must be 64 chars + 0x)")); }
    let exec = env::var("EXECUTOR_ADDRESS").map_err(|_| anyhow!("Missing EXECUTOR_ADDRESS"))?;
    if exec.len() != 42 { return Err(anyhow!("Invalid Contract Address Length (Must be 42 chars)")); }
    Ok(())
}

// --- RECURSIVE DFS ---
fn find_arb_recursive(
    graph: &UnGraph<Address, PoolEdge>,
    curr: NodeIndex,
    start: NodeIndex,
    amt: U256,
    depth: u8,
    mut path: Vec<(Address, Address)>
) -> Option<(U256, Vec<(Address, Address)>)> {
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

// --- UTILS ---
fn get_amount_out(amt_in: U256, edge: &PoolEdge, curr: NodeIndex, graph: &UnGraph<Address, PoolEdge>) -> U256 {
    let addr = graph.node_weight(curr).unwrap();
    let (r_in, r_out) = if *addr == edge.token_0 { (edge.reserve_0, edge.reserve_1) } else { (edge.reserve_1, edge.reserve_0) };
    if r_in.is_zero() || r_out.is_zero() { return U256::zero(); }
    let amt_fee = amt_in * edge.fee_numerator;
    (amt_fee * r_out) / ((r_in * 1000) + amt_fee)
}

// --- ZERO-COPY ENCODER ---
fn build_strategy(
    route: Vec<(Address, Address)>,
    init_amt: U256,
    bribe: U256,
    contract: Address,
    graph: &UnGraph<Address, PoolEdge>
) -> Result<Bytes> {
    let mut targets = Vec::new();
    let mut payloads = Vec::new();
    let mut curr_in = init_amt;

    let t_sig = [0xa9, 0x05, 0x9c, 0xbb]; // transfer
    let s_sig = [0x02, 0x2c, 0x0d, 0x9f]; // swap

    for (i, (tin, tout)) in route.iter().enumerate() {
        let nin = graph.node_indices().find(|i| *graph.node_weight(*i).unwrap() == tin).unwrap();
        let nout = graph.node_indices().find(|i| *graph.node_weight(*i).unwrap() == tout).unwrap();
        let edge = &graph[graph.find_edge(nin, nout).unwrap()];

        if i == 0 {
            targets.push(tin);
            let mut d = t_sig.to_vec();
            d.extend(ethers::abi::encode(&[Token::Address(edge.pair_address), Token::Uint(init_amt)]));
            payloads.push(Bytes::from(d));
        }

        let out = get_amount_out(curr_in, edge, nin, graph);
        let (a0, a1) = if tin == edge.token_0 { (U256::zero(), out) } else { (out, U256::zero()) };
        
        let to = if i == route.len() - 1 { contract } else {
            let (n_next_in, n_next_out) = (nout, graph.node_indices().find(|i| *graph.node_weight(*i).unwrap() == route[i+1].1).unwrap());
            graph[graph.find_edge(n_next_in, n_next_out).unwrap()].pair_address
        };

        targets.push(edge.pair_address);
        let mut d = s_sig.to_vec();
        d.extend(ethers::abi::encode(&[Token::Uint(a0), Token::Uint(a1), Token::Address(to), Token::Bytes(vec![])]));
        payloads.push(Bytes::from(d));

        curr_in = out;
    }

    let encoded = encode(&[
        Token::Array(targets.into_iter().map(Token::Address).collect()),
        Token::Array(payloads.into_iter().map(Token::Bytes).collect()),
        Token::Uint(bribe),
    ]);

    Ok(Bytes::from(encoded))
}

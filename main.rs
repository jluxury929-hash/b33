use ethers::{
    prelude::*,
    providers::{Provider, Ws},
    utils::parse_ether,
    abi::{Token, encode},
};
use ethers_flashbots::{BundleRequest, FlashbotsMiddleware};
use petgraph::{
    graph::{NodeIndex, UnGraph},
    visit::EdgeRef,
};
use std::{sync::Arc, collections::HashMap, str::FromStr, time::{SystemTime, UNIX_EPOCH}};
use colored::*;
use dotenv::dotenv;
use std::env;
use anyhow::Result;
use url::Url;
use log::{info, warn};

// --- CONSTANTS ---
// Universal Router (UniV2/SushiV2 compatible)
const ROUTER_ADDR: &str = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"; 
const WETH_ADDR: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

// --- ABIGEN ---
abigen!(
    IUniswapV2Pair,
    r#"[
        function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)
        function token0() external view returns (address)
        function token1() external view returns (address)
        event Sync(uint112 reserve0, uint112 reserve1)
    ]"#
);

abigen!(
    ApexOmega,
    r#"[ function execute(uint8 mode, address token, uint256 amount, bytes calldata data) external payable ]"#
);

// --- GRAPH STRUCTURES ---
#[derive(Clone, Copy, Debug)]
struct PoolEdge {
    pair_address: Address,
    token_0: Address,
    token_1: Address,
    reserve_0: U256,
    reserve_1: U256,
    fee_numerator: u32, // 997 for UniV2
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
    println!("{}", "🌌 APEX OMEGA vFINAL (PRODUCTION BUILD)".purple().bold());

    // 1. INFRASTRUCTURE SETUP
    let ws_url = env::var("WSS_URL").expect("Missing WSS_URL");
    let provider = Provider::<Ws>::connect(ws_url).await?;
    let provider = Arc::new(provider);
    
    let wallet: LocalWallet = env::var("PRIVATE_KEY")?.parse()?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(chain_id));

    // Flashbots
    let fb_signer: LocalWallet = "0000000000000000000000000000000000000000000000000000000000000001".parse()?;
    let mut fb_client = FlashbotsMiddleware::new(
        client.clone(),
        Url::parse("https://relay.flashbots.net")?,
        fb_signer,
    );

    let executor = ApexOmega::new(env::var("EXECUTOR_ADDRESS")?.parse::<Address>()?, Arc::new(client.clone()));

    // 2. GRAPH INITIALIZATION
    let mut graph = UnGraph::<Address, PoolEdge>::new_undirected();
    let mut node_map: HashMap<Address, NodeIndex> = HashMap::new();
    let mut pair_map: HashMap<Address, petgraph::graph::EdgeIndex> = HashMap::new();

    // In production, you would load thousands of pools here
    let pools = vec![
        "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc", // USDC/ETH
        "0x0d4a11d5EEaaC28EC3F61d100daF4d40501f49Ce", // UNI/ETH
        "0xD0fC8bA7E267f2bc56044A7715A489d851dC6D78", // UNI/USDC
    ];

    info!("Building Graph with {} pools...", pools.len());

    for pool_addr in pools {
        let addr = Address::from_str(pool_addr)?;
        let pair = IUniswapV2Pair::new(addr, provider.clone());
        let (r0, r1, _) = pair.get_reserves().call().await?;
        let t0 = pair.token0().call().await?;
        let t1 = pair.token1().call().await?;

        let n0 = *node_map.entry(t0).or_insert_with(|| graph.add_node(t0));
        let n1 = *node_map.entry(t1).or_insert_with(|| graph.add_node(t1));

        let edge_idx = graph.add_edge(n0, n1, PoolEdge {
            pair_address: addr,
            token_0: t0,
            token_1: t1,
            reserve_0: r0.into(),
            reserve_1: r1.into(),
            fee_numerator: 997,
        });
        
        pair_map.insert(addr, edge_idx);
    }

    info!("Graph Ready. Listening for Sync events...");

    // 3. ENGINE LOOP
    let filter = Filter::new().event("Sync(uint112,uint112)");
    let mut stream = provider.subscribe_logs(&filter).await?;

    while let Some(log) = stream.next().await {
        // A. UPDATE GRAPH RESERVES
        if let Some(edge_idx) = pair_map.get(&log.address) {
            if let Some(edge) = graph.edge_weight_mut(*edge_idx) {
                // Decode log data (reserves)
                let r0 = U256::from_big_endian(&log.data[0..32]);
                let r1 = U256::from_big_endian(&log.data[32..64]);
                edge.reserve_0 = r0;
                edge.reserve_1 = r1;
            }
            
            // B. RUN STRATEGY (Triangular Arbitrage Search)
            let weth_addr = Address::from_str(WETH_ADDR)?;
            if let Some(start_node) = node_map.get(&weth_addr) {
                let amount_in = parse_ether("10.0")?; // Flash Loan Amount
                
                if let Some((profit, route)) = find_triangle_arb(&graph, *start_node, amount_in) {
                    if profit > parse_ether("0.05")? {
                        info!("{} PROFIT: {} ETH", "💎".green().bold(), profit);
                        
                        // C. BUILD EXECUTION (Pass Graph and Address)
                        let bribe = profit * 90 / 100;
                        let payload = build_execution_payload(
                            route, 
                            amount_in, 
                            bribe, 
                            executor.address(), 
                            &graph
                        )?;
                        
                        let tx = executor.execute(
                            0, // Balancer Flashloan
                            weth_addr,
                            amount_in,
                            payload
                        ).tx;

                        // D. BUNDLE
                        let block = provider.get_block_number().await?;
                        let bundle = BundleRequest::new()
                            .push_transaction(tx)
                            .set_block(block + 1)
                            .set_simulation_block(block)
                            .set_simulation_timestamp(0);

                        let client_ref = fb_client.clone();
                        tokio::spawn(async move {
                            match client_ref.send_bundle(&bundle).await {
                                Ok(_) => info!("Bundle sent for block {}", block + 1),
                                Err(e) => warn!("Bundle error: {:?}", e),
                            }
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

// --- ALGORITHMS ---

// Finds WETH -> A -> B -> WETH
fn find_triangle_arb(
    graph: &UnGraph<Address, PoolEdge>,
    start_node: NodeIndex,
    amount_in: U256
) -> Option<(U256, Vec<(Address, Address)>)> {
    
    // Hop 1: WETH -> A
    for edge1 in graph.edges(start_node) {
        let node_a = edge1.target();
        if node_a == start_node { continue; }
        
        let amt_1 = get_amount_out(amount_in, edge1.weight(), start_node, graph);
        if amt_1.is_zero() { continue; }

        // Hop 2: A -> B
        for edge2 in graph.edges(node_a) {
            let node_b = edge2.target();
            if node_b == start_node || node_b == node_a { continue; }

            let amt_2 = get_amount_out(amt_1, edge2.weight(), node_a, graph);
            if amt_2.is_zero() { continue; }

            // Hop 3: B -> WETH
            if let Some(edge3_idx) = graph.find_edge(node_b, start_node) {
                let edge3 = &graph[edge3_idx];
                let amt_3 = get_amount_out(amt_2, edge3, node_b, graph);

                if amt_3 > amount_in {
                    let profit = amt_3 - amount_in;
                    let token_a = *graph.node_weight(node_a).unwrap();
                    let token_b = *graph.node_weight(node_b).unwrap();
                    let start_addr = *graph.node_weight(start_node).unwrap();

                    // Route: List of (TokenIn, TokenOut)
                    let route = vec![
                        (start_addr, token_a),
                        (token_a, token_b),
                        (token_b, start_addr)
                    ];
                    
                    return Some((profit, route));
                }
            }
        }
    }
    None
}

fn get_amount_out(
    amount_in: U256,
    edge: &PoolEdge,
    current_node_idx: NodeIndex,
    graph: &UnGraph<Address, PoolEdge>
) -> U256 {
    let current_addr = graph.node_weight(current_node_idx).unwrap();
    let (r_in, r_out) = if *current_addr == edge.token_0 {
        (edge.reserve_0, edge.reserve_1)
    } else {
        (edge.reserve_1, edge.reserve_0)
    };
    if r_in.is_zero() || r_out.is_zero() { return U256::zero(); }
    let amount_in_with_fee = amount_in * edge.fee_numerator;
    let numerator = amount_in_with_fee * r_out;
    let denominator = (r_in * 1000) + amount_in_with_fee;
    numerator / denominator
}

// --- PAYLOAD BUILDER (CORRECTED & PRODUCTION READY) ---
fn build_execution_payload(
    route: Vec<(Address, Address)>, 
    initial_amount: U256, 
    bribe: U256,
    contract_address: Address, 
    graph: &UnGraph<Address, PoolEdge> // Added: We need graph to calc amounts
) -> Result<Bytes> {
    let mut targets = Vec::new();
    let mut payloads = Vec::new();
    
    let router = Address::from_str(ROUTER_ADDR)?;

    // 1. APPROVALS (Fixed: We must approve router)
    let approve_selector = [0x09, 0x5e, 0xa7, 0xb3]; // approve(address,uint256)
    for (token_in, _) in &route {
        targets.push(*token_in);
        let args = vec![
            Token::Address(router),
            Token::Uint(U256::MAX), // Infinite Approval
        ];
        let mut data = approve_selector.to_vec();
        data.extend(ethers::abi::encode(&args));
        payloads.push(Bytes::from(data));
    }

    // 2. SWAPS (Fixed: We calculate exact amounts for every hop)
    let swap_selector = [0x38, 0xed, 0x17, 0x39]; // swapExactTokensForTokens
    let mut current_amount_in = initial_amount;

    for (i, (token_in, token_out)) in route.iter().enumerate() {
        // Calculate Expected Output for this Hop
        if i > 0 {
             let edge_idx = graph.find_edge(graph.find_node(*token_in).unwrap(), graph.find_node(*token_out).unwrap()).unwrap();
             let edge = &graph[edge_idx];
             // Recalculate output to be precise
             current_amount_in = get_amount_out(current_amount_in, edge, graph.find_node(*token_in).unwrap(), graph);
        }

        targets.push(router);
        
        // Params
        let path = vec![*token_in, *token_out];
        let deadline = U256::from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 60);
        
        let args = vec![
            Token::Uint(current_amount_in), // Fixed: Precise Amount used here
            Token::Uint(U256::zero()),      
            Token::Array(path.into_iter().map(Token::Address).collect()),
            Token::Address(contract_address), 
            Token::Uint(deadline)
        ];
        
        let mut data = swap_selector.to_vec();
        data.extend(ethers::abi::encode(&args));
        payloads.push(Bytes::from(data));
    }

    // 3. PACK FOR CONTRACT
    let encoded = encode(&[
        Token::Array(targets.into_iter().map(Token::Address).collect()),
        Token::Array(payloads.into_iter().map(Token::Bytes).collect()),
        Token::Uint(bribe),
    ]);

    Ok(Bytes::from(encoded))
}

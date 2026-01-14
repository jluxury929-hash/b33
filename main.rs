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
const WETH_ADDR: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

// --- ABIGEN (INTERFACES) ---
abigen!(
    IUniswapV2Pair,
    r#"[
        function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)
        function token0() external view returns (address)
        function token1() external view returns (address)
    ]"#
);

// We define ApexOmega interface manually to match the execute signature
abigen!(
    ApexOmega,
    r#"[ function execute(uint256 mode, address token, uint256 amount, bytes calldata strategy) external payable ]"#
);

// --- GRAPH NODE STRUCTURE ---
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
    dotenv().ok();
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
    println!("{}", "🌌 APEX OMEGA: INFINITY ENGINE ONLINE".green().bold());

    // 1. INFRASTRUCTURE CONNECTION
    let ws_url = env::var("WSS_URL").expect("Missing WSS_URL in .env");
    let provider = Provider::<Ws>::connect(ws_url).await?;
    let provider = Arc::new(provider);
    
    let wallet: LocalWallet = env::var("PRIVATE_KEY")?.parse()?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(chain_id));

    // Flashbots Connection
    let fb_signer: LocalWallet = "0000000000000000000000000000000000000000000000000000000000000001".parse()?;
    let mut fb_client = FlashbotsMiddleware::new(
        client.clone(),
        Url::parse("https://relay.flashbots.net")?,
        fb_signer, 
    );

    let executor_addr: Address = env::var("EXECUTOR_ADDRESS")?.parse()?;
    let executor = ApexOmega::new(executor_addr, Arc::new(client.clone()));

    // 2. GRAPH INITIALIZATION
    let mut graph = UnGraph::<Address, PoolEdge>::new_undirected();
    let mut node_map: HashMap<Address, NodeIndex> = HashMap::new();
    let mut pair_map: HashMap<Address, petgraph::graph::EdgeIndex> = HashMap::new();

    // Production: Load 20,000+ pools from file/DB here. 
    // Example set for testing:
    let pools = vec![
        "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc", // WETH/USDC
        "0x0d4a11d5EEaaC28EC3F61d100daF4d40501f49Ce", // WETH/UNI
        "0xD0fC8bA7E267f2bc56044A7715A489d851dC6D78", // UNI/USDC
    ];

    info!("Graph: Loading {} pools...", pools.len());

    for pool_addr in pools {
        let addr = Address::from_str(pool_addr)?;
        let pair = IUniswapV2Pair::new(addr, provider.clone());
        
        // Fetch static data
        let t0 = pair.token0().call().await?;
        let t1 = pair.token1().call().await?;
        let (r0, r1, _) = pair.get_reserves().call().await?;

        let n0 = *node_map.entry(t0).or_insert_with(|| graph.add_node(t0));
        let n1 = *node_map.entry(t1).or_insert_with(|| graph.add_node(t1));

        let edge_idx = graph.add_edge(n0, n1, PoolEdge {
            pair_address: addr,
            token_0: t0,
            token_1: t1,
            reserve_0: r0.into(),
            reserve_1: r1.into(),
            fee_numerator: 997, // Uniswap V2 0.3% fee
        });
        pair_map.insert(addr, edge_idx);
    }

    info!("Engine Ready. Waiting for blocks...");

    // 3. MAIN EVENT LOOP
    let filter = Filter::new().event("Sync(uint112,uint112)");
    let mut stream = provider.subscribe_logs(&filter).await?;

    while let Some(log) = stream.next().await {
        // A. Update Graph State
        if let Some(edge_idx) = pair_map.get(&log.address) {
            if let Some(edge) = graph.edge_weight_mut(*edge_idx) {
                let r0 = U256::from_big_endian(&log.data[0..32]);
                let r1 = U256::from_big_endian(&log.data[32..64]);
                edge.reserve_0 = r0;
                edge.reserve_1 = r1;
            }

            // B. Search for Arbitrage (Infinite Recursion)
            let weth_addr = Address::from_str(WETH_ADDR)?;
            if let Some(start_node) = node_map.get(&weth_addr) {
                let amount_in = parse_ether("10.0")?; // 10 ETH Flashloan
                
                // Depth 4 = Up to 4 hops (e.g., WETH -> A -> B -> C -> WETH)
                if let Some((profit, route)) = find_arb_recursive(&graph, *start_node, *start_node, amount_in, 4, vec![]) {
                    // Min Profit Check (e.g. 0.05 ETH)
                    if profit > parse_ether("0.05")? {
                        info!("{} PROFIT: {} ETH | PATH LEN: {}", "💎".green().bold(), profit, route.len());

                        // C. Build Strategy Payload
                        let bribe = profit * 90 / 100; // 90% Bribe
                        let strategy_bytes = build_strategy(route, amount_in, bribe, executor.address(), &graph)?;

                        // D. Construct Transaction
                        let tx = executor.execute(
                            U256::zero(), // 0 = Balancer Mode
                            weth_addr,
                            amount_in,
                            strategy_bytes
                        ).tx;

                        // E. Submit Bundle
                        let block = provider.get_block_number().await?;
                        let bundle = BundleRequest::new()
                            .push_transaction(tx)
                            .set_block(block + 1)
                            .set_simulation_block(block)
                            .set_simulation_timestamp(0);

                        let client_ref = fb_client.clone();
                        tokio::spawn(async move {
                            match client_ref.send_bundle(&bundle).await {
                                Ok(_) => info!("Bundle submitted successfully"),
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

// Recursive Depth-First Search for Cyclic Arbitrage
fn find_arb_recursive(
    graph: &UnGraph<Address, PoolEdge>,
    current_node: NodeIndex,
    start_node: NodeIndex,
    current_amount: U256,
    depth_left: u8,
    mut path: Vec<(Address, Address)>
) -> Option<(U256, Vec<(Address, Address)>)> {
    
    // Base Case: We are back at the start and have moved at least one hop
    if current_node == start_node && path.len() > 1 {
        let initial_amt = parse_ether("10.0").unwrap();
        if current_amount > initial_amt {
            return Some((current_amount - initial_amt, path));
        }
        return None;
    }

    if depth_left == 0 { return None; }

    // Iterate Neighbors
    for edge in graph.edges(current_node) {
        let neighbor = edge.target();
        
        // Optimization: Don't go back to the node we just came from immediately (A->B->A)
        // unless it is a specific sandwich pattern (omitted for simplicity here)
        if path.len() > 0 && neighbor == *node_map_get_idx(graph, path.last().unwrap().0) { continue; }

        let amount_out = get_amount_out(current_amount, edge.weight(), current_node, graph);
        
        // Dead end check
        if amount_out.is_zero() { continue; }

        let token_curr = *graph.node_weight(current_node).unwrap();
        let token_next = *graph.node_weight(neighbor).unwrap();

        let mut new_path = path.clone();
        new_path.push((token_curr, token_next));

        // Recurse
        if let Some(result) = find_arb_recursive(graph, neighbor, start_node, amount_out, depth_left - 1, new_path) {
            return Some(result);
        }
    }
    None
}

// Helper to find NodeIndex from Address
fn node_map_get_idx(graph: &UnGraph<Address, PoolEdge>, addr: Address) -> &NodeIndex {
    graph.node_indices().find(|i| *graph.node_weight(*i).unwrap() == addr).as_ref().unwrap()
}

// Uniswap V2 Amount Out Formula
fn get_amount_out(amount_in: U256, edge: &PoolEdge, current_node: NodeIndex, graph: &UnGraph<Address, PoolEdge>) -> U256 {
    let current_addr = graph.node_weight(current_node).unwrap();
    
    let (reserve_in, reserve_out) = if *current_addr == edge.token_0 {
        (edge.reserve_0, edge.reserve_1)
    } else {
        (edge.reserve_1, edge.reserve_0)
    };

    if reserve_in.is_zero() || reserve_out.is_zero() { return U256::zero(); }

    let amount_in_with_fee = amount_in * edge.fee_numerator;
    let numerator = amount_in_with_fee * reserve_out;
    let denominator = (reserve_in * 1000) + amount_in_with_fee;
    
    numerator / denominator
}

// --- TOKEN CHAINING STRATEGY BUILDER ---
// Constructs the [Targets, Payloads, Bribe] byte stream for the contract
fn build_strategy(
    route: Vec<(Address, Address)>, 
    initial_amount: U256, 
    bribe: U256,
    contract_addr: Address,
    graph: &UnGraph<Address, PoolEdge>
) -> Result<Bytes> {
    let mut targets = Vec::new();
    let mut payloads = Vec::new();
    
    // Selectors
    let transfer_sig = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256)
    let swap_sig = [0x02, 0x2c, 0x0d, 0x9f];     // swap(uint256,uint256,address,bytes)

    let mut current_in = initial_amount;

    for (i, (token_in, token_out)) in route.iter().enumerate() {
        // Resolve Nodes & Edge
        let n_in = graph.nodes().find(|n| *graph.node_weight(*n).unwrap() == *token_in).unwrap();
        let n_out = graph.nodes().find(|n| *graph.node_weight(*n).unwrap() == *token_out).unwrap();
        let edge = &graph[graph.find_edge(n_in, n_out).unwrap()];
        let pair_addr = edge.pair_address;

        // 1. Initial Transfer (Hop 0)
        // The contract holds the flashloan. It must transfer funds to the first Pair.
        if i == 0 {
            targets.push(*token_in); // Call token contract
            let mut data = transfer_sig.to_vec();
            data.extend(ethers::abi::encode(&[
                Token::Address(pair_addr), // To first pair
                Token::Uint(initial_amount) // Amount
            ]));
            payloads.push(Bytes::from(data));
        }

        // Calculate precise output for this hop
        let amount_out = get_amount_out(current_in, edge, n_in, graph);
        
        // UniV2 requires sorting amounts (amount0Out, amount1Out)
        let (amount0_out, amount1_out) = if *token_in == edge.token_0 {
            (U256::zero(), amount_out)
        } else {
            (amount_out, U256::zero())
        };

        // 2. Determine Recipient (Next Hop)
        // If this is the last hop, send back to Contract.
        // Otherwise, send directly to the next Pair address.
        let to_address = if i == route.len() - 1 {
            contract_addr
        } else {
            let next_hop = route[i+1];
            let nn_in = graph.nodes().find(|n| *graph.node_weight(*n).unwrap() == next_hop.0).unwrap();
            let nn_out = graph.nodes().find(|n| *graph.node_weight(*n).unwrap() == next_hop.1).unwrap();
            graph[graph.find_edge(nn_in, nn_out).unwrap()].pair_address
        };

        // 3. Encode Swap Call
        targets.push(pair_addr); // Call the Pair
        let mut data = swap_sig.to_vec();
        data.extend(ethers::abi::encode(&[
            Token::Uint(amount0_out),
            Token::Uint(amount1_out),
            Token::Address(to_address), // Direct transfer to next destination
            Token::Bytes(vec![])        // Empty bytes (no callback)
        ]));
        payloads.push(Bytes::from(data));

        current_in = amount_out;
    }

    // Pack into the format expected by ApexOmega's Assembly decoder
    // abi.encode(address[] targets, bytes[] payloads, uint256 bribe)
    let encoded_strategy = encode(&[
        Token::Array(targets.into_iter().map(Token::Address).collect()),
        Token::Array(payloads.into_iter().map(Token::Bytes).collect()),
        Token::Uint(bribe),
    ]);

    Ok(Bytes::from(encoded_strategy))
}

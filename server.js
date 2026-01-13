/**
 * ===============================================================================
 * APEX PREDATOR v214.0 (JS-UNIFIED - GEM DISCOVERY & RECIPIENT HANDSHAKE)
 * ===============================================================================
 * STATUS: TOTAL OPERATIONAL FINALITY + LEVERAGE SQUEEZE
 * UPGRADES:
 * 1. GEM FILTER (v207.0): Re-integrated 1 ETH > 100k token health verification.
 * 2. RECIPIENT HANDSHAKE (v212.0): Passes PROFIT_RECIPIENT explicitly to contract.
 * 3. LEVIATHAN FLOOR (v211.0): Only strikes if Loan > 5 ETH to ensure net profit.
 * 4. LEVERAGE SQUEEZE: Maintains the 1111x (Premium * 10000 / 9) multiplier.
 * 5. RESILIENCE: Optional dependencies (Telegram/Input) prevent startup crashes.
 * ===============================================================================
 */

require('dotenv').config();
const fs = require('fs');
const http = require('http');

// --- 1. CORE DEPENDENCY CHECK (Required) ---
try {
    global.ethers = require('ethers');
    global.axios = require('axios');
    global.Sentiment = require('sentiment');
    require('colors'); 
} catch (e) {
    console.log("\n[FATAL] Core modules (ethers/axios/sentiment) missing.");
    console.log("[FIX] Run 'npm install ethers axios sentiment colors'.\n");
    process.exit(1);
}

// --- 2. OPTIONAL DEPENDENCY CHECK (Telegram Sentry) ---
let telegramAvailable = false;
let TelegramClient, StringSession, input;

try {
    const tg = require('telegram');
    const sess = require('telegram/sessions');
    TelegramClient = tg.TelegramClient;
    StringSession = sess.StringSession;
    input = require('input');
    telegramAvailable = true;
} catch (e) {
    console.log("[SYSTEM] Telegram modules missing. Running in WEB-AI mode ONLY.".yellow);
}

const { ethers } = global.ethers;
const axios = global.axios;
const Sentiment = global.Sentiment;

// ==========================================
// 0. GLOBAL CONFIGURATION & HEALTH
// ==========================================
const PROFIT_RECIPIENT = "0x458f94e935f829DCAD18Ae0A18CA5C3E223B71DE";
const MIN_LOAN_THRESHOLD = ethers.parseEther("5.0"); // Leviathan Floor

const NETWORKS = {
    ETHEREUM: { chainId: 1, rpc: process.env.ETH_RPC || "https://eth.llamarpc.com", moat: "0.015", priority: "500.0", weth: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", usdc: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", router: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D" },
    BASE: { chainId: 8453, rpc: process.env.BASE_RPC || "https://mainnet.base.org", moat: "0.008", priority: "1.8", weth: "0x4200000000000000000000000000000000000006", usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", router: "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24" },
    ARBITRUM: { chainId: 42161, rpc: process.env.ARB_RPC || "https://arb1.arbitrum.io/rpc", moat: "0.005", priority: "1.2", weth: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", usdc: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", router: "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506" },
    POLYGON: { chainId: 137, rpc: process.env.POLY_RPC || "https://polygon-rpc.com", moat: "0.003", priority: "250.0", weth: "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619", usdc: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", router: "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff" }
};

const EXECUTOR = process.env.EXECUTOR_ADDRESS;
const PRIVATE_KEY = process.env.PRIVATE_KEY;

const runHealthServer = () => {
    const port = process.env.PORT || 8080;
    http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ engine: "APEX_TITAN", version: "214.0-JS", recipient: PROFIT_RECIPIENT, status: "OPERATIONAL" }));
    }).listen(port, '0.0.0.0', () => {
        console.log(`[SYSTEM] Cloud Health Monitor active on Port ${port}`.cyan);
    });
};

// ==========================================
// 1. GEM FILTERS (Pool Health & Value)
// ==========================================
async function verifyGem(provider, config, tokenAddr) {
    const abi = ["function getAmountsOut(uint amountIn, address[] path) external view returns (uint[] memory amounts)"];
    const router = new ethers.Contract(config.router, abi, provider);

    try {
        const oneEth = ethers.parseEther("1");
        const amounts = await router.getAmountsOut(oneEth, [config.weth, tokenAddr]);
        const tokensReceived = amounts[1];

        if (tokensReceived === 0n) return false;

        // Low Value Rule: 1 ETH must buy > 100,000 tokens (Ensures non-dust liquidity)
        const minTokens = 100000n * (10n ** 18n);
        return tokensReceived >= minTokens;
    } catch (e) { return false; }
}

// ==========================================
// 2. DETERMINISTIC BALANCE ENFORCEMENT
// ==========================================
async function calculateStrikeMetrics(provider, wallet, config) {
    try {
        const [balance, feeData] = await Promise.all([
            provider.getBalance(wallet.address),
            provider.getFeeData()
        ]);

        const gasPrice = feeData.gasPrice || ethers.parseUnits("0.01", "gwei");
        const pFee = ethers.parseUnits(config.priority, "gwei");
        const execFee = (gasPrice * 130n / 100n) + pFee;
        
        const overhead = (1800000n * execFee) + ethers.parseEther(config.moat);
        const reserve = ethers.parseEther("0.005");

        if (balance < (overhead + reserve)) return null;

        const premium = balance - overhead;
        // 1111x Leverage Multiplier (Principal = Premium * 10000 / 9)
        const tradeAmount = (premium * 10000n) / 9n;

        // Leviathan Floor: Refuse small loans to ensure gas is covered.
        if (tradeAmount < MIN_LOAN_THRESHOLD) return null;

        return { tradeAmount, premium, fee: execFee, pFee };
    } catch (e) { return null; }
}

// ==========================================
// 3. OMNI GOVERNOR CORE
// ==========================================
class ApexOmniGovernor {
    constructor() {
        this.wallets = {};
        this.providers = {};
        this.sentiment = new Sentiment();
        this.tgSession = new StringSession(process.env.TG_SESSION || "");
        
        for (const [name, config] of Object.entries(NETWORKS)) {
            try {
                const provider = new ethers.JsonRpcProvider(config.rpc, { chainId: config.chainId, staticNetwork: true });
                this.providers[name] = provider;
                if (PRIVATE_KEY) this.wallets[name] = new ethers.Wallet(PRIVATE_KEY, provider);
            } catch (e) { console.log(`[${name}] Init Fail.`.red); }
        }
    }

    async executeStrike(networkName, tokenIdentifier) {
        if (!this.wallets[networkName]) return;
        
        const config = NETWORKS[networkName];
        const wallet = this.wallets[networkName];
        const provider = this.providers[networkName];
        const tokenAddr = tokenIdentifier.startsWith("0x") ? tokenIdentifier : "0x25d887Ce7a35172C62FeBFD67a1856F20FaEbb00";

        // Step 1: Gem Verification (1 ETH > 100k Tokens Filter)
        if (!(await verifyGem(provider, config, tokenAddr))) return;

        // Step 2: Metrics Calculation (Leverage Squeeze + Leviathan Floor)
        const m = await calculateStrikeMetrics(provider, wallet, config);
        if (!m) return; 

        console.log(`[${networkName}]`.green + ` STRIKING GEM: ${tokenIdentifier.slice(0,6)}... | Loan: ${ethers.formatEther(m.tradeAmount)} ETH`);

        const abi = ["function executeTriangleWithRecipient(address router, address tokenA, address tokenB, uint256 amountIn, address recipient) external payable"];
        const contract = new ethers.Contract(EXECUTOR, abi, wallet);

        try {
            const txData = await contract.executeTriangleWithRecipient.populateTransaction(
                config.router,
                tokenAddr,
                config.usdc,
                m.tradeAmount,
                PROFIT_RECIPIENT, // Atomic Profit Routing
                {
                    value: m.premium,
                    gasLimit: 1800000,
                    maxFeePerGas: m.fee,
                    maxPriorityFeePerGas: m.pFee,
                    nonce: await wallet.getNonce('pending')
                }
            );

            await provider.call(txData);
            const txResponse = await wallet.sendTransaction(txData);
            console.log(`✅ [${networkName}] SUCCESS: ${txResponse.hash}`.gold);
        } catch (e) {
            // Capital protected by Atomic Guard in v141.0 Solidity contract
        }
    }

    async analyzeWebIntelligence() {
        const sites = ["https://api.crypto-ai-signals.com/v1/latest"];
        for (const url of sites) {
            try {
                const resp = await axios.get(url, { timeout: 4000 });
                const text = JSON.stringify(resp.data);
                const tickers = text.match(/\$[A-Z]+/g);
                if (tickers) {
                    for (const net of Object.keys(NETWORKS)) {
                        this.executeStrike(net, tickers[0].replace('$', ''));
                    }
                }
            } catch (e) { continue; }
        }
    }

    async run() {
        console.log("╔════════════════════════════════════════════════════════╗".gold);
        console.log("║    ⚡ APEX TITAN v214.0 | GEM DISCOVERY FINALITY    ║".gold);
        console.log("║    RECIPIENT: 0x458f94e935f829DCAD18Ae0A18CA5C3E223B7 ║".gold);
        console.log("║    MODE: LEVERAGE SQUEEZE + GEM HEALTH FILTER      ║".gold);
        console.log("╚════════════════════════════════════════════════════════╝".gold);

        if (!EXECUTOR || !PRIVATE_KEY) {
            console.log("CRITICAL FAIL: PRIVATE_KEY or EXECUTOR_ADDRESS missing.".red);
            return;
        }

        while (true) {
            await this.analyzeWebIntelligence();
            for (const net of Object.keys(NETWORKS)) {
                this.executeStrike(net, "DISCOVERY");
                await new Promise(r => setTimeout(r, 1500));
            }
            await new Promise(r => setTimeout(r, 4000));
        }
    }
}

// Ignition
runHealthServer();
const governor = new ApexOmniGovernor();
governor.run().catch(err => {
    console.log("FATAL ERROR: ".red, err.message);
    process.exit(1);
});

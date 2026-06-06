#!/usr/bin/env node

/**
 * OpenSea SeaDrop Auto Mint
 * Usage: npm start
 *
 * .env format:
 *   OPENSEA_API_KEY=your_key_here   <- opsional
 *   RPC_ethereum=https://eth.llamarpc.com
 *   RPC_base=https://base.llamarpc.com
 *
 *   PK_FIRST=0xprivkey...
 *   PK_1=0xprivkey...
 *   PK_2=0xprivkey...
 */

import { readFileSync } from "fs";
import { resolve } from "path";
import { createInterface } from "readline";

// ─── SeaDrop contract ─────────────────────────────────────────────────────────
const SEADROP_ADDRESS = "0x00005EA00Ac477B1030CE78506496e8C2dE24bf5";
const FEE_RECIPIENT  = "0x0000a26b00c1F0DF003000390027140000fAa719"; // OpenSea fee recipient

const SEADROP_ABI = [
  // Public mint
  "function mintPublic(address nftContract, address feeRecipient, address minterIfNotPayer, uint256 quantity) payable",
  // Allowlist mint
  "function mintAllowList(address nftContract, address feeRecipient, address minterIfNotPayer, uint256 quantity, tuple(uint80 mintPrice, uint24 maxTotalMintableByWallet, uint40 startTime, uint40 endTime, uint16 dropStageIndex, uint32 maxTokenSupplyForStage, uint16 feeBps, bool restrictFeeRecipients) mintParams, bytes32[] proof) payable",
  // Signed mint
  "function mintSigned(address nftContract, address feeRecipient, address minterIfNotPayer, uint256 quantity, tuple(uint80 mintPrice, uint24 maxTotalMintableByWallet, uint40 startTime, uint40 endTime, uint16 dropStageIndex, uint32 maxTokenSupplyForStage, uint16 feeBps, bool restrictFeeRecipients) mintParams, uint256 salt, bytes signature) payable",
];

// Default RPCs per chain
const DEFAULT_RPC = {
  ethereum: "https://eth.llamarpc.com",
  base:     "https://base.llamarpc.com",
  polygon:  "https://polygon.llamarpc.com",
  arbitrum: "https://arbitrum.llamarpc.com",
  optimism: "https://optimism.llamarpc.com",
};

// ─── Load .env ────────────────────────────────────────────────────────────────
function loadEnv() {
  const result = { apiKey: "", rpcs: {}, privateKeys: [] };
  try {
    const lines = readFileSync(resolve(process.cwd(), ".env"), "utf8").split("\n");
    for (const line of lines) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const eq = t.indexOf("=");
      if (eq === -1) continue;
      const key = t.slice(0, eq).trim();
      const val = t.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
      if (key === "OPENSEA_API_KEY") result.apiKey = val;
      else if (key.startsWith("RPC_")) result.rpcs[key.slice(4).toLowerCase()] = val;
      else if (key === "PK_FIRST" || key.startsWith("PK_")) {
      const rawLabel = key === "PK_FIRST" ? "first" : key.slice(3).toLowerCase();
      result.privateKeys.push({ label: rawLabel, key: val });
    }
    }
  } catch { /* .env not found */ }
  return result;
}

// ─── Prompt ───────────────────────────────────────────────────────────────────
function prompt(q) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((res) => rl.question(q, (a) => { rl.close(); res(a.trim()); }));
}

// ─── Extract slug dari URL ────────────────────────────────────────────────────
function extractSlug(url) {
  const parts = new URL(url).pathname.split("/").filter(Boolean);
  const idx = parts.indexOf("collection");
  if (idx !== -1 && parts[idx + 1]) return parts[idx + 1];
  throw new Error("Tidak ketemu 'collection' di URL");
}

// ─── Derive address dari private key ─────────────────────────────────────────
async function getWallet(privateKey, rpcUrl) {
  const { ethers } = await import("ethers");
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  return new ethers.Wallet(privateKey, provider);
}

// ─── SIWE Auth → JWT ─────────────────────────────────────────────────────────
async function siweAuth(privateKey, walletAddress, collectionUrl) {
  const headers = {
    "Content-Type": "application/json",
    "Origin": "https://opensea.io",
    "Referer": "https://opensea.io/",
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
  };

  // Step 1: Nonce
  const nonceRes = await fetch("https://opensea.io/__api/auth/siwe/nonce", {
    method: "POST", headers,
    body: JSON.stringify({ address: walletAddress }),
  });
  if (!nonceRes.ok) throw new Error(`Nonce ${nonceRes.status}`);
  const { nonce } = await nonceRes.json();
  const nonceCookies = nonceRes.headers.getSetCookie?.() ?? [];

  // Step 2: Sign
  const { ethers } = await import("ethers");
  const wallet = new ethers.Wallet(privateKey);
  const issuedAt = new Date().toISOString();
  const message = {
    domain: "opensea.io",
    address: walletAddress,
    statement: "Click to sign in and accept the OpenSea Terms of Service (https://opensea.io/tos) and Privacy Policy (https://opensea.io/privacy).",
    uri: collectionUrl,
    version: "1",
    chainId: "1",
    nonce,
    issuedAt,
    accountType: "Ethereum",
  };
  const siweStr = [
    `${message.domain} wants you to sign in with your Ethereum account:`,
    message.address, ``,
    message.statement, ``,
    `URI: ${message.uri}`,
    `Version: ${message.version}`,
    `Chain ID: ${message.chainId}`,
    `Nonce: ${message.nonce}`,
    `Issued At: ${message.issuedAt}`,
  ].join("\n");
  const signature = await wallet.signMessage(siweStr);

  // Step 3: Verify
  const verifyRes = await fetch("https://opensea.io/__api/auth/siwe/verify", {
    method: "POST",
    headers: { ...headers, ...(nonceCookies.length ? { Cookie: nonceCookies.join("; ") } : {}) },
    body: JSON.stringify({ message, signature, chainArch: "EVM", connectorId: "io.metamask" }),
  });
  if (!verifyRes.ok) throw new Error(`Verify ${verifyRes.status}`);

  // Ambil JWT dari cookie
  const setCookies = verifyRes.headers.getSetCookie?.() ?? [];
  for (const c of setCookies) {
    const m = c.match(/access_token=([^;]+)/);
    if (m) return m[1];
  }
  throw new Error("JWT tidak ditemukan di response");
}

// ─── GraphQL DropEligibilityQuery ─────────────────────────────────────────────
async function fetchEligibility(walletAddress, collectionSlug, jwt, apiKey) {
  const headers = {
    "Content-Type": "application/json",
    "Origin": "https://opensea.io",
    "X-App-Id": "opensea-web",
    ...(apiKey ? { "X-API-KEY": apiKey } : {}),
    ...(jwt ? { Cookie: `access_token=${jwt}` } : {}),
  };
  const res = await fetch("https://gql.opensea.io/graphql", {
    method: "POST", headers,
    body: JSON.stringify({
      operationName: "DropEligibilityQuery",
      variables: { address: walletAddress, collectionSlug },
      extensions: {
        persistedQuery: {
          version: 1,
          sha256Hash: "d893f026d731e8f14986921fa4229098e018289f6cc7683f8ee2dd83749dd95d",
        },
      },
    }),
  });
  if (!res.ok) throw new Error(`GraphQL ${res.status}`);
  return res.json();
}

// ─── Ambil Merkle proof untuk allowlist stage ─────────────────────────────────
async function fetchMerkleProof(collectionSlug, walletAddress, stageIndex, jwt, apiKey) {
  const headers = {
    "Content-Type": "application/json",
    "Origin": "https://opensea.io",
    ...(apiKey ? { "X-API-KEY": apiKey } : {}),
    ...(jwt ? { Cookie: `access_token=${jwt}` } : {}),
  };
  // OpenSea allowlist proof endpoint
  const res = await fetch(
    `https://api.opensea.io/api/v2/drops/${collectionSlug}/allowlist-proof?wallet_address=${walletAddress}&stage_index=${stageIndex}`,
    { headers }
  );
  if (!res.ok) return null;
  const data = await res.json();
  return data.proof ?? data.merkle_proof ?? null;
}

// ─── Fetch drop info ──────────────────────────────────────────────────────────
async function fetchDrop(slug, apiKey) {
  const headers = { "Content-Type": "application/json" };
  if (apiKey) headers["X-API-KEY"] = apiKey;
  const res = await fetch(`https://api.opensea.io/api/v2/drops/${slug}`, { headers });
  if (!res.ok) throw new Error(`Drop API ${res.status}: ${await res.text()}`);
  return res.json();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function formatPrice(p) {
  if (!p) return "FREE";
  const eth = Number(BigInt(p.value ?? p.amount ?? 0)) / Math.pow(10, p.decimals ?? 18);
  return eth === 0 ? "FREE" : `${eth} ETH`;
}
function formatDate(iso) {
  if (!iso) return "TBA";
  return new Date(iso).toLocaleString("id-ID");
}
function stageStatus(s) {
  const now = Date.now();
  const start = s.start_time ? new Date(s.start_time).getTime() : null;
  const end = s.end_time ? new Date(s.end_time).getTime() : null;
  if (start && now < start) return "UPCOMING";
  if (end && now > end) return "ENDED";
  return "ACTIVE";
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── Mint satu stage ──────────────────────────────────────────────────────────
async function mintStage(wallet, contractAddress, stage, gqlStage, quantity, slug, walletAddress, jwt, apiKey) {
  const { ethers } = await import("ethers");
  const seadrop = new ethers.Contract(SEADROP_ADDRESS, SEADROP_ABI, wallet);

  const stageType = gqlStage?.stageType ?? "";
  const price = gqlStage?.eligiblePrice?.token?.unit ?? 0;
  const priceWei = ethers.parseEther(String(price));
  const totalValue = priceWei * BigInt(quantity);

  // Build mintParams dari data stage
  const mintParams = {
    mintPrice: priceWei,
    maxTotalMintableByWallet: gqlStage?.maxTotalMintableByWallet ?? gqlStage?.eligibleMaxTotalMintableByWallet ?? 1,
    startTime: stage.start_time ? Math.floor(new Date(stage.start_time).getTime() / 1000) : 0,
    endTime: stage.end_time ? Math.floor(new Date(stage.end_time).getTime() / 1000) : Math.floor(Date.now() / 1000) + 86400,
    dropStageIndex: gqlStage?.stageIndex ?? 1,
    maxTokenSupplyForStage: 0xffffffff,
    feeBps: 500, // 5% OpenSea fee
    restrictFeeRecipients: true,
  };

  let tx;
  if (stageType === "PUBLIC_SALE") {
    // mintPublic
    tx = await seadrop.mintPublic(
      contractAddress,
      FEE_RECIPIENT,
      ethers.ZeroAddress,
      quantity,
      { value: totalValue }
    );
  } else {
    // mintAllowList — butuh Merkle proof
    const proof = await fetchMerkleProof(slug, walletAddress, mintParams.dropStageIndex, jwt, apiKey);
    if (!proof || proof.length === 0) {
      throw new Error("Merkle proof tidak ditemukan — mungkin tidak eligible");
    }
    tx = await seadrop.mintAllowList(
      contractAddress,
      FEE_RECIPIENT,
      ethers.ZeroAddress,
      quantity,
      mintParams,
      proof,
      { value: totalValue }
    );
  }

  return tx;
}

// ─── Fetch drop info via GraphQL (lebih lengkap) ─────────────────────────────
async function fetchDropGQL(collectionSlug, walletAddress, jwt, apiKey) {
  const headers = {
    "Content-Type": "application/json",
    "Origin": "https://opensea.io",
    "X-App-Id": "opensea-web",
    ...(apiKey ? { "X-API-KEY": apiKey } : {}),
    ...(jwt ? { Cookie: `access_token=${jwt}` } : {}),
  };
  const res = await fetch("https://gql.opensea.io/graphql", {
    method: "POST", headers,
    body: JSON.stringify({
      operationName: "DropEligibilityQuery",
      variables: { address: walletAddress, collectionSlug },
      extensions: {
        persistedQuery: {
          version: 1,
          sha256Hash: "d893f026d731e8f14986921fa4229098e018289f6cc7683f8ee2dd83749dd95d",
        },
      },
    }),
  });
  if (!res.ok) throw new Error(`GQL drop ${res.status}`);
  return res.json();
}

// ─── Parse wallet selection input ────────────────────────────────────────────
function parseWalletSelection(input, keys) {
  const total = keys.length;
  input = input.trim().toLowerCase();
  if (!input || input === "all") return keys.map((_, i) => i);

  // "from X" — dari index X sampai akhir
  const fromMatch = input.match(/^from\s+(\d+)$/);
  if (fromMatch) {
    const start = parseInt(fromMatch[1]) - 1;
    return Array.from({ length: total - start }, (_, i) => start + i).filter(i => i >= 0 && i < total);
  }

  // Comma separated: "1,3,16" atau "first,2,8"
  // Single wallet
  if (!input.includes(",")) {
    if (input === "first") return [0];
    const n = parseInt(input);
    if (!isNaN(n) && n >= 1 && n <= total) return [n - 1];
    // Cari by label
    const idx = keys.findIndex(k => k.label === input);
    if (idx !== -1) return [idx];
    return [];
  }
  return input.split(",").map(s => {
    s = s.trim();
    if (s === "first") return 0;
    const n = parseInt(s);
    if (!isNaN(n)) return n - 1;
    const idx = keys.findIndex(k => k.label === s);
    return idx;
  }).filter(i => i >= 0 && i < total);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const env = loadEnv();
  const LINE = "═".repeat(62);

  if (env.privateKeys.length === 0) {
    console.error("[!] Tidak ada private key di .env");
    console.error("    Format: PK_FIRST=0x... atau PK_1=0x...");
    process.exit(1);
  }

  const inputUrl = await prompt("\n[?] OpenSea collection URL: ");
  if (!inputUrl) { console.error("[!] URL kosong"); process.exit(1); }

  const contractAddress = await prompt("[?] Contract address koleksi: ");
  if (!contractAddress || !/^0x[0-9a-fA-F]{40}$/.test(contractAddress)) {
    console.error("[!] Contract address tidak valid"); process.exit(1);
  }

  let slug;
  try { slug = extractSlug(inputUrl); }
  catch (e) { console.error(`[!] ${e.message}`); process.exit(1); }

  const cleanUrl = inputUrl.replace(/\/(overview|drop|mint)\/?$/, "");
  const chain = "ethereum";
  const rpcUrl = env.rpcs[chain] ?? DEFAULT_RPC[chain];

  // ── Pilih wallet ──
  console.log(`\n[@] Wallet tersedia (${env.privateKeys.length} total):`);
  env.privateKeys.forEach((pk, i) => console.log(`    [${i+1}] wallet ${pk.label}`));
  console.log(`\n    Opsi:`);
  console.log(`    [1] 1 wallet      contoh: first  atau  3`);
  console.log(`    [2] Beberapa      contoh: first,2,5  atau  1,3,7`);
  console.log(`    [3] Semua         ketik:  all`);
  console.log(`    [4] Dari X        contoh: from 3`);
  const walletInput = await prompt(`\n[?] Pilih wallet: `);
  const selectedIdx = parseWalletSelection(walletInput, env.privateKeys);
  if (selectedIdx.length === 0) { console.error("[!] Tidak ada wallet yang dipilih"); process.exit(1); }
  const selectedWallets = selectedIdx.map(i => env.privateKeys[i]);
  console.log(`[@] Dipilih: ${selectedWallets.map(w => `wallet ${w.label}`).join(", ")}`);

  // ── Fetch drop info dari GQL pake wallet pertama (tanpa auth dulu) ──
  console.log(`\n[@] Fetching drop info ...`);
  let gqlDropData;
  try {
    // Ambil address dari PK pertama buat dummy fetch
    const { ethers } = await import("ethers");
    const firstAddr = new ethers.Wallet(selectedWallets[0].key).address;
    // Auth dulu biar dapat data lengkap
    let jwt = null;
    try {
      jwt = await siweAuth(selectedWallets[0].key, firstAddr, cleanUrl);
    } catch { /* lanjut tanpa auth */ }
    gqlDropData = await fetchDropGQL(slug, firstAddr, jwt, env.apiKey);
  } catch (e) {
    console.error(`[!] Gagal fetch drop: ${e.message}`); process.exit(1);
  }

  const gqlStagesInfo = gqlDropData?.data?.dropBySlug?.stages ?? [];

  // Fetch REST juga buat data tambahan (start_time, end_time)
  let restStages = [];
  try {
    const drop = await fetchDrop(slug, env.apiKey);
    restStages = drop.stages ?? [];
  } catch { /* opsional */ }

  // ── Tampilkan mint schedule dari GQL ──
  console.log(`\n${LINE}`);
  console.log(`[+] ${slug}`);
  console.log(`[@] Chain    : ethereum`);
  console.log(`[@] Contract : ${contractAddress}`);
  console.log(LINE);
  console.log(`\n[+] MINT SCHEDULE (${gqlStagesInfo.length} phase)\n`);
  gqlStagesInfo.forEach((gs, i) => {
    const rs = restStages[i] ?? {};
    const name = rs.name ?? gs.label ?? gs.stageType ?? `Phase ${i+1}`;
    const status = rs.start_time ? stageStatus(rs) : "ACTIVE";
    const icon = status === "ACTIVE" ? "[LIVE]" : status === "UPCOMING" ? "[SOON]" : "[END] ";
    const price = gs.eligiblePrice?.token?.unit ?? 0;
    const maxW = gs.eligibleMaxTotalMintableByWallet ?? gs.maxTotalMintableByWallet ?? 1;
    console.log(`  ${icon} [${i+1}] ${name} | ${price === 0 ? "FREE" : price + " ETH"} | max ${maxW}/wallet`);
    if (rs.start_time) console.log(`         Starts: ${formatDate(rs.start_time)}`);
  });

  // ── Proses tiap wallet ──
  console.log(`\n${LINE}`);
  console.log(`[+] MINT — ${selectedWallets.length} wallet`);
  console.log(LINE);

  for (const { label, key: privKey } of selectedWallets) {
    let wallet, walletAddress;
    try {
      const { ethers } = await import("ethers");
      const w = new ethers.Wallet(privKey);
      walletAddress = w.address;
      wallet = await getWallet(privKey, rpcUrl);
    } catch {
      console.log(`\n[!] ${label}: Gagal init wallet`);
      continue;
    }

    console.log(`\n[@] wallet ${label} | ${walletAddress}`);

    // Auth SIWE
    let jwt = null;
    try {
      process.stdout.write(`    [~] Auth ...`);
      jwt = await siweAuth(privKey, walletAddress, cleanUrl);
      process.stdout.write(`\r    [+] Auth OK\n`);
    } catch (e) {
      process.stdout.write(`\r    [!] Auth gagal: ${e.message}\n`);
    }

    // Cek eligibility via GraphQL
    let gqlStages = [];
    try {
      const gqlData = await fetchDropGQL(slug, walletAddress, jwt, env.apiKey);
      gqlStages = gqlData?.data?.dropBySlug?.stages ?? [];
    } catch (e) {
      console.log(`    [!] Gagal fetch eligibility: ${e.message}`);
    }

    // Cek ETH balance
    let balance;
    try {
      const { ethers } = await import("ethers");
      const provider = new ethers.JsonRpcProvider(rpcUrl);
      balance = await provider.getBalance(walletAddress);
      console.log(`    [@] Balance: ${ethers.formatEther(balance)} ETH`);
    } catch { balance = 0n; }

    // Loop semua stage
    for (let i = 0; i < gqlStages.length; i++) {
      const gs = gqlStages[i];
      const rs = restStages[i] ?? {};
      const stageName = rs.name ?? gs.label ?? gs.stageType ?? `Phase ${i + 1}`;
      const status = rs.start_time ? stageStatus(rs) : "ACTIVE";

      if (!gs.isEligible) {
        console.log(`    [-] ${stageName}: Skip (not eligible)`);
        continue;
      }
      if (status === "ENDED") {
        console.log(`    [-] ${stageName}: Skip (ended)`);
        continue;
      }
      if (status === "UPCOMING") {
        console.log(`    [~] ${stageName}: Skip (belum mulai)`);
        continue;
      }

      const maxQty = gs.eligibleMaxTotalMintableByWallet ?? gs.maxTotalMintableByWallet ?? 1;
      const pricePerUnit = gs.eligiblePrice?.token?.unit ?? 0;

      // Tanya jumlah mint kalau max > 1
      let quantity = maxQty;
      if (maxQty > 1) {
        const input = await prompt(`    [?] ${stageName}: max ${maxQty}/wallet — mau mint berapa? `);
        const parsed = parseInt(input);
        quantity = (!parsed || parsed < 1) ? maxQty : Math.min(parsed, maxQty);
      }

      const totalEth = pricePerUnit * quantity;
      console.log(`    [+] ${stageName}: qty ${quantity}/${maxQty} | total ${totalEth} ETH`);

      // Cek balance cukup
      const { ethers } = await import("ethers");
      const totalWei = ethers.parseEther(String(totalEth));
      if (balance < totalWei) {
        console.log(`    [!] Balance tidak cukup (perlu ${totalEth} ETH)`);
        continue;
      }

      try {
        process.stdout.write(`    [~] Minting ${quantity}x ${stageName} ...`);
        const tx = await mintStage(wallet, contractAddress, rs, gs, quantity, slug, walletAddress, jwt, env.apiKey);
        process.stdout.write(`\r    [+] TX sent: ${tx.hash}\n`);
        process.stdout.write(`    [~] Waiting confirmation ...`);
        const receipt = await tx.wait();
        process.stdout.write(`\r    [+] Confirmed! Block: ${receipt.blockNumber} | Gas: ${receipt.gasUsed}\n`);
      } catch (e) {
        process.stdout.write(`\r    [!] Mint gagal: ${e.message?.slice(0, 80)}\n`);
      }

      await sleep(1000); // delay antar stage
    }
  }

  console.log(`\n[@] ${cleanUrl}`);
  console.log(`${LINE}\n`);
}

main().catch((e) => {
  console.error("[!] Fatal:", e.message);
  process.exit(1);
});

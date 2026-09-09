// Deploy ReleaseProvenanceAttestor to GenLayer studionet.
//
// Usage:
//   cd 23-ReleaseAttestor
//   npm install                      # pulls genlayer-js
//   source ~/.genlayer/env.sh        # exports GENLAYER_PRIVATE_KEY (a funded studionet key)
//   node scripts/deploy.mjs          # deploys sanity first, then the main contract
//
// Prints the finalized contract address. Copy it into .env (VITE_CONTRACT_ADDRESS)
// and the README. Deploy is a plain __init__ (no non-determinism), so a FINALIZED
// receipt whose view calls answer is a SUCCESS.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { createClient, createAccount } from "genlayer-js";
import { studionet } from "genlayer-js/chains";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MAIN = resolve(root, "contracts/release_provenance_attestor.py");
const SANITY = resolve(root, "sanity/storage_test.py");

let pk = process.env.GENLAYER_PRIVATE_KEY;
if (!pk) { console.error("GENLAYER_PRIVATE_KEY not set - run: source ~/.genlayer/env.sh"); process.exit(1); }
if (!pk.startsWith("0x")) pk = "0x" + pk;

const account = createAccount(pk);
const client = createClient({ chain: studionet, account });
console.log("Deployer:", account.address, "\n");

async function deploy(label, path) {
  const code = readFileSync(path, "utf8");
  console.log(`==> Deploying ${label} (${code.length} bytes)`);
  const hash = await client.deployContract({ code, args: [], leaderOnly: false });
  const receipt = await client.waitForTransactionReceipt({ hash, status: "FINALIZED", interval: 4000, retries: 60 });
  const addr = receipt?.data?.contract_address;
  console.log(`    status=${receipt?.status} address=${addr}\n`);
  return addr;
}

await deploy("sanity/storage_test.py", SANITY);
const address = await deploy("ReleaseProvenanceAttestor", MAIN);
const cfg = await client.readContract({ address, functionName: "get_config", args: [] });
console.log("Live get_config:", JSON.stringify(cfg, (k, v) => typeof v === "bigint" ? v.toString() : v));
console.log("\nCONTRACT_ADDRESS:", address);

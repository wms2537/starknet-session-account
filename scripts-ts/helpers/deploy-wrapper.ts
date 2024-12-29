#!/usr/bin/env node
import yargs from "yargs";
import { execSync } from "child_process";

interface CommandLineOptions {
  _: string[];
  $0: string;
  network?: string;
  reset?: boolean;
  fee?: string;
  declare?: boolean;
}

const argv = yargs(process.argv.slice(2))
  .options({
    network: { type: "string" },
    reset: { type: "boolean", default: false },
    fee: { type: "string", choices: ["eth", "strk"], default: "eth" },
    declare: { type: "boolean", default: false },
  })
  .parseSync() as CommandLineOptions;

// Set environment variables
process.env.NETWORK = argv.network || "devnet";
process.env.FEE_TOKEN = argv.fee || "eth";

// Choose which script to run based on the --declare flag
const scriptToRun = argv.declare ? "declare.ts" : "deploy.ts";

// Execute the selected script
execSync(
  "cd contracts && scarb build && ts-node ../scripts-ts/" + 
    scriptToRun +
    " --network " +
    process.env.NETWORK +
    " --fee " +
    process.env.FEE_TOKEN +
    (argv.reset ? " --reset" : "") +
    " && ts-node ../scripts-ts/helpers/parse-deployments.ts" +
    " && cd ..",
  { stdio: "inherit" }
);

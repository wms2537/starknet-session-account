import {
  deployContract,
  executeDeployCalls,
  exportDeployments,
  deployer,
  declareContract,
} from "./deploy-contract";
import { green } from "./helpers/colorize-log";

const MAIN_PUBLIC_KEY = "0x00c6c2f7833f681c8fe001533e99571f6ff8dec59268792a429a14b5b252f1ad";

/**
 * Deploy a contract using the specified parameters.
 *
 * @example (deploy contract with contructorArgs)
 * const deployScript = async (): Promise<void> => {
 *   await deployContract(
 *     {
 *       contract: "YourContract",
 *       contractName: "YourContractExportName",
 *       constructorArgs: {
 *         owner: deployer.address,
 *       },
 *       options: {
 *         maxFee: BigInt(1000000000000)
 *       }
 *     }
 *   );
 * };
 *
 * @example (deploy contract without contructorArgs)
 * const deployScript = async (): Promise<void> => {
 *   await deployContract(
 *     {
 *       contract: "YourContract",
 *       contractName: "YourContractExportName",
 *       options: {
 *         maxFee: BigInt(1000000000000)
 *       }
 *     }
 *   );
 * };
 *
 *
 * @returns {Promise<void>}
 */
const deployScript = async (): Promise<void> => {
  // Declare InfiniRewardsPoints contract
  const nexAccountClassHash = await declareContract({
    contract: "NexAccount",
  });
  console.log("NexAccount class hash:", nexAccountClassHash);

  
  // Deploy InfiniRewardsFactory contract
  await deployContract({
    contract: "NexAccount",
    constructorArgs: {
      public_key: MAIN_PUBLIC_KEY,
    },
  });
};

deployScript()
  .then(async () => {
    await executeDeployCalls();
    exportDeployments();

    console.log(green("All Setup Done"));
  })
  .catch(console.error);

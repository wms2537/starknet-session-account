import {
    declareContract,
    executeDeployCalls,
    exportDeployments,
    deployer,
  } from "./deploy-contract";
  import { green } from "./helpers/colorize-log";
  
  /**
   * Declare contracts to get their class hashes.
   * 
   * @returns {Promise<void>}
   */
  const declareScript = async (): Promise<void> => {
    // Declare InfiniRewardsPoints contract
    const pointsClassHash = await declareContract({
      contract: "InfiniRewardsPoints",
    });
    console.log("InfiniRewardsPoints class hash:", pointsClassHash);
  
    // Declare InfiniRewardsCollectible contract
    const collectibleClassHash = await declareContract({
      contract: "InfiniRewardsCollectible",
    });
    console.log("InfiniRewardsCollectible class hash:", collectibleClassHash);
  
    // Declare InfiniRewardsUserAccount contract
    const userAccountClassHash = await declareContract({
      contract: "InfiniRewardsUserAccount",
    });
    console.log("InfiniRewardsUserAccount class hash:", userAccountClassHash);
  
    // Declare InfiniRewardsMerchantAccount contract
    const merchantAccountClassHash = await declareContract({
      contract: "InfiniRewardsMerchantAccount",
    });
    console.log("InfiniRewardsMerchantAccount class hash:", merchantAccountClassHash);
  
    // Declare InfiniRewardsFactory contract
    const factoryClassHash = await declareContract({
      contract: "InfiniRewardsFactory",
    });
    console.log("InfiniRewardsFactory class hash:", factoryClassHash);
  };
  
  declareScript()
    .catch(console.error);
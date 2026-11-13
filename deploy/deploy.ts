import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const PROPOSAL = process.env.PROPOSAL ?? "Adopt the new treasury policy?";
const DURATION_SECONDS = Number(process.env.DURATION_SECONDS ?? 600);

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy } = hre.deployments;

  const deployed = await deploy("ConfidentialVote", {
    from: deployer,
    args: [PROPOSAL, DURATION_SECONDS],
    log: true,
  });

  console.log(`ConfidentialVote contract: `, deployed.address);
};
export default func;
func.id = "deploy_confidentialVote"; // id required to prevent reexecution
func.tags = ["ConfidentialVote"];

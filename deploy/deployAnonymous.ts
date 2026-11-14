import fs from "fs";
import path from "path";
import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { Identity, newIdentities, voterRoot } from "../zk/client";

const PROPOSAL = process.env.PROPOSAL ?? "Adopt the new treasury policy?";
const DURATION_SECONDS = Number(process.env.DURATION_SECONDS ?? 600);
const VOTER_COUNT = Number(process.env.VOTER_COUNT ?? 5);

// Demo shortcut: the registrar generates every identity in one file. In reality each voter generates their own
// secret (`zkvote identity`) and hands over only the commitment.
export const VOTERS_FILE = path.resolve(__dirname, "..", "zk", "build", "voters.json");

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy } = hre.deployments;

  if (!fs.existsSync(VOTERS_FILE)) {
    fs.writeFileSync(VOTERS_FILE, JSON.stringify(newIdentities(VOTER_COUNT), null, 2));
    console.log(`Created ${VOTER_COUNT} voter identities in ${VOTERS_FILE}`);
  }
  const voters: Identity[] = JSON.parse(fs.readFileSync(VOTERS_FILE, "utf8"));
  const root = voterRoot(voters.map((v) => v.commitment));

  const verifier = await deploy("Verifier", { from: deployer, log: true });
  const deployed = await deploy("AnonymousConfidentialVote", {
    from: deployer,
    args: [PROPOSAL, DURATION_SECONDS, root, verifier.address],
    log: true,
  });

  console.log(`AnonymousConfidentialVote contract: `, deployed.address, `(voter root ${root})`);
};
export default func;
func.id = "deploy_anonymousConfidentialVote"; // id required to prevent reexecution
func.tags = ["AnonymousConfidentialVote"];

import fs from "fs";
import { task } from "hardhat/config";
import type { HardhatRuntimeEnvironment, TaskArguments } from "hardhat/types";
import { VOTERS_FILE } from "../deploy/deployAnonymous";
import { Identity, proveVote } from "../zk/client";

/**
 * Tutorial: Deploy and Interact Locally (--network localhost)
 * ===========================================================
 *
 * 1. From a separate terminal window:
 *
 *   npx hardhat node
 *
 * 2. Deploy the ConfidentialVote contract (600s voting window by default)
 *
 *   DURATION_SECONDS=60 npx hardhat --network localhost deploy
 *
 * 3. Vote from different accounts, then reveal the result after the deadline
 *
 *   npx hardhat --network localhost task:vote --support yes --voter 1
 *   npx hardhat --network localhost task:vote --support no  --voter 2
 *   npx hardhat --network localhost task:vote --support yes --voter 3
 *   npx hardhat --network localhost task:status
 *   npx hardhat --network localhost task:advance-time --seconds 60   (localhost only)
 *   npx hardhat --network localhost task:tally
 *
 * The same tasks work with --network sepolia (skip task:advance-time; wait for the deadline instead).
 *
 * Anonymous variant (zkSNARK membership proof + FHE ballot), after `npm run zk:setup`:
 *
 *   npx hardhat --network localhost task:anon-vote --support yes --voter 0
 *   npx hardhat --network localhost task:anon-vote --support no  --voter 1
 *   npx hardhat --network localhost task:status --contract AnonymousConfidentialVote
 *   npx hardhat --network localhost task:advance-time --seconds 60
 *   npx hardhat --network localhost task:tally  --contract AnonymousConfidentialVote
 */

async function getVote(hre: HardhatRuntimeEnvironment, address?: string, name = "ConfidentialVote") {
  const deployment = address ? { address } : await hre.deployments.get(name);
  console.log(`${name}: ${deployment.address}`);
  // Both vote contracts share the EncryptedTally interface used by the status and tally tasks.
  const contract = await hre.ethers.getContractAt("EncryptedTally", deployment.address);
  return { contract, address: deployment.address };
}

task("task:status", "Prints the proposal, deadline and (once revealed) the result")
  .addOptionalParam("address", "Optionally specify the vote contract address")
  .addOptionalParam("contract", "ConfidentialVote or AnonymousConfidentialVote", "ConfidentialVote")
  .setAction(async function (taskArguments: TaskArguments, hre) {
    const { contract } = await getVote(hre, taskArguments.address, taskArguments.contract);

    const deadline = Number(await contract.deadline());
    const now = (await hre.ethers.provider.getBlock("latest"))!.timestamp;
    const [yesHandle, noHandle] = await contract.getEncryptedTally();

    console.log(`Proposal       : ${await contract.proposal()}`);
    console.log(`Deadline       : ${new Date(deadline * 1000).toISOString()} (${deadline - now}s left)`);
    console.log(`Voters         : ${await contract.voterCount()}`);
    console.log(`Encrypted yes  : ${yesHandle}`);
    console.log(`Encrypted no   : ${noHandle}`);
    if (await contract.tallyRevealed()) {
      console.log(`Result         : yes=${await contract.yesResult()} no=${await contract.noResult()}`);
    } else {
      console.log(`Result         : hidden until the tally is revealed`);
    }
  });

task("task:vote", "Casts an encrypted yes/no ballot")
  .addOptionalParam("address", "Optionally specify the ConfidentialVote contract address")
  .addParam("support", "yes or no")
  .addOptionalParam("voter", "Signer index to vote from", "0")
  .setAction(async function (taskArguments: TaskArguments, hre) {
    const { ethers, fhevm } = hre;

    const support = String(taskArguments.support).toLowerCase();
    if (support !== "yes" && support !== "no") {
      throw new Error(`Argument --support must be "yes" or "no"`);
    }

    await fhevm.initializeCLIApi();

    const { address } = await getVote(hre, taskArguments.address);
    const contract = await ethers.getContractAt("ConfidentialVote", address);
    const voter = (await ethers.getSigners())[parseInt(taskArguments.voter)];

    // Encrypted locally: the chain only ever sees the ciphertext handle and its input proof
    const ballot = await fhevm
      .createEncryptedInput(address, voter.address)
      .addBool(support === "yes")
      .encrypt();

    const tx = await contract.connect(voter).vote(ballot.handles[0], ballot.inputProof);
    console.log(`Wait for tx:${tx.hash}...`);
    const receipt = await tx.wait();
    console.log(`tx:${tx.hash} status=${receipt?.status}`);
    console.log(`${voter.address} voted (ballot stays encrypted)`);
  });

task("task:anon-vote", "Casts an anonymous encrypted ballot through a relayer")
  .addOptionalParam("address", "Optionally specify the AnonymousConfidentialVote contract address")
  .addParam("support", "yes or no")
  .addOptionalParam("voter", "Index of the voter identity in zk/build/voters.json", "0")
  .addOptionalParam("relayer", "Signer index that submits the transaction", "0")
  .setAction(async function (taskArguments: TaskArguments, hre) {
    const { ethers, fhevm } = hre;

    const support = String(taskArguments.support).toLowerCase();
    if (support !== "yes" && support !== "no") {
      throw new Error(`Argument --support must be "yes" or "no"`);
    }
    const voters: Identity[] = JSON.parse(fs.readFileSync(VOTERS_FILE, "utf8"));
    const voter = voters[parseInt(taskArguments.voter)];
    if (!voter) {
      throw new Error(`No voter #${taskArguments.voter} in ${VOTERS_FILE} (${voters.length} registered)`);
    }

    await fhevm.initializeCLIApi();

    const { address } = await getVote(hre, taskArguments.address, "AnonymousConfidentialVote");
    const contract = await ethers.getContractAt("AnonymousConfidentialVote", address);
    const relayer = (await ethers.getSigners())[parseInt(taskArguments.relayer)];

    // The ballot is encrypted for the relayer (the tx sender), and the zk proof is bound to that ciphertext.
    const ballot = await fhevm
      .createEncryptedInput(address, relayer.address)
      .addBool(support === "yes")
      .encrypt();
    const zk = proveVote({
      secret: voter.secret,
      commitments: voters.map((v) => v.commitment),
      pollId: await contract.pollId(),
      ballotHash: await contract.ballotHash(ballot.handles[0]),
    });

    const tx = await contract.connect(relayer).vote(zk.nullifier, ballot.handles[0], ballot.inputProof, zk.proof);
    console.log(`Wait for tx:${tx.hash}...`);
    const receipt = await tx.wait();
    console.log(`tx:${tx.hash} status=${receipt?.status}`);
    console.log(`Relayer ${relayer.address} submitted an anonymous ballot (nullifier ${zk.nullifier})`);
  });

task("task:tally", "Requests public decryption of the totals and submits the KMS-signed result")
  .addOptionalParam("address", "Optionally specify the vote contract address")
  .addOptionalParam("contract", "ConfidentialVote or AnonymousConfidentialVote", "ConfidentialVote")
  .setAction(async function (taskArguments: TaskArguments, hre) {
    const { fhevm } = hre;

    await fhevm.initializeCLIApi();

    const { contract } = await getVote(hre, taskArguments.address, taskArguments.contract);

    if (!(await contract.tallyRequested())) {
      const tx = await contract.requestTally();
      console.log(`requestTally tx:${tx.hash}...`);
      await tx.wait();
    }

    const [yesHandle, noHandle] = await contract.getEncryptedTally();
    const decrypted = await fhevm.publicDecrypt([yesHandle, noHandle]);

    if (!(await contract.tallyRevealed())) {
      const tx = await contract.revealTally(decrypted.abiEncodedClearValues, decrypted.decryptionProof);
      console.log(`revealTally tx:${tx.hash}...`);
      await tx.wait();
    }

    console.log(`Result: yes=${await contract.yesResult()} no=${await contract.noResult()}`);
  });

task("task:advance-time", "Fast-forwards the local chain (localhost/hardhat only)")
  .addParam("seconds", "Seconds to advance")
  .setAction(async function (taskArguments: TaskArguments, hre) {
    await hre.network.provider.send("evm_increaseTime", [parseInt(taskArguments.seconds)]);
    await hre.network.provider.send("evm_mine");
    console.log(`Advanced time by ${taskArguments.seconds}s`);
  });

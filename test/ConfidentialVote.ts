import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { ethers, fhevm } from "hardhat";
import { ConfidentialVote, ConfidentialVote__factory } from "../types";
import { expect } from "chai";
import { FhevmType } from "@fhevm/hardhat-plugin";

const DURATION = 3600;

type Signers = {
  deployer: HardhatEthersSigner;
  voters: HardhatEthersSigner[];
};

async function deployFixture() {
  const factory = (await ethers.getContractFactory("ConfidentialVote")) as ConfidentialVote__factory;
  const vote = (await factory.deploy("Adopt the new treasury policy?", DURATION)) as ConfidentialVote;
  const address = await vote.getAddress();
  return { vote, address };
}

describe("ConfidentialVote", function () {
  let signers: Signers;
  let vote: ConfidentialVote;
  let address: string;

  before(async function () {
    const ethSigners = await ethers.getSigners();
    signers = { deployer: ethSigners[0], voters: ethSigners.slice(1, 6) };
  });

  beforeEach(async function () {
    if (!fhevm.isMock) {
      console.warn(`This hardhat test suite cannot run on Sepolia Testnet`);
      this.skip();
    }
    ({ vote, address } = await deployFixture());
  });

  async function castVote(voter: HardhatEthersSigner, support: boolean) {
    const ballot = await fhevm.createEncryptedInput(address, voter.address).addBool(support).encrypt();
    return vote.connect(voter).vote(ballot.handles[0], ballot.inputProof);
  }

  async function revealTally() {
    await (await vote.requestTally()).wait();
    const [yesHandle, noHandle] = await vote.getEncryptedTally();
    const decrypted = await fhevm.publicDecrypt([yesHandle, noHandle]);
    await (await vote.revealTally(decrypted.abiEncodedClearValues, decrypted.decryptionProof)).wait();
  }

  it("tallies encrypted ballots and reveals only the totals", async function () {
    const ballots = [true, true, false, true, false];
    for (let i = 0; i < ballots.length; i++) {
      await (await castVote(signers.voters[i], ballots[i])).wait();
    }
    expect(await vote.voterCount()).to.eq(5);

    await time.increase(DURATION);
    await revealTally();

    expect(await vote.tallyRevealed()).to.eq(true);
    expect(await vote.yesResult()).to.eq(3);
    expect(await vote.noResult()).to.eq(2);
  });

  it("keeps running totals undecryptable before the tally is requested", async function () {
    await (await castVote(signers.voters[0], true)).wait();
    const [yesHandle] = await vote.getEncryptedTally();

    // Not marked publicly decryptable, and no user was granted ACL access.
    await expect(fhevm.publicDecryptEuint(FhevmType.euint32, yesHandle)).to.be.rejected;
    await expect(fhevm.userDecryptEuint(FhevmType.euint32, yesHandle, address, signers.voters[0])).to.be.rejected;
  });

  it("rejects double voting", async function () {
    await (await castVote(signers.voters[0], true)).wait();
    await expect(castVote(signers.voters[0], false)).to.be.revertedWithCustomError(vote, "AlreadyVoted");
  });

  it("rejects votes after the deadline", async function () {
    await time.increase(DURATION);
    await expect(castVote(signers.voters[0], true)).to.be.revertedWithCustomError(vote, "VotingClosed");
  });

  it("rejects tally request while voting is open", async function () {
    await expect(vote.requestTally()).to.be.revertedWithCustomError(vote, "VotingStillOpen");
  });

  it("rejects a forged tally", async function () {
    await (await castVote(signers.voters[0], true)).wait();
    await time.increase(DURATION);
    await (await vote.requestTally()).wait();

    const [yesHandle, noHandle] = await vote.getEncryptedTally();
    const decrypted = await fhevm.publicDecrypt([yesHandle, noHandle]);
    const forged = ethers.AbiCoder.defaultAbiCoder().encode(["uint32", "uint32"], [0, 1]);

    await expect(vote.revealTally(forged, decrypted.decryptionProof)).to.be.reverted;
  });

  it("rejects a ballot encrypted for a different sender", async function () {
    const [alice, bob] = signers.voters;
    const ballot = await fhevm.createEncryptedInput(address, alice.address).addBool(true).encrypt();
    await expect(vote.connect(bob).vote(ballot.handles[0], ballot.inputProof)).to.be.reverted;
  });
});

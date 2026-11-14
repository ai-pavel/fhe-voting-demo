import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { ethers, fhevm } from "hardhat";
import { expect } from "chai";
import { AnonymousConfidentialVote, Verifier } from "../types";
import { Identity, newIdentities, proveVote, voterRoot } from "../zk/client";

const DURATION = 3600;
const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

describe("AnonymousConfidentialVote", function () {
  // Each vote shells out to the gnark prover.
  this.timeout(120_000);

  let relayer: HardhatEthersSigner;
  let voters: Identity[];
  let outsider: Identity;
  let commitments: string[];
  let verifier: Verifier;
  let vote: AnonymousConfidentialVote;
  let address: string;

  before(async function () {
    if (!fhevm.isMock) {
      console.warn(`This hardhat test suite cannot run on Sepolia Testnet`);
      this.skip();
    }
    relayer = (await ethers.getSigners())[1];
    [outsider, ...voters] = newIdentities(6);
    commitments = voters.map((v) => v.commitment);
    verifier = await (await ethers.getContractFactory("Verifier")).deploy();
  });

  async function deployPoll(root: bigint) {
    const factory = await ethers.getContractFactory("AnonymousConfidentialVote");
    return factory.deploy("Adopt the new treasury policy?", DURATION, root, await verifier.getAddress());
  }

  beforeEach(async function () {
    vote = await deployPoll(voterRoot(commitments));
    address = await vote.getAddress();
  });

  async function encryptBallot(support: boolean, sender = relayer) {
    return fhevm.createEncryptedInput(address, sender.address).addBool(support).encrypt();
  }

  /** What the voter does off-chain: encrypt the ballot for the relayer, then prove membership bound to it. */
  async function prepareVote(voter: Identity, support: boolean, voterList = commitments) {
    const ballot = await encryptBallot(support);
    const zk = proveVote({
      secret: voter.secret,
      commitments: voterList,
      pollId: await vote.pollId(),
      ballotHash: await vote.ballotHash(ballot.handles[0]),
    });
    return { ballot, zk };
  }

  async function castVote(voter: Identity, support: boolean) {
    const { ballot, zk } = await prepareVote(voter, support);
    return vote.connect(relayer).vote(zk.nullifier, ballot.handles[0], ballot.inputProof, zk.proof);
  }

  async function revealTally() {
    await (await vote.requestTally()).wait();
    const [yesHandle, noHandle] = await vote.getEncryptedTally();
    const decrypted = await fhevm.publicDecrypt([yesHandle, noHandle]);
    await (await vote.revealTally(decrypted.abiEncodedClearValues, decrypted.decryptionProof)).wait();
  }

  it("tallies anonymous encrypted ballots and reveals only the totals", async function () {
    const ballots = [true, true, false, true, false];
    for (let i = 0; i < ballots.length; i++) {
      const receipt = await (await castVote(voters[i], ballots[i])).wait();
      // Every vote comes from the relayer: the chain shows neither who voted nor how.
      expect(receipt!.from).to.eq(relayer.address);
    }
    expect(await vote.voterCount()).to.eq(5);

    await time.increase(DURATION);
    await revealTally();

    expect(await vote.yesResult()).to.eq(3);
    expect(await vote.noResult()).to.eq(2);
  });

  it("rejects a second vote from the same voter, even with a different ballot", async function () {
    await (await castVote(voters[0], true)).wait();
    await expect(castVote(voters[0], false)).to.be.revertedWithCustomError(vote, "NullifierAlreadyUsed");
  });

  it("rejects a voter who is not in the registered list", async function () {
    // The outsider proves membership of a list they made up; its root does not match the contract's.
    const { ballot, zk } = await prepareVote(outsider, true, [...commitments, outsider.commitment]);
    expect(zk.root).to.not.eq(await vote.voterRoot());
    await expect(
      vote.connect(relayer).vote(zk.nullifier, ballot.handles[0], ballot.inputProof, zk.proof),
    ).to.be.revertedWithCustomError(verifier, "ProofInvalid");
  });

  it("rejects a front-runner who reuses a proof with their own ballot", async function () {
    const { zk } = await prepareVote(voters[0], true);
    const forged = await encryptBallot(false);
    await expect(
      vote.connect(relayer).vote(zk.nullifier, forged.handles[0], forged.inputProof, zk.proof),
    ).to.be.revertedWithCustomError(verifier, "ProofInvalid");
  });

  it("rejects a proof made for another poll", async function () {
    // Same voter list and a valid ballot for the other poll, but the proof carries this poll's id.
    const otherPoll = await deployPoll(await vote.voterRoot());
    address = await otherPoll.getAddress();
    const ballot = await encryptBallot(true);
    const zk = proveVote({
      secret: voters[0].secret,
      commitments,
      pollId: await vote.pollId(),
      ballotHash: await otherPoll.ballotHash(ballot.handles[0]),
    });
    await expect(
      otherPoll.connect(relayer).vote(zk.nullifier, ballot.handles[0], ballot.inputProof, zk.proof),
    ).to.be.revertedWithCustomError(verifier, "ProofInvalid");
  });

  it("rejects an unreduced nullifier (nullifier + p) that would allow a second vote", async function () {
    const { ballot, zk } = await prepareVote(voters[0], true);
    await (await vote.connect(relayer).vote(zk.nullifier, ballot.handles[0], ballot.inputProof, zk.proof)).wait();

    const again = await prepareVote(voters[0], true);
    await expect(
      vote
        .connect(relayer)
        .vote(again.zk.nullifier + FIELD_MODULUS, again.ballot.handles[0], again.ballot.inputProof, again.zk.proof),
    ).to.be.revertedWithCustomError(verifier, "PublicInputNotInField");
  });

  it("rejects votes after the deadline", async function () {
    const { ballot, zk } = await prepareVote(voters[0], true);
    await time.increase(DURATION);
    await expect(
      vote.connect(relayer).vote(zk.nullifier, ballot.handles[0], ballot.inputProof, zk.proof),
    ).to.be.revertedWithCustomError(vote, "VotingClosed");
  });
});

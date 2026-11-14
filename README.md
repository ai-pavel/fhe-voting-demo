# FHE Voting Demo

A minimal confidential yes/no vote on [Zama FHEVM](https://docs.zama.ai/protocol). Ballots are encrypted on the client,
tallied on-chain **under encryption**, and only the final totals are ever decrypted.

It comes in two versions:

- **`ConfidentialVote`**: FHE only. Nobody learns _how_ you voted, but your address shows _that_ you voted.
- **`AnonymousConfidentialVote`**: zkSNARK + FHE + MPC. Nobody learns how you voted _or_ which registered voter you are.
  See [Anonymous variant](#anonymous-variant-zksnark--fhe--mpc).

Built on [`fhevm-hardhat-template`](https://github.com/zama-ai/fhevm-hardhat-template).

## How it works

```
voter                      ConfidentialVote                         Zama KMS (threshold)
  │ Enc(true/false) + proof   │                                         │
  ├──────────────────────────►│ yes += asEuint32(b)                     │
  │                           │ no  += asEuint32(!b)                    │
  │                           │ (both counters change every vote)       │
  │                           │                                         │
  │          after deadline:  │ requestTally()                          │
  │                           │   makePubliclyDecryptable(yes, no) ────►│ decrypts ONLY the totals
  │                           │ revealTally(clear, proof) ◄─────────────┤ + signs the result
  │                           │   checkSignatures() — forgeries revert  │
```

| Concern                     | How the demo handles it                                                                                                       |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Ballot privacy              | Ballots are `ebool` ciphertexts. Nobody, including the contract owner, can decrypt an individual vote                         |
| Ballot stuffing (Enc(1000)) | The ballot type is `ebool`, so its value can only be 0 or 1. The input proof binds the ciphertext to this contract and sender |
| Double voting               | `hasVoted[msg.sender]`                                                                                                        |
| Who holds the key           | The Zama KMS uses threshold MPC. Only handles explicitly marked publicly decryptable can be decrypted                         |
| Forged result               | `FHE.checkSignatures` verifies the KMS signatures on-chain                                                                    |

Out of scope for a demo: eligibility lists, coercion resistance or receipt-freeness, and hiding _who_ voted. Voter
addresses are public; only their choices are hidden.

## Anonymous variant: zkSNARK + FHE + MPC

```
voter (off-chain)                                  relayer            AnonymousConfidentialVote
  secret s, registered commitment H(s)
  1. ballot = Enc(yes/no) for the relayer  (FHE)
  2. proof  = "H(s) is in the voter tree,           │                    │
              nullifier = H(s, pollId),             │                    │
              bound to this ballot"   (zkSNARK)     │                    │
  ──── ballot, proof, nullifier ──────────────────► │ vote(...) ───────► │ nullifier unused?
                                                    │                    │ Groth16 verifyProof
                                                    │                    │ yes += b, no += !b  (FHE)
```

Each technique answers a different question:

| Technique                        | Where                                   | What it hides or guarantees                                                     | Trust assumption                                                 |
| -------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| **zkSNARK** (gnark, Groth16)     | `zk/circuit`, generated `Verifier`      | _Who_ voted: proves membership in the voter list without saying which entry     | None beyond the setup below; the proof itself reveals nothing    |
| **FHE** (Zama FHEVM)             | `EncryptedTally`                        | _How_ each person voted: ballots are tallied encrypted, only totals decrypted   | Fewer than the threshold of KMS operators collude                |
| **MPC #1**: trusted setup        | `zkvote ceremony` (gnark `mpcsetup`)    | Nobody holds the Groth16 "toxic waste", which would let them forge voter proofs | **At least one** ceremony participant discarded their randomness |
| **MPC #2**: threshold decryption | Zama KMS (part of FHEVM, not this repo) | Nobody holds the FHE private key                                                | Fewer than _t_ of _n_ KMS operators collude                      |

Note the two different MPC trust models: the ceremony is safe if **1 of N** participants is honest, while the KMS is
safe if **fewer than _t_** operators are dishonest.

How each attack is stopped (all covered by `test/AnonymousConfidentialVote.ts`):

| Attack                                            | Defence                                                                                                          |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Unregistered voter                                | The proof must reach the contract's `voterRoot`                                                                  |
| Voting twice                                      | `nullifier = MiMC(secret, pollId)` is the same every time and is stored as used                                  |
| Voting twice with `nullifier + p`                 | The generated verifier rejects public inputs that are not reduced modulo the BN254 field                         |
| Front-runner copies the proof with its own ballot | The proof is bound to the ballot handle (`ballotHash`); the handle is bound to the sender by the FHE input proof |
| Reusing a proof in another poll                   | `pollId` is the contract address and is a public input                                                           |
| Relayer changes the vote                          | It cannot: the ballot is encrypted and the proof is bound to it                                                  |

### The trusted-setup ceremony

Groth16 needs secret randomness to build its keys, and whoever knows it can forge proofs. The ceremony splits it across
participants: each one loads the previous state, mixes in fresh randomness and forgets it. Every contribution carries a
proof that it builds on the previous one, and a public random beacon seals each phase.

```bash
npm run zk:build
zk/bin/zkvote ceremony init                           # phase 1 (powers of tau) starts
zk/bin/zkvote ceremony contribute --phase 1 --name alice
zk/bin/zkvote ceremony contribute --phase 1 --name bob
zk/bin/zkvote ceremony seal --phase 1 --beacon "<value nobody knew in advance>"
zk/bin/zkvote ceremony contribute --phase 2 --name alice   # phase 2: specific to the vote circuit
zk/bin/zkvote ceremony contribute --phase 2 --name bob
zk/bin/zkvote ceremony seal --phase 2 --beacon "<another beacon value>"
zk/bin/zkvote ceremony verify                         # anyone can replay the transcript and check the keys
```

`npm run zk:setup` runs all of this with alice, bob and carol. The transcript is `zk/build/ceremony/transcript.json`;
sealing phase 2 writes `zk/build/vote.pk`, `zk/build/vote.vk` and the Solidity verifier `contracts/zk/VoteVerifier.sol`.
In this demo all participants run on one machine, so it shows the protocol, not the trust: a real ceremony has
independent people contributing from their own machines.

### Still out of scope

- **Voter registration.** The demo generates every identity in one file (`zk/build/voters.json`). In reality each voter
  generates their own secret with `zkvote identity` and hands only the commitment to the registrar.
- **Network-level privacy.** The relayer sees the voter's IP and timing unless the voter connects through Tor or a
  similar mixnet.
- **Coercion and vote buying.** A voter can still prove how they voted by revealing their secret and encryption
  randomness.

## Quick start (mock mode, no real FHE needed)

Requires Node 20+ and Go 1.26+.

```bash
npm install
npm test          # builds zkvote and runs the demo ceremony first if the keys are missing
npm run zk:test   # Go tests for the circuit
```

## Local CLI walkthrough

```bash
# terminal 1
npx hardhat node

# terminal 2
DURATION_SECONDS=60 npx hardhat --network localhost deploy
npx hardhat --network localhost task:vote --support yes --voter 1
npx hardhat --network localhost task:vote --support no  --voter 2
npx hardhat --network localhost task:vote --support yes --voter 3
npx hardhat --network localhost task:status         # totals are opaque handles
npx hardhat --network localhost task:advance-time --seconds 60
npx hardhat --network localhost task:tally          # Result: yes=2 no=1
```

Anonymous variant, on the same node. `deploy` also creates five voter identities in `zk/build/voters.json`, and every
ballot is submitted by the relayer account:

```bash
npx hardhat --network localhost task:anon-vote --support yes --voter 0
npx hardhat --network localhost task:anon-vote --support no  --voter 1
npx hardhat --network localhost task:anon-vote --support yes --voter 2
npx hardhat --network localhost task:anon-vote --support no  --voter 2   # reverts: NullifierAlreadyUsed
npx hardhat --network localhost task:status --contract AnonymousConfidentialVote
npx hardhat --network localhost task:advance-time --seconds 60
npx hardhat --network localhost task:tally  --contract AnonymousConfidentialVote   # Result: yes=2 no=1
```

## Sepolia (real FHE via the Zama coprocessor)

```bash
npx hardhat vars set MNEMONIC
npx hardhat vars set INFURA_API_KEY
DURATION_SECONDS=600 npx hardhat --network sepolia deploy
npx hardhat --network sepolia task:vote --support yes
# ...wait for the deadline...
npx hardhat --network sepolia task:tally
```

## Files

- `contracts/EncryptedTally.sol`: shared FHE core (encrypted counters, deadline, tally request and reveal)
- `contracts/ConfidentialVote.sol`: FHE-only vote, one ballot per address
- `contracts/AnonymousConfidentialVote.sol`: zk membership proof + FHE ballot, one ballot per nullifier
- `contracts/zk/VoteVerifier.sol`: Groth16 verifier generated by the ceremony (not committed)
- `zk/circuit/`: the gnark circuit (Merkle membership, nullifier, ballot binding) and its Go tests
- `zk/cmd/zkvote/`: CLI for the MPC ceremony, voter identities, the voter root and proving
- `zk/client.ts`: TypeScript wrapper used by the tests, tasks and deploy script
- `test/`: mock-mode tests for both contracts
- `tasks/ConfidentialVote.ts`: CLI tasks `task:vote`, `task:anon-vote`, `task:status`, `task:tally`, `task:advance-time`
- `deploy/`: deployment (`PROPOSAL`, `DURATION_SECONDS`, `VOTER_COUNT` env vars)

## License

BSD-3-Clause-Clear (inherited from the Zama template). See [LICENSE](LICENSE).

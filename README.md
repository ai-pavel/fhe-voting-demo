# FHE Voting Demo

A minimal confidential yes/no vote on [Zama FHEVM](https://docs.zama.ai/protocol). Ballots are encrypted on the client,
tallied on-chain **under encryption**, and only the final totals are ever decrypted.

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

## Quick start (mock mode, no real FHE needed)

```bash
npm install
npm test
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

- `contracts/ConfidentialVote.sol`: the contract
- `test/ConfidentialVote.ts`: mock-mode tests (tally, privacy before reveal, double vote, deadline, forged tally, wrong
  sender)
- `tasks/ConfidentialVote.ts`: CLI tasks `task:vote`, `task:status`, `task:tally`, `task:advance-time`
- `deploy/deploy.ts`: deployment (`PROPOSAL`, `DURATION_SECONDS` env vars)

## License

BSD-3-Clause-Clear (inherited from the Zama template). See [LICENSE](LICENSE).

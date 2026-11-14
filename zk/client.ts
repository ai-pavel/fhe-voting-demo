import { execFileSync } from "child_process";
import path from "path";

// Thin wrapper around the Go `zkvote` binary (built by `npm run zk:build`). In a real dApp the prover would run
// in the voter's browser (gnark compiles to WASM); shelling out keeps the demo simple.

const ROOT = path.resolve(__dirname, "..");
const BIN = path.join(ROOT, "zk", "bin", "zkvote");

// Demo shortcut: the deploy script generates every voter identity into one file. In reality each voter generates
// their own secret (`zkvote identity`) and hands only the commitment to the registrar.
export const VOTERS_FILE = path.join(ROOT, "zk", "build", "voters.json");

function zkvote<T>(args: string[], input?: unknown): T {
  const out = execFileSync(BIN, args, {
    cwd: ROOT,
    input: input === undefined ? undefined : JSON.stringify(input),
    stdio: ["pipe", "pipe", "pipe"],
  });
  return JSON.parse(out.toString()) as T;
}

/** A voter identity: the secret never leaves the voter, the commitment goes to the registrar. */
export type Identity = { secret: string; commitment: string };

export type VoteProof = { root: bigint; nullifier: bigint; proof: string };

export function newIdentities(count: number): Identity[] {
  return zkvote<Identity[]>(["identity", "--count", String(count)]);
}

/** Merkle root of the voter list, as stored in the contract. */
export function voterRoot(commitments: string[]): bigint {
  return BigInt(zkvote<{ root: string }>(["root"], commitments).root);
}

/** Prove "I own one of these commitments" for one poll, bound to one encrypted ballot. */
export function proveVote(args: {
  secret: string;
  commitments: string[];
  pollId: bigint;
  ballotHash: bigint;
}): VoteProof {
  const res = zkvote<{ root: string; nullifier: string; proof: string }>(["prove"], {
    secret: args.secret,
    commitments: args.commitments,
    pollId: args.pollId.toString(),
    ballotHash: args.ballotHash.toString(),
  });
  return { root: BigInt(res.root), nullifier: BigInt(res.nullifier), proof: res.proof };
}

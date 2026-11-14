// Package circuit defines the zkSNARK that lets a registered voter cast a ballot anonymously.
//
// The prover shows, without revealing which voter they are, that:
//  1. they know a Secret whose commitment MiMC(Secret) is a leaf of the voter Merkle tree with root Root;
//  2. Nullifier = MiMC(Secret, PollID), so each voter gets exactly one nullifier per poll;
//  3. the proof is bound to BallotHash, the handle of the FHE-encrypted ballot submitted alongside it.
//
// Root, Nullifier, PollID and BallotHash are public inputs; Secret and the Merkle path stay private.
package circuit

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativemimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Depth of the voter Merkle tree: up to 2^Depth registered voters.
const Depth = 4

// MaxVoters is the capacity of the voter tree.
const MaxVoters = 1 << Depth

// VoteCircuit is the statement proven by each voter. Public inputs are ordered as declared,
// which must match the order the Solidity verifier receives them in.
type VoteCircuit struct {
	Root       frontend.Variable `gnark:",public"`
	Nullifier  frontend.Variable `gnark:",public"`
	PollID     frontend.Variable `gnark:",public"`
	BallotHash frontend.Variable `gnark:",public"`

	Secret   frontend.Variable
	Path     [Depth]frontend.Variable // sibling hashes from leaf to root
	PathBits [Depth]frontend.Variable // 1 if the current node is the right child
}

func (c *VoteCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hash := func(xs ...frontend.Variable) frontend.Variable {
		h.Reset()
		h.Write(xs...)
		return h.Sum()
	}

	node := hash(c.Secret)
	for i := 0; i < Depth; i++ {
		api.AssertIsBoolean(c.PathBits[i])
		left := api.Select(c.PathBits[i], c.Path[i], node)
		right := api.Select(c.PathBits[i], node, c.Path[i])
		node = hash(left, right)
	}
	api.AssertIsEqual(node, c.Root)

	api.AssertIsEqual(hash(c.Secret, c.PollID), c.Nullifier)

	// Bind the proof to the encrypted ballot so a front-runner cannot replay it with their own ballot.
	// A public input that appears in no constraint gets a zero point in the verifying key and is not
	// bound at all, so it is squared into a dummy constraint (the same trick Semaphore uses).
	api.Mul(c.BallotHash, c.BallotHash)
	return nil
}

var errTooManyVoters = errors.New("too many voters for the tree depth")

// Compile builds the R1CS for VoteCircuit over BN254.
func Compile() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &VoteCircuit{})
}

// Hash computes MiMC over field elements, matching the in-circuit hash.
func Hash(xs ...*big.Int) *big.Int {
	h := nativemimc.NewMiMC()
	for _, x := range xs {
		var e fr.Element
		e.SetBigInt(x)
		b := e.Bytes()
		h.Write(b[:])
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// Tree is the voter registry: leaves are identity commitments, padded with zeros up to MaxVoters.
type Tree struct {
	levels [][]*big.Int // levels[0] = leaves, levels[Depth] = [root]
}

// NewTree builds the Merkle tree over the given commitments.
func NewTree(commitments []*big.Int) (*Tree, error) {
	if len(commitments) > MaxVoters {
		return nil, errTooManyVoters
	}
	leaves := make([]*big.Int, MaxVoters)
	for i := range leaves {
		if i < len(commitments) {
			leaves[i] = commitments[i]
		} else {
			leaves[i] = big.NewInt(0)
		}
	}
	levels := [][]*big.Int{leaves}
	for d := 0; d < Depth; d++ {
		prev := levels[d]
		next := make([]*big.Int, len(prev)/2)
		for i := range next {
			next[i] = Hash(prev[2*i], prev[2*i+1])
		}
		levels = append(levels, next)
	}
	return &Tree{levels: levels}, nil
}

// Root of the tree.
func (t *Tree) Root() *big.Int { return t.levels[Depth][0] }

// Path returns the sibling hashes and direction bits for the leaf at index.
func (t *Tree) Path(index int) (path [Depth]*big.Int, bits [Depth]int) {
	for d := 0; d < Depth; d++ {
		bits[d] = index & 1
		path[d] = t.levels[d][index^1]
		index >>= 1
	}
	return path, bits
}

// Assignment builds a full witness for the voter at index.
func (t *Tree) Assignment(secret *big.Int, index int, pollID, ballotHash *big.Int) *VoteCircuit {
	path, bits := t.Path(index)
	a := &VoteCircuit{
		Root:       t.Root(),
		Nullifier:  Hash(secret, pollID),
		PollID:     pollID,
		BallotHash: ballotHash,
		Secret:     secret,
	}
	for i := 0; i < Depth; i++ {
		a.Path[i] = path[i]
		a.PathBits[i] = bits[i]
	}
	return a
}

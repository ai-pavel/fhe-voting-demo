package circuit

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func randomSecret(t *testing.T) *big.Int {
	s, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVoteCircuit(t *testing.T) {
	ccs, err := Compile()
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}

	secrets := make([]*big.Int, 5)
	commitments := make([]*big.Int, len(secrets))
	for i := range secrets {
		secrets[i] = randomSecret(t)
		commitments[i] = Hash(secrets[i])
	}
	tree, err := NewTree(commitments)
	if err != nil {
		t.Fatal(err)
	}

	pollID := big.NewInt(42)
	ballot := big.NewInt(1234)
	assignment := tree.Assignment(secrets[3], 3, pollID, ballot)

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatal(err)
	}

	verify := func(mutate func(a *VoteCircuit)) error {
		pub := *assignment
		mutate(&pub)
		w, err := frontend.NewWitness(&pub, ecc.BN254.ScalarField(), frontend.PublicOnly())
		if err != nil {
			t.Fatal(err)
		}
		return groth16.Verify(proof, vk, w)
	}

	if err := verify(func(*VoteCircuit) {}); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	if verify(func(a *VoteCircuit) { a.BallotHash = big.NewInt(9999) }) == nil {
		t.Fatal("proof verified for a different ballot")
	}
	if verify(func(a *VoteCircuit) { a.Nullifier = big.NewInt(7) }) == nil {
		t.Fatal("proof verified for a different nullifier")
	}
	if verify(func(a *VoteCircuit) { a.PollID = big.NewInt(43) }) == nil {
		t.Fatal("proof verified for a different poll")
	}

	outsider := tree.Assignment(randomSecret(t), 3, pollID, ballot)
	w, err := frontend.NewWitness(outsider, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groth16.Prove(ccs, pk, w); err == nil {
		t.Fatal("non-member produced a proof")
	}
}

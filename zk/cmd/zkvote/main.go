// Command zkvote is the off-chain half of the anonymous confidential vote:
//
//	zkvote ceremony ...  run the Groth16 trusted setup as a multi-party ceremony (see ceremony.go)
//	zkvote identity      create voter identities (secret + public commitment)
//	zkvote root          compute the voter-registry Merkle root from commitments (JSON on stdin)
//	zkvote prove         prove membership for one vote (JSON on stdin, JSON on stdout)
//
// Numbers are exchanged as decimal strings; the proof is hex in the layout the Solidity verifier expects.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"

	"zk-voting/zk/circuit"
)

func main() {
	logger.Disable()
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: zkvote <ceremony|identity|root|prove> [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "ceremony":
		err = runCeremony(os.Args[2:])
	case "identity":
		err = runIdentity(os.Args[2:])
	case "root":
		err = runRoot()
	case "prove":
		err = runProve(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type identity struct {
	Secret     string `json:"secret"`
	Commitment string `json:"commitment"`
}

// runIdentity creates fresh voter identities. The voter keeps the secret; only the commitment is
// handed to the registrar.
func runIdentity(args []string) error {
	fs := flag.NewFlagSet("identity", flag.ExitOnError)
	count := fs.Int("count", 1, "number of identities")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ids := make([]identity, *count)
	for i := range ids {
		secret, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
		if err != nil {
			return err
		}
		ids[i] = identity{Secret: secret.String(), Commitment: circuit.Hash(secret).String()}
	}
	return json.NewEncoder(os.Stdout).Encode(ids)
}

func runRoot() error {
	var commitments []string
	if err := json.NewDecoder(os.Stdin).Decode(&commitments); err != nil {
		return err
	}
	tree, err := buildTree(commitments)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"root": tree.Root().String()})
}

type proveRequest struct {
	Secret      string   `json:"secret"`
	Commitments []string `json:"commitments"`
	PollID      string   `json:"pollId"`
	BallotHash  string   `json:"ballotHash"`
}

type proveResponse struct {
	Root      string `json:"root"`
	Nullifier string `json:"nullifier"`
	Proof     string `json:"proof"`
}

func runProve(args []string) error {
	fs := flag.NewFlagSet("prove", flag.ExitOnError)
	pkPath := fs.String("pk", "zk/build/vote.pk", "proving key from the ceremony")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var req proveRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return err
	}
	secret, err := parseInt(req.Secret)
	if err != nil {
		return err
	}
	pollID, err := parseInt(req.PollID)
	if err != nil {
		return err
	}
	ballotHash, err := parseInt(req.BallotHash)
	if err != nil {
		return err
	}
	tree, err := buildTree(req.Commitments)
	if err != nil {
		return err
	}
	index := -1
	commitment := circuit.Hash(secret).String()
	for i, c := range req.Commitments {
		if c == commitment {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("secret is not registered in the voter list")
	}

	ccs, err := circuit.Compile()
	if err != nil {
		return err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := readObject(*pkPath, pk); err != nil {
		return fmt.Errorf("reading proving key (run the ceremony first): %w", err)
	}
	assignment := tree.Assignment(secret, index, pollID, ballotHash)
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(proveResponse{
		Root:      tree.Root().String(),
		Nullifier: assignment.Nullifier.(*big.Int).String(),
		Proof:     "0x" + hex.EncodeToString(proof.(*groth16bn254.Proof).MarshalSolidity()),
	})
}

func buildTree(commitments []string) (*circuit.Tree, error) {
	leaves := make([]*big.Int, len(commitments))
	for i, c := range commitments {
		v, err := parseInt(c)
		if err != nil {
			return nil, err
		}
		leaves[i] = v
	}
	return circuit.NewTree(leaves)
}

// parseInt accepts decimal or 0x-prefixed hex and requires a canonical BN254 field element.
func parseInt(s string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(s, 0)
	if !ok || v.Sign() < 0 || v.Cmp(ecc.BN254.ScalarField()) >= 0 {
		return nil, fmt.Errorf("%q is not a BN254 field element", s)
	}
	return v, nil
}

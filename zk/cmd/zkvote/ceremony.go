package main

// Groth16 trusted setup as a multi-party computation (MPC ceremony).
//
// Groth16 needs secret randomness (tau, alpha, beta, delta) to build its keys. Whoever knows that "toxic
// waste" can forge proofs: here, cast votes without being a registered voter. In the ceremony each
// participant mixes in their own random contribution and then forgets it. The final keys are safe as long
// as at least ONE participant was honest and discarded their randomness (1-of-N trust).
//
// Phase 1 (powers of tau) is circuit-independent; phase 2 specialises it to VoteCircuit. Every contribution
// carries a proof that it was built on top of the previous one, so anyone can re-verify the whole transcript
// with `zkvote ceremony verify`. A public random beacon seals each phase so the last contributor cannot
// bias the result.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/backend/solidity"
	cs "github.com/consensys/gnark/constraint/bn254"

	"fhe-voting-demo/zk/circuit"
)

type contribution struct {
	Name string `json:"name"`
	File string `json:"file"`
	Hash string `json:"sha256"`
}

type transcript struct {
	DomainSize uint64         `json:"domainSize"`
	Phase1     []contribution `json:"phase1"`
	Beacon1    string         `json:"beacon1,omitempty"`
	Phase2     []contribution `json:"phase2"`
	Beacon2    string         `json:"beacon2,omitempty"`
	VKHash     string         `json:"vkSha256,omitempty"`
}

type ceremony struct {
	dir string // holds transcript.json and the contribution files
	out string // holds the final proving and verifying keys
	sol string // generated Solidity verifier
}

func runCeremony(args []string) error {
	fs := flag.NewFlagSet("ceremony", flag.ExitOnError)
	out := fs.String("out", "zk/build", "output directory for keys and the ceremony transcript")
	sol := fs.String("sol", "contracts/zk/VoteVerifier.sol", "where to write the Solidity verifier")
	name := fs.String("name", "", "contributor name (contribute)")
	phase := fs.Int("phase", 0, "1 or 2 (contribute, seal)")
	beacon := fs.String("beacon", "", "public random beacon value (seal)")
	participants := fs.String("participants", "alice,bob,carol", "comma-separated contributors (demo)")
	ifMissing := fs.Bool("if-missing", false, "skip the demo if keys already exist (demo)")
	if len(args) == 0 {
		return errors.New("usage: zkvote ceremony <init|contribute|seal|verify|demo> [flags]")
	}
	sub := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	c := ceremony{dir: filepath.Join(*out, "ceremony"), out: *out, sol: *sol}

	switch sub {
	case "init":
		return c.init()
	case "contribute":
		return c.contribute(*phase, *name)
	case "seal":
		return c.seal(*phase, *beacon)
	case "verify":
		return c.verify()
	case "demo":
		if *ifMissing && fileExists(filepath.Join(*out, "vote.pk")) && fileExists(*sol) {
			fmt.Println("keys already exist, skipping ceremony")
			return nil
		}
		return c.demo(strings.Split(*participants, ","))
	}
	return fmt.Errorf("unknown ceremony command %q", sub)
}

func (c ceremony) demo(names []string) error {
	steps := []func() error{c.init}
	for _, n := range names {
		steps = append(steps, func() error { return c.contribute(1, n) })
	}
	// In a real ceremony the beacon is a value nobody knows in advance, e.g. a future block hash or a
	// League of Entropy drand round, fixed after the last contribution.
	steps = append(steps, func() error { return c.seal(1, "demo beacon phase 1") })
	for _, n := range names {
		steps = append(steps, func() error { return c.contribute(2, n) })
	}
	steps = append(steps, func() error { return c.seal(2, "demo beacon phase 2") }, c.verify)
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func (c ceremony) init() error {
	r1cs, err := compileR1CS()
	if err != nil {
		return err
	}
	if err := os.RemoveAll(c.dir); err != nil {
		return err
	}
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return err
	}
	domain := ecc.NextPowerOfTwo(uint64(r1cs.GetNbConstraints()))
	fmt.Printf("circuit: %d constraints, domain size %d\n", r1cs.GetNbConstraints(), domain)
	if _, err := writeObject(filepath.Join(c.dir, "phase1-0000-init.bin"), mpcsetup.NewPhase1(domain)); err != nil {
		return err
	}
	return c.saveTranscript(&transcript{DomainSize: domain})
}

func (c ceremony) contribute(phase int, name string) error {
	if name == "" {
		return errors.New("--name is required")
	}
	t, err := c.loadTranscript()
	if err != nil {
		return err
	}
	var (
		obj interface {
			io.ReaderFrom
			io.WriterTo
		}
		list *[]contribution
		base string
	)
	switch phase {
	case 1:
		if t.Beacon1 != "" {
			return errors.New("phase 1 is already sealed")
		}
		obj, list, base = new(mpcsetup.Phase1), &t.Phase1, "phase1-0000-init.bin"
	case 2:
		if t.Beacon1 == "" {
			return errors.New("seal phase 1 first")
		}
		if t.Beacon2 != "" {
			return errors.New("phase 2 is already sealed")
		}
		obj, list, base = new(mpcsetup.Phase2), &t.Phase2, "phase2-0000-init.bin"
	default:
		return errors.New("--phase must be 1 or 2")
	}
	if n := len(*list); n > 0 {
		base = (*list)[n-1].File
	}
	if err := readObject(filepath.Join(c.dir, base), obj); err != nil {
		return err
	}

	// Contribute samples fresh randomness, applies it and drops it when the process exits.
	// That forgetting is the entire security of the ceremony.
	switch p := obj.(type) {
	case *mpcsetup.Phase1:
		p.Contribute()
	case *mpcsetup.Phase2:
		p.Contribute()
	}

	file := fmt.Sprintf("phase%d-%04d-%s.bin", phase, len(*list)+1, name)
	hash, err := writeObject(filepath.Join(c.dir, file), obj)
	if err != nil {
		return err
	}
	*list = append(*list, contribution{Name: name, File: file, Hash: hash})
	fmt.Printf("phase %d: %s contributed, sha256 %s\n", phase, name, hash)
	return c.saveTranscript(t)
}

func (c ceremony) seal(phase int, beacon string) error {
	if beacon == "" {
		return errors.New("--beacon is required")
	}
	t, err := c.loadTranscript()
	if err != nil {
		return err
	}
	switch phase {
	case 1:
		commons, err := c.verifyPhase1(t, beacon)
		if err != nil {
			return err
		}
		if _, err := writeObject(filepath.Join(c.dir, "commons.bin"), &commons); err != nil {
			return err
		}
		r1cs, err := compileR1CS()
		if err != nil {
			return err
		}
		var p2 mpcsetup.Phase2
		p2.Initialize(r1cs, &commons)
		if _, err := writeObject(filepath.Join(c.dir, "phase2-0000-init.bin"), &p2); err != nil {
			return err
		}
		t.Beacon1 = beacon
		fmt.Printf("phase 1 sealed after %d contributions\n", len(t.Phase1))
	case 2:
		if t.Beacon1 == "" {
			return errors.New("seal phase 1 first")
		}
		pk, vk, err := c.verifyPhase2(t, beacon)
		if err != nil {
			return err
		}
		if _, err := writeObject(filepath.Join(c.out, "vote.pk"), pk); err != nil {
			return err
		}
		if t.VKHash, err = writeObject(filepath.Join(c.out, "vote.vk"), vk); err != nil {
			return err
		}
		if err := c.exportSolidity(vk); err != nil {
			return err
		}
		t.Beacon2 = beacon
		fmt.Printf("phase 2 sealed after %d contributions; keys in %s, verifier in %s\n", len(t.Phase2), c.out, c.sol)
	default:
		return errors.New("--phase must be 1 or 2")
	}
	return c.saveTranscript(t)
}

// verify replays the whole transcript from scratch, as any outside observer could, and checks that it
// yields exactly the published verifying key.
func (c ceremony) verify() error {
	t, err := c.loadTranscript()
	if err != nil {
		return err
	}
	if t.Beacon2 == "" {
		return errors.New("ceremony is not finished")
	}
	commons, err := c.verifyPhase1(t, t.Beacon1)
	if err != nil {
		return err
	}
	if err := writeAndCompare(filepath.Join(c.dir, "commons.bin"), &commons); err != nil {
		return err
	}
	_, vk, err := c.verifyPhase2(t, t.Beacon2)
	if err != nil {
		return err
	}
	if err := writeAndCompare(filepath.Join(c.out, "vote.vk"), vk); err != nil {
		return err
	}
	fmt.Printf("transcript verified: %d + %d contributions reproduce vote.vk (sha256 %s)\n",
		len(t.Phase1), len(t.Phase2), t.VKHash)
	return nil
}

func (c ceremony) verifyPhase1(t *transcript, beacon string) (mpcsetup.SrsCommons, error) {
	contribs := make([]*mpcsetup.Phase1, len(t.Phase1))
	for i, ct := range t.Phase1 {
		contribs[i] = new(mpcsetup.Phase1)
		if err := c.readContribution(ct, contribs[i]); err != nil {
			return mpcsetup.SrsCommons{}, err
		}
	}
	commons, err := mpcsetup.VerifyPhase1(t.DomainSize, []byte(beacon), contribs...)
	if err != nil {
		return commons, fmt.Errorf("phase 1 transcript invalid: %w", err)
	}
	return commons, nil
}

func (c ceremony) verifyPhase2(t *transcript, beacon string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	var commons mpcsetup.SrsCommons
	if err := readObject(filepath.Join(c.dir, "commons.bin"), &commons); err != nil {
		return nil, nil, err
	}
	contribs := make([]*mpcsetup.Phase2, len(t.Phase2))
	for i, ct := range t.Phase2 {
		contribs[i] = new(mpcsetup.Phase2)
		if err := c.readContribution(ct, contribs[i]); err != nil {
			return nil, nil, err
		}
	}
	r1cs, err := compileR1CS()
	if err != nil {
		return nil, nil, err
	}
	pk, vk, err := mpcsetup.VerifyPhase2(r1cs, &commons, []byte(beacon), contribs...)
	if err != nil {
		return nil, nil, fmt.Errorf("phase 2 transcript invalid: %w", err)
	}
	return pk, vk, nil
}

func (c ceremony) readContribution(ct contribution, obj io.ReaderFrom) error {
	path := filepath.Join(c.dir, ct.File)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != ct.Hash {
		return fmt.Errorf("%s does not match its transcript hash", ct.File)
	}
	_, err = obj.ReadFrom(bytes.NewReader(data))
	return err
}

func (c ceremony) exportSolidity(vk groth16.VerifyingKey) error {
	if err := os.MkdirAll(filepath.Dir(c.sol), 0o755); err != nil {
		return err
	}
	f, err := os.Create(c.sol)
	if err != nil {
		return err
	}
	defer f.Close()
	return vk.ExportSolidity(f, solidity.WithPragmaVersion("^0.8.24"))
}

func (c ceremony) loadTranscript() (*transcript, error) {
	data, err := os.ReadFile(filepath.Join(c.dir, "transcript.json"))
	if err != nil {
		return nil, fmt.Errorf("no ceremony in progress (run `zkvote ceremony init`): %w", err)
	}
	var t transcript
	return &t, json.Unmarshal(data, &t)
}

func (c ceremony) saveTranscript(t *transcript) error {
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.dir, "transcript.json"), append(data, '\n'), 0o644)
}

func compileR1CS() (*cs.R1CS, error) {
	ccs, err := circuit.Compile()
	if err != nil {
		return nil, err
	}
	return ccs.(*cs.R1CS), nil
}

// writeObject serialises obj to path and returns the sha256 of what was written.
func writeObject(path string, obj io.WriterTo) (string, error) {
	var buf bytes.Buffer
	if _, err := obj.WriteTo(&buf); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:]), os.WriteFile(path, buf.Bytes(), 0o644)
}

func readObject(path string, obj io.ReaderFrom) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = obj.ReadFrom(f)
	return err
}

func writeAndCompare(path string, obj io.WriterTo) error {
	var buf bytes.Buffer
	if _, err := obj.WriteTo(&buf); err != nil {
		return err
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(stored, buf.Bytes()) {
		return fmt.Errorf("%s does not match the transcript", path)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

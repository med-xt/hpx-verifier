// verify checks an hpx/1 evidence bundle offline.
//
// This is what an auditor runs. It makes no network call, needs no service, no
// account and no licence check, and it does not care whether the organisation
// that produced the records still exists. Give it a bundle and a public key
// registry and it answers.
//
// Exit codes are the interface:
//
//	0  the bundle verifies
//	1  the bundle does not verify, and every problem is named
//	2  the tool could not run, which is a different thing entirely
//
// That last distinction matters more than it looks. A verifier that returns
// "failed" when it merely could not read a file has told an auditor that
// evidence is bad when the truth is that the tool is broken. Those must never
// share an exit code.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/med-xt/hpx-verifier"
	"github.com/med-xt/hpx-verifier/mldsa"
)

const usage = `verify, hpx/1 evidence verifier

  verify --bundle BUNDLE.json [--keys KEYS.json] [flags]

  verify --checkpoint NOW.txt --against EARLIER.txt --proof PROOF.json --keys KEYS.json

Flags:
  --bundle   the evidence bundle to check
  --keys     the public key registry. Optional when the bundle carries its own
             keys, which an exported audit bundle does. Supplying it anyway
             overrides them, which is what a reviewer who got the registry from
             somewhere other than the party under review should do.
  --explain  print every check as it runs, rather than only the verdict
  --json     emit the result as JSON, for a pipeline rather than a person
  --structural
             skip signature checking. Digests, the chain, the Merkle path and
             key resolution still run. Useful on a machine with no
             post-quantum library, and honest about what it did not check.

  --checkpoint
             a signed checkpoint to verify. A bundle that carries one is
             checked automatically; this is for checking one on its own.
  --against  an earlier checkpoint for the same log. With --proof, verifies
             that the log now contains the log then, unchanged.
  --proof    a consistency proof, a JSON array of hex hashes.
  --log-key  the key id belonging to the log itself, for the quorum check.
  --witnesses
             how many signatures from keys other than the log are required
             before a checkpoint counts as independently anchored. Default 0,
             which checks signatures and asserts nothing about independence.

Exit codes:
  0  verifies
  1  does not verify
  2  could not run

It makes no network call and depends on no service.
`

func main() {
	var (
		bundlePath = flag.String("bundle", "", "path to the evidence bundle")
		keysPath   = flag.String("keys", "", "path to the public key registry")
		explain    = flag.Bool("explain", false, "print every check as it runs")
		asJSON     = flag.Bool("json", false, "emit the result as JSON")
		structural = flag.Bool("structural", false, "skip signature checking")

		checkpointPath = flag.String("checkpoint", "", "a signed checkpoint to verify on its own")
		againstPath    = flag.String("against", "", "an earlier checkpoint for the same log")
		proofPath      = flag.String("proof", "", "a consistency proof, JSON array of hex hashes")
		logKeyID       = flag.String("log-key", "", "the key id belonging to the log itself")
		witnesses      = flag.Int("witnesses", 0, "independent signatures required")
	)
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if *bundlePath == "" && *checkpointPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	var sigForCheckpoint verify.SignatureVerifier
	if !*structural {
		sigForCheckpoint = mldsa.New()
	}

	// Checkpoints on their own. This is the mode a reviewer uses with two text
	// files and no access to the log at all, which is the asymmetry the whole
	// design is built on. It needs a key registry: a checkpoint is not
	// self-describing and must not be.
	if *checkpointPath != "" && *bundlePath == "" {
		if *keysPath == "" {
			fail("a key registry is required to check a checkpoint, pass --keys")
		}
		reg := loadKeys(*keysPath)
		checkpointMode(*checkpointPath, *againstPath, *proofPath, *logKeyID, *witnesses, reg, sigForCheckpoint)
		return
	}

	bundleRaw, err := os.ReadFile(*bundlePath)
	if err != nil {
		fail("cannot read the bundle: %v", err)
	}

	var b verify.Bundle
	if err := json.Unmarshal(bundleRaw, &b); err != nil {
		fail("bundle will not parse: %v", err)
	}
	if len(b.Records) == 0 {
		fail("bundle contains no records")
	}

	// Keys come from the bundle when it carries them, which is what makes a
	// bundle sufficient on its own. An explicit --keys still wins: a reviewer
	// who obtained the registry from somewhere other than the party under
	// review should be able to use that copy instead, and that is the whole
	// point of being able to.
	var reg *verify.Registry
	switch {
	case *keysPath != "":
		reg = loadKeys(*keysPath)
	case len(b.Keys) > 0:
		reg, err = verify.LoadRegistry(b.Keys)
		if err != nil {
			fail("the keys carried in the bundle will not load: %v", err)
		}
	default:
		fail("no keys. The bundle carries none, so pass --keys with the public key registry")
	}

	sig := sigForCheckpoint

	if *explain {
		explainRun(&b, reg, sig, *structural)
	}

	res := verify.VerifyBundle(&b, reg, sig)

	// A checkpoint the bundle carries is checked here rather than left to a
	// separate invocation. A reviewer who has to know to run a second command
	// will not run it.
	cp, cpProblems := verify.VerifyBundleCheckpoint(&b, reg, sig)
	res.Problems = append(res.Problems, cpProblems...)
	res.OK = len(res.Problems) == 0

	if *logKeyID != "" && *witnesses > 0 && cp.Present {
		if ok, reason := verify.MeetsQuorum(verify.CheckpointResult{OK: cp.Verified, SignedBy: cp.SignedBy}, *logKeyID, *witnesses); !ok {
			res.Problems = append(res.Problems, verify.Problem{Record: -1, Code: verify.CodeCheckpointInvalid, Detail: reason})
			res.OK = false
		}
	}

	if *asJSON {
		out := struct {
			verify.Result
			Episode           string                   `json:"episode"`
			SignaturesChecked bool                     `json:"signaturesChecked"`
			LogRootChecked    bool                     `json:"logRootChecked"`
			Anchoring         verify.CheckpointOutcome `json:"anchoring"`
		}{res, b.Episode, !*structural, b.LogRoot != "", cp}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		report(&b, res, *structural, cp)
	}

	if res.OK {
		os.Exit(0)
	}
	os.Exit(1)
}

func loadKeys(path string) *verify.Registry {
	raw, err := os.ReadFile(path)
	if err != nil {
		fail("cannot read the key registry: %v", err)
	}
	reg, err := verify.LoadRegistry(raw)
	if err != nil {
		fail("%v", err)
	}
	return reg
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "verify: "+format+"\n", args...)
	os.Exit(2)
}

// checkpointMode verifies checkpoints with no bundle in sight.
//
// This is the mode that matters most and costs least. Two checkpoints and a
// proof are a few hundred bytes of text, and with them a reviewer can establish
// that the log did or did not rewrite its own history without any access to the
// log, any cooperation from its operator, and any of the records.
func checkpointMode(path, againstPath, proofPath, logKeyID string, witnesses int, reg *verify.Registry, sig verify.SignatureVerifier) {
	now, err := os.ReadFile(path)
	if err != nil {
		fail("cannot read the checkpoint: %v", err)
	}
	res := verify.VerifyCheckpoint(string(now), reg, sig)
	if res.Checkpoint == nil {
		fmt.Printf("DOES NOT VERIFY  the checkpoint will not parse\n\n")
		for _, p := range res.Problems {
			fmt.Printf("  %s\n", p)
		}
		os.Exit(1)
	}

	cp := res.Checkpoint
	problems := append([]string{}, res.Problems...)

	fmt.Printf("checkpoint  %s\n", filepath.Base(path))
	fmt.Printf("origin      %s\n", cp.Origin)
	fmt.Printf("size        %d records\n", cp.Size)
	fmt.Printf("root        %s\n", cp.Root)
	fmt.Printf("time        %s\n", cp.Time)
	if len(res.SignedBy) == 0 {
		fmt.Printf("signed by   nothing that verifies\n")
	}
	for _, s := range res.SignedBy {
		who := s.Owner
		if who == "" {
			who = "owner not named in the registry"
		}
		fmt.Printf("signed by   %s#%d  %s\n", s.KeyID, s.Version, who)
	}
	fmt.Println()

	// The consistency check. Without --against this tool has verified a
	// signature and nothing about history, and it says so rather than letting a
	// signature check read like continuity.
	if againstPath == "" {
		fmt.Println("No earlier checkpoint supplied, so nothing about this log's history was")
		fmt.Println("checked. A valid signature says the log made this statement. It does not")
		fmt.Println("say the log has not been rebuilt. Pass --against and --proof for that.")
	} else {
		earlier, err := os.ReadFile(againstPath)
		if err != nil {
			fail("cannot read the earlier checkpoint: %v", err)
		}
		prior := verify.VerifyCheckpoint(string(earlier), reg, sig)
		if prior.Checkpoint == nil {
			fail("the earlier checkpoint will not parse")
		}
		problems = append(problems, prior.Problems...)
		// An origin mismatch means these are two different logs, and comparing
		// them establishes nothing whatever the arithmetic says.
		if prior.Checkpoint.Origin != cp.Origin {
			fail("these are checkpoints for different logs, %q and %q", prior.Checkpoint.Origin, cp.Origin)
		}

		var proof []string
		if proofPath != "" {
			raw, err := os.ReadFile(proofPath)
			if err != nil {
				fail("cannot read the proof: %v", err)
			}
			if err := json.Unmarshal(raw, &proof); err != nil {
				fail("the proof is not a JSON array of hex hashes: %v", err)
			}
		}

		c := verify.VerifyConsistency(prior.Checkpoint.Root, prior.Checkpoint.Size, cp.Root, cp.Size, proof)
		fmt.Printf("earlier     %d records at %s\n", prior.Checkpoint.Size, prior.Checkpoint.Time)
		if c.OK {
			fmt.Printf("CONSISTENT  the log of %d records contains the log of %d, unchanged\n",
				cp.Size, prior.Checkpoint.Size)
		} else {
			fmt.Printf("INCONSISTENT  %s\n", c.Reason)
			problems = append(problems, c.Reason)
		}
	}

	if logKeyID != "" && witnesses > 0 {
		if ok, reason := verify.MeetsQuorum(res, logKeyID, witnesses); ok {
			noun := "independent signatures"
			if witnesses == 1 {
				noun = "independent signature"
			}
			fmt.Printf("ANCHORED    %d %s, as required\n", witnesses, noun)
		} else {
			fmt.Printf("NOT ANCHORED  %s\n", reason)
			problems = append(problems, reason)
		}
	}

	if len(problems) > 0 {
		fmt.Println()
		for _, p := range problems {
			fmt.Printf("  %s\n", p)
		}
		os.Exit(1)
	}
	os.Exit(0)
}

func report(b *verify.Bundle, res verify.Result, structural bool, cp verify.CheckpointOutcome) {
	if res.OK {
		fmt.Printf("VERIFIES  %d records", res.Records)
		if b.Episode != "" {
			fmt.Printf(", episode %s", b.Episode)
		}
		fmt.Println()
		fmt.Printf("          chain intact, every record links to its predecessor\n")
		if b.LogRoot != "" {
			fmt.Printf("          every record included under the published log root\n")
		} else {
			fmt.Printf("          no log root supplied, inclusion was not checked\n")
		}
		if structural {
			// Never let a structural pass read like a full pass. An auditor who
			// skims this line and reports "verified" has reported something
			// this run did not establish.
			fmt.Printf("          signatures NOT checked, this was a structural run only\n")
		} else {
			fmt.Printf("          every signature verifies over the canonical payload\n")
		}
		// Said either way. A bundle with no checkpoint is still a valid bundle,
		// and a reviewer needs to know which of the two they are holding: one
		// whose log root a third party attested, or one whose log root the
		// operator computed and nobody else has ever seen.
		if cp.Present && cp.Verified {
			fmt.Printf("          log root published at size %d, checkpoint signed by %d key(s)\n", cp.Size, len(cp.SignedBy))
		} else if !cp.Present {
			fmt.Printf("          no checkpoint supplied, the log's history was not checked\n")
		}
		return
	}

	fmt.Printf("DOES NOT VERIFY  %d records, %d problems\n\n", res.Records, len(res.Problems))
	for _, p := range res.Problems {
		fmt.Printf("  %s\n", p)
	}
	fmt.Println()
	fmt.Println("Each problem names the record by its position in the chain and the")
	fmt.Println("check that failed. A digest or signature failure means the record was")
	fmt.Println("altered after signing. A chain or sequence failure means a record was")
	fmt.Println("moved, removed or inserted.")
}

func explainRun(b *verify.Bundle, reg *verify.Registry, sig verify.SignatureVerifier, structural bool) {
	fmt.Printf("bundle    %s\n", filepath.Base(flagValue("bundle")))
	fmt.Printf("episode   %s\n", b.Episode)
	fmt.Printf("records   %d\n", len(b.Records))
	fmt.Printf("keys      %d in the registry\n", reg.Len())
	if structural {
		fmt.Printf("mode      structural, signatures are not checked\n")
	} else {
		fmt.Printf("mode      full, including signatures\n")
	}
	fmt.Println()

	for i, e := range b.Records {
		p, err := e.ParsePayload()
		typ, when := "unreadable", ""
		if err == nil {
			typ, when = p.Type, p.Time
		}
		problems := verify.VerifyRecord(e, reg, sig)
		mark := "ok  "
		if len(problems) > 0 {
			mark = "FAIL"
		}
		fmt.Printf("  %s  %d  %-18s %s  key %s#%d\n", mark, i, typ, when, e.Signature.KeyID, e.Signature.Version)
		for _, pr := range problems {
			fmt.Printf("          %s: %s\n", pr.Code, pr.Detail)
		}
	}
	fmt.Println()
}

// flagValue reads a flag back by name so the explain header can show the file
// without threading it through every call.
func flagValue(name string) string {
	f := flag.Lookup(name)
	if f == nil {
		return ""
	}
	return f.Value.String()
}

//go:build js && wasm

// The verifier, compiled to WebAssembly.
//
// This is the same verification code the command line tool runs, built for a
// browser. It exists so that a claim this project makes everywhere becomes
// literally true on a web page: verification needs nothing from us, and the
// reader can watch it happen on their own machine.
//
// A page using this performs real cryptography locally. No request is made,
// no evidence leaves the browser, and there is no server to trust, to secure,
// or to keep running. If the page is saved to disk it keeps working.
//
// Build:
//
//	GOOS=js GOARCH=wasm go build -o web/verify.wasm ./cmd/wasm
//
// The runtime shim ships with Go and must sit beside it:
//
//	cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/
//
// Functions exposed on window:
//
//	hpxVerifyBundle(bundleJSON)                  -> result object
//	hpxVerifyCheckpoint(document, keysJSON)      -> result object
//	hpxVersion()                                 -> string
//
// Each returns a plain object rather than throwing, because a page that has to
// wrap every call in a try block will eventually catch an error and render it
// as a verification failure.
//
// The build constraint at the top of this file is load-bearing, not decoration.
// syscall/js exists only for GOOS=js, so without it `go build ./...`,
// `go vet ./...` and `go test ./...` all fail on this package on any ordinary
// machine, including in CI and including for the first reviewer who clones the
// repository and runs the obvious command.
package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/med-xt/hpx-verifier"
	"github.com/med-xt/hpx-verifier/mldsa"
)

// bundleWire is the published bundle shape, plus the keys a bundle carries so
// that a page can verify a file exactly as downloaded.
type bundleWire struct {
	Episode         string                  `json:"episode"`
	Records         []*verify.Envelope      `json:"records"`
	LogRoot         string                  `json:"logRoot"`
	InclusionProofs []verify.InclusionProof `json:"inclusionProofs"`
	Checkpoint      string                  `json:"checkpoint"`
	Keys            json.RawMessage         `json:"keys"`
}

func fail(format string, args ...any) map[string]any {
	return map[string]any{
		"ran":      false,
		"ok":       false,
		"problems": []any{fmt.Sprintf(format, args...)},
	}
}

func problemList(ps []verify.Problem) []any {
	out := make([]any, 0, len(ps))
	for _, p := range ps {
		out = append(out, map[string]any{
			"record": p.Record,
			"type":   p.Type,
			"code":   p.Code,
			"detail": p.Detail,
			"text":   p.String(),
		})
	}
	return out
}

// verifyBundle takes the bundle JSON as a string and returns the same answer
// the command line tool would give for the same file.
func verifyBundle(this js.Value, args []js.Value) any {
	if len(args) < 1 || args[0].Type() != js.TypeString {
		return fail("a bundle, as a JSON string, is required")
	}

	var b bundleWire
	if err := json.Unmarshal([]byte(args[0].String()), &b); err != nil {
		return fail("bundle will not parse: %v", err)
	}
	if len(b.Records) == 0 {
		return fail("bundle contains no records")
	}

	// Keys come from the bundle when it carries them, which is what makes a
	// bundle sufficient on its own. A second argument overrides, for a reader
	// who obtained the registry from somewhere other than the party under review.
	keysRaw := b.Keys
	if len(args) > 1 && args[1].Type() == js.TypeString && args[1].String() != "" {
		keysRaw = json.RawMessage(args[1].String())
	}
	if len(keysRaw) == 0 {
		return fail("no keys: the bundle carries none, so a key registry must be supplied")
	}
	reg, err := verify.LoadRegistry(keysRaw)
	if err != nil {
		return fail("key registry will not load: %v", err)
	}

	sig := mldsa.New()

	core := verify.Bundle{
		Episode:         b.Episode,
		Records:         b.Records,
		LogRoot:         b.LogRoot,
		InclusionProofs: b.InclusionProofs,
		Checkpoint:      b.Checkpoint,
	}
	res := verify.VerifyBundle(&core, reg, sig)

	cp, cpProblems := verify.VerifyBundleCheckpoint(&core, reg, sig)
	res.Problems = append(res.Problems, cpProblems...)
	res.OK = len(res.Problems) == 0

	signedBy := make([]any, 0, len(cp.SignedBy))
	for _, s := range cp.SignedBy {
		signedBy = append(signedBy, map[string]any{
			"keyId": s.KeyID, "version": s.Version, "owner": s.Owner,
		})
	}

	// Per record detail, so a page can mark the exact row that failed rather
	// than colouring the whole episode red.
	records := make([]any, 0, len(b.Records))
	for i, e := range b.Records {
		typ, when := "unreadable", ""
		if p, err := e.ParsePayload(); err == nil {
			typ, when = p.Type, p.Time
		}
		problems := verify.VerifyRecord(e, reg, sig)
		records = append(records, map[string]any{
			"index":    i,
			"type":     typ,
			"time":     when,
			"digest":   e.Digest,
			"keyId":    e.Signature.KeyID,
			"ok":       len(problems) == 0,
			"problems": problemList(problems),
		})
	}

	return map[string]any{
		"ran":      true,
		"ok":       res.OK,
		"episode":  b.Episode,
		"count":    res.Records,
		"problems": problemList(res.Problems),
		"records":  records,
		"logRoot":  b.LogRoot,
		"anchoring": map[string]any{
			"present":        cp.Present,
			"verified":       cp.Verified,
			"matchesLogRoot": cp.MatchesLogRoot,
			"origin":         cp.Origin,
			"size":           cp.Size,
			"time":           cp.Time,
			"signedBy":       signedBy,
		},
	}
}

// verifyCheckpoint checks a checkpoint document on its own, which is the mode
// a reviewer uses holding two text files and no access to the log.
func verifyCheckpoint(this js.Value, args []js.Value) any {
	if len(args) < 2 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeString {
		return fail("a checkpoint document and a key registry, both as strings, are required")
	}
	reg, err := verify.LoadRegistry([]byte(args[1].String()))
	if err != nil {
		return fail("key registry will not load: %v", err)
	}

	res := verify.VerifyCheckpoint(args[0].String(), reg, mldsa.New())

	problems := make([]any, 0, len(res.Problems))
	for _, p := range res.Problems {
		problems = append(problems, p)
	}
	signedBy := make([]any, 0, len(res.SignedBy))
	for _, s := range res.SignedBy {
		signedBy = append(signedBy, map[string]any{
			"keyId": s.KeyID, "version": s.Version, "owner": s.Owner,
		})
	}

	out := map[string]any{
		"ran":      true,
		"ok":       res.OK,
		"problems": problems,
		"signedBy": signedBy,
	}
	if res.Checkpoint != nil {
		out["origin"] = res.Checkpoint.Origin
		out["size"] = res.Checkpoint.Size
		out["root"] = res.Checkpoint.Root
		out["time"] = res.Checkpoint.Time
	}
	return out
}

// verifyConsistency answers the question a reviewer asks with two checkpoints
// and nothing else: did this log grow from the one I already hold.
func verifyConsistency(this js.Value, args []js.Value) any {
	if len(args) < 5 {
		return fail("oldRoot, oldSize, newRoot, newSize and a proof array are required")
	}
	proof := make([]string, 0)
	if args[4].Type() == js.TypeObject {
		for i := 0; i < args[4].Length(); i++ {
			proof = append(proof, args[4].Index(i).String())
		}
	}
	r := verify.VerifyConsistency(
		args[0].String(), args[1].Int(),
		args[2].String(), args[3].Int(),
		proof,
	)
	return map[string]any{"ran": true, "ok": r.OK, "reason": r.Reason}
}

func version(this js.Value, args []js.Value) any {
	return map[string]any{
		"spec":     verify.SupportedSpec,
		"contract": "hpx-contract/1",
		"note":     "Verification runs in this browser. Nothing is sent anywhere.",
	}
}

func main() {
	js.Global().Set("hpxVerifyBundle", js.FuncOf(verifyBundle))
	js.Global().Set("hpxVerifyCheckpoint", js.FuncOf(verifyCheckpoint))
	js.Global().Set("hpxVerifyConsistency", js.FuncOf(verifyConsistency))
	js.Global().Set("hpxVersion", js.FuncOf(version))

	// Signal to the page that the module is live, so it can enable its controls
	// rather than guessing when the download finished.
	if ready := js.Global().Get("hpxReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}

	// A Go WASM module exits when main returns, taking the exported functions
	// with it. Block forever.
	select {}
}

// Command sign signs a release's SHA256SUMS.txt with the release key.
//
//	SENTIENT1_SIGNING_KEY=<base64 ed25519 seed> go run ./scripts/sign SHA256SUMS.txt SHA256SUMS.txt.sig
//
// It refuses to sign with a key that doesn't match the public key built into
// SENTIENT1, so a wrong or rotated secret fails the release instead of shipping
// updates nobody can install.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/xak1234/sentient1/internal/update"
)

func main() {
	if len(os.Args) != 3 {
		fail("usage: sign <file> <signature-out>")
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("SENTIENT1_SIGNING_KEY")))
	if err != nil || len(seed) != ed25519.SeedSize {
		fail("SENTIENT1_SIGNING_KEY is missing or not a base64 ed25519 seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if pub != update.PublicKey {
		fail("SENTIENT1_SIGNING_KEY does not match the public key built into SENTIENT1 (internal/update)")
	}
	msg, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail(err.Error())
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)) + "\n"
	if err := update.VerifySignature(msg, []byte(sig)); err != nil {
		fail("self-check failed: " + err.Error())
	}
	if err := os.WriteFile(os.Args[2], []byte(sig), 0o644); err != nil {
		fail(err.Error())
	}
	fmt.Println("signed", os.Args[1])
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "sign:", msg)
	os.Exit(1)
}

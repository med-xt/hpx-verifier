package verify

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// SignatureVerifier is the seam the post-quantum library sits behind.
//
// Everything structural in this package works without it. That is deliberate:
// an auditor can check digests, the chain and the log with the standard library
// alone, and the cryptographic provider becomes a swappable component rather
// than a dependency of the whole tool. It is the same reason the reference
// implementation routes all signing through one interface, and it is what makes
// moving to a FIPS validated module a deployment change rather than a rewrite.
type SignatureVerifier interface {
	Verify(alg, signatureB64 string, message, publicKey []byte) (bool, error)
}

type Key struct {
	ID        string `json:"id"`
	Version   int    `json:"version"`
	Alg       string `json:"alg"`
	Owner     string `json:"owner"`
	Status    string `json:"status"`
	NotAfter  string `json:"notAfter"`
	PublicKey []byte `json:"-"`

	PublicKeyHex string `json:"publicKey"`
}

// Registry holds public keys only. This is the object an auditor is given, and
// it is why it can be handed over without any further precaution.
//
// Retired keys are retained permanently. Deleting a public key destroys the
// ability to verify everything it ever signed, which is the one irreversible
// mistake available to whoever operates this.
type Registry struct {
	keys map[string]*Key
}

func key(id string, version int) string { return fmt.Sprintf("%s#%d", id, version) }

func NewRegistry() *Registry { return &Registry{keys: map[string]*Key{}} }

func (r *Registry) Add(k *Key) error {
	if k.PublicKey == nil && k.PublicKeyHex != "" {
		b, err := hex.DecodeString(k.PublicKeyHex)
		if err != nil {
			return fmt.Errorf("key %s has a non-hex public key: %w", key(k.ID, k.Version), err)
		}
		k.PublicKey = b
	}
	if len(k.PublicKey) == 0 {
		return fmt.Errorf("key %s has no public key material", key(k.ID, k.Version))
	}
	r.keys[key(k.ID, k.Version)] = k
	return nil
}

func (r *Registry) Resolve(id string, version int) *Key {
	return r.keys[key(id, version)]
}

func (r *Registry) Len() int { return len(r.keys) }

// LoadRegistry reads the exported key list.
func LoadRegistry(data []byte) (*Registry, error) {
	var list []*Key
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("key registry is not readable: %w", err)
	}
	r := NewRegistry()
	for _, k := range list {
		if err := r.Add(k); err != nil {
			return nil, err
		}
	}
	if r.Len() == 0 {
		return nil, fmt.Errorf("key registry is empty")
	}
	return r, nil
}

package crypto

import (
	"errors"
	"testing"
)

func TestKeyGeneratorStore_UnsupportedAlgorithmError(t *testing.T) {
	store := NewKeyGeneratorStore(map[SignatureAlgorithm]KeyGenerator{})
	_, err := store.Get(RSA)
	if err == nil {
		t.Fatalf("expected error for unsupported algorithm, got nil")
	}
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestRSAGenerator_Generate_StructIntegrity(t *testing.T) {
	gen := &RSAGenerator{}
	kp, err := gen.Generate()
	if err != nil {
		t.Fatalf("RSAGenerator.Generate error: %v", err)
	}
	if kp == nil || kp.Private == nil || kp.Public == nil {
		t.Fatalf("generated RSA keypair should be non-nil")
	}
	// Public must correspond to Private.PublicKey
	if kp.Private.N.Cmp(kp.Public.N) != 0 {
		t.Fatalf("RSA public key modulus does not match private key modulus")
	}
}

func TestECCGenerator_Generate_StructIntegrity(t *testing.T) {
	gen := &ECCGenerator{}
	kp, err := gen.Generate()
	if err != nil {
		t.Fatalf("ECCGenerator.Generate error: %v", err)
	}
	if kp == nil || kp.Private == nil || kp.Public == nil {
		t.Fatalf("generated ECC keypair should be non-nil")
	}
	// Public must correspond to Private.PublicKey: compare curve and coordinates
	if kp.Private.Curve != kp.Public.Curve {
		t.Fatalf("ECC curve mismatch between private and public")
	}
	if kp.Private.PublicKey.X.Cmp(kp.Public.X) != 0 || kp.Private.PublicKey.Y.Cmp(kp.Public.Y) != 0 {
		t.Fatalf("ECC public coordinates do not match private's public key")
	}
}

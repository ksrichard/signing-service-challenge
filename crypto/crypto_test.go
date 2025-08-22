package crypto

import "testing"

func TestKeyGeneratorStore_Get(t *testing.T) {
	store := NewKeyGeneratorStore(map[SignatureAlgorithm]KeyGenerator{
		RSA: &RSAGenerator{},
	})
	if _, err := store.Get(RSA); err != nil {
		t.Fatalf("expected RSA generator, got error: %v", err)
	}
	if _, err := store.Get(ECC); err == nil {
		t.Fatalf("expected error for unsupported algorithm ECC, got nil")
	}
}

func TestRSAMarshalUnmarshalAndSign(t *testing.T) {
	// generate keys
	gen := &RSAGenerator{}
	pub, priv, err := gen.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	if len(pub) == 0 || len(priv) == 0 {
		t.Fatalf("generated keys should be non-empty")
	}

	// unmarshal private
	mar := NewRSAMarshaler()
	kp, err := mar.Unmarshal(priv)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if kp.Private == nil || kp.Public == nil {
		t.Fatalf("keypair fields should be non-nil")
	}

	// sign with signer store
	ss := NewSignerStore(map[SignatureAlgorithm]SignerCreateFunc{
		RSA: func(privateKey []byte) (Signer, error) { return NewRSASigner(privateKey) },
	})
	signer, err := ss.Get(RSA, priv)
	if err != nil {
		t.Fatalf("SignerStore.Get error: %v", err)
	}
	if _, err := signer.Sign([]byte("hello")); err != nil {
		t.Fatalf("RSASigner.Sign error: %v", err)
	}
}

func TestECCEncodeDecodeAndSign(t *testing.T) {
	gen := &ECCGenerator{}
	pub, priv, err := gen.GenerateKeyPair()
	if err != nil {
		t.Fatalf("ECC GenerateKeyPair error: %v", err)
	}
	if len(pub) == 0 || len(priv) == 0 {
		t.Fatalf("ECC generated keys should be non-empty")
	}
	mar := NewECCMarshaler()
	kp, err := mar.Decode(priv)
	if err != nil {
		t.Fatalf("ECC Decode error: %v", err)
	}
	if kp.Private == nil || kp.Public == nil {
		t.Fatalf("ECC keypair fields should be non-nil")
	}
	ss := NewSignerStore(map[SignatureAlgorithm]SignerCreateFunc{
		ECC: func(privateKey []byte) (Signer, error) { return NewECCSigner(privateKey) },
	})
	signer, err := ss.Get(ECC, priv)
	if err != nil {
		t.Fatalf("SignerStore.Get ECC error: %v", err)
	}
	if _, err := signer.Sign([]byte("hello")); err != nil {
		t.Fatalf("ECCSigner.Sign error: %v", err)
	}
}

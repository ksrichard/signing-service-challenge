package domain

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ksrichard/signing-service-challenge/crypto"
)

func newStores() (crypto.KeyGeneratorStore, crypto.SignerStore) {
	kg := crypto.NewKeyGeneratorStore(map[crypto.SignatureAlgorithm]crypto.KeyGenerator{
		crypto.RSA: &crypto.RSAGenerator{},
		crypto.ECC: &crypto.ECCGenerator{},
	})
	ss := crypto.NewSignerStore(map[crypto.SignatureAlgorithm]crypto.SignerCreateFunc{
		crypto.RSA: func(privateKey []byte) (crypto.Signer, error) { return crypto.NewRSASigner(privateKey) },
		crypto.ECC: func(privateKey []byte) (crypto.Signer, error) { return crypto.NewECCSigner(privateKey) },
	})
	return kg, ss
}

func TestNewSignatureDeviceAndSignDataFlow_RSA(t *testing.T) {
	kg, ss := newStores()
	dev, err := NewSignatureDevice(&kg, &ss, crypto.RSA, "label")
	if err != nil {
		t.Fatalf("NewSignatureDevice RSA error: %v", err)
	}
	if strings.Contains(dev.GetIDStr(), "-") {
		t.Fatalf("GetIDStr should not contain hyphens: %s", dev.GetIDStr())
	}

	if dev.GetSignatureCounter() != 0 {
		t.Fatalf("initial signature counter should be 0")
	}

	// First signature: last signature should be base64 of UUID bytes
	res1, err := dev.SignData("hello")
	if err != nil {
		t.Fatalf("SignData 1 error: %v", err)
	}
	if dev.GetSignatureCounter() != 1 {
		t.Fatalf("signature counter should be 1 after first sign, got %d", dev.GetSignatureCounter())
	}
	parts := strings.Split(res1.SignedData, "_")
	if len(parts) != 3 {
		t.Fatalf("signed data should have 3 parts, got: %s", res1.SignedData)
	}
	if parts[0] != "0" {
		t.Fatalf("first counter in signed data should be 0, got %s", parts[0])
	}
	if parts[1] != "hello" {
		t.Fatalf("data part mismatch: %s", parts[1])
	}
	// parts[2] must be valid base64 (either UUID bytes)
	if _, err := base64.StdEncoding.DecodeString(parts[2]); err != nil {
		t.Fatalf("last signature part not valid base64: %v", err)
	}
	// Signature must be base64
	if _, err := base64.StdEncoding.DecodeString(res1.Signature); err != nil {
		t.Fatalf("signature not valid base64: %v", err)
	}

	// Second signature: last signature should equal previous signature (base64)
	res2, err := dev.SignData("world")
	if err != nil {
		t.Fatalf("SignData 2 error: %v", err)
	}
	if dev.GetSignatureCounter() != 2 {
		t.Fatalf("signature counter should be 2 after second sign, got %d", dev.GetSignatureCounter())
	}
	parts2 := strings.Split(res2.SignedData, "_")
	if len(parts2) != 3 {
		t.Fatalf("signed data 2 should have 3 parts, got: %s", res2.SignedData)
	}
	if parts2[0] != "1" {
		t.Fatalf("first part should be previous counter 1, got %s", parts2[0])
	}
	if parts2[2] != res1.Signature {
		t.Fatalf("last signature should equal previous base64 signature")
	}
}

func TestNewSignatureDevice_ECC(t *testing.T) {
	kg, ss := newStores()
	dev, err := NewSignatureDevice(&kg, &ss, crypto.ECC, "ecc")
	if err != nil {
		t.Fatalf("NewSignatureDevice ECC error: %v", err)
	}
	// quick sign to ensure signer works
	if _, err := dev.SignData("x"); err != nil {
		t.Fatalf("ECC SignData error: %v", err)
	}
}

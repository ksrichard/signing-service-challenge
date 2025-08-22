package domain

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/ksrichard/signing-service-challenge/crypto"
)

// SignDataResult is the result of signing any data.
type SignDataResult struct {
	Signature  string
	SignedData string
}

// SignatureDevice is a device that stores public/private keys and can sign data with them.
type SignatureDevice struct {
	ID                 uuid.UUID
	Algorithm          crypto.SignatureAlgorithm
	privateKey         []byte
	PublicKey          []byte
	Label              string
	signatureCounter   atomic.Uint64
	generator          crypto.KeyGenerator
	signer             crypto.Signer
	lastSignature      string
	lastSignatureMutex sync.RWMutex
}

// NewSignatureDevice creates a new SignatureDevice.
// Here we generate a new key pair (based on the given algorithm) and a new signer with the private key.
func NewSignatureDevice(
	keyGeneratorStore *crypto.KeyGeneratorStore,
	signerStore *crypto.SignerStore,
	algorithm crypto.SignatureAlgorithm,
	label string,
) (*SignatureDevice, error) {
	// generate new keypair
	generator, err := keyGeneratorStore.Get(algorithm)
	if err != nil {
		return nil, err
	}

	public, private, err := generator.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// get a new signer with our new private key
	signer, err := signerStore.Get(algorithm, private)
	if err != nil {
		return nil, err
	}

	return &SignatureDevice{
		ID:                 uuid.New(),
		Algorithm:          algorithm,
		privateKey:         private,
		PublicKey:          public,
		Label:              label,
		signatureCounter:   atomic.Uint64{},
		generator:          generator,
		signer:             signer,
		lastSignature:      "",
		lastSignatureMutex: sync.RWMutex{},
	}, nil
}

func (d *SignatureDevice) GetIDStr() string {
	return strings.ReplaceAll(d.ID.String(), "-", "")
}

func (d *SignatureDevice) GetSignatureCounter() uint64 {
	return d.signatureCounter.Load()
}

func (d *SignatureDevice) base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func (d *SignatureDevice) signedData(data string) (string, error) {
	d.lastSignatureMutex.RLock()
	lastSig := d.lastSignature
	d.lastSignatureMutex.RUnlock()
	if lastSig == "" {
		idBytes, err := d.ID.MarshalBinary()
		if err != nil {
			return "", err
		}
		lastSig = d.base64Encode(idBytes)
	}
	return fmt.Sprintf("%d_%s_%s", d.signatureCounter.Load(), data, lastSig), nil
}

func (d *SignatureDevice) SignData(data string) (SignDataResult, error) {
	signedData, err := d.signedData(data)
	if err != nil {
		return SignDataResult{}, err
	}

	signature, err := d.signer.Sign([]byte(signedData))
	if err != nil {
		return SignDataResult{}, err
	}
	signatureB64 := d.base64Encode(signature)

	// setting last signature and increase signature counter
	d.lastSignatureMutex.Lock()
	d.lastSignature = signatureB64
	d.lastSignatureMutex.Unlock()

	d.signatureCounter.Add(1)

	return SignDataResult{
		Signature:  signatureB64,
		SignedData: signedData,
	}, nil
}

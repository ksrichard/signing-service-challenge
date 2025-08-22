package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

var (
	ErrUninitializedPrivateKey = errors.New("uninitialized private key")
)

type SignerCreateFunc = func(privateKey []byte) (Signer, error)

// SignerStore holds a map of supported signature algorithms and their respective SignerCreateFunc functions.
type SignerStore struct {
	signers map[SignatureAlgorithm]SignerCreateFunc
}

func NewSignerStore(signers map[SignatureAlgorithm]SignerCreateFunc) SignerStore {
	return SignerStore{
		signers: signers,
	}
}

func (s *SignerStore) Get(algorithm SignatureAlgorithm, privateKey []byte) (Signer, error) {
	signer, ok := s.signers[algorithm]
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}
	return signer(privateKey)
}

// Signer defines a contract for different types of signing implementations.
type Signer interface {
	// Sign signs the given data.
	Sign(dataToBeSigned []byte) ([]byte, error)
}

// RSASigner implements the Signer interface for RSA keys.
type RSASigner struct {
	privateKey *rsa.PrivateKey
}

func NewRSASigner(privateKey []byte) (Signer, error) {
	marshaler := NewRSAMarshaler()
	keyPair, err := marshaler.Unmarshal(privateKey)
	if err != nil {
		return nil, err
	}
	return &RSASigner{
		privateKey: keyPair.Private,
	}, nil
}

func (s *RSASigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	if s.privateKey == nil {
		return nil, ErrUninitializedPrivateKey
	}

	// hash the data before signing
	dataHash := sha256.New()
	_, err := dataHash.Write(dataToBeSigned)
	if err != nil {
		return nil, err
	}
	dataHashSum := dataHash.Sum(nil)
	return rsa.SignPSS(rand.Reader, s.privateKey, crypto.SHA256, dataHashSum, nil)
}

// ECCSigner implements the Signer interface for ECC keys.
type ECCSigner struct {
	privateKey *ecdsa.PrivateKey
}

func (s *ECCSigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	if s.privateKey == nil {
		return nil, ErrUninitializedPrivateKey
	}
	// hash the data before signing
	dataHash := sha256.New()
	_, err := dataHash.Write(dataToBeSigned)
	if err != nil {
		return nil, err
	}
	dataHashSum := dataHash.Sum(nil)
	return s.privateKey.Sign(rand.Reader, dataHashSum, nil)
}

func NewECCSigner(privateKey []byte) (Signer, error) {
	marshaler := NewECCMarshaler()
	keyPair, err := marshaler.Decode(privateKey)
	if err != nil {
		return nil, err
	}
	return &ECCSigner{
		privateKey: keyPair.Private,
	}, nil
}

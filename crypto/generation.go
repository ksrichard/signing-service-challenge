package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

var (
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
)

// KeyGeneratorStore stores a map of supported algorithms to their respective generators.
type KeyGeneratorStore struct {
	generators map[SignatureAlgorithm]KeyGenerator
}

func NewKeyGeneratorStore(generators map[SignatureAlgorithm]KeyGenerator) KeyGeneratorStore {
	return KeyGeneratorStore{
		generators: generators,
	}
}

func (s *KeyGeneratorStore) Get(algorithm SignatureAlgorithm) (KeyGenerator, error) {
	generator, ok := s.generators[algorithm]
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}
	return generator, nil
}

// KeyGenerator is the interface that must be implemented by all the key generators.
// It returns the public and private key as a byte slice (in this order).
type KeyGenerator interface {
	GenerateKeyPair() ([]byte, []byte, error)
}

// RSAGenerator generates an RSA key pair.
type RSAGenerator struct{}

// Generate generates a new RSAKeyPair.
func (g *RSAGenerator) Generate() (*RSAKeyPair, error) {
	// Security has been ignored for the sake of simplicity.
	key, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return nil, err
	}

	return &RSAKeyPair{
		Public:  &key.PublicKey,
		Private: key,
	}, nil
}

func (g *RSAGenerator) GenerateKeyPair() ([]byte, []byte, error) {
	keyPair, err := g.Generate()
	if err != nil {
		return nil, nil, err
	}
	marshaler := NewRSAMarshaler()
	return marshaler.Marshal(*keyPair)
}

// ECCGenerator generates an ECC key pair.
type ECCGenerator struct{}

// Generate generates a new ECCKeyPair.
func (g *ECCGenerator) Generate() (*ECCKeyPair, error) {
	// Security has been ignored for the sake of simplicity.
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECCKeyPair{
		Public:  &key.PublicKey,
		Private: key,
	}, nil
}

func (g *ECCGenerator) GenerateKeyPair() ([]byte, []byte, error) {
	keyPair, err := g.Generate()
	if err != nil {
		return nil, nil, err
	}
	marshaler := NewECCMarshaler()
	return marshaler.Encode(*keyPair)
}

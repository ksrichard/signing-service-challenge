package main

import (
	"log"

	"github.com/ksrichard/signing-service-challenge/api"
	"github.com/ksrichard/signing-service-challenge/crypto"
	"github.com/ksrichard/signing-service-challenge/persistence"
)

const (
	ListenAddress = ":8080"
)

func main() {
	// init stores
	signerStore := crypto.NewSignerStore(map[crypto.SignatureAlgorithm]crypto.SignerCreateFunc{
		crypto.RSA: func(privateKey []byte) (crypto.Signer, error) {
			return crypto.NewRSASigner(privateKey)
		},
		crypto.ECC: func(privateKey []byte) (crypto.Signer, error) {
			return crypto.NewECCSigner(privateKey)
		},
	})
	keyGeneratorStore := crypto.NewKeyGeneratorStore(map[crypto.SignatureAlgorithm]crypto.KeyGenerator{
		crypto.RSA: &crypto.RSAGenerator{},
		crypto.ECC: &crypto.ECCGenerator{},
	})
	deviceStore := persistence.NewInMemorySignatureDeviceStore()

	// init server
	params := api.ServerParams{
		ListenAddress:     ListenAddress,
		SignerStore:       signerStore,
		KeyGeneratorStore: keyGeneratorStore,
		DeviceStore:       deviceStore,
	}
	server := api.NewServer(params)

	log.Printf("Starting server on %s...\n", ListenAddress)

	if err := server.Run(); err != nil {
		log.Fatal("Could not start server on ", ListenAddress)
	}
}

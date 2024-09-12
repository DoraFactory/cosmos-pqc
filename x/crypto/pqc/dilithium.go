package pqc

import (
	"log"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

type DilithiumPrivateKey struct {
	Key []byte
}

type DilithiumPublicKey struct {
	Key []byte
}

// GenerateKeyPair generates a new Dilithium key pair using liboqs-go
func GenerateDilithiumKeyPair(algorithm string) (DilithiumPublicKey, DilithiumPrivateKey, error) {
	signer := oqs.Signature{}

	// Initialize Dilithium3, can be changed to "Dilithium3" or "Dilithium5"
	err := signer.Init(algorithm, nil)
	if err != nil {
		log.Fatalf("Failed to initialize Dilithium: %v", err)
	}

	pubKey, err := signer.GenerateKeyPair()
	if err != nil {
		return DilithiumPublicKey{}, DilithiumPrivateKey{}, err
	}

	return DilithiumPublicKey{Key: pubKey}, DilithiumPrivateKey{Key: signer.ExportSecretKey()}, nil
}

// Sign signs a message using the Dilithium private key
func (privKey DilithiumPrivateKey) DilithiumSign(algorithm string, message []byte) ([]byte, error) {
	signer := oqs.Signature{}
	defer signer.Clean()

	err := signer.Init(algorithm, privKey.Key)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(message)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// Verify verifies a signature using the Dilithium public key
func (pubKey DilithiumPublicKey) DilithiumVerify(algorithm string, message, signature []byte) bool {
	verifier := oqs.Signature{}
	defer verifier.Clean()

	err := verifier.Init(algorithm, nil)
	if err != nil {
		return false
	}

	valid, err := verifier.Verify(message, signature, pubKey.Key)
	if err != nil {
		return false
	}

	return valid
}

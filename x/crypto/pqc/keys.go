package pqc

import (
	"errors"
	"fmt"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

var SupportedPQCSchemes = []string{"Dilithium3", "Dilithium3", "Dilithium5"}

// PrivateKey defines a struct to hold the private key bytes
type PrivateKey struct {
	Key []byte
}

// PublicKey defines a struct to hold the public key bytes
type PublicKey struct {
	Key []byte
}

func GenerateKeyPair(algorithm string) (PublicKey, error) {
	if !isSupportedPQC(algorithm) {
		return PublicKey{}, errors.New("unsupported PQC algorithm")
	}

	signer := oqs.Signature{}
	defer signer.Clean()

	err := signer.Init(algorithm, nil)
	if err != nil {
		return PublicKey{}, fmt.Errorf("failed to initialize algorithm %s: %w", algorithm, err)
	}

	pubKey, err := signer.GenerateKeyPair()
	if err != nil {
		return PublicKey{}, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return PublicKey{Key: pubKey}, nil
}

// Sign signs a message using the provided private key
func (privKey PrivateKey) Sign(algorithm string, message []byte) ([]byte, error) {
	signer := oqs.Signature{}
	defer signer.Clean()

	err := signer.Init(algorithm, nil)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(message)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// Verify verifies a signature using the provided public key
func (pubKey PublicKey) Verify(algorithm string, message, signature []byte) bool {
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

// Check if the algorithm is supported
func isSupportedPQC(algorithm string) bool {
	for _, algo := range SupportedPQCSchemes {
		if algo == algorithm {
			return true
		}
	}
	return false
}

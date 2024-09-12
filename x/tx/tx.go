package tx

import (
	"fmt"
	"os"

	"github.com/cosmosregistry/chain-minimal/x/crypto/pqc"
)

// SignTx signs a message (transaction) with a Dilithium private key and returns the signature.
func SignTx(algorithm string, message []byte, privKeyPath string) ([]byte, error) {
	// Load the private key from file
	privKeyBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key from %s: %v", privKeyPath, err)
	}
	// fmt.Println(privKeyBytes)

	privKey := pqc.DilithiumPrivateKey{Key: privKeyBytes}

	// Now sign the message with the private key
	signature, err := privKey.DilithiumSign(algorithm, message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}

	return signature, nil
}

// VerifyTxSignature verifies a transaction's signature using a Dilithium public key.
func VerifyTxSignature(algorithm string, message, signature []byte, pubKeyPath string) (bool, error) {
	// Load the public key from file
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return false, fmt.Errorf("failed to read public key from %s: %v", pubKeyPath, err)
	}

	// Initialize public key struct
	pubKey := pqc.DilithiumPublicKey{Key: pubKeyBytes}

	// Verify the signature
	valid := pubKey.DilithiumVerify(algorithm, message, signature)

	return valid, err
}

// ExampleTransaction is an example of a basic transaction (message) structure.
// This is a simplified version for demonstration purposes.
type ExampleTransaction struct {
	From   string
	To     string
	Amount int
	Nonce  int
}

// SerializeTransaction serializes a transaction to a byte array.
func SerializeTransaction(tx ExampleTransaction) []byte {
	// Convert the transaction into a byte array (basic serialization for demo purposes)
	return []byte(fmt.Sprintf("%s->%s:%d:%d", tx.From, tx.To, tx.Amount, tx.Nonce))
}

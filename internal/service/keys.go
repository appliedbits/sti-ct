package service

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadPrivateKeyFromPEM reads a PEM file and extracts the first private key it finds.
func LoadPrivateKeyFromPEM(data []byte) (crypto.Signer, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, errors.New("no PEM data found")
		}
		data = rest

		if block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
			continue
		}

		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		} else if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			privKey, ok := key.(crypto.Signer)
			if !ok {
				return nil, errors.New("not a valid private key")
			}
			return privKey, nil
		} else if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
	}
}

// LoadPublicKeyFromPEM reads a PEM file and extracts the first public key it finds.
func LoadPublicKeyFromPEM(data []byte) (crypto.PublicKey, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, errors.New("no PEM data found")
		}
		data = rest

		if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" && block.Type != "EC PUBLIC KEY" {
			continue
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue // Try the next block
		}

		return pub, nil
	}
}

func LoadKeysFromFile(path string) (crypto.Signer, crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := LoadPrivateKeyFromPEM(data)
	if err != nil {
		return nil, nil, fmt.Errorf("error loading private key: %w", err)
	}

	publicKey, err := LoadPublicKeyFromPEM(data)
	if err != nil {
		return nil, nil, fmt.Errorf("error loading public key: %w", err)
	}

	return privateKey, publicKey, nil
}

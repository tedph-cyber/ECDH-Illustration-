package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func generateECDHKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pub := &priv.PublicKey
	return priv, pub, nil
}

func savePEMKey(fileName string, key *ecdsa.PrivateKey) error {
	privBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	privBlock := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}

	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	return pem.Encode(outFile, &privBlock)
}

func savePublicPEMKey(fileName string, pubKey *ecdsa.PublicKey) error {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}

	pubBlock := pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: pubBytes,
	}

	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	return pem.Encode(outFile, &pubBlock)
}

func main() {
	privKey, pubKey, err := generateECDHKeyPair()
	if err != nil {
		fmt.Println("Error generating ECDH key pair:", err)
		return
	}

	err = savePEMKey("ecdh_private.pem", privKey)
	if err != nil {
		fmt.Println("Error saving private key:", err)
		return
	}

	err = savePublicPEMKey("ecdh_public.pem", pubKey)
	if err != nil {
		fmt.Println("Error saving public key:", err)
		return
	}

	fmt.Println("ECDH keys generated and saved.")
}

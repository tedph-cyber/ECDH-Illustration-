package main

import (
	"crypto/ecdsa"
	// "crypto/elliptic"
	// "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	// "math/big"
	"net/http"
)

func loadECPrivateKeyFromString(privKeyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func loadECPublicKeyFromString(pubKeyPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pubKey := pubKey.(type) {
	case *ecdsa.PublicKey:
		return pubKey, nil
	default:
		return nil, errors.New("not an ECDSA public key")
	}
}

func computeSharedSecret(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([]byte, error) {
	x, _ := privKey.PublicKey.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())
	sharedSecret := sha256.Sum256(x.Bytes())
	return sharedSecret[:], nil
}

func main() {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/encrypt", encryptHandler)
	http.HandleFunc("/decrypt", decryptHandler)
	http.HandleFunc("/ecdh", ecdhHandler)

	fmt.Println("Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func homePage(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("index.html"))
	tmpl.Execute(w, nil)
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		message := r.FormValue("message")
		publicKeyPEM := r.FormValue("publicKey")

		publicKey, err := loadPublicKeyFromString(publicKeyPEM)
		if err != nil {
			http.Error(w, "Invalid public key: "+err.Error(), http.StatusBadRequest)
			return
		}

		encryptedMessage, err := encryptMessage(message, publicKey)
		if err != nil {
			http.Error(w, "Encryption failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl := template.Must(template.ParseFiles("encrypt.html"))
		tmpl.Execute(w, map[string]string{
			"Message":          message,
			"EncryptedMessage": fmt.Sprintf("%x", encryptedMessage),
		})
	}
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		encryptedMessageHex := r.FormValue("encryptedMessage")
		privateKeyPEM := r.FormValue("privateKey")

		encryptedMessage, err := hex.DecodeString(encryptedMessageHex)
		if err != nil {
			http.Error(w, "Invalid encrypted message: "+err.Error(), http.StatusBadRequest)
			return
		}

		privateKey, err := loadPrivateKeyFromString(privateKeyPEM)
		if err != nil {
			http.Error(w, "Invalid private key: "+err.Error(), http.StatusBadRequest)
			return
		}

		decryptedMessage, err := decryptMessage(encryptedMessage, privateKey)
		if err != nil {
			http.Error(w, "Decryption failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl := template.Must(template.ParseFiles("decrypt.html"))
		tmpl.Execute(w, map[string]string{
			"EncryptedMessage": encryptedMessageHex,
			"DecryptedMessage": decryptedMessage,
		})
	}
}

func ecdhHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		privateKeyPEM := r.FormValue("privateKey")
		publicKeyPEM := r.FormValue("publicKey")

		privateKey, err := loadECPrivateKeyFromString(privateKeyPEM)
		if err != nil {
			http.Error(w, "Invalid private key: "+err.Error(), http.StatusBadRequest)
			return
		}

		publicKey, err := loadECPublicKeyFromString(publicKeyPEM)
		if err != nil {
			http.Error(w, "Invalid public key: "+err.Error(), http.StatusBadRequest)
			return
		}

		sharedSecret, err := computeSharedSecret(privateKey, publicKey)
		if err != nil {
			http.Error(w, "Failed to compute shared secret: "+err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl := template.Must(template.ParseFiles("ecdh.html"))
		tmpl.Execute(w, map[string]string{
			"SharedSecret": fmt.Sprintf("%x", sharedSecret),
		})
	}
}

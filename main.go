package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	var privateKeyFile string
	var JWTPayloadFile string

	flag.StringVar(&JWTPayloadFile, "payload", "", "BASE64(header).BASE64(payload)")
	flag.StringVar(&privateKeyFile, "pk", "", "PK file in PKCS8 format")

	flag.Parse()

	privateKey, err := loadPrivateKeyFromPEM(privateKeyFile)
	if err != nil {
		panic(err)
	}

	hasher := crypto.SHA256.New()

	base64HeaderPayload, err := os.ReadFile(JWTPayloadFile)
	if err != nil {
		panic(err)
	}

	_, _ = hasher.Write([]byte(base64HeaderPayload))
	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		panic(err)
	}

	keyBytes := 32

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	result := append(rBytesPadded, sBytesPadded...)

	fmt.Println(base64.RawURLEncoding.EncodeToString(result))
}

func loadPrivateKeyFromPEM(privateKeyFile string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey.(*ecdsa.PrivateKey), nil
}

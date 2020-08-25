package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/karlscheibelhofer/hsm/p11"

	logger "github.com/izumin5210/gentleman-logger"
	log "github.com/sirupsen/logrus"
	"gopkg.in/h2non/baloo.v3"
)

func TestSuiteDecrypt(t *testing.T) {
	// <setup code>

	// start HTTP server on random free port
	var wg sync.WaitGroup
	wg.Add(1)
	testServer, err := StartHTTPServer(":0", &wg)
	if err != nil {
		t.Fatal(err)
	}
	defer testServer.Close()
	serverAddress = testServer.Addr
	test = baloo.New("http://" + serverAddress)
	test.Use(logger.New(os.Stdout))

	t.Run("Decrypt", SubTestDecrypt)

	// <tear-down cod
}

func encryptData(keyID string, plaintext []byte) ([]byte, error) {
	pemEncodedKey, err := ioutil.ReadFile("../key-" + keyID + "-public.pem")
	if err != nil {
		return nil, errors.New("failed to read key file: " + err.Error())
	}
	encodedKey, _ := pem.Decode(pemEncodedKey)
	if encodedKey == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(encodedKey.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse key: " + err.Error())
	}

	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		fmt.Println("pub is of type RSA:", pub)
	case *ecdsa.PublicKey:
		return nil, errors.New("unsupported type EC of public key")
	default:
		return nil, errors.New("unknown type of public key")
	}

	rng := rand.Reader
	var label []byte = nil

	// note: SoftHSM2 only supports OAEP with SHA-1 but not with SHA256
	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rng, pubKey.(*rsa.PublicKey), plaintext, label)
	if err != nil {
		return nil, err
	}

	ioutil.WriteFile("plaintext.bin", plaintext, 0644)
	ioutil.WriteFile("test-ciphertext.bin", ciphertext, 0644)
	return ciphertext, nil
}

func SubTestDecrypt(t *testing.T) {
	keyID := "2"
	resourcePath := "/hsm/" + keyID + "/decrypt"
	var plaintext []byte = []byte{
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	}

	ciphertext, err := encryptData(keyID, plaintext)
	if err != nil {
		t.Error("preparing encrypted data failed " + err.Error())
	}

	test.Post(resourcePath).
		Body(bytes.NewReader(ciphertext)).
		Expect(t).
		Status(200).
		AssertFunc(assertDecryption(plaintext)).
		Done()
}

func assertDecryption(expectedPlaintext []byte) func(res *http.Response, req *http.Request) error {
	f := func(res *http.Response, req *http.Request) error {
		var plaintext p11.Plaintext
		json.NewDecoder(res.Body).Decode(&plaintext)
		log.WithFields(log.Fields{"value": plaintext.Value}).Info("plaintext")

		if bytes.Equal(expectedPlaintext, plaintext.Value) == false {
			return errors.New("expected plaintext and response body differ")
		}
		return nil
	}
	return f
}

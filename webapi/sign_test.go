package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
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

func TestSuiteSign(t *testing.T) {
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

	t.Run("SignECDSA", SubTestSignECDSA)
	t.Run("SignRSA", SubTestSignRSA)

	// <tear-down cod
}

func verifySignature(keyID string, data []byte, signature *p11.Signature) error {
	pemEncodedKey, err := ioutil.ReadFile("../key-" + keyID + "-public.pem")
	if err != nil {
		return errors.New("failed to read key file: " + err.Error())
	}
	encodedKey, _ := pem.Decode(pemEncodedKey)
	if encodedKey == nil {
		return errors.New("failed to parse PEM block containing the key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(encodedKey.Bytes)
	if err != nil {
		return errors.New("failed to parse key: " + err.Error())
	}

	hash := sha256.Sum256(data)
	log.WithFields(log.Fields{"value": hex.EncodeToString(hash[:])}).Info("hash")

	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		fmt.Println("pub is of type RSA:", pub)
		err := rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, hash[:], signature.Value)
		if err != nil {
			return err
		}
	case *ecdsa.PublicKey:
		fmt.Println("pub is of type ECDSA:", pub)
		var ecSig p11.ECSignature
		_, err = asn1.Unmarshal(signature.Value, &ecSig)
		if err != nil {
			return errors.New("failed to parse ASN.1 EC signature: " + err.Error())
		}
		if !ecdsa.Verify(pubKey.(*ecdsa.PublicKey), hash[:], ecSig.R, ecSig.S) {
			return errors.New("signature verification failed ")
		}
	default:
		return errors.New("unknown type of public key")
	}

	ioutil.WriteFile("data.bin", data, 0644)
	ioutil.WriteFile("test-signature.bin", signature.Value, 0644)
	return nil
}

func assertSignatureValid(keyID string, data []byte) func(res *http.Response, req *http.Request) error {
	f := func(res *http.Response, req *http.Request) error {
		var signature p11.Signature
		json.NewDecoder(res.Body).Decode(&signature)
		log.WithFields(log.Fields{"value": signature.Value}).Info("signature")

		return verifySignature(keyID, data, &signature)
	}
	return f
}

func SubTestSignECDSA(t *testing.T) {
	keyID := "1"
	resourcePath := "/hsm/" + keyID + "/sign"

	var data []byte = []byte{
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	}

	hash := sha256.Sum256(data)

	test.Post(resourcePath).
		Body(bytes.NewReader(hash[:])).
		Expect(t).
		Status(200).
		AssertFunc(assertSignatureValid(keyID, data)).
		Done()
}

func SubTestSignRSA(t *testing.T) {
	keyID := "rsa"
	resourcePath := "/hsm/" + keyID + "/sign"

	var data []byte = []byte{
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	}

	hash := sha256.Sum256(data)

	sha256DigestInfoPrefix := []byte{
		0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20,
	}

	encodedHash := append(sha256DigestInfoPrefix, hash[:]...)

	test.Post(resourcePath).
		Body(bytes.NewReader(encodedHash)).
		Expect(t).
		Status(200).
		AssertFunc(assertSignatureValid(keyID, data)).
		Done()
}

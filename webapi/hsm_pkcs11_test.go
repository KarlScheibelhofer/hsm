package main

import (
	"bytes"
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
	"testing"

	"github.com/karlscheibelhofer/hsm/p11"

	logger "github.com/izumin5210/gentleman-logger"
	log "github.com/sirupsen/logrus"
	"gopkg.in/h2non/baloo.v3"
)

// var serverAddress string
// var test *baloo.Client

var data []byte = []byte{
	0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
}

func TestSuitePkcs11(t *testing.T) {
	// <setup code>
	// start HTTP server on random free port
	testServer, err := StartHTTPServer(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer testServer.Close()
	serverAddress = testServer.Addr
	test = baloo.New("http://" + serverAddress)
	test.Use(logger.New(os.Stdout))

	t.Run("Sign", SubTestSign)

	// <tear-down cod
}

func assertSignatureValid(res *http.Response, req *http.Request) error {

	var signature p11.Signature
	json.NewDecoder(res.Body).Decode(&signature)
	log.WithFields(log.Fields{"value": signature.Value}).Info("signature")

	pemEncodedKey, err := ioutil.ReadFile("../key-1-ec-p256-public.pem")
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
	case *ecdsa.PublicKey:
		fmt.Println("pub is of type ECDSA:", pub)
	default:
		return errors.New("unknown type of public key")
	}

	var ecSig p11.ECSignature
	_, err = asn1.Unmarshal(signature.Value, &ecSig)
	if err != nil {
		return errors.New("failed to parse ASN.1 EC signature: " + err.Error())
	}
	valid := ecdsa.Verify(pubKey.(*ecdsa.PublicKey), hash[:], ecSig.R, ecSig.S)
	if !valid {
		return errors.New("signature verification failed ")
	}
	ioutil.WriteFile("data.bin", data, 0644)
	ioutil.WriteFile("test-signature.bin", signature.Value, 0644)
	return nil
}

func SubTestSign(t *testing.T) {
	keyID := "1"
	resourcePath := "/hsm/" + keyID + "/sign"

	hash := sha256.Sum256(data)

	test.Post(resourcePath).
		Body(bytes.NewReader(hash[:])).
		Expect(t).
		Status(200).
		AssertFunc(assertSignatureValid).
		Done()
}

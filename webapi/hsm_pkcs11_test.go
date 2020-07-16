package main

import (
	"os"
	"strings"
	"testing"

	logger "github.com/izumin5210/gentleman-logger"
	"gopkg.in/h2non/baloo.v3"
)

// var serverAddress string
// var test *baloo.Client

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

func SubTestSign(t *testing.T) {
	keyID := "1"
	resourcePath := "/hsm/" + keyID + "/sign"
	data := "1234567890abcdef1234567890abcdef"

	test.Post(resourcePath).
		Body(strings.NewReader(data)).
		Expect(t).
		Status(200).
		Done()
}

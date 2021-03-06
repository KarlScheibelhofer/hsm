package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/karlscheibelhofer/hsm/keys"

	logger "github.com/izumin5210/gentleman-logger"

	"gopkg.in/h2non/baloo.v3"
)

var serverAddress string
var test *baloo.Client

var schemaGeneratedKey string = `{
	"title": "Test GenerateKey Schema",
	"type": "object",
	"properties": {
		"id": { "type": "string" },
		"type": { "type": "string" },
		"private": { "type": "string", "pattern": "^[0-9a-zA-Z/+]*={0,3}$" },
		"public": { "type": "string",	"pattern": "^[0-9a-zA-Z/+]*={0,3}$"	},
		"nonce": { "type": "string", "pattern": "^[0-9a-zA-Z/+]*={0,3}$" }
	},
	"required": [ "id", "type", "private", "public", "nonce" ]
}`

func TestSuite(t *testing.T) {
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

	t.Run("GenerateKey", SubTestGenerateKey)
	t.Run("GetKey", SubTestGetKey)
	t.Run("GenerateNewKey", SubTestGenerateNewKey)
	t.Run("ListKeys", SubTestListKeys)
	t.Run("DeleteKeys", SubTestDeleteKeys)

	// <tear-down cod
}

func SubTestGenerateKey(t *testing.T) {
	keyID := "456"
	resourcePath := "/keys/" + keyID

	test.Post(resourcePath).
		Expect(t).
		Status(201).
		BodyLength(0).
		Done()
}

func SubTestGetKey(t *testing.T) {
	keyID := "456"
	resourcePath := "/keys/" + keyID

	test.Get(resourcePath).
		Expect(t).
		Status(200).
		Type("json").
		JSONSchema(schemaGeneratedKey).
		AssertFunc(func(res *http.Response, req *http.Request) error {
			resKey := new(keys.Key)
			json.NewDecoder(res.Body).Decode(resKey)
			expectedKeyType := "ec-p256"
			if resKey.Type != expectedKeyType {
				return errors.New("expected key type " + expectedKeyType + " but was " + resKey.Type)
			}
			expectedID := keyID
			if resKey.ID != expectedID {
				return errors.New("expected key ID " + expectedID + " but was " + resKey.ID)
			}
			return nil
		}).
		Done()
}

func SubTestGenerateNewKey(t *testing.T) {
	keyID := "789"
	collectionsPath := "/keys"

	test.Post(collectionsPath).
		JSON(map[string]string{"id": keyID}).
		Expect(t).
		Status(201).
		JSONSchema(schemaGeneratedKey).
		AssertFunc(func(res *http.Response, req *http.Request) error {
			resKey := new(keys.Key)
			json.NewDecoder(res.Body).Decode(resKey)
			expectedKeyType := "ec-p256"
			if resKey.Type != expectedKeyType {
				return errors.New("expected key type " + expectedKeyType + " but was " + resKey.Type)
			}
			expectedID := keyID
			if resKey.ID != expectedID {
				return errors.New("expected key ID " + expectedID + " but was " + resKey.ID)
			}
			return nil
		}).
		Done()
}

func SubTestListKeys(t *testing.T) {
	collectionPath := "/keys"

	test.Get(collectionPath).
		Expect(t).
		Status(200).
		Type("json").
		AssertFunc(func(res *http.Response, req *http.Request) error {
			var resKeyAr []keys.Key
			json.NewDecoder(res.Body).Decode(&resKeyAr)
			expectedArrayLen := 2
			if len(resKeyAr) != expectedArrayLen {
				return errors.New("expected key list length " + strconv.Itoa(expectedArrayLen) + " but was " + strconv.Itoa(len(resKeyAr)))
			}
			return nil
		}).
		Done()
}

func SubTestDeleteKeys(t *testing.T) {
	keyIDList := []string{"456", "789"}
	for _, id := range keyIDList {
		resourcePath := "/keys/" + id
		test.Delete(resourcePath).
			Expect(t).
			Status(204).
			BodyLength(0).
			Done()
	}
}

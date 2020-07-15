package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"gopkg.in/h2non/baloo.v3"
)

func toJSONReader(value interface{}) (io.Reader, error) {
	b := new(bytes.Buffer)
	err := json.NewEncoder(b).Encode(value)
	if err != nil {
		return nil, err
	}

	return b, nil
}

var serverAddress string
var test *baloo.Client

func TestSuite(t *testing.T) {
	// <setup code>
	// start HTTP server on random free port
	testServer, err := StartHTTPServer(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer testServer.Close()
	serverAddress = testServer.Addr
	test = baloo.New("http://" + serverAddress)

	t.Run("GenerateKey", SubTestGenerateKey)
	t.Run("GetKey", SubTestGetKey)
	t.Run("GenerateNewKey", SubTestGenerateNewKey)

	// <tear-down cod
}

func SubTestGenerateKey(t *testing.T) {
	keyID := "456"

	schema := `{
		"title": "Test GenerateKey Schema",
		"type": "object",
		"properties": {
		"id": { "type": "string" },
		"type": { "type": "string" },
		"private": {
			"type": "string",
			"pattern": "^[0-9a-zA-Z/+]*={0,3}$"
		},
		"public": {
			"type": "string",
			"pattern": "^[0-9a-zA-Z/+]*={0,3}$"
		},
		"nonce": {
			"type": "string",
			"pattern": "^[0-9a-zA-Z/+]*={0,3}$"
		}
		},
		"required": [ "id", "type", "private", "public", "nonce" ]
	}`

	test.Post("/keys/" + keyID).
		Expect(t).
		Status(201).
		Type("json").
		JSONSchema(schema).
		AssertFunc(func(res *http.Response, req *http.Request) error {
			return nil
		}).
		Done()
}

func SubTestGenerateKeyOld(t *testing.T) {
	baseURL := "http://" + serverAddress
	keyID := "456"
	resourcePath := "/keys/" + keyID
	url := baseURL + resourcePath
	res, err := http.Post(url, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%s", responseBody)

	schema := `{
			"title": "Test GenerateKey Schema",
			"type": "object",
			"properties": {
			"id": { "type": "string" },
			"type": { "type": "string" },
			"private": {
				"type": "string",
				"pattern": "^[0-9a-zA-Z/+]*={0,3}$"
			},
			"public": {
				"type": "string",
				"pattern": "^[0-9a-zA-Z/+]*={0,3}$"
			},
			"nonce": {
				"type": "string",
				"pattern": "^[0-9a-zA-Z/+]*={0,3}$"
			}
			},
			"required": [ "id", "type", "private", "public", "nonce" ]
		}`

	var test = baloo.New(baseURL)

	test.Get(resourcePath).
		Expect(t).
		Status(200).
		Type("json").
		JSONSchema(schema).
		Done()

	var decodedResponse interface{}
	err = json.Unmarshal(responseBody, &decodedResponse)
	if err != nil {
		t.Fatal(err)
	}

	responseMap := decodedResponse.(map[string]interface{})

	assert := assert.New(t)
	assert.EqualValues(keyID, responseMap["id"], "key ID must be %v", keyID)
	expectedType := "ec-p256"
	assert.EqualValues(expectedType, responseMap["type"], "key type must be %v", expectedType)
	value := responseMap["private"].(string)
	assert.NotEmpty(value, "value must not be empty")
}

func SubTestGenerateNewKey(t *testing.T) {
	baseURL := "http://" + serverAddress
	resourcePath := "/keys"
	url := baseURL + resourcePath

	keyID := "789"
	requestBody := `{
			"id": "789",
			"type": "ec-p256"
		}`

	res, err := http.Post(url, "", strings.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%s", responseBody)

	schema := `{
			"title": "Test GenerateKey Schema",
			"type": "object",
			"properties": {
			"id": { "type": "string" },
			"type": { "type": "string" },
			"private": {
				"type": "string",
				"pattern": "^[0-9a-zA-Z/+]*={0,3}$"
			},
			"public": {
				"type": "string",
				"pattern": "^[0-9a-zA-Z/+]*={0,3}$"
			},
			"nonce": {
				"type": "string",
				"pattern": "^[0-9a-zA-Z/+]*={0,3}$"
			}
			},
			"required": [ "id", "type", "private", "public", "nonce" ]
		}`

	var test = baloo.New(baseURL)

	test.Get(resourcePath + "/" + keyID).
		Expect(t).
		Status(200).
		Type("json").
		JSONSchema(schema).
		Done()

	var decodedResponse interface{}
	err = json.Unmarshal(responseBody, &decodedResponse)
	if err != nil {
		t.Fatal(err)
	}

	responseMap := decodedResponse.(map[string]interface{})

	assert := assert.New(t)
	assert.EqualValues(keyID, responseMap["id"], "key ID must be %v", keyID)
	expectedType := "ec-p256"
	assert.EqualValues(expectedType, responseMap["type"], "key type must be %v", expectedType)
	value := responseMap["private"].(string)
	assert.NotEmpty(value, "value must not be empty")
}

func SubTestGetKey(t *testing.T) {
	//TODO: create key in advance
	baseURL := "http://" + serverAddress

	keyID := "123"
	res, err := http.Post(baseURL+"/keys", "", strings.NewReader("{ \"id\": \""+keyID+"\" }"))
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%s", responseBody)

	res, err = http.Get("http://" + serverAddress + "/keys/" + keyID)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%s", responseBody)

	// expectedBody := []byte(`{
	// 	"id": "123",
	// 	"type": "ec-p256",
	// 	"private": "MHcCAQEEIIJYx2GeHYGNqDXzw6VGOgEQjpSIqLAPLN4iqBQ3/u7GoAoGCCqGSM49AwEHoUQDQgAEwI7kOyxoj+tdab4JEBL+UxXm1r0FurMdb6nEVDAncebrUDaTRm7ZMLyqKpVEVnvbpQzqjK3mSvPiTteABjs0QA=="
	// }`)
	// assert.True(t, JSONBytesEqual(responseBody, expectedBody), "expected body must match")

	var decodedResponse interface{}
	err = json.Unmarshal(responseBody, &decodedResponse)
	if err != nil {
		t.Fatal(err)
	}

	responseMap := decodedResponse.(map[string]interface{})

	assert := assert.New(t)
	assert.EqualValues(keyID, responseMap["id"], "key ID must be %v", keyID)
	expectedType := "ec-p256"
	assert.EqualValues(expectedType, responseMap["type"], "key type must be %v", expectedType)
	value := responseMap["private"].(string)
	assert.NotEmpty(value, "value must not be empty")
}

// JSONBytesEqual compares the JSON in two byte slices.
func JSONBytesEqual(a, b []byte) bool {
	var j, j2 interface{}
	if err := json.Unmarshal(a, &j); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &j2); err != nil {
		return false
	}
	return reflect.DeepEqual(j2, j)
}

// func TestPost(t *testing.T) {
// 	router := setupRouter()

// 	w := httptest.NewRecorder()
// 	key := keys.Key{
// 		ID:   "1",
// 		Type: "ec-p256",
// 	}
// 	reqBody, _ := json.Marshal(key)
// 	req, _ := http.NewRequest("POST", "/keys", bytes.NewReader(reqBody))

// 	router.ServeHTTP(w, req)

// 	assert.Equal(t, 201, w.Code)

// 	w = httptest.NewRecorder()
// 	req, _ = http.NewRequest("GET", "/keys/1", nil)

// 	router.ServeHTTP(w, req)

// 	assert.Equal(t, 200, w.Code)

// 	var response map[string]string
// 	err := json.Unmarshal([]byte(w.Body.String()), &response)
// 	// Grab the value & whether or not it exists
// 	id, exists := response["id"]

// 	assert.Nil(t, err)
// 	assert.True(t, exists)
// 	assert.Equal(t, "1", id)

// 	// assert.JSONEq(t, `{ "id": "1", "type": "ec-p256" }`, w.Body.String())
// }

// func BenchmarkPost(b *testing.B) {
// 	router := setupRouter()

// 	for index := 0; index < 100; index++ {
// 		w := httptest.NewRecorder()

// 		key := keys.Key{
// 			ID:   strconv.Itoa(index),
// 			Type: "ec-p256",
// 		}
// 		reqBody, _ := json.Marshal(key)
// 		req, _ := http.NewRequest("POST", "/keys", bytes.NewReader(reqBody))

// 		router.ServeHTTP(w, req)

// 		assert.Equal(b, 201, w.Code)
// 	}
// }

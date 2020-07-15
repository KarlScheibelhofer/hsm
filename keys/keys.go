package keys

import (
	"encoding/json"
	"net/http"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io/ioutil"

	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

//Link supports ref and hfer links in responses.
type Link struct {
	Rel  string `json:"ref"`
	Href string `json:"href"`
}

//Key holds key material of private, public and secret keys.
type Key struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Private []byte `json:"private,omitempty"`
	Public  []byte `json:"public,omitempty"`
	Nonce   []byte `json:"nonce,omitempty"`
	Links   []Link `json:"links,omitempty"`
}

//ErrorResponse wrapps multiple error structures
type ErrorResponse struct {
	Errors []Error `json:"errors"`
}

//Error signals a detailed error message in the response
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

var masterKey Key

func init() {
	id := "masterkey"
	key, err := readKey(id)
	if err != nil {
		log.Info("master key does not exist, generating new one")

		// master key is a AES 256 bit key
		keyValue := make([]byte, 32)
		_, err := rand.Read(keyValue)
		if err != nil {
			panic(err)
		}

		key := Key{
			ID:      id,
			Type:    "aes-256",
			Private: keyValue,
		}
		err = writeKey(id, key)
		if err != nil {
			panic(err)
		}
	} else {
		log.Info("found master key")
	}
	masterKey = key
}

func newKey(id string) Key {
	key := Key{
		ID:   id,
		Type: "ec-p256",
	}
	return key
}

//GetKeyByID finds an existing key by its id.
func GetKeyByID(id string) (Key, error) {
	return readKey("key-" + id)
}

func readKey(filename string) (Key, error) {
	var key Key

	encodedKey, err := ioutil.ReadFile(filename)
	if err != nil {
		return key, err
	}

	err = json.Unmarshal(encodedKey, &key)
	if err != nil {
		return key, err
	}

	return key, err
}

func writeKey(filename string, key Key) error {
	encodedKey, err := json.MarshalIndent(key, "", "\t")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename, encodedKey, 0644)
	if err != nil {
		return err
	}

	return nil
}

//GetKey returns an existing key by id, which ist a parameter.
func GetKey(c *gin.Context) {
	keyID := c.Param("id")

	log.WithFields(log.Fields{"id": keyID}).Info("Getting key")

	file := "key-" + keyID
	if key, err := readKey(file); err == nil {
		c.JSON(http.StatusOK, key)
	} else {
		c.Status(http.StatusNotFound)
	}
}

// func ListKeys(w http.ResponseWriter, r *http.Request) {
// 	log.Info("Listing keys")
// 	fileInfos, err := ioutil.ReadDir(".")
// 	if err != nil {
// 		writeJsonError(err, http.StatusNotFound, w)
// 		return
// 	}
// 	var keyList []Key
// 	fileRegex := regexp.MustCompile("key-[0-9]+")
// 	for _, info := range fileInfos {
// 		if !info.IsDir() {
// 			filename := info.Name()
// 			matches := fileRegex.MatchString(filename)
// 			if matches {
// 				key, err := readKey(filename)
// 				if err == nil {
// 					log.WithFields(log.Fields{
// 						"keyId": key.Id,
// 					}).Debug("Found key")
// 					key.Links = []Link{
// 						{
// 							Rel:  "self",
// 							Href: r.RequestURI + "/" + key.Id,
// 						},
// 					}
// 					keyList = append(keyList, key)
// 				}
// 			}
// 		}
// 	}

// 	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
// 	encoder := json.NewEncoder(w)
// 	encoder.SetIndent("", "\t")
// 	if err := encoder.Encode(keyList); err != nil {
// 		writeJsonError(err, http.StatusInternalServerError, w)
// 		return
// 	}
// }

// func DeleteKey(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	keyId := vars["keyId"]
// 	log.WithFields(log.Fields{
// 		"keyId": keyId,
// 	}).Info("Delete key")

// 	file := "key-" + keyId
// 	if _, err := os.Stat(file); os.IsNotExist(err) {
// 		writeJsonError(err, http.StatusNotFound, w)
// 		return
// 	}
// 	err := os.Remove(file)
// 	if err != nil {
// 		writeJsonError(err, http.StatusInternalServerError, w)
// 		return
// 	}
// }

//GenerateKey generates a new key with ID specified as parameter.
func GenerateKey(c *gin.Context) {
	keyID := c.Param("id")
	log.WithFields(log.Fields{
		"keyId": keyID,
	}).Info("Generate key")

	key := newKey(keyID)
	if c.Request.ContentLength > 0 {
		c.BindJSON(&key)
	}

	err := generateKey(&key)
	if err != nil {
		writeJSONError(err, http.StatusUnprocessableEntity, c)
		return
	}

	jsonKey, err := json.MarshalIndent(key, "", "\t")
	if err != nil {
		writeJSONError(err, http.StatusInternalServerError, c)
		return
	}

	file := "key-" + key.ID
	err = ioutil.WriteFile(file, jsonKey, 0644)
	if err != nil {
		writeJSONError(err, http.StatusInternalServerError, c)
		return
	}

	log.WithFields(log.Fields{"keyId": key.ID, "file": file}).Info("Generated key stored in file")

	c.Header("Location", c.Request.URL.String())
	c.Status(http.StatusCreated)
}

// generateRawKeyPair generate a crypto key pair of the given key type.
// which can be rsa-2048, ec-p256.
// it returns the encoded private key, public key and error.s
func generateRawKeyPair(keytype string) ([]byte, []byte, error) {
	switch keytype {
	case "", "ec-p256":
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		encodedPrivKey, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return nil, nil, err
		}
		encodedPubKey, err := x509.MarshalPKIXPublicKey(ecKey.Public())
		if err != nil {
			return nil, nil, err
		}
		return encodedPrivKey, encodedPubKey, nil
	case "rsa-2048":
	}
	return nil, nil, errors.New("unknown key type " + keytype)
}

func generateKey(keyTemplate *Key) error {
	// generate
	rawPrivKey, rawPubKey, err := generateRawKeyPair(keyTemplate.Type)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(masterKey.Private)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}

	// wrap private key with master key
	wrappedPrivKey := aesgcm.Seal(nil, nonce, rawPrivKey, nil)

	keyTemplate.Private = wrappedPrivKey
	keyTemplate.Public = rawPubKey
	keyTemplate.Nonce = nonce

	return nil
}

func writeJSONError(err error, statusCode int, c *gin.Context) {
	log.WithFields(log.Fields{
		"error":      err,
		"statusCode": statusCode,
	}).Info("Delete key")

	var errorStruct = ErrorResponse{
		[]Error{
			{
				Code:    "123",
				Message: err.Error(),
			},
		},
	}
	c.JSON(statusCode, errorStruct)
}

//GenerateNewKey generates a new key, saves it to file and returns key info
func GenerateNewKey(c *gin.Context) {
	log.Info("Generate key using template")

	key := newKey("")

	if err := c.BindJSON(&key); err != nil {
		writeJSONError(err, http.StatusBadRequest, c)
		return
	}

	if err := generateKey(&key); err != nil {
		writeJSONError(err, http.StatusUnprocessableEntity, c)
		return
	}

	jsonKey, err := json.MarshalIndent(key, "", "\t")
	if err != nil {
		writeJSONError(err, http.StatusInternalServerError, c)
		return
	}

	file := "key-" + key.ID
	err = ioutil.WriteFile(file, jsonKey, 0644)
	if err != nil {
		writeJSONError(err, http.StatusInternalServerError, c)
		return
	}

	log.WithFields(log.Fields{"keyId": key.ID, "file": file}).Info("Generated key stored in file")

	c.Header("Location", c.Request.URL.String()+"/"+key.ID)
	c.JSON(http.StatusCreated, key)
}

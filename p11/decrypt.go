package p11

import (
	"encoding/hex"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

//Plaintext holds a plaintext value
type Plaintext struct {
	Value []byte `json:"value,omitempty"`
}

//Decrypt decrypts with RSA OAEP
func Decrypt(c *gin.Context) {
	keyID := c.Param("id")
	requestData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		panic(err)
	}

	log.WithFields(log.Fields{"id": keyID}).Info("Decrypt with key")
	log.WithFields(log.Fields{"ciphertext": hex.EncodeToString(requestData)}).Debug("cipertext to decrypt")

	label := "key-" + keyID
	if key, exists := keyMap[label]; exists {
		session, err := module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			panic(err)
		}
		defer module.CloseSession(session)
		params := pkcs11.NewOAEPParams(pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, pkcs11.CKZ_DATA_SPECIFIED, nil)
		err = module.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}, key.privKeyHandle)
		if err != nil {
			panic(err)
		}
		plaintext, err := module.Decrypt(session, requestData)
		if err != nil {
			panic(err)
		}
		log.WithFields(log.Fields{"value": hex.EncodeToString(plaintext)}).Debug("plaintext")

		c.JSON(http.StatusOK, Plaintext{Value: plaintext})
	} else {
		c.Status(http.StatusNotFound)
	}
}

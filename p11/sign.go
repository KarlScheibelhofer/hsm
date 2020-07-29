package p11

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

//Signature holds a signature value
type Signature struct {
	Value []byte `json:"value,omitempty"`
}

//ECSignature holds EC signature components r and s for ASN.1 encoding
type ECSignature struct {
	R *big.Int
	S *big.Int
}

//Sign creates a signature with ECDSA
func Sign(c *gin.Context) {
	keyID := c.Param("id")
	requestData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		panic(err)
	}

	log.WithFields(log.Fields{"id": keyID}).Info("Sign with key")
	log.WithFields(log.Fields{"hash": hex.EncodeToString(requestData)}).Debug("hash to sign")

	label := "key-" + keyID
	if handle, exists := keyHandles[label]; exists {
		session, err := module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			panic(err)
		}
		defer module.CloseSession(session)
		err = module.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, handle)
		if err != nil {
			panic(err)
		}
		sigVal, err := module.Sign(session, requestData)
		if err != nil {
			panic(err)
		}
		log.WithFields(log.Fields{"value": hex.EncodeToString(sigVal)}).Debug("signature")

		sig := createECSignature(sigVal)
		c.JSON(http.StatusOK, sig)
	} else {
		c.Status(http.StatusNotFound)
	}
}

func createECSignature(val []byte) Signature {
	// split value into two halves r and s
	len := len(val)
	r, s := val[:len/2], val[len/2:]
	log.WithFields(log.Fields{"r": hex.EncodeToString(r), "s": hex.EncodeToString(s)}).Info("signature")
	ecSig := ECSignature{R: new(big.Int).SetBytes(r), S: new(big.Int).SetBytes(s)}
	encodedSig, err := asn1.Marshal(ecSig)
	if err != nil {
		panic(errors.New("failed encode signature: " + err.Error()))
	}
	return Signature{Value: encodedSig}
}

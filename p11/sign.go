package p11

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

var module *pkcs11.Ctx
var slot uint
var globalSession pkcs11.SessionHandle
var keyHandles map[string]pkcs11.ObjectHandle

//Signature holds a signature value
type Signature struct {
	Value []byte `json:"value,omitempty"`
}

//ECSignature holds EC signature components r and s for ASN.1 encoding
type ECSignature struct {
	R *big.Int
	S *big.Int
}

func init() {
	module = pkcs11.New("/usr/lib/softhsm/libsofthsm2.so")
	err := module.Initialize()
	if err != nil {
		panic(err)
	}

	// defer p.Destroy()
	// defer p.Finalize()

	slots, err := module.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	slot = slots[0]
	globalSession, err = module.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	// defer module.CloseSession(globalSession)

	err = module.Login(globalSession, pkcs11.CKU_USER, "1234")
	if err != nil {
		panic(err)
	}
	// defer module.Logout(globalSession)

	keyHandles = make(map[string]pkcs11.ObjectHandle)

	module.FindObjectsInit(globalSession, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	})
	objs, _, err := module.FindObjects(globalSession, 100)
	if err != nil {
		panic(err)
	}

	for _, handle := range objs {
		attrs, err := module.GetAttributeValue(globalSession, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		})
		if err != nil {
			panic(err)
		}
		label := string(attrs[0].Value)
		keyHandles[label] = handle
		fmt.Printf("Object: %d, Label: %s", handle, attrs[0].Value)
	}
	module.FindObjectsFinal(globalSession)
}

//Sign creates a signature
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
		session, err := module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			panic(err)
		}
		defer module.CloseSession(session)
		module.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, handle)
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

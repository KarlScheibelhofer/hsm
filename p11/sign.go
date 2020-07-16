package p11

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

var module *pkcs11.Ctx
var slot uint
var globalSession pkcs11.SessionHandle
var keyHandles map[string]pkcs11.ObjectHandle

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

type signature struct {
	Value []byte `json:"value,omitempty"`
}

//Sign creates a signature
func Sign(c *gin.Context) {
	keyID := c.Param("id")
	requestData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		panic(err)
	}

	log.WithFields(log.Fields{"id": keyID}).Info("Sign with key")

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
		sig := signature{
			Value: sigVal,
		}
		c.JSON(http.StatusOK, sig)
	} else {
		c.Status(http.StatusNotFound)
	}
}

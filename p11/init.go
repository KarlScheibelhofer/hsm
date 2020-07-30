package p11

import (
	"encoding/binary"
	"fmt"

	"github.com/miekg/pkcs11"
)

var module *pkcs11.Ctx
var slot uint
var globalSession pkcs11.SessionHandle

//Key holde handles for PKCS#11 and the type info
type Key struct {
	privKeyHandle pkcs11.ObjectHandle
	pubKeyHandle  pkcs11.ObjectHandle
	keyType       uint64
}

var keyMap map[string]Key

//initialize the pkcs#11 module, open one session and login, search for keys
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

	keyMap = make(map[string]Key)

	err = findKeys(keyMap)
	if err != nil {
		panic(err)
	}
}

func findKeys(keyMap map[string]Key) error {
	module.FindObjectsInit(globalSession, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	})
	objs, _, err := module.FindObjects(globalSession, 100)
	if err != nil {
		return err
	}

	for _, keyHandle := range objs {
		attrs, err := module.GetAttributeValue(globalSession, keyHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		})
		if err != nil {
			return err
		}
		label := string(attrs[0].Value)
		keyType := binary.LittleEndian.Uint64(attrs[1].Value)
		key := Key{
			privKeyHandle: keyHandle,
			pubKeyHandle:  0,
			keyType:       keyType,
		}
		keyMap[label] = key
		fmt.Printf("Object: %d, Label: %s, Type: %X", keyHandle, label, keyType)
	}
	err = module.FindObjectsFinal(globalSession)
	if err != nil {
		return err
	}
	return nil
}

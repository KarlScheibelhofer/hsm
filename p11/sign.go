package p11

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"

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
	if key, exists := keyMap[label]; exists {
		session, err := module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			panic(err)
		}
		defer module.CloseSession(session)
		var mechansim *pkcs11.Mechanism
		switch key.keyType {
		case pkcs11.CKK_EC:
			mechansim = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
		case pkcs11.CKK_RSA:
			mechansim = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
		default:
			panic(errors.New("unsupported key type " + strconv.FormatUint(key.keyType, 16)))
		}
		err = module.SignInit(session, []*pkcs11.Mechanism{mechansim}, key.privKeyHandle)
		if err != nil {
			panic(err)
		}
		sigVal, err := module.Sign(session, requestData)
		if err != nil {
			panic(err)
		}
		log.WithFields(log.Fields{"value": hex.EncodeToString(sigVal)}).Debug("signature")

		var encodedSig []byte
		if mechansim.Mechanism == pkcs11.CKM_ECDSA {
			encodedSig, err = encodeECSignature(sigVal)
			if err != nil {
				panic(err)
			}
		} else {
			encodedSig = sigVal
		}
		sig := Signature{Value: encodedSig}
		c.JSON(http.StatusOK, sig)
	} else {
		c.Status(http.StatusNotFound)
	}
}

func encodeECSignature(val []byte) ([]byte, error) {
	// split value into two halves r and s
	len := len(val)
	r, s := val[:len/2], val[len/2:]
	log.WithFields(log.Fields{"r": hex.EncodeToString(r), "s": hex.EncodeToString(s)}).Info("signature")
	ecSig := ECSignature{R: new(big.Int).SetBytes(r), S: new(big.Int).SetBytes(s)}
	encodedSig, err := asn1.Marshal(ecSig)
	if err != nil {
		return nil, errors.New("failed encode signature: " + err.Error())
	}
	return encodedSig, nil
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

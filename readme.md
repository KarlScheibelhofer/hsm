# Web API to HSMs

This is a web API to access HSMs using PKCS#11.

Written in Go.

Install PKCS#11 module softhsm2 (Ubuntu 20.04)
```
sudo apt install softhsm2
softhsm2-util --init-token --slot 0 --label "token-0" --so-pin 1234 --pin 1234
softhsm2-util --show-slots
openssl genpkey -algorithm EC -out key-1-ec-p256.pem -pkeyopt ec_paramgen_curve:secp384r1 -pkeyopt ec_param_enc:named_curve
openssl ec -in key-1-ec-p256.pem -pubout -out key-1-ec-p256-public.pem
openssl asn1parse -in key-1-ec-p256.pem
softhsm2-util --import key-1-ec-p256.pem --slot 2143836342 --label "key-1" --id 01 --pin 1234 
```

```
openssl dgst -sha256 -sign key-1-ec-p256.pem -out signature.bin data
openssl dgst -sha256 -verify key-1-ec-p256-public.pem -signature signature.bin data
dumpasn1 signature.bin
```

```
dumpasn1 webapi/test-signature.bin
openssl dgst -sha256 -verify key-1-ec-p256-public.pem -signature webapi/test-signature.bin data
```

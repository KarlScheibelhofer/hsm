# Web API to HSMs

This is a web API to access HSMs using PKCS#11.

Written in Go.

Install PKCS#11 module softhsm2 (Ubuntu 20.04)

Initialize Tokens
```
sudo apt install softhsm2
softhsm2-util --init-token --slot 0 --label "token-0" --so-pin 1234 --pin 1234
softhsm2-util --show-slots
```

Generate and Import EC key for signing
```
openssl genpkey -algorithm EC -out key-1-ec-p256.pem -pkeyopt ec_paramgen_curve:secp384r1 -pkeyopt ec_param_enc:named_curve
openssl ec -in key-1-ec-p256.pem -pubout -out key-1-ec-p256-public.pem
openssl asn1parse -in key-1-ec-p256.pem
softhsm2-util --import key-1-ec-p256.pem --slot 2143836342 --label "key-1" --id 01 --pin 1234 
```

Generate and Import RSA key for decryption
```
openssl genpkey -algorithm RSA -out key-2-rsa-2048.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in key-2-rsa-2048.pem -pubout -out key-2-rsa-2048-public.pem
openssl asn1parse -in key-2-rsa-2048.pem
softhsm2-util --import key-2-rsa-2048.pem --slot 2143836342 --label "key-2" --id 02 --pin 1234 
```

Test signature manually against service
```
openssl dgst -sha256 -sign key-1-ec-p256.pem -out signature.bin data
openssl dgst -sha256 -verify key-1-ec-p256-public.pem -signature signature.bin data
dumpasn1 signature.bin
```

```
dumpasn1 webapi/test-signature.bin
openssl dgst -sha256 -verify key-1-ec-p256-public.pem -signature webapi/test-signature.bin data
```

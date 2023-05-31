package acme_http

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type DERCertificateBytes []byte

func PEMEncode(data interface{}) []byte {
	return pem.EncodeToMemory(PEMBlock(data))
}

func PEMBlock(data interface{}) *pem.Block {
	var pemBlock *pem.Block
	switch key := data.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, _ := x509.MarshalECPrivateKey(key)
		pemBlock = &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	case *x509.CertificateRequest:
		pemBlock = &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: key.Raw}
	case DERCertificateBytes:
		pemBlock = &pem.Block{Type: "CERTIFICATE", Bytes: []byte(data.(DERCertificateBytes))}
	}

	return pemBlock
}

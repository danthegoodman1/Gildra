package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// Constants for OCSP must staple.
var (
	tlsFeatureExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	ocspMustStapleFeature  = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
)

func GenerateCSR(privateKey crypto.PrivateKey, domain string, san []string, mustStaple bool) ([]byte, error) {
	template := x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: san,
	}

	if mustStaple {
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    tlsFeatureExtensionOID,
			Value: ocspMustStapleFeature,
		})
	}

	return x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
}

// CSRMessage Certificate Signing Request.
// - https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
type CSRMessage struct {
	// csr (required, string):
	// A CSR encoding the parameters for the certificate being requested [RFC2986].
	// The CSR is sent in the base64url-encoded version of the DER format.
	// (Note: Because this field uses base64url, and does not include headers, it is different from PEM.).
	Csr string `json:"csr"`
}

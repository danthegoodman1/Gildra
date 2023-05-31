package acme_http

// RawCertificate raw data of a certificate.
type RawCertificate struct {
	Cert   []byte
	Issuer []byte
}

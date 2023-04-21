package acme

// RawCertificate raw data of a certificate.
type RawCertificate struct {
	Cert   []byte
	Issuer []byte
}

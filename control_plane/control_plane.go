package control_plane

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var (
	ErrDecoding = errors.New("error decoding")
)

type (
	FQDNConfig struct {
		Cert Cert
	}
	Cert struct {
		CertPEM string
		KeyPEM  string
	}
)

func GetFQDNConfig(fqdn string) (*FQDNConfig, error) {
	// TODO: First check groupcache for stored results
	// TODO: If not in groupcache, then we need to visit the
	return nil, nil
}

// GetHTTPChallengeToken fetches the HTTP challenge token from the control plane
// to fulfil the HTTP ACME challenge.
func GetHTTPChallengeToken(fqdn, idToken string) (string, error) {
	return "", nil
}

func (c *FQDNConfig) GetCert() (*tls.Certificate, error) {
	certDERBlock, _ := pem.Decode([]byte(c.Cert.CertPEM))
	if certDERBlock == nil {
		return nil, fmt.Errorf("error decoding CertPEM: %w", ErrDecoding)
	}
	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing decoded cert block: %w", err)
	}

	keyDERBlock, _ := pem.Decode([]byte(c.Cert.KeyPEM))
	if keyDERBlock == nil {
		return nil, fmt.Errorf("error decoding KeyPEM: %w", ErrDecoding)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing decoded key block: %w", err)
	}

	certificate := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}
	return &certificate, nil
}

// Methods for groupcache
func (c *FQDNConfig) String() string {
	return ""
}

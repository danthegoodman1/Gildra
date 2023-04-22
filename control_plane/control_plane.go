package control_plane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/danthegoodman1/Gildra/gologger"
	"github.com/danthegoodman1/Gildra/internal"
	"github.com/go-redis/redis/v8"
	"github.com/mailgun/groupcache/v2"
	"log"
	"time"
)

var (
	ErrDecoding = errors.New("error decoding")

	// Idempotency check
	registeredHandlers = false

	FQDNGroupCache *groupcache.Group
	CertGroupCache *groupcache.Group

	redisClient = redis.NewClient(func() *redis.Options {
		opt, _ := redis.ParseURL("redis://default:33584fc0dfa54056b5af3ad060e99918@us1-dominant-antelope-38601.upstash.io:38601")
		return opt
	}())

	logger = gologger.NewLogger()
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

func RegisterCacheHandlers() {
	if registeredHandlers {
		return
	}
	FQDNGroupCache = groupcache.NewGroup("fqdn_config", Env_FQDNCacheMB, groupcache.GetterFunc(
		func(ctx context.Context, fqdn string, dest groupcache.Sink) error {

			fqdnConf, err := getFQDNConfig(fqdn)
			if err != nil {
				return fmt.Errorf("error in GetFQDNConfig: %w", err)
			}

			// serialize as JSON - optimize later
			jsonBytes, err := json.Marshal(fqdnConf)
			if err != nil {
				return fmt.Errorf("error in json.Marshal for fqdnConf: %w", err)
			}

			// Set the user in the groupcache to expire after 5 minutes
			return dest.SetBytes(jsonBytes, time.Now().Add(time.Second*time.Duration(Env_FQDNCacheSeconds)))
		},
	))

	// The cert group will look up through the FQDNConfigGroup, and store the result for longer.
	// Not very elegant but this is the way we have to handle it to both only ever need to both serve
	// on request and cache the certs and routing config with separate timeouts
	CertGroupCache = groupcache.NewGroup("certs", Env_CertCacheMB, groupcache.GetterFunc(
		func(ctx context.Context, fqdn string, dest groupcache.Sink) error {

			// TODO: Do the request
			fqdnConf, err := getFQDNConfig(fqdn)
			if err != nil {
				return fmt.Errorf("error in GetFQDNConfig: %w", err)
			}

			cert, err := fqdnConf.GetCert()
			if err != nil {
				return fmt.Errorf("error in GetCert: %w", err)
			}

			// serialize as JSON - optimize later
			jsonBytes, err := json.Marshal(cert)
			if err != nil {
				return fmt.Errorf("error in json.Marshal for tls.Certificate: %w", err)
			}

			internal.Metric_CacheMissTLSLookups.Inc()

			// Set the user in the groupcache to expire after 5 minutes
			return dest.SetBytes(jsonBytes, time.Now().Add(time.Second*time.Duration(Env_CertCacheSeconds)))
		},
	))
	registeredHandlers = true
}

func getFQDNConfig(fqdn string) (*FQDNConfig, error) {
	return nil, nil
}

func GetFQDNConfig(fqdn string) (*FQDNConfig, error) {
	// TODO: First check groupcache for stored results
	// TODO: If not in groupcache, then we need to visit the
	return nil, nil
}

func GetFQDNCert(fqdn string) (*tls.Certificate, error) {
	log.Println("getting cert for fqdn", fqdn)
	keyString, err := redisClient.Get(context.Background(), "key").Result()
	if err != nil {
		return nil, fmt.Errorf("error in redis get: %w", err)
	}
	certString, err := redisClient.Get(context.Background(), "cert").Result()
	if err != nil {
		return nil, fmt.Errorf("error in redis get: %w", err)
	}

	config := FQDNConfig{Cert: Cert{
		CertPEM: certString,
		KeyPEM:  keyString,
	}}

	return config.GetCert()
}

// GetHTTPChallengeToken fetches the HTTP challenge token from the control plane
// to fulfil the HTTP ACME challenge.
func GetHTTPChallengeToken(fqdn, idToken string) (string, error) {
	token, err := redisClient.Get(context.Background(), idToken).Result()
	if err != nil {
		return "", fmt.Errorf("error in redis get: %w", err)
	}
	return token, nil
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

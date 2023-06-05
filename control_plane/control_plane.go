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
	"github.com/danthegoodman1/Gildra/routing"
	"github.com/danthegoodman1/Gildra/utils"
	"github.com/go-redis/redis/v8"
	"github.com/mailgun/groupcache/v2"
	"io"
	"log"
	"net/http"
	"time"
)

var (
	ErrDecoding = errors.New("error decoding")

	// Idempotency check
	registeredHandlers = false

	// Returns a `FQDNConfig`
	FQDNGroupCache *groupcache.Group

	// Returns a `Cert`.
	CertGroupCache *groupcache.Group

	redisClient = redis.NewClient(func() *redis.Options {
		opt, _ := redis.ParseURL("redis://default:33584fc0dfa54056b5af3ad060e99918@us1-dominant-antelope-38601.upstash.io:38601")
		return opt
	}())

	logger = gologger.NewLogger()
)

type (
	Cert struct {
		CertPEM string
		KeyPEM  string
	}
)

// RegisterCacheHandlers must only be called after groupcache is registered
func RegisterCacheHandlers() {
	logger.Debug().Msg("registering cache handlers")
	if registeredHandlers {
		return
	}

	FQDNGroupCache = groupcache.NewGroup("fqdn_config", Env_FQDNCacheMB, groupcache.GetterFunc(
		func(ctx context.Context, fqdn string, dest groupcache.Sink) error {

			fqdnConf, err := getFQDNConfigFromCP(fqdn)
			if err != nil {
				return fmt.Errorf("error in GetFQDNConfig: %w", err)
			}

			// serialize as JSON - optimize later
			jsonBytes, err := json.Marshal(fqdnConf)
			if err != nil {
				return fmt.Errorf("error in json.Marshal for fqdnConf: %w", err)
			}

			internal.Metric_RoutingConfigCacheFill.Inc()

			return dest.SetBytes(jsonBytes, time.Now().Add(time.Second*time.Duration(Env_FQDNCacheSeconds)))
		},
	))

	CertGroupCache = groupcache.NewGroup("certs", Env_CertCacheMB, groupcache.GetterFunc(
		func(ctx context.Context, fqdn string, dest groupcache.Sink) error {
			certResp, err := getFQDNCertFromCP(fqdn)
			if err != nil {
				return fmt.Errorf("error in GetFQDNConfig: %w", err)
			}

			go func(ctx context.Context, fqdn string) {
				// async fill the cache for the routing config in the background
				err := FQDNGroupCache.Get(ctx, fqdn, nil)
				if err != nil {
					logger.Error().Err(err).Str("fqdn", fqdn).Msg("error fetching routing config async from cert cache")
				}
			}(ctx, fqdn)

			cert, err := certResp.GetCert()
			if err != nil {
				return fmt.Errorf("error in GetCert: %w", err)
			}

			// serialize as JSON - optimize later
			jsonBytes, err := json.Marshal(cert)
			if err != nil {
				return fmt.Errorf("error in json.Marshal for tls.Certificate: %w", err)
			}

			internal.Metric_CertCacheFill.Inc()

			return dest.SetBytes(jsonBytes, time.Now().Add(time.Second*time.Duration(Env_CertCacheSeconds)))
		},
	))
	registeredHandlers = true
}

func getFQDNConfigFromCP(fqdn string) (*routing.Config, error) {
	return nil, nil
}

func getFQDNCertFromCP(fqdn string) (*Cert, error) {
	return nil, nil
}

func GetFQDNConfig(ctx context.Context, fqdn string) (*routing.Config, error) {
	return &routing.Config{Rules: []routing.Rule{
		{
			Matches: []routing.Match{
				{
					Destinations: []routing.Destination{
						{
							DEVTextResponse: true,
						},
					},
				},
			},
		},
	}}, nil

	var b []byte
	err := FQDNGroupCache.Get(ctx, fqdn, groupcache.AllocatingByteSliceSink(&b))
	if err != nil {
		return nil, fmt.Errorf("error getting from groupcache: %w", err)
	}

	var config routing.Config
	err = json.Unmarshal(b, &config)
	if err != nil {
		return nil, fmt.Errorf("error in json.Unmarshal: %w", err)
	}

	internal.Metric_RoutingConfigLookups.Inc()
	return &config, nil
}

type GetCertRes struct {
	Cert       string
	PrivateKey string
}

func GetFQDNCert(fqdn string) (*tls.Certificate, error) {
	log.Println("getting cert for fqdn", fqdn)
	req, err := http.NewRequestWithContext(context.Background(), "GET", utils.Env_ControlPlaneAddr+"/cert?domain="+fqdn, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating new request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error doing request: %w", err)
	}
	defer res.Body.Close()
	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body: %w", err)
	}

	var resBody GetCertRes
	err = json.Unmarshal(resBytes, &resBody)
	if err != nil {
		return nil, fmt.Errorf("error in Unmarshal: %w", err)
	}

	c := Cert{
		CertPEM: resBody.Cert,
		KeyPEM:  resBody.PrivateKey,
	}

	internal.Metric_CertLookups.Inc()

	return c.GetCert()
}

func GetFQDNCertForReal(ctx context.Context, fqdn string) (*tls.Certificate, error) {
	log.Println("getting cert for fqdn", fqdn)
	var b []byte
	err := CertGroupCache.Get(ctx, fqdn, groupcache.AllocatingByteSliceSink(&b))
	if err != nil {
		return nil, fmt.Errorf("error getting from groupcache: %w", err)
	}

	var cert Cert
	err = json.Unmarshal(b, &cert)
	if err != nil {
		return nil, fmt.Errorf("error in json.Unmarshal: %w", err)
	}

	c, err := cert.GetCert()
	if err != nil {
		return nil, fmt.Errorf("error in cert.GetCert(): %w", err)
	}

	internal.Metric_CertLookups.Inc()
	return c, nil
}

// GetHTTPChallengeToken fetches the HTTP challenge token from the control plane
// to fulfil the HTTP ACME challenge.
func GetHTTPChallengeToken(fqdn, idToken string) (string, error) {
	log.Println("getting http challenge token")
	req, err := http.NewRequestWithContext(context.Background(), "GET", utils.Env_ControlPlaneAddr+"/cert/token?token="+idToken, nil)
	if err != nil {
		return "", fmt.Errorf("error creating new request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error doing request: %w", err)
	}
	defer res.Body.Close()
	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("error reading body: %w", err)
	}

	return string(resBytes), nil
}

func (c *Cert) GetCert() (*tls.Certificate, error) {
	certDERBlock, _ := pem.Decode([]byte(c.CertPEM))
	if certDERBlock == nil {
		return nil, fmt.Errorf("error decoding CertPEM: %w", ErrDecoding)
	}
	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing decoded cert block: %w", err)
	}

	keyDERBlock, _ := pem.Decode([]byte(c.KeyPEM))
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

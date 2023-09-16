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
	"github.com/mailgun/groupcache/v2"
	"github.com/rs/zerolog"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ErrDecoding       = errors.New("error decoding")
	ErrHighStatusCode = errors.New("high status code")

	poolServer     *http.Server
	FQDNGroupCache *groupcache.Group
	CertGroupCache *groupcache.Group

	logger = gologger.NewLogger()
)

type (
	Cert struct {
		CertPEM string
		KeyPEM  string
	}
)

// InitCache must only be called after groupcache is registered
func InitCache(ctx context.Context) {
	logger := zerolog.Ctx(ctx)
	logger.Debug().Msg("initializing cache")
	pool := groupcache.NewHTTPPoolOpts(utils.CacheSelfAddr, &groupcache.HTTPPoolOptions{})

	// Add more peers to the cluster You MUST Ensure our instance is included in this list else
	// determining who owns the key across the cluster will not be consistent, and the pool won't
	// be able to determine if our instance owns the key.
	pool.Set(utils.CachePeers...)

	listenAddr := strings.Split(utils.CacheSelfAddr, "://")[1]
	poolServer = &http.Server{
		Addr:    listenAddr,
		Handler: pool,
	}

	// Start an HTTP server to listen for peer requests from the groupcache
	go func() {
		logger.Debug().Msgf("cache pool server listening on %s", listenAddr)
		if err := poolServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error().Err(err).Msg("error on pool server listen")
		}
	}()

	FQDNGroupCache = groupcache.NewGroup("config", utils.Env_FQDNCacheMB, groupcache.GetterFunc(
		func(ctx context.Context, fqdn string, dest groupcache.Sink) error {
			configBytes, err := getFQDNConfigBytes(ctx, fqdn)
			if err != nil {
				return fmt.Errorf("error in GetFQDNConfig: %w", err)
			}

			internal.Metric_RoutingConfigCacheFill.Inc()

			return dest.SetBytes(configBytes, time.Now().Add(time.Second*time.Duration(utils.Env_ConfigCacheSeconds)))
		},
	))

	CertGroupCache = groupcache.NewGroup("cert", utils.Env_CertCacheMB, groupcache.GetterFunc(
		func(ctx context.Context, fqdn string, dest groupcache.Sink) error {
			certBytes, err := getFQDNCertBytes(ctx, fqdn)
			if err != nil {
				return fmt.Errorf("error in GetFQDNConfig: %w", err)
			}

			if utils.Env_FetchConfigConcurrently {
				go func(ctx context.Context, fqdn string) {
					// async fill the cache for the routing config in the background
					err := FQDNGroupCache.Get(ctx, fqdn, nil)
					if err != nil {
						logger.Error().Err(err).Str("fqdn", fqdn).Msg("error fetching routing config async from cert cache")
					}
				}(ctx, fqdn)
			}

			internal.Metric_CertCacheFill.Inc()

			return dest.SetBytes(certBytes, time.Now().Add(time.Second*time.Duration(utils.Env_CertCacheSeconds)))
		},
	))
}

func StopCache(ctx context.Context) error {
	return poolServer.Shutdown(ctx)
}

// Bytes of routing.Config
func getFQDNConfigBytes(ctx context.Context, fqdn string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/domains/%s/config", utils.Env_ControlPlaneAddr, fqdn), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating new request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", utils.Env_ControlPlaneAuthHeader))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error doing request: %w", err)
	}
	defer res.Body.Close()
	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body: %w", err)
	}

	if res.StatusCode > 299 {
		return nil, fmt.Errorf("high status code %d - %s: %w", res.StatusCode, string(resBytes), ErrHighStatusCode)
	}

	return resBytes, nil
}

// Bytes of control_plane.GetCertRes
func getFQDNCertBytes(ctx context.Context, fqdn string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/domains/%s/cert", utils.Env_ControlPlaneAddr, fqdn), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating new request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", utils.Env_ControlPlaneAuthHeader))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error doing request: %w", err)
	}
	defer res.Body.Close()
	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body: %w", err)
	}

	if res.StatusCode > 299 {
		return nil, fmt.Errorf("high status code %d - %s: %w", res.StatusCode, string(resBytes), ErrHighStatusCode)
	}

	return resBytes, nil
}

func GetFQDNConfig(ctx context.Context, fqdn string) (*routing.Config, error) {
	var b []byte
	var err error
	if utils.CacheEnabled {
		err = FQDNGroupCache.Get(ctx, fqdn, groupcache.AllocatingByteSliceSink(&b))
		if err != nil {
			return nil, fmt.Errorf("error getting from groupcache: %w", err)
		}
	} else {
		b, err = getFQDNConfigBytes(ctx, fqdn)
		if err != nil {
			return nil, fmt.Errorf("error in getFQDNConfigBytes: %w", err)
		}
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
	Cert string
	Key  string
}

func GetFQDNCert(ctx context.Context, fqdn string) (*tls.Certificate, error) {
	var b []byte
	var err error
	if utils.CacheEnabled {
		err = CertGroupCache.Get(ctx, fqdn, groupcache.AllocatingByteSliceSink(&b))
		if err != nil {
			return nil, fmt.Errorf("error getting from groupcache: %w", err)
		}
	} else {
		b, err = getFQDNCertBytes(ctx, fqdn)
		if err != nil {
			return nil, fmt.Errorf("error in getFQDNCertBytes: %w", err)
		}
	}

	var cert GetCertRes
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

type ChallengeTokenRes struct {
	Key string
}

// GetHTTPChallengeToken fetches the HTTP challenge token from the control plane
// to fulfil the HTTP ACME challenge.
func GetHTTPChallengeToken(fqdn, idToken string) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("%s/domains/%s/challenge/%s", utils.Env_ControlPlaneAddr, fqdn, idToken), nil)
	if err != nil {
		return "", fmt.Errorf("error creating new request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", utils.Env_ControlPlaneAuthHeader))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error doing request: %w", err)
	}
	defer res.Body.Close()
	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("error reading body: %w", err)
	}

	if res.StatusCode > 299 {
		return "", fmt.Errorf("high status code %d - %s: %w", res.StatusCode, string(resBytes), ErrHighStatusCode)
	}

	var resBody ChallengeTokenRes
	err = json.Unmarshal(resBytes, &resBody)
	if err != nil {
		return "", fmt.Errorf("error in Unmarshal: %w", err)
	}

	return resBody.Key, nil
}

func (c *GetCertRes) GetCert() (*tls.Certificate, error) {
	certDERBlock, _ := pem.Decode([]byte(c.Cert))
	if certDERBlock == nil {
		return nil, fmt.Errorf("error decoding CertPEM: %w", ErrDecoding)
	}
	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing decoded cert block: %w", err)
	}

	keyDERBlock, _ := pem.Decode([]byte(c.Key))
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

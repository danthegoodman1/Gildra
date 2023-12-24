package http_server

import (
	"context"
	"fmt"
	"github.com/danthegoodman1/Gildra/control_plane"
	"github.com/danthegoodman1/Gildra/internal"
	"github.com/danthegoodman1/Gildra/tracing"
	"go.opentelemetry.io/otel/attribute"
	"net/http"
	"path"
	"strings"
)

func handleHTTPChallenge(ctx context.Context, fqdn string, w http.ResponseWriter, r *http.Request) {
	ctx, span := tracing.GildraTracer.Start(ctx, "handleHTTPChallenge")
	defer span.End()

	if strings.HasPrefix(r.URL.Path, ZeroSSLPathPrefix) {
		span.SetAttributes(attribute.Bool("zeroSSLChallenge", true))
		logger.Debug().Msgf("got ZeroSSL HTTP challenge request for FQDN %s", fqdn)

		_, token := path.Split(r.URL.Path)
		logger.Debug().Msg(fmt.Sprint("Got challenge for fqdn", fqdn, "token", token))
		key, err := control_plane.GetHTTPChallengeKey(fqdn, token)
		if err != nil {
			logger.Error().Err(err).Msgf("error in GetHTTPChallengeToken for FQDN %s", fqdn)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logger.Debug().Msg(fmt.Sprint("Got key", key))
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(key))
		if err != nil {
			logger.Error().Err(err).Msg("error in writing bytes to response for HTTP ZeroSSL challenge")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logger.Debug().Msg(fmt.Sprint("wrote response", key))
		internal.Metric_ZEROSSL_HTTP_Challenges.Inc()
		return
	}

	// Otherwise ACME
	span.SetAttributes(attribute.Bool("acmeChallenge", true))
	logger.Debug().Msgf("got ACME HTTP challenge request for FQDN %s", fqdn)

	_, token := path.Split(r.URL.Path)
	logger.Debug().Msg(fmt.Sprint("Got challenge for fqdn", fqdn, "token", token))
	key, err := control_plane.GetHTTPChallengeKey(fqdn, token)
	if err != nil {
		logger.Error().Err(err).Msgf("error in GetHTTPChallengeToken for FQDN %s", fqdn)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Debug().Msg(fmt.Sprint("Got key", key))
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(key))
	if err != nil {
		logger.Error().Err(err).Msg("error in writing bytes to response for HTTP ACME challenge")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Debug().Msg(fmt.Sprint("wrote response", key))
	internal.Metric_ACME_HTTP_Challenges.Inc()
	return
}

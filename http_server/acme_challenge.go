package http_server

import (
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/danthegoodman1/Gildra/control_plane"
	"github.com/danthegoodman1/Gildra/internal"
	"github.com/danthegoodman1/Gildra/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// func handleHTTPChallenge(ctx context.Context, fqdn string, w http.ResponseWriter, r *http.Request) {
func handleHTTPChallenge(rc *RequestContext) {
	_, span := tracing.GildraTracer.Start(rc.Request.Context(), "handleHTTPChallenge")
	defer span.End()

	if strings.HasPrefix(rc.Request.URL.Path, ZeroSSLPathPrefix) {
		span.SetAttributes(attribute.Bool("zeroSSLChallenge", true))
		globalLogger.Debug().Msgf("got ZeroSSL HTTP challenge request for FQDN %s", rc.FQDN)

		_, token := path.Split(rc.Request.URL.Path)
		globalLogger.Debug().Msg(fmt.Sprint("Got challenge for fqdn", rc.FQDN, "token", token))
		key, err := control_plane.GetHTTPChallengeKey(rc.FQDN, token)
		if err != nil {
			globalLogger.Error().Err(err).Msgf("error in GetHTTPChallengeToken for FQDN %s", rc.FQDN)
			rc.responseWriter.WriteHeader(http.StatusInternalServerError)
			return
		}
		globalLogger.Debug().Msg(fmt.Sprint("Got key", key))
		rc.responseWriter.WriteHeader(http.StatusOK)
		_, err = rc.responseWriter.Write([]byte(key))
		if err != nil {
			globalLogger.Error().Err(err).Msg("error in writing bytes to response for HTTP ZeroSSL challenge")
			rc.responseWriter.WriteHeader(http.StatusInternalServerError)
			return
		}
		globalLogger.Debug().Msg(fmt.Sprint("wrote response", key))
		internal.Metric_ZEROSSL_HTTP_Challenges.Inc()
		return
	}

	// Otherwise ACME
	span.SetAttributes(attribute.Bool("acmeChallenge", true))
	globalLogger.Debug().Msgf("got ACME HTTP challenge request for FQDN %s", rc.FQDN)

	_, token := path.Split(rc.Request.URL.Path)
	globalLogger.Debug().Msg(fmt.Sprint("Got challenge for fqdn", rc.FQDN, "token", token))
	key, err := control_plane.GetHTTPChallengeKey(rc.FQDN, token)
	if err != nil {
		globalLogger.Error().Err(err).Msgf("error in GetHTTPChallengeToken for FQDN %s", rc.FQDN)
		rc.responseWriter.WriteHeader(http.StatusInternalServerError)
		return
	}
	globalLogger.Debug().Msg(fmt.Sprint("Got key", key))
	rc.responseWriter.WriteHeader(http.StatusOK)
	_, err = rc.responseWriter.Write([]byte(key))
	if err != nil {
		globalLogger.Error().Err(err).Msg("error in writing bytes to response for HTTP ACME challenge")
		rc.responseWriter.WriteHeader(http.StatusInternalServerError)
		return
	}
	globalLogger.Debug().Msg(fmt.Sprint("wrote response", key))
	internal.Metric_ACME_HTTP_Challenges.Inc()
}

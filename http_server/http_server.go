package http_server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/danthegoodman1/Gildra/control_plane"
	"github.com/danthegoodman1/Gildra/gologger"
	"github.com/danthegoodman1/Gildra/internal"
	"github.com/danthegoodman1/Gildra/routing"
	"github.com/danthegoodman1/Gildra/tracing"
	"github.com/danthegoodman1/Gildra/utils"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/samber/lo"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/context"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/sync/errgroup"

	"golang.org/x/net/http2"
)

var (
	globalLogger = gologger.NewLogger()
	httpServer   *http.Server
	h3Server     *http3.Server

	ErrInternalErrorFetchingTLS = errors.New("internal error fetching TLS")
	ErrNoDestination            = errors.New("no destination for config")
	ErrFailedToCast             = errors.New("failed to cast")
)

const (
	ACMETestPathPrefix = "/.well-known/acme-test-challenge/"
	ACMEPathPrefix     = "/.well-known/acme-challenge/"
	ZeroSSLPathPrefix  = "/.well-known/pki-validation/"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close() // close when we are done JUST in case (but I think it does by default)

	internal.Metric_OpenConnections.Inc()
	defer internal.Metric_OpenConnections.Dec()

	rc := NewRequestContext(r, w)
	ctx := rc.Request.Context()
	logger := zerolog.Ctx(ctx)

	logger.Info().Msg("request")

	_, span := tracing.GildraTracer.Start(ctx, "HTTPHandler")
	defer span.End()

	if utils.Env_HTTPTimeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel := context.WithTimeout(rc.Request.Context(), time.Second*time.Duration(utils.Env_HTTPTimeoutSec))
		defer cancel()
		rc.Request.WithContext(ctx)
	}

	logger.Debug().Msg(fmt.Sprint("Proto:", r.Proto))
	logger.Debug().Msg(fmt.Sprint("Headers:", r.Header))
	logger.Debug().Msg(fmt.Sprint("Host:", r.Host))

	// Check for an ACME challenge
	if strings.HasPrefix(r.URL.Path, ACMEPathPrefix) || strings.HasPrefix(r.URL.Path, ACMETestPathPrefix) || strings.HasPrefix(r.URL.Path, ZeroSSLPathPrefix) {
		// This has its own handling
		handleHTTPChallenge(rc)
		return
	}

	err := writeRequest(rc, handleRequest(rc))
	if err != nil {
		logger.Error().Err(err).Msg("error in writeRequest")
	}
})

func handleRequest(rc *RequestContext) error {
	ctx := rc.Request.Context()
	logger := zerolog.Ctx(ctx)

	_, span := tracing.GildraTracer.Start(ctx, "handleRequest")
	defer span.End()

	span.SetAttributes(attribute.String("fqdn", rc.FQDN))
	span.SetAttributes(attribute.Bool("tls", rc.IsTLS))
	span.SetAttributes(attribute.String("requestID", rc.ReqID))
	span.SetAttributes(attribute.String("proto", rc.Proto))

	if utils.Dev_TextResponse {
		logger.Debug().Msg("dev response, writing text")
		return rc.RespondString(http.StatusCreated, fmt.Sprintf("DEV response\n\tproto: %s\n", rc.Proto))
	}

	config, err := control_plane.GetFQDNConfig(ctx, rc.FQDN)
	if err != nil {
		return fmt.Errorf("error in control_plane.GetFQDNConfig: %w", err)
	}

	dest, err := config.MatchDestination(ctx, rc.FQDN, rc.PathQuery, rc.Request)
	if err != nil {
		return fmt.Errorf("error in config.MatchDestination: %w", err)
	}
	if dest == nil {
		return ErrNoDestination
	}

	if dest.DEVTextResponse {
		logger.Debug().Msg("dev response, writing text")
		return rc.RespondString(http.StatusOK, fmt.Sprintf("DEV response\n\tproto: %s\n", rc.Proto))
	}

	if dest.TimeoutSec != nil {
		// If we have a timeout override, set it
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Second*time.Duration(*dest.TimeoutSec))
		defer cancel()
		rc.Request.WithContext(ctx)
	}

	// Proxy the request
	originReq, err := makeOriginRequest(rc, dest)
	if err != nil {
		return fmt.Errorf("error in makeOriginRequest: %w", err)
	}

	originRes, err := doOriginRequest(ctx, originReq, -1)
	if err != nil {
		return fmt.Errorf("error in doOriginRequest: %w", err)
	}
	// The response writer will close the body

	// Check for replay header
	var replays int64 = 0
	replayHeader := originRes.Header.Get("x-replay")
	for replayHeader != "" && replays < utils.Env_MaxReplays && originRes.StatusCode < 500 {
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("replayHeader", replayHeader).Int64("replays", replays)
		})
		logger.Debug().Msg("replaying request")
		originReq, err = makeOriginRequest(rc, dest)
		if err != nil {
			return fmt.Errorf("error in makeOriginRequest: %w", err)
		}
		originReq.Header.Set("X-Replayed", fmt.Sprint(replays))

		originRes, err = doOriginRequest(ctx, originReq, replays)
		if err != nil {
			return fmt.Errorf("error in doOriginRequest: %w", err)
		}
		// The response writer will close the body

		replayHeader = originRes.Header.Get("x-replay")
		replays++
	}

	if replays >= utils.Env_MaxReplays && replayHeader != "" {
		// We hit the limit
		logger.Warn().Msg("exceeded max replays, sending error to client")
		span.SetAttributes(attribute.Bool("exceededMaxReplays", true))
		return rc.RespondString(http.StatusBadGateway, "exceeded max replays")
	}

	logger.Debug().Msg(fmt.Sprint(rc.Request.Header.Get("Connection") == "Upgrade", originRes.StatusCode, originRes.StatusCode == http.StatusSwitchingProtocols))

	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Int("status", originRes.StatusCode).Int64("responseLength", originRes.ContentLength)
	})

	if rc.Request.Header.Get("Connection") == "Upgrade" && originRes.StatusCode == http.StatusSwitchingProtocols {
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Bool("websocket", true)
		})
		// Websocket
		return handleUpgradeResponse(rc, originReq, originRes)
	}

	// Copy the headers
	for key, vals := range originRes.Header {
		for _, val := range vals {
			rc.responseHeaders.Add(key, val)
		}
	}

	return rc.RespondReader(originRes.StatusCode, originRes.Body)
}

func writeRequest(rc *RequestContext, handlerError error) error {
	ctx := rc.Request.Context()
	logger := zerolog.Ctx(ctx)
	responseStatus := rc.responseStatus

	// Error-based overrides
	if errors.Is(handlerError, ErrNoDestination) {
		responseStatus = http.StatusServiceUnavailable
	} else if handlerError != nil {
		responseStatus = http.StatusInternalServerError
	}

	// Write the response headers
	for key, vals := range rc.responseHeaders {
		for _, val := range vals {
			rc.responseWriter.Header().Add(key, val)
		}
	}

	var err error
	if !rc.Hijacked() {
		if rc.responseReader != nil {
			defer rc.responseReader.Close()
		}
		// Write the status code
		rc.responseWriter.WriteHeader(responseStatus)

		_, span := tracing.GildraTracer.Start(ctx, "writeRequest")
		defer span.End()

		span.SetAttributes(attribute.Int("status", responseStatus))

		if handlerError != nil {
			// Let's first write the request ID
			_, err := rc.responseWriter.Write([]byte(fmt.Sprintf("Internal Error: %s", handlerError.Error())))
			if err != nil {
				return fmt.Errorf("error writing request ID to error response: %w", err)
			}
		} else {
			// Otherwise write the response
			_, err = io.Copy(rc.responseWriter, rc.responseReader)
		}
	}

	logger.Info().Int64("ms", time.Since(rc.Created).Milliseconds()).Msg("response")
	return err
}

func handleUpgradeResponse(rc *RequestContext, req *http.Request, res *http.Response) error {
	ctx := rc.Request.Context()
	ctx, span := tracing.GildraTracer.Start(ctx, "handleUpgradeResponse")
	defer span.End()
	logger := zerolog.Ctx(ctx)

	if req.Header.Get("Upgrade") != res.Header.Get("Upgrade") {
		logger.Warn().Msg("mismatched upgrade headers")
		return rc.RespondString(http.StatusConflict, "mismatched upgrade headers")
	}

	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		return fmt.Errorf("%w: response body to readwritecloser", ErrFailedToCast)
	}
	defer backConn.Close()

	// Hijack the handler
	hj, ok := rc.responseWriter.(http.Hijacker)
	if !ok {
		return fmt.Errorf("%w: responseWriter to http.Hijacker", ErrFailedToCast)
	}

	if err := rc.Hijack(); err != nil {
		return err
	}

	conn, brw, err := hj.Hijack()
	if err != nil {
		return fmt.Errorf("error in hj.Hijack: %w", err)
	}
	defer conn.Close()

	// **We now own the response**

	res.Body = nil // res.Write only writes the headers; we have res.Body in backConn above
	if err := res.Write(brw); err != nil {
		logger.Error().Err(err).Msgf("Failed to write headers: %s\n", err)
		return nil
	}
	if err := brw.Flush(); err != nil {
		logger.Error().Err(err).Msgf("Failed to flush headers: %s\n", err)
		return nil
	}

	spc := switchProtocolCopier{user: conn, backend: backConn}
	g := errgroup.Group{}
	g.Go(spc.copyToBackend)
	g.Go(spc.copyFromBackend)

	internal.Metric_OpenWebSockets.Inc()
	defer internal.Metric_OpenWebSockets.Dec()

	err = g.Wait()
	if err != nil {
		logger.Error().Err(err).Msgf("Failed copying websocket bytes: %s\n", err)
	} else {
		logger.Debug().Msg("Websocket hung up")
	}
	return nil
}

func StartServers() error {
	tlsConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			logger := zerolog.Ctx(ctx)
			fqdn := info.ServerName
			logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str("fqdn", fqdn)
			})
			opts := []trace.SpanStartOption{
				trace.WithSpanKind(trace.SpanKindServer),
			}
			ctx, span := tracing.GildraTracer.Start(ctx, "GetCertificate", opts...)
			defer span.End()
			span.SetAttributes(attribute.String("fqdn", fqdn))

			// You can use info.ServerName to determine which certificate to load
			logger.Debug().Msgf("fetching cert for fqdn %s", fqdn)
			logger.Debug().Msg(fmt.Sprint("Getting cert for fqdn", fqdn))

			// Load the certificate
			cert, err := control_plane.GetFQDNCert(ctx, fqdn)
			if err != nil {
				logger.Error().Err(err).Msg("error in control_plane.GetFQDNCert")
				// This error will get returned to the client
				return nil, ErrInternalErrorFetchingTLS
			}

			return cert, nil
		},
		NextProtos: []string{"h2", "http/1.1", "h3", "h3-29"},
	}

	listener, _ := net.Listen("tcp", ":80")

	h2cServer := &http2.Server{}
	httpServer = &http.Server{
		ReadTimeout:  0,
		WriteTimeout: 0,
		Handler:      h2c.NewHandler(handler, h2cServer),
	}

	// Configure the httpServer to support HTTP/2
	err := http2.ConfigureServer(httpServer, nil)
	if err != nil {
		return fmt.Errorf("error in http2.ConfigureServer: %w", err)
	}

	// Create a raw TCP listener for TLS
	rawTLSListener, err := net.Listen("tcp", ":443")
	if err != nil {
		return fmt.Errorf("failed to listen on :443: %w", err)
	}

	// Create SNI listener that will handle routing and TLS
	// It starts listening automatically
	NewSNIListener(rawTLSListener, tlsConfig, nil, httpServer) // nil uses DefaultSNIRouter

	h3Server = &http3.Server{
		TLSConfig:  tlsConfig,
		Handler:    handler,
		QUICConfig: &quic.Config{},
		Addr:       ":443",
	}

	globalLogger.Debug().Msg("Gildra listening on :80 (HTTP/1.1 and HTTP/2)")
	go httpServer.Serve(listener)
	globalLogger.Debug().Msg("Gildra listening on :443 (HTTP/1.1 and HTTP/2 with SNI routing)")
	// SNI listener is already running in its own goroutine
	globalLogger.Debug().Msg("Gildra listening on :443 (HTTP/3)")
	go h3Server.ListenAndServe()
	return nil
}

func Shutdown(ctx context.Context) error {
	g := errgroup.Group{}
	g.Go(func() error {
		return httpServer.Shutdown(ctx)
	})
	g.Go(func() error {
		return h3Server.Shutdown(ctx)
	})
	return g.Wait()
}

// handles writing the error, should always return after calling this. Has overrides for common errors
// like context.DeadlineExceeded
func respondServerError(ctx context.Context, span trace.Span, w http.ResponseWriter, status int, e error, msg string) {
	span.SetAttributes(attribute.Int("status", status))
	logger := zerolog.Ctx(ctx)
	var err error
	if errors.Is(e, context.DeadlineExceeded) {
		logger.Warn().Err(e).Msg("request deadline exceeded")
		w.WriteHeader(http.StatusRequestTimeout)
		_, err = fmt.Fprint(w, "internal error")
	} else {
		logger.Error().Err(e).Msg(msg)
		w.WriteHeader(status)
		_, err = fmt.Fprint(w, "internal error")
	}
	if err != nil {
		logger.Error().Err(err).Msg("error writing internal error to HTTP request")
	}
}

// makeOriginRequest makes a clone of the incoming request with additional headers added and adjustments to the destination.
func makeOriginRequest(rc *RequestContext, dest *routing.Destination) (*http.Request, error) {
	ctx := rc.Request.Context()
	finalURL := dest.URL + rc.PathQuery
	originReq, err := http.NewRequestWithContext(ctx, rc.Request.Method, finalURL, rc.Request.Body)
	if err != nil {
		return nil, err
	}

	// Switch in the headers, but keep original Host
	originReq.Header = rc.Request.Header.Clone()

	if utils.Env_DevDisableHost {
		originReq.Host = ""
	} else {
		// Forward the host
		originReq.Host = rc.FQDN
	}

	// Additional headers
	originReq.Header.Set("X-Url-Scheme", lo.Ternary(rc.IsTLS, "https", "http"))
	originReq.Header.Set("X-Forwarded-Proto", rc.Proto)
	originReq.Header.Set("X-Forwarded-To", finalURL)
	originReq.Header.Set("X-Forwarded-For", func(r *http.Request) string {
		incomingIP := strings.Split(r.RemoteAddr, ":")[0] // remove the port
		if existing := r.Header.Get("X-Forwarded-For"); existing != "" {
			return existing + fmt.Sprintf(", %s", incomingIP)
		}
		return incomingIP
	}(rc.Request))
	return originReq, nil
}

func doOriginRequest(ctx context.Context, req *http.Request, replays int64) (*http.Response, error) {
	ctx, span := tracing.GildraTracer.Start(ctx, "originRequest")
	defer span.End()
	if replays >= 0 {
		span.SetAttributes(attribute.Bool("replaying", true))
		span.SetAttributes(attribute.Int64("replays", replays))
	}
	res, err := http.DefaultClient.Do(req)
	if res != nil {
		span.SetAttributes(attribute.Int("originResponseStatus", res.StatusCode))
	}
	return res, err
}

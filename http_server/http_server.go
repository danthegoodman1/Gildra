package http_server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/danthegoodman1/Gildra/control_plane"
	"github.com/danthegoodman1/Gildra/gologger"
	"github.com/danthegoodman1/Gildra/internal"
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
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

var (
	globalLogger = gologger.NewLogger()
	httpServer   *http.Server
	h3Server     *http3.Server

	ErrInternalErrorFetchingTLS = errors.New("internal error fetching TLS")
)

const (
	ACMETestPathPrefix = "/.well-known/acme-test-challenge/"
	ACMEPathPrefix     = "/.well-known/acme-challenge/"
	ZeroSSLPathPrefix  = "/.well-known/pki-validation/"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fqdn := r.Host
	isTLS := r.TLS != nil
	ctx := context.Background()
	start := time.Now()

	logger := zerolog.Ctx(ctx)

	ctx, span := tracing.GildraTracer.Start(ctx, "HTTPHandler")
	defer span.End()

	requestID := utils.GenKSortedID("req_")
	span.SetAttributes(attribute.String("fqdn", fqdn))
	span.SetAttributes(attribute.Bool("tls", isTLS))
	span.SetAttributes(attribute.String("requestID", requestID))

	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("fqdn", fqdn).Bool("tls", isTLS).Str("requestID", requestID).Int64("requestLength", r.ContentLength)
	})

	internal.Metric_OpenConnections.Inc()
	defer internal.Metric_OpenConnections.Dec()
	if upgradeHeader := r.Header.Get("Upgrade"); upgradeHeader == "h2c" {
		logger.Debug().Msg(fmt.Sprint("Marking h2c as HTTP/2.0"))
		r.Proto = "HTTP/2.0"
	}
	logger.Debug().Msg(fmt.Sprint("Proto:", r.Proto))
	logger.Debug().Msg(fmt.Sprint("Headers:", r.Header))
	logger.Debug().Msg(fmt.Sprint("Host:", r.Host))
	span.SetAttributes(attribute.String("proto", r.Proto))
	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("proto", r.Proto)
	})

	ctx, cancel := context.WithTimeout(ctx, time.Second*time.Duration(utils.Env_HTTPTimeoutSec))
	defer cancel()

	// Check for an ACME challenge
	if strings.HasPrefix(r.URL.Path, ACMEPathPrefix) || strings.HasPrefix(r.URL.Path, ACMETestPathPrefix) || strings.HasPrefix(r.URL.Path, ZeroSSLPathPrefix) {
		handleHTTPChallenge(ctx, fqdn, w, r)
		return
	}

	if utils.Dev_TextResponse {
		logger.Debug().Msg("dev response, writing text")
		w.Header().Add("alt-svc", "h3=\":443\"; ma=86400")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "DEV response\n\tproto: %s\n", r.Proto)
		return
	}

	config, err := control_plane.GetFQDNConfig(ctx, fqdn)
	if err != nil {
		respondServerError(ctx, span, w, http.StatusInternalServerError, err, "error in control_plane.GetFQDNConfig")
		return
	}

	// Replace up through the domain name with destination
	// this only works because incoming requests don't have the scheme and host attached to the URL
	path := r.URL.String()

	dest, err := config.MatchDestination(ctx, fqdn, path, r)
	if err != nil {
		respondServerError(ctx, span, w, http.StatusInternalServerError, err, "error in config.MatchDestination")
		return
	}
	if dest == nil {
		respondServerError(ctx, span, w, http.StatusServiceUnavailable, err, "got no destination")
		return
	}

	if dest.DEVTextResponse {
		logger.Debug().Msg("dev response, writing text")
		w.Header().Add("alt-svc", "h3=\":443\"; ma=86400")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "DEV response\n\tproto: %s\n", r.Proto)
		return
	}

	// Proxy the request
	originReq, err := makeOriginRequest(ctx, fqdn, dest.URL+path, isTLS, r)
	if err != nil {
		respondServerError(ctx, span, w, http.StatusInternalServerError, err, "error making origin request")
		return
	}

	originRes, err := doOriginRequest(ctx, originReq, -1)
	if err != nil {
		respondServerError(ctx, span, w, http.StatusInternalServerError, err, "error doing origin request")
		return
	}
	defer originRes.Body.Close()

	logger.Info().Msg("request")

	// Check for replay header
	var replays int64 = 0
	replayHeader := originRes.Header.Get("x-replay")
	for replayHeader != "" && replays < utils.Env_MaxReplays && originRes.StatusCode < 500 {
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("replayHeader", replayHeader).Int64("replays", replays)
		})
		logger.Debug().Msg("replaying request")
		originReq, err = makeOriginRequest(ctx, fqdn, replayHeader+path, isTLS, r)
		if err != nil {
			respondServerError(ctx, span, w, http.StatusInternalServerError, err, "error making origin request after replay")
			return
		}
		originReq.Header.Set("X-Replayed", fmt.Sprint(replays))

		originRes, err = doOriginRequest(ctx, originReq, replays)
		if err != nil {
			respondServerError(ctx, span, w, http.StatusInternalServerError, err, "error doing origin request after replay")
			return
		}
		defer originRes.Body.Close()

		replayHeader = originRes.Header.Get("x-replay")
		replays++
	}

	if replays >= utils.Env_MaxReplays && replayHeader != "" {
		// We hit the limit
		logger.Warn().Msg("exceeded max replays, sending error to client")
		span.SetAttributes(attribute.Bool("exceededMaxReplays", true))
		w.WriteHeader(http.StatusBadGateway)
		_, err := fmt.Fprint(w, "exceeded max replays")
		if err != nil {
			logger.Error().Err(err).Msg("error writing internal error to HTTP request")
		}
		return
	}

	logger.Debug().Msg(fmt.Sprint(r.Header.Get("Connection") == "Upgrade", originRes.StatusCode, originRes.StatusCode == http.StatusSwitchingProtocols))

	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Int("status", originRes.StatusCode).Int64("responseLength", originRes.ContentLength)
	})

	defer func() {
		logger.Info().Int64("ms", time.Now().Sub(start).Milliseconds()).Msg("response")
	}()

	if r.Header.Get("Connection") == "Upgrade" && originRes.StatusCode == http.StatusSwitchingProtocols {
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Bool("websocket", true)
		})
		// Websocket
		handleUpgradeResponse(ctx, w, originReq, originRes)
		return
	}

	// Copy the headers
	for key, vals := range originRes.Header {
		for _, val := range vals {
			w.Header().Add(key, val)
		}
	}
	// Add h3 header
	w.Header().Add("alt-svc", "h3=\":443\"; ma=86400")
	// Start the response
	w.WriteHeader(originRes.StatusCode)
	span.SetAttributes(attribute.Int("status", originRes.StatusCode))

	// Pump the body
	_, err = io.Copy(w, originRes.Body)
	if err != nil {
		logger.Error().Err(err).Msg("error copying body from origin to client, this request is pretty broken at this point and the client will probably fail due to mismatched headers and body content")
	}

	fmt.Printf("%+v\n", w.Header())

	return
})

func handleUpgradeResponse(ctx context.Context, w http.ResponseWriter, req *http.Request, res *http.Response) {
	ctx, span := tracing.GildraTracer.Start(ctx, "handleUpgradeResponse")
	defer span.End()
	logger := zerolog.Ctx(ctx)

	if req.Header.Get("Upgrade") != res.Header.Get("Upgrade") {
		logger.Warn().Msg("mismatched upgrade headers")
		w.WriteHeader(http.StatusConflict)
		_, err := fmt.Fprint(w, "mismatched upgrade headers")
		if err != nil {
			logger.Error().Err(err).Msg("error writing to HTTP request")
		}
		return
	}

	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		logger.Fatal().Msg("failed to cast response body to readwritecloser")
		return
	}
	defer backConn.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		logger.Fatal().Msg("failed to cast responsewriter to hijacker")
		return
	}

	conn, brw, err := hj.Hijack()
	if err != nil {
		logger.Fatal().Msgf("Failed to hijack: %s\n", err)
		return
	}
	defer conn.Close()

	res.Body = nil // res.Write only writes the headers; we have res.Body in backConn above
	if err := res.Write(brw); err != nil {
		logger.Fatal().Msgf("Failed to write headers: %s\n", err)
		return
	}
	if err := brw.Flush(); err != nil {
		logger.Fatal().Msgf("Failed to flush headers: %s\n", err)
		return
	}

	spc := switchProtocolCopier{user: conn, backend: backConn}
	g := errgroup.Group{}
	g.Go(spc.copyToBackend)
	g.Go(spc.copyFromBackend)

	internal.Metric_OpenWebSockets.Inc()
	defer internal.Metric_OpenWebSockets.Dec()

	err = g.Wait()
	if err != nil {
		fmt.Printf("Error with websocket: %s\n", err)
	} else {
		logger.Debug().Msg(fmt.Sprint("Websocket hung up"))
	}
	return
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

	tlsListener, _ := tls.Listen("tcp", ":443", tlsConfig)

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

	h3Server = &http3.Server{
		TLSConfig:  tlsConfig,
		Handler:    handler,
		QuicConfig: &quic.Config{},
		Addr:       ":443",
	}

	globalLogger.Debug().Msg("Starting httpServer on :80 (HTTP/1.1 and HTTP/2)")
	go httpServer.Serve(listener)
	globalLogger.Debug().Msg("Starting httpServer on :443 (HTTP/1.1 and HTTP/2)")
	go httpServer.Serve(tlsListener)
	globalLogger.Debug().Msg("Starting httpServer on :443 (HTTP/3)")
	go h3Server.ListenAndServe()
	return nil
}

func Shutdown(ctx context.Context) error {
	g := errgroup.Group{}
	g.Go(func() error {
		return httpServer.Shutdown(ctx)
	})
	g.Go(func() error {
		delta := time.Second * 5
		deadline, ok := ctx.Deadline()
		if ok {
			delta = time.Now().Sub(deadline)
		}
		return h3Server.CloseGracefully(delta)
	})
	return g.Wait()
}

// handles writing the error, should always return after calling this
func respondServerError(ctx context.Context, span trace.Span, w http.ResponseWriter, status int, e error, msg string) {
	logger := zerolog.Ctx(ctx)
	logger.Error().Err(e).Msg(msg)
	w.WriteHeader(status)
	span.SetAttributes(attribute.Int("status", status))
	_, err := fmt.Fprint(w, "internal error")
	if err != nil {
		logger.Error().Err(err).Msg("error writing internal error to HTTP request")
	}
}

// makeOriginRequest makes a clone of the incoming request with additional headers added and adjustments to the destination.
func makeOriginRequest(ctx context.Context, fqdn, finalURL string, isTLS bool, r *http.Request) (*http.Request, error) {
	originReq, err := http.NewRequestWithContext(ctx, r.Method, finalURL, r.Body)
	if err != nil {
		return nil, err
	}

	// Switch in the headers, but keep original Host
	originReq.Header = r.Header.Clone()

	if utils.Env_DevDisableHost {
		originReq.Host = ""
	} else {
		// Forward the host
		originReq.Host = fqdn
	}

	// Additional headers
	originReq.Header.Set("X-Url-Scheme", lo.Ternary(isTLS, "https", "http"))
	originReq.Header.Set("X-Forwarded-Proto", r.Proto)
	originReq.Header.Set("X-Forwarded-To", finalURL)
	originReq.Header.Set("X-Forwarded-For", func(r *http.Request) string {
		incomingIP := strings.Split(r.RemoteAddr, ":")[0] // remove the port
		if existing := r.Header.Get("X-Forwarded-For"); existing != "" {
			return existing + fmt.Sprintf(", %s", incomingIP)
		}
		return incomingIP
	}(r))
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

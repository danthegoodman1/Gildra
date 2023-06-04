package http_server

import (
	"crypto/tls"
	"fmt"
	"github.com/danthegoodman1/Gildra/control_plane"
	"github.com/danthegoodman1/Gildra/gologger"
	"github.com/danthegoodman1/Gildra/internal"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/context"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/sync/errgroup"
	"io"
	"log"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

var (
	logger     = gologger.NewLogger()
	httpServer *http.Server
	h3Server   *http3.Server
)

const (
	ACMETestPathPrefix = "/.well-known/acme-test-challenge/"
	ACMEPathPrefix     = "/.well-known/acme-challenge/"
	ZeroSSLPathPrefix  = "/.well-known/pki-validation/"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	internal.Metric_OpenConnections.Inc()
	defer internal.Metric_OpenConnections.Dec()
	if upgradeHeader := r.Header.Get("Upgrade"); upgradeHeader == "h2c" {
		r.Proto = "HTTP/2.0"
	}
	fmt.Println("Proto:", r.Proto)
	fmt.Println("Headers:", r.Header)

	// Check for an ACME challenge
	fqdn := r.Header.Get("Host")
	if strings.HasPrefix(r.URL.Path, ACMEPathPrefix) || strings.HasPrefix(r.URL.Path, ACMETestPathPrefix) {
		logger.Debug().Msgf("got ACME HTTP challenge request for FQDN %s", fqdn)

		_, key := path.Split(r.URL.Path)
		fmt.Println("Got challenge for fqdn", fqdn, "key", key)
		token, err := control_plane.GetHTTPChallengeToken(fqdn, key)
		if err != nil {
			logger.Error().Err(err).Msgf("error in GetHTTPChallengeToken for FQDN %s", fqdn)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Println("Got token", token)
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(token))
		if err != nil {
			logger.Error().Err(err).Msg("error in writing bytes to response for HTTP ACME challenge")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Println("wrote response", token)
		internal.Metric_ACME_HTTP_Challenges.Inc()
		return
	} else if strings.HasPrefix(r.URL.Path, ZeroSSLPathPrefix) {
		logger.Debug().Msgf("got ZeroSSL HTTP challenge request for FQDN %s", fqdn)

		_, key := path.Split(r.URL.Path)
		fmt.Println("Got challenge for fqdn", fqdn, "key", key)
		token, err := control_plane.GetHTTPChallengeToken(fqdn, key)
		if err != nil {
			logger.Error().Err(err).Msgf("error in GetHTTPChallengeToken for FQDN %s", fqdn)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Println("Got token", token)
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(token))
		if err != nil {
			logger.Error().Err(err).Msg("error in writing bytes to response for HTTP ZeroSSL challenge")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Println("wrote response", token)
		internal.Metric_ZEROSSL_HTTP_Challenges.Inc()
		return
	}

	// TODO: Make timeout customizable
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	config, err := control_plane.GetFQDNConfig(ctx, fqdn)
	if err != nil {
		handlingError(w, r, err, "error in control_plane.GetFQDNConfig")
		return
	}

	dest, err := config.MatchDestination(r)
	if err != nil {
		handlingError(w, r, err, "error in config.MatchDestination")
		return
	}

	if r.Header.Get("Connection") == "Upgrade" {
		fmt.Println("Handling a websocket connection", r.Header.Get("Connection"), r.Header.Get("Upgrade"))
		//req, err := http.NewRequestWithContext(context.Background(), r.Method, "http://demo.piesocket.com/v3/channel_123?api_key=VCXCEuvhGcBDP7XhiJJUDvR1e1D3eiVjgZ9VRiaV&notify_self", r.Body)
		req, err := http.NewRequestWithContext(context.Background(), r.Method, "http://websockets.chilkat.io/wsChilkatEcho.ashx", r.Body)
		if err != nil {
			log.Fatalln(err)
		}
		// Fix the host header from the copy
		ogHost := req.Header.Get("Host")
		req.Header = r.Header
		req.Header.Set("Host", ogHost)

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalln(err)
		}

		if res.StatusCode == http.StatusSwitchingProtocols {
			fmt.Println("Switching protocols response")
			handleUpgradeResponse(w, req, res)
			return
		}
	}

	w.Header().Add("alt-svc", "h3=\":443\"; ma=86400, h3-29=\":443\"; ma=86400")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Hello world, proto: %s\n", r.Proto)
	return
})

func handleUpgradeResponse(rw http.ResponseWriter, req *http.Request, res *http.Response) {
	if req.Header.Get("Upgrade") != res.Header.Get("Upgrade") {
		log.Fatalln("mismatched upgrade headers")
	}

	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		log.Fatalln("failed to cast response body to readwritecloser")
		return
	}
	defer backConn.Close()

	hj, ok := rw.(http.Hijacker)
	if !ok {
		log.Fatalln("failed to cast responsewriter to hijacker")
		return
	}

	conn, brw, err := hj.Hijack()
	if err != nil {
		log.Fatalf("Failed to hijack: %s\n", err)
		return
	}
	defer conn.Close()

	res.Body = nil // res.Write only writes the headers; we have res.Body in backConn above
	if err := res.Write(brw); err != nil {
		log.Fatalf("Failed to write headers: %s\n", err)
		return
	}
	if err := brw.Flush(); err != nil {
		log.Fatalf("Failed to flush headers: %s\n", err)
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
		fmt.Println("Websocket hung up")
	}
	return
}

func StartServers() error {
	tlsConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// You can use info.ServerName to determine which certificate to load
			fqdn := info.ServerName
			// TODO: Look up cert from control plane
			logger.Debug().Msgf("fetching cert for fqdn %s", fqdn)
			fmt.Println("Getting cert for fqdn", fqdn)

			// Load the certificate
			cert, err := control_plane.GetFQDNCert(fqdn)
			if err != nil {
				return nil, err
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

	logger.Debug().Msg("Starting httpServer on :80 (HTTP/1.1 and HTTP/2)")
	go httpServer.Serve(listener)
	logger.Debug().Msg("Starting httpServer on :443 (HTTP/1.1 and HTTP/2)")
	go httpServer.Serve(tlsListener)
	logger.Debug().Msg("Starting httpServer on :443 (HTTP/3)")
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
func handlingError(w http.ResponseWriter, r *http.Request, e error, msg string) {
	logger.Error().Err(e).Msg(msg)
	w.WriteHeader(http.StatusInternalServerError)
	_, err := fmt.Fprint(w, "internal error")
	if err != nil {
		logger.Error().Err(err).Msg("error writing internal error to HTTP request")
	}
}

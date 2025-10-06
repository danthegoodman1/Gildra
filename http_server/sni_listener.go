package http_server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
)

// SNIListener wraps a net.Listener to intercept TLS connections and peek at the ClientHello
type SNIListener struct {
	net.Listener
	tlsConfig  *tls.Config
	router     SNIRouter
	httpServer *http.Server
}

// SNIRouter decides where to route a connection based on SNI and ALPN
type SNIRouter interface {
	// Route returns the backend address (ip:port) to proxy to, or empty string to handle via HTTP server
	Route(ctx context.Context, sni string, alpn []string) (backendAddr string, err error)
}

// DefaultSNIRouter is a simple implementation that routes everything to the HTTP server
type DefaultSNIRouter struct{}

func (d *DefaultSNIRouter) Route(ctx context.Context, sni string, alpn []string) (string, error) {
	// Hardcoded list of domains to proxy directly
	backendMap := map[string]string{
		"api.test": "127.0.0.1:8443",
		"app.test": "127.0.0.1:9443",
		"db.test":  "127.0.0.1:5432",
	}

	globalLogger.Debug().
		Str("sni", sni).
		Strs("alpn", alpn).
		Msg("DefaultSNIRouter checking route")

	// Check if this domain should be directly proxied
	if backendAddr, ok := backendMap[sni]; ok {
		globalLogger.Info().
			Str("sni", sni).
			Str("backend", backendAddr).
			Msg("Domain should be proxied directly")
		return backendAddr, nil
	}

	globalLogger.Debug().
		Str("sni", sni).
		Msg("Domain should go through HTTP server")
	// Empty string means handle via HTTP server
	return "", nil
}

// NewSNIListener creates a new SNI-aware listener and starts handling connections
func NewSNIListener(inner net.Listener, tlsConfig *tls.Config, router SNIRouter, httpServer *http.Server) *SNIListener {
	if router == nil {
		router = &DefaultSNIRouter{}
	}
	l := &SNIListener{
		Listener:   inner,
		tlsConfig:  tlsConfig,
		router:     router,
		httpServer: httpServer,
	}

	go l.acceptLoop()

	return l
}

// acceptLoop continuously accepts and handles connections
func (l *SNIListener) acceptLoop() {
	globalLogger.Debug().Msg("SNI listener started accepting connections")
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			globalLogger.Error().Err(err).Msg("Failed to accept connection")
			continue
		}

		globalLogger.Debug().Str("remote", conn.RemoteAddr().String()).Msg("Accepted new TLS connection")
		go l.handleConnection(conn)
	}
}

// Accept is not used - connections are handled internally by acceptLoop
func (l *SNIListener) Accept() (net.Conn, error) {
	// This listener handles connections internally
	// This method is here to satisfy the net.Listener interface if needed
	return nil, fmt.Errorf("SNIListener handles connections internally")
}

// handleConnection processes a single connection
func (l *SNIListener) handleConnection(conn net.Conn) {
	defer conn.Close()
	ctx := context.Background()
	logger := globalLogger.With().Str("remote", conn.RemoteAddr().String()).Logger()

	// Set deadline for reading ClientHello
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		logger.Error().Err(err).Msg("Failed to set read deadline")
		return
	}

	clientHello, clientReader, err := peekClientHello(conn)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to peek ClientHello")
		return
	}

	// Clear deadline after reading ClientHello
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		logger.Error().Err(err).Msg("Failed to clear read deadline")
		return
	}

	logger.Info().
		Str("sni", clientHello.ServerName).
		Strs("alpn", clientHello.SupportedProtos).
		Msg("Peeked ClientHello")

	backendAddr, err := l.router.Route(ctx, clientHello.ServerName, clientHello.SupportedProtos)
	if err != nil {
		logger.Error().Err(err).Msg("Routing error")
		return
	}

	if backendAddr != "" {
		// Proxy directly to backend
		logger.Info().
			Str("sni", clientHello.ServerName).
			Str("backend", backendAddr).
			Msg("Proxying connection to backend")

		// Create a connection that replays the ClientHello
		replayConn := &replayConn{
			Conn:   conn,
			reader: clientReader,
		}

		if err := proxyConnection(replayConn, backendAddr); err != nil {
			logger.Error().Err(err).Msg("Failed to proxy connection")
		}
		return
	}

	// Pass to HTTP server with TLS
	logger.Debug().
		Str("sni", clientHello.ServerName).
		Strs("alpn", clientHello.SupportedProtos).
		Msg("Routing to HTTP server")

	// Create a connection that replays the ClientHello and wrap with TLS
	replayConn := &replayConn{
		Conn:   conn,
		reader: clientReader,
	}
	tlsConn := tls.Server(replayConn, l.tlsConfig)

	// Serve the HTTP request
	l.httpServer.Serve(&singleConnListener{conn: tlsConn})
}

// singleConnListener is a listener that returns a single connection once
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	if s.done {
		return nil, io.EOF
	}
	s.done = true
	return s.conn, nil
}

func (s *singleConnListener) Close() error {
	return nil
}

func (s *singleConnListener) Addr() net.Addr {
	return s.conn.LocalAddr()
}

// replayConn wraps a connection and replays buffered data on Read
type replayConn struct {
	net.Conn
	reader io.Reader
}

// Read replays the buffered ClientHello bytes first, then reads from the underlying connection
func (c *replayConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// peekClientHello reads the ClientHello using Go's crypto/tls package and returns
// the ClientHelloInfo along with a reader that replays the entire TLS stream
// https://www.agwa.name/blog/post/writing_an_sni_proxy_in_go helped me simplify this code
func peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	hello, err := readClientHello(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return nil, nil, err
	}
	return hello, io.MultiReader(peekedBytes, reader), nil
}

// readClientHello uses crypto/tls to parse the ClientHello from a reader
func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo

	err := tls.Server(readOnlyConn{reader: reader}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = argHello
			return nil, nil
		},
	}).Handshake()

	if hello == nil {
		return nil, err
	}

	return hello, nil
}

// readOnlyConn wraps an io.Reader to satisfy the net.Conn interface
// It simulates a broken pipe on write (as if the client closed the connection)
type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

// proxyConnection handles the bidirectional proxying between client and backend
// This version expects the client connection to already include any buffered data (like ClientHello)
func proxyConnection(client net.Conn, backendAddr string) error {
	defer client.Close()

	// Connect to backend
	upstream, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %v", backendAddr, err)
	}
	defer upstream.Close()

	globalLogger.Debug().
		Str("backend", backendAddr).
		Msg("Connected to backend, starting bidirectional copy")

	// the client conn already has the ClientHello buffered
	return bidirectionalCopy(client, upstream)
}

// bidirectionalCopy handles the bidirectional data transfer between client and upstream
func bidirectionalCopy(client net.Conn, upstream net.Conn) error {
	g := &errgroup.Group{}

	// Copy from client to backend
	g.Go(func() error {
		_, err := io.Copy(upstream, client)
		// Try to do half-close if it's a TCP connection
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		if err != nil && err != io.EOF {
			return err
		}
		return nil
	})

	// Copy from backend to client
	g.Go(func() error {
		_, err := io.Copy(client, upstream)
		// Try to do half-close if it's a TCP connection
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		if err != nil && err != io.EOF {
			return err
		}
		return nil
	})

	// Wait for both goroutines to complete
	return g.Wait()
}

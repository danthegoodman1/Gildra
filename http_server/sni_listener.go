package http_server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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
	ctx := context.Background()
	logger := globalLogger.With().Str("remote", conn.RemoteAddr().String()).Logger()

	sniConn := newSNIConn(conn, l.tlsConfig, l.router)
	if err := sniConn.peekClientHello(); err != nil {
		logger.Error().Err(err).Msg("Failed to peek ClientHello")
		conn.Close()
		return
	}

	logger.Info().
		Str("sni", sniConn.sni).
		Strs("alpn", sniConn.alpn).
		Msg("Peeked ClientHello")

	backendAddr, err := l.router.Route(ctx, sniConn.sni, sniConn.alpn)
	if err != nil {
		logger.Error().Err(err).Msg("Routing error")
		conn.Close()
		return
	}

	if backendAddr != "" {
		// Proxy directly to backend
		logger.Info().
			Str("sni", sniConn.sni).
			Str("backend", backendAddr).
			Msg("Proxying connection to backend")

		// sniConn already replays the buffered ClientHello via its Read() method
		if err := proxyConnection(sniConn, backendAddr); err != nil {
			logger.Error().Err(err).Msg("Failed to proxy connection")
		}
		return
	}

	// Pass to HTTP server with TLS
	logger.Debug().
		Str("sni", sniConn.sni).
		Strs("alpn", sniConn.alpn).
		Msg("Routing to HTTP server")

	// Wrap with TLS - sniConn already replays the ClientHello via its Read() method
	tlsConn := tls.Server(sniConn, l.tlsConfig)

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

// sniConn wraps a connection to peek at the ClientHello
type sniConn struct {
	net.Conn
	peeked    []byte
	reader    io.Reader
	tlsConfig *tls.Config
	router    SNIRouter
	sni       string
	alpn      []string
}

func newSNIConn(conn net.Conn, tlsConfig *tls.Config, router SNIRouter) *sniConn {
	return &sniConn{
		Conn:      conn,
		tlsConfig: tlsConfig,
		router:    router,
	}
}

// Read implements net.Conn Read, replaying the peeked ClientHello bytes first
func (c *sniConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// peekClientHello reads and parses the ClientHello to extract SNI and ALPN
func (c *sniConn) peekClientHello() error {
	// Set a reasonable timeout for reading the ClientHello
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.Conn.SetReadDeadline(time.Time{})

	br := bufio.NewReader(c.Conn)

	sni, alpnProtocols, clientHelloBytes, err := readClientHelloWithALPN(br)
	if err != nil {
		return fmt.Errorf("failed to parse ClientHello: %w", err)
	}

	c.sni = sni
	c.alpn = alpnProtocols
	c.peeked = clientHelloBytes

	globalLogger.Debug().
		Str("sni", c.sni).
		Strs("alpn", c.alpn).
		Int("clientHelloSize", len(clientHelloBytes)).
		Msg("Parsed ClientHello with readClientHelloWithALPN")

	if c.sni == "" {
		globalLogger.Warn().Msg("No SNI found in ClientHello - client may not be sending SNI")
	}

	// Set the reader to the initial peeked bytes and the remaining buffered data
	c.reader = io.MultiReader(bytes.NewReader(c.peeked), br)
	return nil
}

// GetSNI returns the SNI hostname from the ClientHello
func (c *sniConn) GetSNI() string {
	return c.sni
}

// GetALPN returns the ALPN protocols from the ClientHello
func (c *sniConn) GetALPN() []string {
	return c.alpn
}

// PeekClientHello returns the raw ClientHello bytes if available
func (c *sniConn) PeekClientHello() []byte {
	return c.peeked
}

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

// readClientHelloWithALPN parses TLS ClientHello to extract both SNI and ALPN protocols
func readClientHelloWithALPN(br *bufio.Reader) (string, []string, []byte, error) {
	// TLS record header: 5 bytes
	hdr, err := br.Peek(5)
	if err != nil {
		return "", nil, nil, fmt.Errorf("peek header: %w", err)
	}
	// content type 22 = handshake
	if hdr[0] != 22 {
		return "", nil, nil, errors.New("not a TLS handshake record")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	total := 5 + recLen

	rec, err := br.Peek(total)
	if err != nil {
		return "", nil, nil, fmt.Errorf("peek record: %w", err)
	}

	// Parse ClientHello
	p := 5
	if rec[p] != 1 { // handshake type 1 = ClientHello
		return "", nil, nil, errors.New("not a ClientHello")
	}
	p += 4 // handshake length(3) + type(1 already read)

	// version(2) + random(32)
	if p+34 > len(rec) {
		return "", nil, nil, errors.New("short clienthello")
	}
	p += 34

	// session id
	if p+1 > len(rec) {
		return "", nil, nil, errors.New("short session id")
	}
	sidLen := int(rec[p])
	p += 1 + sidLen

	// cipher suites
	if p+2 > len(rec) {
		return "", nil, nil, errors.New("short ciphers len")
	}
	csLen := int(rec[p])<<8 | int(rec[p+1])
	p += 2 + csLen

	// compression methods
	if p+1 > len(rec) {
		return "", nil, nil, errors.New("short compression methods len")
	}
	cmLen := int(rec[p])
	p += 1 + cmLen

	// extensions
	if p+2 > len(rec) {
		return "", nil, nil, errors.New("no extensions")
	}
	extLen := int(rec[p])<<8 | int(rec[p+1])
	p += 2
	extEnd := p + extLen
	if extEnd > len(rec) {
		return "", nil, nil, errors.New("short extensions")
	}

	var sni string
	var alpnProtocols []string

	for p+4 <= extEnd {
		etype := int(rec[p])<<8 | int(rec[p+1])
		elen := int(rec[p+2])<<8 | int(rec[p+3])
		p += 4
		if p+elen > extEnd {
			break
		}

		switch etype {
		case 0: // SNI
			if elen < 2 {
				break
			}
			listLen := int(rec[p])<<8 | int(rec[p+1])
			q := p + 2
			listEnd := q + listLen
			for q+3 <= listEnd && listEnd <= len(rec) {
				nameType := rec[q]
				nameLen := int(rec[q+1])<<8 | int(rec[q+2])
				q += 3
				if nameType == 0 && q+nameLen <= listEnd {
					sni = string(rec[q : q+nameLen])
					break
				}
				q += nameLen
			}

		case 16: // ALPN (Application-Layer Protocol Negotiation)
			if elen < 2 {
				break
			}
			listLen := int(rec[p])<<8 | int(rec[p+1])
			q := p + 2
			listEnd := q + listLen
			for q < listEnd && listEnd <= len(rec) {
				if q+1 > listEnd {
					break
				}
				protoLen := int(rec[q])
				q++
				if q+protoLen <= listEnd {
					alpnProtocols = append(alpnProtocols, string(rec[q:q+protoLen]))
				}
				q += protoLen
			}
		}

		p += elen
	}

	// Consume exactly the bytes we peeked so the remaining stream forwards cleanly.
	raw := make([]byte, total)
	if _, err := io.ReadFull(br, raw); err != nil {
		return "", nil, nil, fmt.Errorf("drain record: %w", err)
	}

	return sni, alpnProtocols, raw, nil
}

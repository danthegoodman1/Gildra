package http_server

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/danthegoodman1/Gildra/routing"
	"github.com/danthegoodman1/Gildra/utils"
	"github.com/rs/zerolog"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ErrRequestAlreadyHijacked = errors.New("request already hijacked")
)

type (
	RequestContext struct {
		Request            *http.Request
		responseWriter     http.ResponseWriter
		IsTLS              bool
		FQDN, Proto, ReqID string
		// PathQuery is the combined path and query params of the request
		PathQuery string
		Created   time.Time

		// FullPath includes the path and query
		FullPath    string
		Destination *routing.Destination

		responseHeaders http.Header
		responseReader  io.ReadCloser
		responseStatus  int

		hijacked bool
	}
)

func NewRequestContext(r *http.Request, rw http.ResponseWriter) *RequestContext {
	rc := &RequestContext{
		Request:        r,
		responseWriter: rw,
		Created:        time.Now(),
		FQDN:           r.Host,
		ReqID:          utils.GenKSortedID("req_"),
		IsTLS:          r.TLS != nil,
		Proto:          r.Proto,

		// Replace up through the domain name with destination
		// this only works because incoming requests don't have the scheme and host attached to the URL
		PathQuery:       r.URL.String(),
		responseHeaders: make(http.Header),
	}
	logger := zerolog.Ctx(r.Context())

	if upgradeHeader := r.Header.Get("Upgrade"); upgradeHeader == "h2c" {
		// Mark h2c as HTTP/2.0
		logger.Debug().Msg(fmt.Sprint("Marking h2c as HTTP/2.0"))
		rc.Proto = "HTTP/2.0"
	}

	// Log context
	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("fqdn", rc.FQDN).Bool("tls", rc.IsTLS).Str("requestID", rc.ReqID).Int64("requestLength", r.ContentLength).Str("proto", rc.Proto)
	})

	// Write HTTP/3 support header
	rc.responseHeaders.Add("alt-svc", "h3=\":443\"; ma=86400")
	rc.responseHeaders.Add("g-req-id", rc.ReqID)

	return rc
}

func (rc *RequestContext) RespondReader(statusCode int, reader io.ReadCloser) error {
	rc.responseStatus = statusCode
	rc.responseReader = reader
	return nil
}

func (rc *RequestContext) RespondString(statusCode int, res string) error {
	rc.responseStatus = statusCode
	rc.responseReader = io.NopCloser(strings.NewReader(res))
	return nil
}

func (rc *RequestContext) RespondBytes(statusCode int, res []byte) error {
	rc.responseStatus = statusCode
	rc.responseReader = io.NopCloser(bytes.NewReader(res))
	return nil
}

// WebsocketHijack tells the request context that it is no longer responsible for writing a response
func (rc *RequestContext) Hijack() error {
	if rc.hijacked {
		return ErrRequestAlreadyHijacked
	}
	rc.hijacked = true
	return nil
}

// Hijacked returns whether the request was previously hijacked
func (rc *RequestContext) Hijacked() bool {
	return rc.hijacked
}

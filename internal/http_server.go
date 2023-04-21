package internal

import (
	"fmt"
	"github.com/danthegoodman1/Gildra/common"
	"github.com/danthegoodman1/Gildra/gologger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/context"
	"net/http"
)

var (
	httpServer *http.Server
	logger     = gologger.NewLogger()
)

func StartMetricsServer() error {
	logger.Debug().Msgf("Starting internal http server on port %s", Env_InternalPort)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%s", Env_InternalPort),
		Handler: mux,
	}
	return httpServer.ListenAndServe()
}

func Shutdown(ctx context.Context) error {
	if httpServer != nil {
		logger.Debug().Msg("Shutting down internal server")
		return httpServer.Shutdown(ctx)
	}
	return common.ErrNoServer
}

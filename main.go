package main

import (
	"github.com/danthegoodman1/Gildra/gologger"
	"github.com/danthegoodman1/Gildra/http_server"
	"golang.org/x/sync/errgroup"
)

var (
	logger = gologger.NewLogger()
)

func main() {
	logger.Info().Msg("starting Gildra")
	g := errgroup.Group{}
	g.Go(func() error {
		logger.Info().Msg("starting http server")
		return http_server.StartServers()
	})

	err := g.Wait()
	if err != nil {
		logger.Error().Err(err).Msg("Error starting services")
	}
}

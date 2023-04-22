package main

import (
	"context"
	"github.com/danthegoodman1/Gildra/gologger"
	"github.com/danthegoodman1/Gildra/http_server"
	"github.com/danthegoodman1/Gildra/internal"
	"golang.org/x/sync/errgroup"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	logger = gologger.NewLogger()
)

func main() {
	logger.Info().Msg("starting Gildra")
	g := errgroup.Group{}
	g.Go(func() error {
		logger.Debug().Msg("starting proxy servers")
		return http_server.StartServers()
	})
	g.Go(func() error {
		logger.Debug().Msg("starting internal server")
		return internal.StartServer()
	})

	err := g.Wait()
	if err != nil {
		logger.Error().Err(err).Msg("Error starting services")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	logger.Info().Msg("received shutdown signal!")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	g = errgroup.Group{}
	g.Go(func() error {
		return http_server.Shutdown(ctx)
	})
	g.Go(func() error {
		return internal.Shutdown(ctx)
	})

	if err := g.Wait(); err != nil {
		logger.Error().Err(err).Msg("error shutting down servers")
		os.Exit(1)
	}
	logger.Info().Msg("shutdown servers, exiting")
}

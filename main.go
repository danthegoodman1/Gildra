package main

import (
	"context"
	"errors"
	"github.com/danthegoodman1/Gildra/control_plane"
	"github.com/danthegoodman1/Gildra/gologger"
	"github.com/danthegoodman1/Gildra/http_server"
	"github.com/danthegoodman1/Gildra/internal"
	"github.com/danthegoodman1/Gildra/observability"
	"github.com/danthegoodman1/Gildra/utils"
	"golang.org/x/sync/errgroup"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	logger = gologger.NewLogger()
)

func main() {
	mainCtx := context.Background()
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
	if utils.CacheEnabled {
		g.Go(func() error {
			logger.Debug().Msg("starting groupcache")
			control_plane.InitCache(mainCtx)
			return nil
		})
	}

	g.Go(func() error {
		prometheusReporter := observability.NewPrometheusReporter()
		err := observability.StartInternalHTTPServer(":8042", prometheusReporter)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})

	err := g.Wait()
	if err != nil {
		logger.Error().Err(err).Msg("Error starting services")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	logger.Info().Msg("received shutdown signal!")

	// Provide time for load balancers to de-register before stopping accepting connections
	if utils.Env_SleepSeconds > 0 {
		logger.Info().Msgf("sleeping for %ds before exiting", utils.Env_SleepSeconds)
		time.Sleep(time.Second * time.Duration(utils.Env_SleepSeconds))
		logger.Info().Msgf("slept for %ds, exiting", utils.Env_SleepSeconds)
	}

	ctx, cancel := context.WithTimeout(mainCtx, time.Second*time.Duration(utils.Env_SleepSeconds))
	defer cancel()

	g = errgroup.Group{}
	g.Go(func() error {
		return http_server.Shutdown(ctx)
	})
	g.Go(func() error {
		return internal.Shutdown(ctx)
	})
	if utils.CacheEnabled {
		g.Go(func() error {
			return control_plane.StopCache(ctx)
		})
	}

	if err := g.Wait(); err != nil {
		logger.Error().Err(err).Msg("error shutting down servers")
		os.Exit(1)
	}
	logger.Info().Msg("shutdown servers, exiting")
}

package cache

import (
	"context"
	"fmt"
	"github.com/danthegoodman1/Gildra/common"
	"github.com/danthegoodman1/Gildra/gologger"
	"github.com/danthegoodman1/Gildra/utils"
	"github.com/mailgun/groupcache/v2"
	"net/http"
)

var (
	SelfAddr   = fmt.Sprintf("%s:%s", utils.Env_SelfIP, Env_GroupCachePort)
	httpServer *http.Server
	logger     = gologger.NewLogger()
)

func CreateGroupCache() error {
	// NOTE: It is important to pass the same peer `http://192.168.1.1:8080` to `NewHTTPPoolOpts`
	// which is provided to `pool.Set()` so the pool can identify which of the peers is our instance.
	// The pool will not operate correctly if it can't identify which peer is our instance.

	// Pool keeps track of peers in our cluster and identifies which peer owns a key.
	pool := groupcache.NewHTTPPoolOpts("http://"+SelfAddr, &groupcache.HTTPPoolOptions{})

	// Add more peers to the cluster You MUST Ensure our instance is included in this list else
	// determining who owns the key accross the cluster will not be consistent, and the pool won't
	// be able to determine if our instance owns the key.
	pool.Set(utils.Env_SelfIP) // TODO: include peers dynamically

	httpServer = &http.Server{
		Addr:    SelfAddr,
		Handler: pool,
	}

	// Start an HTTP server to listen for peer requests from the groupcache
	return httpServer.ListenAndServe()
}

func Shutdown(ctx context.Context) error {
	if httpServer != nil {
		logger.Debug().Msg("Shutting down groupcache server")
		return httpServer.Shutdown(ctx)
	}
	return common.ErrNoServer
}

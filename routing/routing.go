package routing

import (
	"context"
	"errors"
	"fmt"
	"github.com/danthegoodman1/Gildra/tracing"
	"net/http"
)

type (
	Config struct {
		Rules []Rule `json:",omitempty"`
	}
	Rule struct {
		// CURRENTLY ONLY USES THE FIRST ONE
		Matches []Match `json:",omitempty"`
	}

	// Match is a way to match traffic to a destination(s). If neither `Prefix`, `Regex` or `Glob` are defined, then all traffic will be routed here (can be used as a fallback this way).
	Match struct {
		// CURRENTLY ONLY USES THE FIRST ONE Where the traffic will be routed to if it matches
		Destinations []Destination `json:",omitempty"`
		// TODO
		// NOT IMPLEMENTED Uses https://github.com/gobwas/glob, takes priority over Regex.
		Glob *string `json:",omitempty"`
		// TODO
		// NOT IMPLEMENTED Uses golang standard regexp package, will not be used if Glob is defined
		Regex *string `json:",omitempty"`
	}
	Destination struct {
		// ONLY FOR DEV USE will respond with just some text, used for checking certs
		DEVTextResponse bool `json:",omitempty"`

		// URL will replace the all but the path (`http(s)://example.com`) with this value.
		// For example with a value of `http://internal:8080/prefix` and an original request of
		// https://example.com/abc the final request will be constructed as `http://internal:8080/prefix/abc`
		URL string `json:",omitempty" validate:"require"`

		// TODO
		// NOT IMPLEMENTED taken as a part of a sum of weights for all destinations to determine where to send traffic. For example 2 destinations with weights of 1 and 4 will be 20% and 80% respectively. 2 destinations with weights 4 and 6 will be 40% and 60% respectively.
		Weight *int `json:",omitempty"`

		// TODO
		// NOT IMPLEMENTED How long the request to the origin can last before Gildra respond to the client's request with 504
		TimeoutSec *int
	}
)

var (
	ErrInvalidConfig = errors.New("invalid config")
)

// MatchDestination will take in an unmodified request, and will determine where it should be routed to.
// This must be called before we look into anything else
func (c *Config) MatchDestination(ctx context.Context, req *http.Request) (dest Destination, err error) {
	ctx, span := tracing.GildraTracer.Start(ctx, "matchDestination")
	defer span.End()

	if len(c.Rules) == 0 {
		err = fmt.Errorf("no rules found: %w", ErrInvalidConfig)
		return
	}
	if len(c.Rules[0].Matches) == 0 {
		err = fmt.Errorf("no matches found: %w", ErrInvalidConfig)
		return
	}
	if len(c.Rules[0].Matches[0].Destinations) == 0 {
		err = fmt.Errorf("no destinations found: %w", ErrInvalidConfig)
		return
	}
	return c.Rules[0].Matches[0].Destinations[0], nil
}

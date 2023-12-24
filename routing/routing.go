package routing

import (
	"context"
	"errors"
	"fmt"
	"github.com/danthegoodman1/Gildra/tracing"
	"github.com/gobwas/glob"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
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

	// Match is a way to match traffic to a destination(s). If neither `Prefix`, `Regex` or `Glob` are defined, then all traffic will be routed here (can be used as a fallback this way). Uses the `host/path?query` format like `api.example.com/path?q=blah`.
	Match struct {
		// Where the traffic will be routed to if it matches. CURRENTLY ONLY TAKES THE FIRST ONE.
		Destinations []Destination `json:",omitempty"`

		// Uses https://github.com/gobwas/glob, takes priority over Regex.
		// Both '.' and '/' are treated as delimiters. Glob matching should NOT be used for query params,
		// it is only designed for looking at the host and path. If you need to look at query params, use Regex.
		Glob *string `json:",omitempty"`

		// TODO
		// NOT IMPLEMENTED Uses golang standard regexp package, will not be used if Glob is defined
		Regex *string `json:",omitempty"`
	}
	Destination struct {
		// ONLY FOR DEV USE will respond with just some text, used for checking certs
		DEVTextResponse bool `json:",omitempty"`

		// URL prepend the path and query params with this value.
		// For example with a URL of `http://internal:8080/prefix` and an original request url of
		// https://example.com/abc will result in a request to `http://internal:8080/prefix/abc`
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

	globSeparators = []rune{'.', '/'}
)

// MatchDestination will take in an unmodified request, and will determine where it should be routed to.
// This must be called before we look into anything else
func (c *Config) MatchDestination(ctx context.Context, host, path string, req *http.Request) (dest *Destination, err error) {
	ctx, span := tracing.GildraTracer.Start(ctx, "matchDestination")
	defer span.End()

	logger := zerolog.Ctx(ctx)
	logger.Debug().Msgf("got host=%s path=%s", host, path)

	if len(c.Rules) == 0 {
		err = fmt.Errorf("no rules found: %w", ErrInvalidConfig)
		return
	}
	for _, rule := range c.Rules {
		if len(rule.Matches) == 0 {
			err = fmt.Errorf("no matches found: %w", ErrInvalidConfig)
			return
		}

		for _, match := range rule.Matches {
			if len(match.Destinations) == 0 {
				err = fmt.Errorf("no destinations found: %w", ErrInvalidConfig)
				return
			}

			if match.Glob != nil {
				span.SetAttributes(attribute.String("match", "glob"))
				// TODO: Match against blog
				var g glob.Glob
				g, err = glob.Compile(*match.Glob, globSeparators...)
				if err != nil {
					err = fmt.Errorf("error in glob.Compile: %w", err)
					return
				}
				if matched := g.Match(host + path); matched {
					logger.Warn().Msg("matched glob!")
					dest = &match.Destinations[0]
					return
				}
			} else if match.Regex != nil {
				span.SetAttributes(attribute.String("match", "regex"))
				// TODO: Match against regex

			} else {
				// If we have nothing, we just match it
				logger.Warn().Msg("matched nothing!")
				dest = &match.Destinations[0]
				return
			}
		}

	}

	return
}

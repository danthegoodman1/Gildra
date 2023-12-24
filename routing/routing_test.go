package routing

import (
	"github.com/gobwas/glob"
	"testing"
)

type (
	patternTest struct {
		Pattern, Match string
		ShouldMatch    bool
	}
)

func TestGlobMatch(t *testing.T) {
	var g glob.Glob
	patterns := []patternTest{
		{
			Match:       "api.github.com/danthegoodman1/Gildra",
			Pattern:     "api.github.com/*",
			ShouldMatch: false,
		},
		{
			Match:       "api.github.com/danthegoodman1/Gildra?q=hey",
			Pattern:     "api.github.com/**",
			ShouldMatch: true,
		},
		{
			Match:       "api.github.com/danthegoodman1/Gildra",
			Pattern:     "*.github.com/**",
			ShouldMatch: true,
		},
		{
			Match:       "api.github.com/danthegoodman1/Gildra",
			Pattern:     "*.github.com/*",
			ShouldMatch: false,
		},
		{
			Match:       "github.com/danthegoodman1/Gildra",
			Pattern:     "github.com/*/Gildra",
			ShouldMatch: true,
		},
		{
			Match:       "github.com/danthegoodman1/Gildra",
			Pattern:     "github.com/**/Gildra",
			ShouldMatch: true,
		},
		{
			Match:       "a.b.c.github.com/danthegoodman1/Gildra",
			Pattern:     "**github.com/**/Gildra",
			ShouldMatch: true,
		},
		{
			Match:       "a.b.c.github.com/danthegoodman1/Gildra",
			Pattern:     "**.github.com/**/Gildra",
			ShouldMatch: true,
		},
		{
			Match:       "api.github.com/danthegoodman1/Gildra",
			Pattern:     "api.github.com/*/*",
			ShouldMatch: true,
		},
	}

	for _, pattern := range patterns {
		g = glob.MustCompile(pattern.Pattern, globSeparators...)
		matched := g.Match(pattern.Match)
		if matched != pattern.ShouldMatch {
			t.Fatalf("Patern %s == %s = %v expected = %v", pattern.Pattern, pattern.Match, matched, pattern.ShouldMatch)
		}
	}
}

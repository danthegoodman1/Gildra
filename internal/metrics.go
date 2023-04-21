package internal

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	Metric_TLSLookups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tls_lookups",
		Help: "Total TLS lookups, including cached results",
	})
	Metric_CachedTLSLookups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cached_tls_lookups",
		Help: "TLS lookups that hit the cache, includes groupcache peer hits",
	})
)

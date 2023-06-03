package internal

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	Metric_TLSLookups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tls_lookups",
		Help: "Total TLS lookups, including cached results locally and from peers",
	})
	Metric_CacheMissTLSLookups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cache_miss_tls_lookups",
		Help: "TLS lookups that missed the cache (groupcache getter function invoked)",
	})
	Metric_RoutingConfigLookups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "routing_lookups",
		Help: "Total routing config lookups, including cached results locally and from peers",
	})
	Metric_CacheMissRoutingConfigLookups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cache_miss_routing_lookups",
		Help: "Routing config lookups that missed the cache (groupcache getter function invoked)",
	})
	Metric_ACME_HTTP_Challenges = promauto.NewCounter(prometheus.CounterOpts{
		Name: "acme_http_challenges",
		Help: "Successfully answered ACME HTTP challenges",
	})
	Metric_ZEROSSL_HTTP_Challenges = promauto.NewCounter(prometheus.CounterOpts{
		Name: "zerossl_http_challenges",
		Help: "Successfully answered ZeroSSL HTTP challenges (not ACME)",
	})
)

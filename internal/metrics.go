package internal

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	Metric_CertLookups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_lookups",
		Help: "Total cert lookups, including cached results",
	})
	Metric_CertCacheFill = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_cache_fill",
		Help: "Number of requests where the cert cache was filled",
	})
	Metric_RoutingConfigLookups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "routing_config_lookups",
		Help: "Total routing config lookups, including cached results",
	})
	Metric_RoutingConfigCacheFill = promauto.NewCounter(prometheus.CounterOpts{
		Name: "routing_config_cache_fill",
		Help: "Number of requests where the routing config cache was filled, includes concurrent fills when filling cert cache if enabled",
	})
	Metric_ACME_HTTP_Challenges = promauto.NewCounter(prometheus.CounterOpts{
		Name: "acme_http_challenges",
		Help: "Successfully answered ACME HTTP challenges",
	})
	Metric_ZEROSSL_HTTP_Challenges = promauto.NewCounter(prometheus.CounterOpts{
		Name: "zerossl_http_challenges",
		Help: "Successfully answered ZeroSSL HTTP challenges (not ACME)",
	})

	Metric_HTTP_Requests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests",
		Help: "Number of HTTP requests by protocol",
	}, []string{"proto"})

	Metric_OpenWebSockets = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "open_websockets",
		Help: "Number of currently open websockets",
	})

	Metric_OpenConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "open_connections",
		Help: "Number of currently open connections including websockets",
	})
)

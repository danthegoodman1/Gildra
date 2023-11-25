package utils

import (
	"os"
	"strings"
)

var (
	Env_SelfIP                 = os.Getenv("SELF_IP")
	Env_SleepSeconds           = MustEnvOrDefaultInt64("SHUTDOWN_SLEEP_SEC", 0)
	Env_ShutdownTimeoutSeconds = MustEnvOrDefaultInt64("SHUTDOWN_TIMEOUT_SEC", 1)

	Env_ControlPlaneAddr        = os.Getenv("CP_ADDR")
	Env_ControlPlaneAuthHeader  = os.Getenv("CP_AUTH")
	Env_FetchConfigConcurrently = os.Getenv("CONCURRENT_FETCH_ROUTING_CONFIG") == "" || os.Getenv("CONCURRENT_FETCH_ROUTING_CONFIG") == "1"

	// Disables setting the host header so the HTTP client sets it automatically, so forwarding localhost works with clients
	Env_DevDisableHost = os.Getenv("DEV_DISABLE_HOST") == "1"

	CacheEnabled = os.Getenv("CACHE_ENABLED") == "1"
	// http://x:y,http://z:y,... MUST INCLUDE SELF! Only need to include self to cache as a single node
	CachePeers = strings.Split(os.Getenv("CACHE_PEERS"), ",")
	// http://x.x.x.x:yyyy
	CacheSelfAddr          = os.Getenv("CACHE_SELF_ADDR")
	Env_FQDNCacheMB        = MustEnvOrDefaultInt64("FQDN_CACHE_MB", 10_000_000)
	Env_CertCacheMB        = MustEnvOrDefaultInt64("CERT_CACHE_MB", 10_000_000)
	Env_ConfigCacheSeconds = MustEnvOrDefaultInt64("CONFIG_CACHE_SECONDS", 10)
	Env_CertCacheSeconds   = MustEnvOrDefaultInt64("CERT_CACHE_SECONDS", 300)

	Env_HTTPTimeoutSec = MustEnvOrDefaultInt64("HTTP_TIMEOUT_SEC", 60)
	Env_MaxReplays     = MustEnvOrDefaultInt64("MAX_REPLAYS", 3)

	Dev_TextResponse = os.Getenv("DEV_TEXT_RESPONSE") == "1"
)

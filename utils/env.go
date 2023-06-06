package utils

import "os"

var (
	Env_SelfIP                 = os.Getenv("SELF_IP")
	Env_SleepSeconds           = MustEnvOrDefaultInt64("SHUTDOWN_SLEEP_SEC", 0)
	Env_ShutdownTimeoutSeconds = MustEnvOrDefaultInt64("SHUTDOWN_TIMEOUT_SEC", 1)

	Env_ControlPlaneAddr       = os.Getenv("CP_ADDR")
	Env_ControlPlaneAuthHeader = os.Getenv("CP_AUTH")
	Env_FetchCertConcurrently  = os.Getenv("CONCURRENT_FETCH_ROUTING_CONFIG") == "" || os.Getenv("CONCURRENT_FETCH_ROUTING_CONFIG") == "1"

	// Disables setting the host header so the HTTP client sets it automatically, so forwarding localhost works with clients
	Env_DevDisableHost = os.Getenv("DEV_DISABLE_HOST") == "1"

	Env_FQDNCacheMB      = MustEnvOrDefaultInt64("FQDN_CACHE_MB", 10_000_000)
	Env_CertCacheMB      = MustEnvOrDefaultInt64("CERT_CACHE_MB", 10_000_000)
	Env_FQDNCacheSeconds = MustEnvOrDefaultInt64("FQDN_CACHE_SECONDS", 10)
	Env_CertCacheSeconds = MustEnvOrDefaultInt64("CERT_CACHE_SECONDS", 300)
)

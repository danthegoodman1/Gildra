package utils

import "os"

var (
	Env_SelfIP                 = os.Getenv("SELF_IP")
	Env_SleepSeconds           = MustEnvOrDefaultInt64("SHUTDOWN_SLEEP_SEC", 0)
	Env_ShutdownTimeoutSeconds = MustEnvOrDefaultInt64("SHUTDOWN_TIMEOUT_SEC", 1)

	Env_ControlPlaneAddr       = os.Getenv("CP_ADDR")
	Env_ControlPlaneAuthHeader = os.Getenv("CP_AUTH")
	Env_FetchCertConcurrently  = os.Getenv("CONCURRENT_FETCH_ROUTING_CONFIG") == "" || os.Getenv("CONCURRENT_FETCH_ROUTING_CONFIG") == "1"
)

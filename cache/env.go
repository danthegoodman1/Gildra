package cache

import "github.com/danthegoodman1/Gildra/utils"

var (
	Env_GroupCachePort   = utils.EnvOrDefault("CACHE_PORT", "8092")
	Env_FQDNCacheMB      = utils.MustEnvOrDefaultInt64("FQDN_CACHE_MB", 10_000_000)
	Env_FQDNCacheSeconds = utils.MustEnvOrDefaultInt64("FQDN_CACHE_SECONDS", 10)
	Env_CertCacheSeconds = utils.MustEnvOrDefaultInt64("CERT_CACHE_SECONDS", 300)
)

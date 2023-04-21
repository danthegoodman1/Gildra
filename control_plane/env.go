package control_plane

import (
	"github.com/danthegoodman1/Gildra/utils"
	"os"
)

var (
	Env_Address          = os.Getenv("CONTROL_PLANE_ADDR")
	Env_Token            = os.Getenv("CONTROL_PLANE_TOKEN")
	Env_FQDNCacheMB      = utils.MustEnvOrDefaultInt64("FQDN_CACHE_MB", 10_000_000)
	Env_CertCacheMB      = utils.MustEnvOrDefaultInt64("CERT_CACHE_MB", 10_000_000)
	Env_FQDNCacheSeconds = utils.MustEnvOrDefaultInt64("FQDN_CACHE_SECONDS", 10)
	Env_CertCacheSeconds = utils.MustEnvOrDefaultInt64("CERT_CACHE_SECONDS", 300)
)

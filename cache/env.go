package cache

import "github.com/danthegoodman1/Gildra/utils"

var (
	Env_GroupCachePort = utils.EnvOrDefault("CACHE_PORT", "8092")
)

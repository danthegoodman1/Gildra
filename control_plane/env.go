package control_plane

import "os"

var (
	Env_Address = os.Getenv("CONTROL_PLANE_ADDR")
	Env_Token   = os.Getenv("CONTROL_PLANE_TOKEN")
)

// See: https://github.com/golang/go/commit/ee55f0856a3f1fed5d8c15af54c40e4799c2d32f for where a lot of this code came from (expand ServeHTTP to see more too)

package http_server

import "io"

// switchProtocolCopier exists so goroutines proxying data back and
// forth have nice names in stacks.
type switchProtocolCopier struct {
	user, backend io.ReadWriter
}

func (c switchProtocolCopier) copyFromBackend() error {
	_, err := io.Copy(c.user, c.backend)
	return err
}

func (c switchProtocolCopier) copyToBackend() error {
	_, err := io.Copy(c.backend, c.user)
	return err
}

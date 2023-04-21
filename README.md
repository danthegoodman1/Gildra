# Gildra
Mutli-tenant TLS terminating proxy for L7 traffic. Supports unlimited domains and certs with HTTP/1.1, 2, and 3

## Metrics

The metrics server is run by default in port `8091`. This can be changed with the `INTERNAL_PORT` env var. Metrics will be served at `/metrics`.
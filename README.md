# Gildra
Mutli-tenant TLS terminating proxy for L7 traffic. Supports unlimited domains and certs with HTTP/1.1, 2, and 3

## Environment Vairables

| Env Var                | Description                                                                                                                                                                                                                                                                               | Required | Default Value |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---------------|
| INTERNAL_PORT          | The port that the internal API will listen on                                                                                                                                                                                                                                             | yes      | 8091          |
| SHUTDOWN_SLEEP_SECONDS | The number of seconds that the server will sleep before shutting down servers. Used for when cloud load balancer take time to de-register. This will vary by setup.<br/> <br/>For example, AWS NLBs and ALBs with EKS should have this set to ~35 seconds based on production experience. | no       | 0             |
|                        |                                                                                                                                                                                                                                                                                           |          |               |


## Metrics

The metrics server is run by default in port `8091`. This can be changed with the `INTERNAL_PORT` env var. Metrics will be served at `/metrics`.
# Gildra
Mutli-tenant TLS terminating proxy for L7 traffic. Supports unlimited domains and certs with HTTP/1.1, 2, and 3.

Unlike other solutions, Gildra sits in your cloud. This means that requests aren't slowed down, and nobody else sees your unencrypted traffic.

## Environment Vairables

| Env Var                | Description                                                                                                                                                                                                                                                                          | Required (that you set) | Default Value |
|------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------|---------------|
| INTERNAL_PORT          | The port that the internal API will listen on                                                                                                                                                                                                                                        | no                      | 8091          |
| SHUTDOWN_SLEEP_SECONDS | The number of seconds that the server will sleep before shutting down servers. Used for when cloud load balancer take time to de-register. This will vary by setup.<br/> <br/>For example, AWS NLBs and ALBs with EKS should have this set to ~35 seconds based on production experience. | no                      | 0             |
|        SHUTDOWN_TIMEOUT_SEC                | The number of seconds that are allowed for the servers to shutdown (the context deadline). During this time new connections are not accepted and existing connections must be drained. Useful for if you don't need `SHUTDOWN_SLEEP_SECONDS`.                                        | no                      | 1             |


## Metrics

The metrics server is run by default in port `8091`. This can be changed with the `INTERNAL_PORT` env var. Metrics will be served at `/metrics`.

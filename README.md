# Gildra
Mutli-tenant TLS terminating proxy for L7 traffic. Supports unlimited domains and certs with HTTP/1.1, 2, and 3.

<!-- TOC -->
* [Gildra](#gildra)
  * [Supported incoming protocols](#supported-incoming-protocols)
  * [Environment Variables](#environment-variables)
  * [Added Headers](#added-headers)
  * [The `x-replay` header](#the-x-replay-header)
  * [Metrics](#metrics)
  * [Design](#design)
    * [Fetching routing config and cert in separate operations](#fetching-routing-config-and-cert-in-separate-operations)
  * [Why not support TCP (TLS) traffic?](#why-not-support-tcp-tls-traffic)
<!-- TOC -->

Unlike other solutions, Gildra sits in your cloud. This means that requests aren't slowed down by being routed through another provider, and nobody sees your unencrypted traffic but you.

## Supported incoming protocols

- HTTP(S)/1.1
- WS and WSS
- H2C (HTTP/2 cleartext) & HTTP/2
- H3 (TLS only)

All connections will be terminated and forwarded to the origin as HTTP(S)/1.1

## Environment Variables

| Env Var                           | Description                                                                                                                                                                                                                                                                               | Required (that you set) | Default Value |
|-----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------|---------------|
| INTERNAL_PORT                     | The port that the internal API will listen on                                                                                                                                                                                                                                             | no                      | 8091          |
| SHUTDOWN_SLEEP_SECONDS            | The number of seconds that the server will sleep before shutting down servers. Used for when cloud load balancer take time to de-register. This will vary by setup.<br/> <br/>For example, AWS NLBs and ALBs with EKS should have this set to ~35 seconds based on production experience. | no                      | 0             |
| SHUTDOWN_TIMEOUT_SEC              | The number of seconds that are allowed for the servers to shutdown (the context deadline). During this time new connections are not accepted and existing connections must be drained. Useful for if you don't need `SHUTDOWN_SLEEP_SECONDS`.                                             | no                      | 1             |
| `CONCURRENT_FETCH_ROUTING_CONFIG` | Whether to concurrently fetch the routing config when fetching a cert. Set to anything other than `1` to disable.                                                                                                                                                                         | no                      | `1`           |

## Added Headers

- `X-Fowarded-For` - will create or append to the header
- `X-Forwarded-Proto` - the protocol in which the inbound connection was made to the Gildra node. Options `http/1.1`, `http/2`, `h2c`, `h3`
- `X-Url-Scheme` - the URL scheme of the request made to Gildra. Options `https`, `http`, `ws`, `wss`
- `X-Replayed` - whether this request was replayed. Options `t`, `f`

## The `x-replay` header

If your response has a status code of < 500 and has an `x-replay` header, then the request will be replayed by the Gildra node targeting the address provided in the `x-replay` header.

This allows you to relay a request to a specific IP address or domain within your private network.

If you respond with an `x-replay` header to a request that already contains an `X-Replayed` header, then Gildra will respond to the original request with a `502 Bad Gateway`. Gildra will appropriately strip this header from client's requests. 

## Metrics

The metrics server is run by default in port `8091`. This can be changed with the `INTERNAL_PORT` env var. Metrics will be served at `/metrics`.

## Design

### Fetching routing config and cert in separate operations

This was decided for 2 major reasons:

1. Routing configs should probably have a much lower cache than certs
2. Fetching cert and routing config at the same time would guarantee that we use at least two TCP packets in the response, where a routing config can often fit into just one.

This is where the `CONCURRENT_FETCH_ROUTING_CONFIG` setting comes in. Because certs are cached more aggressively, and you always need to have both the cert and routing config to answer a request, when we are filling the cert cache we asynchronously fill the routing config cache in the background.

This works especially well because the groupcache package not only already handles request collapsing, but since it's running on the same pool the owning node for the cert cache will also be the owning node for the routing config cache. In simpler terms that means they are cached in the same spot, so connections to the control plane can be reused when fetching both at the same time.

As a result, after we load the cert into the request handler and go to look up the routing config, we've already started fetching it and save that much time. Often it's ready in cache once we go to look it up!

## Why not support TCP (TLS) traffic?

While this wouldn't be too difficult to add, it does require a decent change in request handling architecture and configurability. Additionally, most services that use TCP directly such as databases prefer to be the managers of certificates and encrypted traffic (just see the warnings that happen when you run them without!), and are not multi-tenant in the same way a web service might be.

TL;DR we wanted to start simple, and hit the majority of uses cases.
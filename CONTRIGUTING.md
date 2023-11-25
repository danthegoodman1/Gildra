# Contributing

<!-- TOC -->
* [Contributing](#contributing)
  * [Running Gildra locally](#running-gildra-locally)
  * [Running the example control plane locally](#running-the-example-control-plane-locally)
<!-- TOC -->

## Running Gildra locally

Your `.env` file might look like this:

```ini
# logs
PRETTY=1
DEBUG=1

# disable caching
CONFIG_CACHE_SECONDS=0
CERT_CACHE_SECONDS=0
CACHE_ENABLED=0
CACHE_SELF_ADDR="http://localhost:8082"
CACHE_PEERS="http://localhost:8082"

# disabled the host header, so forwarding to localhost works
DEV_DISABLE_HOST=1

# instead of hitting a host, just returns a text body response
DEV_TEXT_RESPONSE=1
```

Then run `task` to run the taskfile with the `.env` environment loaded in

## Running the example control plane locally

Run the docker compose file, which is designed to hide the control plane behind Gildra. It can be used both as an example target, and as a control plane. Adjust your environment variable accordingly to a domain and email that you own and have pointed at an ipv4 that is publicly exposed, exposing Gildra to the internet. 
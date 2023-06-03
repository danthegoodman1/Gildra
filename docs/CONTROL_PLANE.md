# Gildra Control Plane

Gildra interfaces with a control plane that has a standard HTTP interface. This standard interface allows users to integrate with their chosen ACME providers, their own internal data stores and systems, choose their language, and more.

A dev/testing control plane written in Go is available at [https://github.com/danthegoodman1/GildraControlPlaneExample](https://github.com/danthegoodman1/GildraControlPlaneExample)

<!-- TOC -->
* [Gildra Control Plane](#gildra-control-plane)
  * [Auth](#auth)
  * [Required Routes](#required-routes)
    * [GET /domain/:domain/config - fetch a routing config for a domain](#get-domaindomainconfig---fetch-a-routing-config-for-a-domain)
    * [GET /domain/:domain/cert - get the current certificate for a domain](#get-domaindomaincert---get-the-current-certificate-for-a-domain)
    * [GET /domain/:domain/challenge/:token - get the challenge token for a domain](#get-domaindomainchallengetoken---get-the-challenge-token-for-a-domain)
  * [Self-implemented routes](#self-implemented-routes)
    * [PUT /domain/:domain/config - set a routing config for a domain](#put-domaindomainconfig---set-a-routing-config-for-a-domain)
    * [DELETE /domain/:domain/config - delete a routing config for a domain](#delete-domaindomainconfig---delete-a-routing-config-for-a-domain)
    * [POST /domain/:domain/cert - create/renew a certificate for a domain](#post-domaindomaincert---createrenew-a-certificate-for-a-domain)
    * [DELETE /domain/:domain/cert - delete the current certificate for a domain](#delete-domaindomaincert---delete-the-current-certificate-for-a-domain)
<!-- TOC -->

## Auth

The control plane should expect a bearer token to be present in the incoming `Authorization` header.

For example, your header might look like:

```
Authorization: Bearer somesupersecrettoken
```

This is configured in Gildra as the required `CP_AUTH` env var.

## Required Routes

The control plane must implement the following endpoints that are used by Gildra. All request and response bodies are JSON.

Any unspecified response body will take the format:
```json
{
  "Msg": "ok"
}
```

Any error status code will have the following body schema:
```json
{
  "Err": "error message" 
}
```

### GET /domain/:domain/config - fetch a routing config for a domain

Gildra uses this endpoint to fetch the routing config when the cache is empty.

Response Body:
```json
{
  "Config": {}
}
```

`Config` is the JSON routing configuration for the domain.

View the routing config spec for more info.

### GET /domain/:domain/cert - get the current certificate for a domain

Gildra uses this endpoint to fetch the routing config when the cache is empty.

Response Body:
```json
{
  "Cert": "...",
  "Key": "..."
}
```


### GET /domain/:domain/challenge/:token - get the challenge token for a domain

For a given HTTP challenge, fetch the key that must be returned. Gildra uses this to complete an incoming HTTP challenge.

Any response with an error status code >=400 will be proxied as the response to the HTTP challenge. 

Request Body:
```json
{
  "Key": "..."
}
```

## Self-implemented routes

These routes are not used by Gildra, however a suggested implementation is provided to be consistent with the rest of the API requirements:

### PUT /domain/:domain/config - set a routing config for a domain

View the routing config spec for more info.

Request Body:
```json
{
  "Config": {}
}
```

### DELETE /domain/:domain/config - delete a routing config for a domain

### POST /domain/:domain/cert - create/renew a certificate for a domain

This endpoint is never used by Gildra, only by the operator. In theory you can customize this however you'd like, so consider this to be a suggestion.

Request Body:
```json
{
  "Wait": false
}
```

`Wait` is whether to wait for the certificate to be created. Otherwise, it will be handled async in the background. Default `false`.

### DELETE /domain/:domain/cert - delete the current certificate for a domain
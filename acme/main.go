package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/go-redis/redis/v8"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/samber/lo"
)

var (
	redisClient = redis.NewClient(func() *redis.Options {
		opt, _ := redis.ParseURL("redis://default:33584fc0dfa54056b5af3ad060e99918@us1-dominant-antelope-38601.upstash.io:38601")
		return opt
	}())
)

func main() {
	zerossl()
}

func letsencrypt() {
	log.Println("starting letsencrypt HTTP challenge (staging)")
	// Get ca info
	// curl https://acme-staging-v02.api.letsencrypt.org/directory
	ca := CADir{
		KeyChange:   "https://acme-staging-v02.api.letsencrypt.org/acme/key-change",
		NewAccount:  "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct",
		NewNonce:    "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce",
		NewOrder:    "https://acme-staging-v02.api.letsencrypt.org/acme/new-order",
		RenewalInfo: "https://acme-staging-v02.api.letsencrypt.org/get/draft-aaron-ari/renewalInfo/",
		RevokeCERT:  "https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert",
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("error generating private key: %s", err)
	}

	// make a new account
	accountJSON, err := json.Marshal(Account{
		TermsOfServiceAgreed: true,
		Contact:              []string{"mailto:danthegoodmanae@icloud.com"},
	})
	if err != nil {
		log.Fatalf("error marshalling account: %s", err)
	}

	signed, err := SignContent(ca.NewAccount, "", accountJSON, privateKey, &ca)
	if err != nil {
		log.Fatalf("error signing content: %s", err)
	}

	log.Println("signed content!")

	log.Printf("acme: Registering account for %s", "danthegoodmanae@icloud.com")

	req, err := http.NewRequest("POST", ca.NewAccount, bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		log.Fatalf("error making new request: %s", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error doing request: %s", err)
	}

	responseBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err)
	}

	log.Printf("code %d", res.StatusCode)
	if res.StatusCode > 299 {
		log.Fatalf("code %d: %s", res.StatusCode, responseBody)
	}
	nonce := res.Header.Get("replay-nonce")
	location := res.Header.Get("location")
	log.Println("account response", string(responseBody))
	log.Println("nonce", nonce)
	log.Println("location", location)
	log.Println("successfully made account!")

	// ---------------------------------------------------------------------------
	// Create the order
	// ---------------------------------------------------------------------------

	order := ExtendedOrder{
		Order: Order{
			Identifiers: []Identifier{
				{
					Type:  "dns",
					Value: "getinsync.co", // the domain to get a cert for
				},
			},
		},
	}

	orderJSON, err := json.Marshal(order)
	if err != nil {
		log.Fatalf("error marshalling account: %s", err)
	}

	signed, err = SignContent(ca.NewOrder, location, orderJSON, privateKey, &ca)
	if err != nil {
		log.Fatalf("error signing content: %s", err)
	}

	log.Printf("Making request to %s", ca.NewOrder)
	req, err = http.NewRequest("POST", ca.NewOrder, bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		log.Fatalf("error making new request: %s", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error doing request: %s", err)
	}

	responseBody, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err)
	}

	log.Printf("code %d", res.StatusCode)
	if res.StatusCode > 299 {
		log.Fatalf("code %d: %s", res.StatusCode, responseBody)
	}
	orderLocation := res.Header.Get("location")
	log.Println("order response", string(responseBody))
	log.Println("order location", orderLocation)
	log.Println("successfully made order!")

	var orderResponse ExtendedOrder
	err = json.Unmarshal(responseBody, &orderResponse)
	if err != nil {
		log.Fatalf("error unmarshalling order response: %s", err)
	}

	// ---------------------------------------------------------------------------
	// Get authorization
	// ---------------------------------------------------------------------------

	signed, err = SignContent(orderResponse.Authorizations[0], location, []byte{}, privateKey, &ca)
	if err != nil {
		log.Fatalf("error signing content: %s", err)
	}

	log.Printf("Making request to %s", orderResponse.Authorizations[0])
	req, err = http.NewRequest("POST", orderResponse.Authorizations[0], bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		log.Fatalf("error making new request: %s", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error doing request: %s", err)
	}

	responseBody, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err)
	}

	log.Printf("code %d", res.StatusCode)
	if res.StatusCode > 299 {
		log.Fatalf("code %d: %s", res.StatusCode, responseBody)
	}
	log.Println("authorization response", string(responseBody))
	log.Println("successfully got authorization!")

	var authResponse Authorization
	err = json.Unmarshal(responseBody, &authResponse)
	if err != nil {
		log.Fatalf("error unmarshalling authorization response: %s", err)
	}

	// ---------------------------------------------------------------------------
	// Create HTTP-01 challenge
	// ---------------------------------------------------------------------------

	domain := authResponse.Identifier.Value
	challenge, found := lo.Find(authResponse.Challenges, func(chal Challenge) bool {
		return chal.Type == "http-01"
	})
	if !found {
		log.Fatalf("http challenge not found")
	}
	log.Printf("using challenge %+v", challenge)

	// Construct key authorization (HTTP-01 response)
	keyAuth, err := GetKeyAuthorization(challenge.Token, privateKey)
	if err != nil {
		log.Fatalf("error getting key authorization: %s", err)
	}

	// at the `domain`, present the `keyAuth` at /.well-known/acme-challenge/{challenge.Token}

	log.Printf("presenting '%s' at http://%s/.well-known/acme-challenge/%s", keyAuth, domain, challenge.Token)

	go func() {
		return
		err := http.ListenAndServe(":80", &ACMEHTTPServer{
			Domain:  domain,
			Token:   challenge.Token,
			KeyAuth: keyAuth,
		})
		if err != nil {
			log.Fatalf("error listening on http: %s", err)
		}
	}()

	cmd := redisClient.Set(context.Background(), challenge.Token, keyAuth, 0)
	if err := cmd.Err(); err != nil {
		log.Fatalf("error in redis get: %w", err)
	}
	log.Println("stored in redis")

	// ---------------------------------------------------------------------------
	// Tell acme server to check the challenge, and validate
	// ---------------------------------------------------------------------------

	signed, err = SignContent(challenge.URL, location, []byte("{}"), privateKey, &ca)
	if err != nil {
		log.Fatalf("error signing content: %s", err)
	}

	log.Printf("Making request to %s", challenge.URL)
	req, err = http.NewRequest("POST", challenge.URL, bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		log.Fatalf("error making new request: %s", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error doing request: %s", err)
	}

	responseBody, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err)
	}

	log.Printf("code %d", res.StatusCode)
	if res.StatusCode > 299 {
		log.Fatalf("code %d: %s", res.StatusCode, responseBody)
	}
	log.Println("challenge response", string(responseBody))
	log.Println("successfully got challenge!")
	nonce = res.Header.Get("Replay-Nonce")
	if nonce == "" {
		log.Fatalf("did not respond with valid nonce header")
	}
	log.Println("got nonce header:", nonce)

	var challengeResponse Challenge
	err = json.Unmarshal(responseBody, &challengeResponse)
	if err != nil {
		log.Fatalf("error unmarshalling challenge response: %s", err)
	}

	// Poll for authorization completion
	s := time.Now()
	var valid bool
	for time.Since(s) < time.Second*300 && !valid {
		time.Sleep(time.Second * 2)
		signed, err = SignContent(orderResponse.Authorizations[0], location, []byte{}, privateKey, &ca)
		if err != nil {
			log.Fatalf("error signing content: %s", err)
		}

		log.Printf("Making request to %s", orderResponse.Authorizations)
		req, err = http.NewRequest("POST", orderResponse.Authorizations[0], bytes.NewReader([]byte(signed.FullSerialize())))
		if err != nil {
			log.Fatalf("error making new request: %s", err)
		}
		req.Header.Add("content-type", "application/jose+json")

		res, err = http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("error doing request: %s", err)
		}

		responseBody, err = ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatalf("error reading body: %s", err)
		}

		log.Printf("code %d", res.StatusCode)
		if res.StatusCode > 299 {
			log.Fatalf("code %d: %s", res.StatusCode, responseBody)
		}
		log.Println("authorization response", string(responseBody))
		log.Println("successfully got authorization!")
		nonce = res.Header.Get("Replay-Nonce")
		if nonce == "" {
			log.Fatalf("did not respond with valid nonce header")
		}
		log.Println("got nonce header:", nonce)

		var authResponse Authorization
		err = json.Unmarshal(responseBody, &authResponse)
		if err != nil {
			log.Fatalf("error unmarshalling authorization response: %s", err)
		}

		valid, err = checkAuthorizationStatus(authResponse)
		if err != nil {
			log.Fatalf("error checking auth status: %s", err)
		}
		log.Println("auth status:", valid)
	}

	// ---------------------------------------------------------------------------
	// Generate CSR and fetch cert
	// ---------------------------------------------------------------------------

	csrKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("error generating private key: %s", err)
	}

	csr, err := GenerateCSR(csrKey, domain, []string{domain}, false)
	if err != nil {
		log.Fatalf("error generating csr: %s", err)
	}

	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(csrKey)}

	// finalize the order
	csrMsg := CSRMessage{
		Csr: base64.RawURLEncoding.EncodeToString(csr),
	}

	csrJSON, err := json.Marshal(csrMsg)
	if err != nil {
		log.Fatalf("error marshalling account: %s", err)
	}

	signed, err = SignContent(orderResponse.Finalize, location, csrJSON, privateKey, &ca)
	if err != nil {
		log.Fatalf("error signing content: %s", err)
	}

	log.Printf("Making request to %s", orderResponse.Finalize)
	req, err = http.NewRequest("POST", orderResponse.Finalize, bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		log.Fatalf("error making new request: %s", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error doing request: %s", err)
	}

	responseBody, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err)
	}

	log.Printf("code %d", res.StatusCode)
	if res.StatusCode > 299 {
		log.Fatalf("code %d: %s", res.StatusCode, responseBody)
	}
	log.Println("order response", string(responseBody))
	log.Println("successfully fulfilled order!")

	var fulfilledOrder Order
	err = json.Unmarshal(responseBody, &fulfilledOrder)
	if err != nil {
		log.Fatalf("error unmarshalling order response: %s", err)
	}

	for time.Since(s) < time.Second*300 && fulfilledOrder.Status == "processing" {
		log.Println("waiting on result processing...", string(responseBody))
		time.Sleep(time.Second * 2)
		log.Println("checking", orderLocation)
		signed, err = SignContent(orderLocation, location, []byte{}, privateKey, &ca)
		if err != nil {
			log.Fatalf("error signing content: %s", err)
		}

		log.Printf("Making request to %s", orderLocation)
		req, err = http.NewRequest("POST", orderLocation, bytes.NewReader([]byte(signed.FullSerialize())))
		if err != nil {
			log.Fatalf("error making new request: %s", err)
		}
		req.Header.Add("content-type", "application/jose+json")

		res, err = http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("error doing request: %s", err)
		}

		responseBody, err = ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatalf("error reading body: %s", err)
		}

		log.Printf("code %d", res.StatusCode)
		if res.StatusCode > 299 {
			log.Fatalf("code %d: %s", res.StatusCode, responseBody)
		}
		err = json.Unmarshal(responseBody, &fulfilledOrder)
		if err != nil {
			log.Fatalf("error unmarshalling order response: %s", err)
		}
	}

	if fulfilledOrder.Status == "valid" {
		log.Println("order valid!")
	} else {
		log.Fatalln("order was not ready, would need to wait by going to the orderLocation and wait")
	}

	certResource := &Resource{
		Domain:        domain,
		CertURL:       fulfilledOrder.Certificate,
		PrivateKey:    pem.EncodeToMemory(pemBlock),
		CertStableURL: fulfilledOrder.Certificate,
	}

	// get the cert
	signed, err = SignContent(certResource.CertURL, location, []byte{}, privateKey, &ca)
	if err != nil {
		log.Fatalf("error signing content: %s", err)
	}

	log.Printf("Making request to %s", certResource.CertURL)
	req, err = http.NewRequest("POST", certResource.CertURL, bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		log.Fatalf("error making new request: %s", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error doing request: %s", err)
	}

	responseBody, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err)
	}

	log.Printf("code %d", res.StatusCode)
	if res.StatusCode > 299 {
		log.Fatalf("code %d: %s", res.StatusCode, responseBody)
	}
	log.Println("raw cert response", string(responseBody))
	log.Println("successfully got raw cert!")

	_, issuer := pem.Decode(responseBody)
	log.Printf("got issuer: %s", string(issuer))

	rawCert := RawCertificate{
		Cert:   responseBody,
		Issuer: issuer,
	}

	certResource.IssuerCertificate = rawCert.Issuer
	certResource.Certificate = rawCert.Cert

	err = ioutil.WriteFile("issuer", certResource.IssuerCertificate, 0666)
	if err != nil {
		log.Fatalf("error writing issuer to disk: %s", err)
	}
	err = ioutil.WriteFile("key", certResource.PrivateKey, 0666)
	if err != nil {
		log.Fatalf("error writing key to disk: %s", err)
	}
	err = ioutil.WriteFile("cert", certResource.Certificate, 0666)
	if err != nil {
		log.Fatalf("error writing cert to disk: %s", err)
	}

	log.Println("done!")
}

func zerossl() {
	log.Println("starting zerossl HTTP challenge")
	// Get ca info
	// curl curl https://acme.zerossl.com/v2/DV90/directory
	ca := CADir{
		KeyChange:   "https://acme.zerossl.com/v2/DV90/keyChange",
		NewAccount:  "https://acme.zerossl.com/v2/DV90/newAccount",
		NewNonce:    "https://acme.zerossl.com/v2/DV90/newNonce",
		NewOrder:    "https://acme.zerossl.com/v2/DV90/newOrder",
		RenewalInfo: "https://acme.zerossl.com/v2/DV90/renewalInfo",
		RevokeCERT:  "https://acme.zerossl.com/v2/DV90/revokeCert",
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("error generating private key: %s", err)
	}

	// make a new account
	eabKID := "CqpjcupAx53vEWtxD6CIxQ"
	hmacKey := "yEmhOx4TOp0bBIiHkR-2o2k3E9T7jxTWJ4ESWXLvkgBQqxd68sQqw1H6TF1K-feCSuJz2LdkUYd9qM5mFdfY9A"
	hmacDecoded, err := base64.RawURLEncoding.DecodeString(hmacKey)
	if err != nil {
		log.Fatalf("error decoding hmacKey: %s", err)
	}

	eabJWS, err := SignEABContent(ca.NewAccount, eabKID, hmacDecoded, privateKey)
	if err != nil {
		log.Fatalf("error creating EAB JWS: %s", err)
	}

	// make a new account
	accountJSON, err := json.Marshal(Account{
		TermsOfServiceAgreed:   true,
		Contact:                []string{"mailto:danthegoodmanae@icloud.com"},
		ExternalAccountBinding: []byte(eabJWS.FullSerialize()),
	})
	if err != nil {
		log.Fatalf("error marshalling account: %s", err)
	}

	signed, err := SignContent(ca.NewAccount, "", accountJSON, privateKey, &ca)
	if err != nil {
		log.Fatalf("error signing content: %s", err)
	}

	log.Println("signed content!")

	log.Printf("acme: Registering account for %s", "danthegoodmanae@icloud.com")

	req, err := http.NewRequest("POST", ca.NewAccount, bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		log.Fatalf("error making new request: %s", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error doing request: %s", err)
	}

	responseBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err)
	}

	log.Printf("code %d", res.StatusCode)
	if res.StatusCode > 299 {
		log.Fatalf("code %d: %s", res.StatusCode, responseBody)
	}
	nonce := res.Header.Get("replay-nonce")
	location := res.Header.Get("location")
	log.Println("account response", string(responseBody))
	log.Println("nonce", nonce)
	log.Println("location", location)
	log.Println("successfully made account!")

	// ---------------------------------------------------------------------------
	// Create the order
	// ---------------------------------------------------------------------------

	order := ExtendedOrder{
		Order: Order{
			Identifiers: []Identifier{
				{
					Type:  "dns",
					Value: "getinsync.co", // the domain to get a cert for
				},
			},
		},
	}

	orderJSON, err := json.Marshal(order)
	if err != nil {
		log.Fatalf("error marshalling account: %s", err)
	}

	signed, err = SignContent(ca.NewOrder, location, orderJSON, privateKey, &ca)
	if err != nil {
		log.Fatalf("error signing content: %s", err)
	}

	log.Printf("Making request to %s", ca.NewOrder)
	req, err = http.NewRequest("POST", ca.NewOrder, bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		log.Fatalf("error making new request: %s", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error doing request: %s", err)
	}

	responseBody, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err)
	}

	log.Printf("code %d", res.StatusCode)
	if res.StatusCode > 299 {
		log.Fatalf("code %d: %s", res.StatusCode, responseBody)
	}
	orderLocation := res.Header.Get("location")
	log.Println("order response", string(responseBody))
	log.Println("order location", orderLocation)
	log.Println("successfully made order!")

	var orderResponse ExtendedOrder
	err = json.Unmarshal(responseBody, &orderResponse)
	if err != nil {
		log.Fatalf("error unmarshalling order response: %s", err)
	}

	// ---------------------------------------------------------------------------
	// Get authorization
	// ---------------------------------------------------------------------------

	signed, err = SignContent(orderResponse.Authorizations[0], location, []byte{}, privateKey, &ca)
	if err != nil {
		log.Fatalf("error signing content: %s", err)
	}

	log.Printf("Making request to %s", orderResponse.Authorizations[0])
	req, err = http.NewRequest("POST", orderResponse.Authorizations[0], bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		log.Fatalf("error making new request: %s", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error doing request: %s", err)
	}

	responseBody, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err)
	}

	log.Printf("code %d", res.StatusCode)
	if res.StatusCode > 299 {
		log.Fatalf("code %d: %s", res.StatusCode, responseBody)
	}
	log.Println("authorization response", string(responseBody))
	log.Println("successfully got authorization!")

	var authResponse Authorization
	err = json.Unmarshal(responseBody, &authResponse)
	if err != nil {
		log.Fatalf("error unmarshalling authorization response: %s", err)
	}

	// ---------------------------------------------------------------------------
	// Create HTTP-01 challenge
	// ---------------------------------------------------------------------------

	domain := authResponse.Identifier.Value
	challenge, found := lo.Find(authResponse.Challenges, func(chal Challenge) bool {
		return chal.Type == "http-01"
	})
	if !found {
		log.Fatalf("http challenge not found")
	}
	log.Printf("using challenge %+v", challenge)

	// Construct key authorization (HTTP-01 response)
	keyAuth, err := GetKeyAuthorization(challenge.Token, privateKey)
	if err != nil {
		log.Fatalf("error getting key authorization: %s", err)
	}

	// at the `domain`, present the `keyAuth` at /.well-known/acme-challenge/{challenge.Token}

	log.Printf("presenting '%s' at http://%s/.well-known/acme-challenge/%s", keyAuth, domain, challenge.Token)

	go func() {
		return
		err := http.ListenAndServe(":80", &ACMEHTTPServer{
			Domain:  domain,
			Token:   challenge.Token,
			KeyAuth: keyAuth,
		})
		if err != nil {
			log.Fatalf("error listening on http: %s", err)
		}
	}()

	cmd := redisClient.Set(context.Background(), challenge.Token, keyAuth, 0)
	if err := cmd.Err(); err != nil {
		log.Fatalf("error in redis get: %w", err)
	}
	log.Println("stored in redis")

	// ---------------------------------------------------------------------------
	// Tell acme server to check the challenge, and validate
	// ---------------------------------------------------------------------------

	signed, err = SignContent(challenge.URL, location, []byte("{}"), privateKey, &ca)
	if err != nil {
		log.Fatalf("error signing content: %s", err)
	}

	log.Printf("Making request to %s", challenge.URL)
	req, err = http.NewRequest("POST", challenge.URL, bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		log.Fatalf("error making new request: %s", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error doing request: %s", err)
	}

	responseBody, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err)
	}

	log.Printf("code %d", res.StatusCode)
	if res.StatusCode > 299 {
		log.Fatalf("code %d: %s", res.StatusCode, responseBody)
	}
	log.Println("challenge response", string(responseBody))
	log.Println("successfully got challenge!")
	nonce = res.Header.Get("Replay-Nonce")
	if nonce == "" {
		log.Fatalf("did not respond with valid nonce header")
	}
	log.Println("got nonce header:", nonce)

	var challengeResponse Challenge
	err = json.Unmarshal(responseBody, &challengeResponse)
	if err != nil {
		log.Fatalf("error unmarshalling challenge response: %s", err)
	}

	// Poll for authorization completion
	s := time.Now()
	var valid bool
	for time.Since(s) < time.Second*300 && !valid {
		time.Sleep(time.Second * 2)
		signed, err = SignContent(orderResponse.Authorizations[0], location, []byte{}, privateKey, &ca)
		if err != nil {
			log.Fatalf("error signing content: %s", err)
		}

		log.Printf("Making request to %s", orderResponse.Authorizations)
		req, err = http.NewRequest("POST", orderResponse.Authorizations[0], bytes.NewReader([]byte(signed.FullSerialize())))
		if err != nil {
			log.Fatalf("error making new request: %s", err)
		}
		req.Header.Add("content-type", "application/jose+json")

		res, err = http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("error doing request: %s", err)
		}

		responseBody, err = ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatalf("error reading body: %s", err)
		}

		log.Printf("code %d", res.StatusCode)
		if res.StatusCode > 299 {
			log.Fatalf("code %d: %s", res.StatusCode, responseBody)
		}
		log.Println("authorization response", string(responseBody))
		log.Println("successfully got authorization!")
		nonce = res.Header.Get("Replay-Nonce")
		if nonce == "" {
			log.Fatalf("did not respond with valid nonce header")
		}
		log.Println("got nonce header:", nonce)

		var authResponse Authorization
		err = json.Unmarshal(responseBody, &authResponse)
		if err != nil {
			log.Fatalf("error unmarshalling authorization response: %s", err)
		}

		valid, err = checkAuthorizationStatus(authResponse)
		if err != nil {
			log.Fatalf("error checking auth status: %s", err)
		}
		log.Println("auth status:", valid)
	}

	// ---------------------------------------------------------------------------
	// Generate CSR and fetch cert
	// ---------------------------------------------------------------------------

	csrKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("error generating private key: %s", err)
	}

	csr, err := GenerateCSR(csrKey, domain, []string{domain}, false)
	if err != nil {
		log.Fatalf("error generating csr: %s", err)
	}

	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(csrKey)}

	// finalize the order
	csrMsg := CSRMessage{
		Csr: base64.RawURLEncoding.EncodeToString(csr),
	}

	csrJSON, err := json.Marshal(csrMsg)
	if err != nil {
		log.Fatalf("error marshalling account: %s", err)
	}

	signed, err = SignContent(orderResponse.Finalize, location, csrJSON, privateKey, &ca)
	if err != nil {
		log.Fatalf("error signing content: %s", err)
	}

	log.Printf("Making request to %s", orderResponse.Finalize)
	req, err = http.NewRequest("POST", orderResponse.Finalize, bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		log.Fatalf("error making new request: %s", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error doing request: %s", err)
	}

	responseBody, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err)
	}

	log.Printf("code %d", res.StatusCode)
	if res.StatusCode > 299 {
		log.Fatalf("code %d: %s", res.StatusCode, responseBody)
	}
	log.Println("order response", string(responseBody))
	log.Println("successfully fulfilled order!")

	var fulfilledOrder Order
	err = json.Unmarshal(responseBody, &fulfilledOrder)
	if err != nil {
		log.Fatalf("error unmarshalling order response: %s", err)
	}

	for time.Since(s) < time.Second*300 && fulfilledOrder.Status == "processing" {
		log.Println("waiting on result processing...", string(responseBody))
		time.Sleep(time.Second * 2)
		log.Println("checking", orderLocation)
		signed, err = SignContent(orderLocation, location, []byte{}, privateKey, &ca)
		if err != nil {
			log.Fatalf("error signing content: %s", err)
		}

		log.Printf("Making request to %s", orderLocation)
		req, err = http.NewRequest("POST", orderLocation, bytes.NewReader([]byte(signed.FullSerialize())))
		if err != nil {
			log.Fatalf("error making new request: %s", err)
		}
		req.Header.Add("content-type", "application/jose+json")

		res, err = http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("error doing request: %s", err)
		}

		responseBody, err = ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatalf("error reading body: %s", err)
		}

		log.Printf("code %d", res.StatusCode)
		if res.StatusCode > 299 {
			log.Fatalf("code %d: %s", res.StatusCode, responseBody)
		}
		err = json.Unmarshal(responseBody, &fulfilledOrder)
		if err != nil {
			log.Fatalf("error unmarshalling order response: %s", err)
		}
	}

	if fulfilledOrder.Status == "valid" {
		log.Println("order valid!")
	} else {
		log.Fatalln("order was not ready, would need to wait by going to the orderLocation and wait")
	}

	certResource := &Resource{
		Domain:        domain,
		CertURL:       fulfilledOrder.Certificate,
		PrivateKey:    pem.EncodeToMemory(pemBlock),
		CertStableURL: fulfilledOrder.Certificate,
	}

	// get the cert
	signed, err = SignContent(certResource.CertURL, location, []byte{}, privateKey, &ca)
	if err != nil {
		log.Fatalf("error signing content: %s", err)
	}

	log.Printf("Making request to %s", certResource.CertURL)
	req, err = http.NewRequest("POST", certResource.CertURL, bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		log.Fatalf("error making new request: %s", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error doing request: %s", err)
	}

	responseBody, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err)
	}

	log.Printf("code %d", res.StatusCode)
	if res.StatusCode > 299 {
		log.Fatalf("code %d: %s", res.StatusCode, responseBody)
	}
	log.Println("raw cert response", string(responseBody))
	log.Println("successfully got raw cert!")

	_, issuer := pem.Decode(responseBody)
	log.Printf("got issuer: %s", string(issuer))

	rawCert := RawCertificate{
		Cert:   responseBody,
		Issuer: issuer,
	}

	certResource.IssuerCertificate = rawCert.Issuer
	certResource.Certificate = rawCert.Cert

	err = ioutil.WriteFile("issuer", certResource.IssuerCertificate, 0666)
	if err != nil {
		log.Fatalf("error writing issuer to disk: %s", err)
	}
	err = ioutil.WriteFile("key", certResource.PrivateKey, 0666)
	if err != nil {
		log.Fatalf("error writing key to disk: %s", err)
	}
	err = ioutil.WriteFile("cert", certResource.Certificate, 0666)
	if err != nil {
		log.Fatalf("error writing cert to disk: %s", err)
	}

	log.Println("done!")
}

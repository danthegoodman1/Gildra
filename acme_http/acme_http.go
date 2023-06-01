package acme_http

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
	"errors"
	"fmt"
	"github.com/samber/lo"
	"io"
	"log"
	"net/http"
	"time"
)

type (
	EABOptions struct {
		KID     string
		HMACKey string
	}
)

var (
	ErrHighStatusCode = errors.New("high status code")
)

func GetCADir(ctx context.Context, caDirURL string) (*CADir, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", caDirURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error in http.NewRequestWithContext: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error in doing request: %w", err)
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading request body: %w", err)
	}
	if res.StatusCode > 299 {
		return nil, fmt.Errorf("status %d - body %s - %w", res.StatusCode, string(resBody), ErrHighStatusCode)
	}

	var caDir CADir
	err = json.Unmarshal(resBody, &caDir)
	if err != nil {
		return nil, fmt.Errorf("error in unmarshaling CA dir: %w", err)
	}

	return &caDir, nil
}

func signedRequest(ctx context.Context, url, kid string, content []byte, pk *ecdsa.PrivateKey, caDir *CADir) (*http.Response, []byte, error) {
	signed, err := SignContent(url, kid, content, pk, caDir)
	if err != nil {
		return nil, nil, fmt.Errorf("error signing content: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader([]byte(signed.FullSerialize())))
	if err != nil {
		return nil, nil, fmt.Errorf("error creating new request: %w", err)
	}
	req.Header.Add("content-type", "application/jose+json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error doing request: %w", err)
	}
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading request body: %w", err)
	}
	if res.StatusCode > 299 {
		return nil, nil, fmt.Errorf("status %d - body %s - %w", res.StatusCode, string(resBody), ErrHighStatusCode)
	}

	return res, resBody, nil
}

func CreateAccount(ctx context.Context, mailTo string, caDir *CADir, eab *EABOptions) (accountKID string, privateKey *ecdsa.PrivateKey, err error) {
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		err = fmt.Errorf("error generating private key: %w", err)
		return
	}

	acc := Account{
		TermsOfServiceAgreed: true,
		Contact:              []string{fmt.Sprintf("mailto:%s", mailTo)},
	}

	if eab != nil {
		hmacDecoded, e := base64.RawURLEncoding.DecodeString(eab.HMACKey)
		if e != nil {
			err = fmt.Errorf("error decoding hmac: %w", e)
			return
		}

		eabJWS, e := SignEABContent(caDir.NewAccount, eab.KID, hmacDecoded, privateKey)
		if e != nil {
			err = fmt.Errorf("error signing EAB content: %w", e)
			return
		}

		acc.ExternalAccountBinding = []byte(eabJWS.FullSerialize())
	}

	// make a new account
	accountJSON, err := json.Marshal(acc)
	if err != nil {
		err = fmt.Errorf("error in marshalling account JSON: %w", err)
		return
	}

	var res *http.Response
	res, _, err = signedRequest(ctx, caDir.NewAccount, "", accountJSON, privateKey, caDir)
	if err != nil {
		err = fmt.Errorf("error in signedRequest: %w", err)
		return
	}

	return res.Header.Get("location"), privateKey, nil
}

func CreateOrder(ctx context.Context, accountKID, domain string, caDir *CADir, pk *ecdsa.PrivateKey) (orderLocation string, orderResponse ExtendedOrder, err error) {
	order := ExtendedOrder{
		Order: Order{
			Identifiers: []Identifier{
				{
					Type:  "dns",
					Value: domain, // the domain to get a cert for
				},
			},
		},
	}

	orderJSON, err := json.Marshal(order)
	if err != nil {
		err = fmt.Errorf("error marshalling order json: %w", err)
		return
	}

	res, resBody, err := signedRequest(ctx, caDir.NewOrder, accountKID, orderJSON, pk, caDir)
	if err != nil {
		err = fmt.Errorf("error in signedRequest: %w", err)
		return
	}

	orderLocation = res.Header.Get("location")
	err = json.Unmarshal(resBody, &orderResponse)
	if err != nil {
		err = fmt.Errorf("error unmarshaling order response: %w", err)
		return
	}

	return
}

func GetAuthorization(ctx context.Context, accountKID string, pk *ecdsa.PrivateKey, caDir *CADir, orderResp ExtendedOrder) (*Authorization, error) {
	_, resBody, err := signedRequest(ctx, orderResp.Authorizations[0], accountKID, []byte{}, pk, caDir)
	if err != nil {
		return nil, fmt.Errorf("error in signedRequest: %w", err)
	}

	var auth Authorization
	err = json.Unmarshal(resBody, &auth)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}
	return &auth, nil
}

type ChallengeContent struct {
	Token, Key, URL string
}

var ErrChallengeNotFound = errors.New("challenge not found")

func CreateChallenge(ctx context.Context, auth Authorization, pk *ecdsa.PrivateKey) (*ChallengeContent, error) {
	challenge, found := lo.Find(auth.Challenges, func(chal Challenge) bool {
		return chal.Type == "http-01"
	})
	if !found {
		return nil, ErrChallengeNotFound
	}

	// Construct key authorization (HTTP-01 response)
	keyAuth, err := GetKeyAuthorization(challenge.Token, pk)
	if err != nil {
		log.Fatalf("error getting key authorization: %s", err)
	}

	return &ChallengeContent{
		Token: challenge.Token,
		Key:   keyAuth,
		URL:   challenge.URL,
	}, nil
}

func NotifyChallenge(ctx context.Context, caDir *CADir, accountKID string, pk *ecdsa.PrivateKey, chal ChallengeContent) (*Challenge, error) {
	_, resBody, err := signedRequest(ctx, chal.URL, accountKID, []byte("{}"), pk, caDir)
	if err != nil {
		return nil, fmt.Errorf("error in signedRequest: %w", err)
	}

	var challengeResponse Challenge
	err = json.Unmarshal(resBody, &challengeResponse)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}

	return &challengeResponse, nil
}

func PollAuthorizationCompleted(ctx context.Context, pollSleep time.Duration, order ExtendedOrder, accountKID string, pk *ecdsa.PrivateKey, caDir *CADir) error {
	for {
		err := ctx.Err()
		if err != nil {
			return err
		}

		_, resBody, err := signedRequest(ctx, order.Authorizations[0], accountKID, []byte{}, pk, caDir)
		if err != nil {
			return fmt.Errorf("error in signedRequest: %w", err)
		}

		var authResponse Authorization
		err = json.Unmarshal(resBody, &authResponse)
		if err != nil {
			return fmt.Errorf("error in json.Unmarshal: %w", err)
		}

		valid, err := checkAuthorizationStatus(authResponse)
		if err != nil {
			return fmt.Errorf("error in checkAuthorizationStatus: %w", err)
		}
		if valid {
			return nil
		}

		time.Sleep(pollSleep)
	}
}

var ErrOrderNotReady = errors.New("order was not ready, would need to wait by going to the orderLocation and wait")

func FinalizeOrder(ctx context.Context, accountKID, domain, orderLocation string, pk *ecdsa.PrivateKey, dir *CADir, pollSleep time.Duration, order ExtendedOrder) (*Resource, error) {

	csrKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("error in rsa.GenerateKey: %w", err)
	}

	csr, err := GenerateCSR(csrKey, domain, []string{domain}, false)
	if err != nil {
		return nil, fmt.Errorf("error in GenerateCSR: %w", err)
	}

	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(csrKey)}

	csrMsg := CSRMessage{
		Csr: base64.RawURLEncoding.EncodeToString(csr),
	}

	csrJSON, err := json.Marshal(csrMsg)
	if err != nil {
		return nil, fmt.Errorf("error marshaling csr message: %w", err)
	}

	// Finalize the order
	_, resBody, err := signedRequest(ctx, order.Finalize, accountKID, csrJSON, pk, dir)
	if err != nil {
		return nil, fmt.Errorf("error in signedRequest for finalizing order: %w", err)
	}

	var fulfilledOrder Order
	err = json.Unmarshal(resBody, &fulfilledOrder)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling finalize response: %w", err)
	}

	for {
		if fulfilledOrder.Status != "processing" {
			break
		}

		err = ctx.Err()
		if err != nil {
			return nil, err
		}

		// Poll the order status
		_, resBody, err = signedRequest(ctx, orderLocation, accountKID, []byte{}, pk, dir)
		if err != nil {
			return nil, fmt.Errorf("error in signedRequest for order location: %w", err)
		}

		err = json.Unmarshal(resBody, &fulfilledOrder)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling finalize response: %w", err)
		}

		time.Sleep(pollSleep)
	}

	if fulfilledOrder.Status != "valid" {
		return nil, ErrOrderNotReady
	}

	return &Resource{
		Domain:        domain,
		CertURL:       fulfilledOrder.Certificate,
		PrivateKey:    pem.EncodeToMemory(pemBlock),
		CertStableURL: fulfilledOrder.Certificate,
		CSR:           csr,
	}, nil
}

func GetCert(ctx context.Context, resource Resource, accountKID string, key *ecdsa.PrivateKey, dir *CADir) (*Resource, error) {
	_, resBody, err := signedRequest(ctx, resource.CertURL, accountKID, []byte{}, key, dir)
	if err != nil {
		return nil, fmt.Errorf("error in signedRequest: %w", err)
	}

	_, issuer := pem.Decode(resBody)

	resource.IssuerCertificate = issuer
	resource.Certificate = resBody

	return &resource, nil
}

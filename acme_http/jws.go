package acme_http

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"net/http"
	"time"
)

// SignContent Signs a content with the JWS.
func SignContent(url, kid string, content []byte, privKey *ecdsa.PrivateKey, ca *CADir) (*jose.JSONWebSignature, error) {

	signKey := jose.SigningKey{
		Algorithm: "ES256",
		Key:       jose.JSONWebKey{Key: privKey, KeyID: kid},
	}

	options := jose.SignerOptions{
		NonceSource: &NonceSource{
			NonceURL: ca.NewNonce,
		},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	if kid == "" {
		options.EmbedJWK = true
	}

	signer, err := jose.NewSigner(signKey, &options)
	if err != nil {
		return nil, fmt.Errorf("failed to create jose signer: %w", err)
	}

	signed, err := signer.Sign(content)
	if err != nil {
		return nil, fmt.Errorf("failed to sign content: %w", err)
	}
	return signed, nil
}

type NonceSource struct {
	NonceURL string
}

func (ns *NonceSource) Nonce() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", ns.NonceURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error doing request: %w", err)
	}

	fmt.Println("getting nonce", res.Header.Get("replay-nonce"), res.StatusCode)
	return res.Header.Get("replay-nonce"), nil
}

func GetKeyAuthorization(token string, privKey *ecdsa.PrivateKey) (string, error) {

	// Generate the Key Authorization for the challenge
	jwk := &jose.JSONWebKey{Key: privKey.Public()}

	thumbBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("error in jwk.Thumbprint: %w", err)
	}

	// unpad the base64URL
	keyThumb := base64.RawURLEncoding.EncodeToString(thumbBytes)

	return token + "." + keyThumb, nil
}

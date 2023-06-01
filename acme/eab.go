package acme

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/go-jose/go-jose/v3"
)

func SignEABContent(url, kid string, hmac []byte, privKey *ecdsa.PrivateKey) (*jose.JSONWebSignature, error) {
	jwk := jose.JSONWebKey{Key: privKey}
	jwkJSON, err := jwk.Public().MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("acme-test: error encoding eab jwk key: %w", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: hmac},
		&jose.SignerOptions{
			EmbedJWK: false,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": kid,
				"url": url,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create External Account Binding jose signer: %w", err)
	}

	signed, err := signer.Sign(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to External Account Binding sign content: %w", err)
	}

	return signed, nil
}

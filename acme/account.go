package acme

import (
	"encoding/json"
	"github.com/go-jose/go-jose/v3"
)

// from lego `commons.go`

// Account the ACME account Object.
// - https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.2
// - https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
type Account struct {
	// status (required, string):
	// The status of this account.
	// Possible values are: "valid", "deactivated", and "revoked".
	// The value "deactivated" should be used to indicate client-initiated deactivation
	// whereas "revoked" should be used to indicate server- initiated deactivation. (See Section 7.1.6)
	Status string `json:"status,omitempty"`

	// contact (optional, array of string):
	// An array of URLs that the server can use to contact the client for issues related to this account.
	// For example, the server may wish to notify the client about server-initiated revocation or certificate expiration.
	// For information on supported URL schemes, see Section 7.3
	Contact []string `json:"contact,omitempty"`

	// termsOfServiceAgreed (optional, boolean):
	// Including this field in a new-account request,
	// with a value of true, indicates the client's agreement with the terms of service.
	// This field is not updateable by the client.
	TermsOfServiceAgreed bool `json:"termsOfServiceAgreed,omitempty"`

	// orders (required, string):
	// A URL from which a list of orders submitted by this account can be fetched via a POST-as-GET request,
	// as described in Section 7.1.2.1.
	Orders string `json:"orders,omitempty"`

	// onlyReturnExisting (optional, boolean):
	// If this field is present with the value "true",
	// then the server MUST NOT create a new account if one does not already exist.
	// This allows a client to look up an account URL based on an account key (see Section 7.3.1).
	OnlyReturnExisting bool `json:"onlyReturnExisting,omitempty"`

	// externalAccountBinding (optional, object):
	// An optional field for binding the new account with an existing non-ACME account (see Section 7.3.4).
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding,omitempty"`
}

type AccountCreateReq struct {
	// b64 encoded signed account
	Payload []byte `json:"payload"`
	// jws signature
	Signature string `json:"signature"`
}

type ProtectedData struct {
	// ex: ES256
	Alg   string          `json:"alg"`
	JWK   jose.JSONWebKey `json:"jwk"`
	Nonce string          `json:"nonce"`
	Url   string          `json:"url"`
}

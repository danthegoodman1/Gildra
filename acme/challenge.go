package acme

import "time"

// Challenge the ACME challenge object.
// - https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.5
// - https://www.rfc-editor.org/rfc/rfc8555.html#section-8
type Challenge struct {
	// type (required, string):
	// The type of challenge encoded in the object.
	Type string `json:"type"`

	// url (required, string):
	// The URL to which a response can be posted.
	URL string `json:"url"`

	// status (required, string):
	// The status of this challenge. Possible values are: "pending", "processing", "valid", and "invalid".
	Status string `json:"status"`

	// validated (optional, string):
	// The time at which the server validated this challenge,
	// encoded in the format specified in RFC 3339 [RFC3339].
	// This field is REQUIRED if the "status" field is "valid".
	Validated time.Time `json:"validated,omitempty"`

	// error (optional, object):
	// Error that occurred while the server was validating the challenge, if any,
	// structured as a problem document [RFC7807].
	// Multiple errors can be indicated by using subproblems Section 6.7.1.
	// A challenge object with an error MUST have status equal to "invalid".
	Error *ProblemDetails `json:"error,omitempty"`

	// token (required, string):
	// A random value that uniquely identifies the challenge.
	// This value MUST have at least 128 bits of entropy.
	// It MUST NOT contain any characters outside the base64url alphabet,
	// and MUST NOT include base64 padding characters ("=").
	// See [RFC4086] for additional information on randomness requirements.
	// https://www.rfc-editor.org/rfc/rfc8555.html#section-8.3
	// https://www.rfc-editor.org/rfc/rfc8555.html#section-8.4
	Token string `json:"token"`

	// https://www.rfc-editor.org/rfc/rfc8555.html#section-8.1
	KeyAuthorization string `json:"keyAuthorization"`
}

// ExtendedChallenge a extended Challenge.
type ExtendedChallenge struct {
	Challenge
	// Contains the value of the response header `Retry-After`
	RetryAfter string `json:"-"`
	// Contains the value of the response header `Link` rel="up"
	AuthorizationURL string `json:"-"`
}

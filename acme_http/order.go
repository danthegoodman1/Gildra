package acme_http

// Order the ACME order Object.
// - https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.3
type Order struct {
	// status (required, string):
	// The status of this order.
	// Possible values are: "pending", "ready", "processing", "valid", and "invalid".
	Status string `json:"status,omitempty"`

	// expires (optional, string):
	// The timestamp after which the server will consider this order invalid,
	// encoded in the format specified in RFC 3339 [RFC3339].
	// This field is REQUIRED for objects with "pending" or "valid" in the status field.
	Expires string `json:"expires,omitempty"`

	// identifiers (required, array of object):
	// An array of identifier objects that the order pertains to.
	Identifiers []Identifier `json:"identifiers"`

	// notBefore (optional, string):
	// The requested value of the notBefore field in the certificate,
	// in the date format defined in [RFC3339].
	NotBefore string `json:"notBefore,omitempty"`

	// notAfter (optional, string):
	// The requested value of the notAfter field in the certificate,
	// in the date format defined in [RFC3339].
	NotAfter string `json:"notAfter,omitempty"`

	// error (optional, object):
	// The error that occurred while processing the order, if any.
	// This field is structured as a problem document [RFC7807].
	Error *ProblemDetails `json:"error,omitempty"`

	// authorizations (required, array of string):
	// For pending orders,
	// the authorizations that the client needs to complete before the requested certificate can be issued (see Section 7.5),
	// including unexpired authorizations that the client has completed in the past for identifiers specified in the order.
	// The authorizations required are dictated by server policy
	// and there may not be a 1:1 relationship between the order identifiers and the authorizations required.
	// For final orders (in the "valid" or "invalid" state), the authorizations that were completed.
	// Each entry is a URL from which an authorization can be fetched with a POST-as-GET request.
	Authorizations []string `json:"authorizations,omitempty"`

	// finalize (required, string):
	// A URL that a CSR must be POSTed to once all of the order's authorizations are satisfied to finalize the order.
	// The result of a successful finalization will be the population of the certificate URL for the order.
	Finalize string `json:"finalize,omitempty"`

	// certificate (optional, string):
	// A URL for the certificate that has been issued in response to this order
	Certificate string `json:"certificate,omitempty"`
}

// ExtendedOrder a extended Order.
type ExtendedOrder struct {
	Order

	// The order URL, contains the value of the response header `Location`
	Location string `json:"-"`
}

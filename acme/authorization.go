package acme

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrUnexpectedState = errors.New("server returned an unexpected state")
)

const (
	StatusDeactivated = "deactivated"
	StatusExpired     = "expired"
	StatusInvalid     = "invalid"
	StatusPending     = "pending"
	StatusProcessing  = "processing"
	StatusReady       = "ready"
	StatusRevoked     = "revoked"
	StatusUnknown     = "unknown"
	StatusValid       = "valid"
)

// Authorization the ACME authorization object.
// - https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.4
type Authorization struct {
	// status (required, string):
	// The status of this authorization.
	// Possible values are: "pending", "valid", "invalid", "deactivated", "expired", and "revoked".
	Status string `json:"status"`

	// expires (optional, string):
	// The timestamp after which the server will consider this authorization invalid,
	// encoded in the format specified in RFC 3339 [RFC3339].
	// This field is REQUIRED for objects with "valid" in the "status" field.
	Expires time.Time `json:"expires,omitempty"`

	// identifier (required, object):
	// The identifier that the account is authorized to represent
	Identifier Identifier `json:"identifier,omitempty"`

	// challenges (required, array of objects):
	// For pending authorizations, the challenges that the client can fulfill in order to prove possession of the identifier.
	// For valid authorizations, the challenge that was validated.
	// For invalid authorizations, the challenge that was attempted and failed.
	// Each array entry is an object with parameters required to validate the challenge.
	// A client should attempt to fulfill one of these challenges,
	// and a server should consider any one of the challenges sufficient to make the authorization valid.
	Challenges []Challenge `json:"challenges,omitempty"`

	// wildcard (optional, boolean):
	// For authorizations created as a result of a newOrder request containing a DNS identifier
	// with a value that contained a wildcard prefix this field MUST be present, and true.
	Wildcard bool `json:"wildcard,omitempty"`
}

func checkAuthorizationStatus(authz Authorization) (bool, error) {
	switch authz.Status {
	case StatusValid:
		return true, nil
	case StatusPending, StatusProcessing:
		return false, nil
	case StatusDeactivated, StatusExpired, StatusRevoked:
		return false, fmt.Errorf("the authorization state %s", authz.Status)
	case StatusInvalid:
		for _, chlg := range authz.Challenges {
			if chlg.Status == StatusInvalid && chlg.Error != nil {
				return false, chlg.Error
			}
		}
		return false, fmt.Errorf("the authorization state %s", authz.Status)
	default:
		return false, fmt.Errorf("unknown state %s: %w", authz.Status, ErrUnexpectedState)
	}
}

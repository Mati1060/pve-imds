package imds

import (
	"context"
	"errors"
	"net/http"

	"github.com/wyattanderson/pve-imds/internal/identity"
)

var (
	// ErrNoUserData is returned by a UserDataProvider when the VM has no
	// user-data block.
	ErrNoUserData = errors.New("imds: no user-data")

	// ErrUserDataUnavailable is returned by a UserDataProvider when the VM
	// has user-data that cannot be served right now, e.g. because a secret
	// could not be resolved. Callers must not serve partial content.
	ErrUserDataUnavailable = errors.New("imds: user-data temporarily unavailable")
)

// userDataRetryAfter is the Retry-After value, in seconds, sent with 503
// responses for unavailable user-data.
const userDataRetryAfter = "10"

// UserDataProvider returns the user-data to serve for a VM. Every endpoint
// that serves user-data (EC2, OpenStack, NoCloud) goes through the same
// provider so that templating behaves identically everywhere.
type UserDataProvider interface {
	// UserData returns the user-data for rec. It returns an error wrapping
	// ErrNoUserData when there is none, and one wrapping
	// ErrUserDataUnavailable when it exists but cannot be served.
	UserData(ctx context.Context, rec *identity.VMRecord) (string, error)
}

// WriteUserDataUnavailable writes a 503 response with a Retry-After header.
// The body is deliberately generic; the reason is logged by the provider.
func WriteUserDataUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", userDataRetryAfter)
	http.Error(w, "user data temporarily unavailable", http.StatusServiceUnavailable)
}

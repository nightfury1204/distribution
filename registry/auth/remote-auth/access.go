// Package htpasswd provides a simple authentication scheme that checks for the
// user credential hash in an htpasswd formatted file in a configuration-determined
// location.
//
// This authentication method MUST be used under TLS, as simple token-replay attack is possible.
package remote

import (
	"context"
	"fmt"
	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/auth"
	"net/http"
	"strings"
)

type accessController struct {
	realm    string
	remoteClient *RemoteClient
}

var _ auth.AccessController = &accessController{}

func newAccessController(options map[string]interface{}) (auth.AccessController, error) {
	realm, present := options["realm"]
	if _, ok := realm.(string); !present || !ok {
		return nil, fmt.Errorf(`"realm" must be set for htpasswd access controller`)
	}
	rc, err := NewRemoteClient(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create remote auth client: %v", err)
	}
	return &accessController{realm: realm.(string), remoteClient:rc}, nil
}

func (ac *accessController) Authorized(ctx context.Context, accessRecords ...auth.Access) (context.Context, error) {
	req, err := dcontext.GetRequest(ctx)
	if err != nil {
		return nil, err
	}

	username, password, ok := req.BasicAuth()
	if !ok {
		return nil, &challenge{
			realm: ac.realm,
			err:   auth.ErrInvalidCredential,
		}
	}

	if _, err := ac.remoteClient.RemoteRequest(username, password, nil); err != nil {
		dcontext.GetLogger(ctx).Errorf("error authenticating user %q: %v", username, err)
		return nil, &challenge{
			realm: ac.realm,
			err:   auth.ErrAuthenticationFailure,
		}
	}

	for _, record := range accessRecords {
		if record.Type == "repository" && !strings.HasPrefix(record.Name, username+"/") {
			return nil, fmt.Errorf("repository must have start with <username>/")
		}
	}
	return auth.WithUser(ctx, auth.UserInfo{Name: username}), nil
}

// challenge implements the auth.Challenge interface.
type challenge struct {
	realm string
	err   error
}

var _ auth.Challenge = challenge{}

// SetHeaders sets the basic challenge header on the response.
func (ch challenge) SetHeaders(r *http.Request, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", ch.realm))
}

func (ch challenge) Error() string {
	return fmt.Sprintf("basic authentication challenge for realm %q: %s", ch.realm, ch.err)
}

func init() {
	auth.Register("remote-auth", auth.InitFunc(newAccessController))
}

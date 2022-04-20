// Copyright (c) 2021 Red Hat, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"context"
	"fmt"
	"html/template"
	"net/http"

	"github.com/alexedwards/scs"
	v1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/util/uuid"

	"strings"

	"github.com/mshaposhnik/service-provider-integration-operator/api/v1beta1"
	"github.com/mshaposhnik/service-provider-integration-operator/pkg/spi-shared/config"
	"github.com/mshaposhnik/service-provider-integration-operator/pkg/spi-shared/oauthstate"
	"github.com/mshaposhnik/service-provider-integration-operator/pkg/spi-shared/tokenstorage"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// commonController is the implementation of the Controller interface that assumes typical OAuth flow.
type commonController struct {
	Config           config.ServiceProviderConfiguration
	JwtSigningSecret []byte
	K8sClient        AuthenticatingClient
	TokenStorage     tokenstorage.TokenStorage
	Endpoint         oauth2.Endpoint
	BaseUrl          string
	SessionManager   *scs.Manager
	RedirectTemplate *template.Template
}

// exchangeState is the state that we're sending out to the SP after checking the anonymous oauth state produced by
// the operator as the initial OAuth URL. Notice that the state doesn't contain any sensitive information. It only
// contains the Key which is the key to the HTTP session that actually contains the authorization header to use when
// finishing the OAuth flow.
type exchangeState struct {
	oauthstate.AnonymousOAuthState
	Key string `json:"key"`
}

// exchangeResult this the result of the OAuth exchange with all the data necessary to store the token into the storage
type exchangeResult struct {
	exchangeState
	result              oauthFinishResult
	token               *oauth2.Token
	authorizationHeader string
}

// newOAuth2Config returns a new instance of the oauth2.Config struct with the clientId, clientSecret and redirect URL
// specific to this controller.
func (c *commonController) newOAuth2Config() oauth2.Config {
	return oauth2.Config{
		ClientID:     c.Config.ClientId,
		ClientSecret: c.Config.ClientSecret,
		RedirectURL:  c.redirectUrl(),
	}
}

// redirectUrl constructs the URL to the callback endpoint so that it can be handled by this controller.
func (c *commonController) redirectUrl() string {
	return strings.TrimSuffix(c.BaseUrl, "/") + "/" + strings.ToLower(string(c.Config.ServiceProviderType)) + "/callback"
}

func (c commonController) Authenticate(w http.ResponseWriter, r *http.Request) {
	stateString := r.FormValue("state")
	codec, err := oauthstate.NewCodec(c.JwtSigningSecret)
	if err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "failed to instantiate OAuth stateString codec", err)
		return
	}

	state, err := codec.ParseAnonymous(stateString)
	if err != nil {
		logAndWriteResponse(w, http.StatusBadRequest, "failed to decode the OAuth state", err)
		return
	}

	session := c.SessionManager.Load(r)

	token := r.FormValue("k8s_token")

	if token == "" {
		token = ExtractTokenFromAuthorizationHeader(r.Header.Get("Authorization"))
	}

	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, "failed extract authorization info either from headers or form/query parameters")
		return
	}

	hasAccess, err := c.checkIdentityHasAccess(token, r, state)
	if err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "failed to determine if the authenticated user has access", err)
		return
	}

	if !hasAccess {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, "authenticating the request in Kubernetes unsuccessful")
		return
	}

	flowKey := string(uuid.NewUUID())

	flows := map[string]string{}

	if err := session.GetObject("flows", &flows); err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "failed to decode session data", err)
		return
	}

	flows[flowKey] = token

	if err := session.PutObject(w, "flows", flows); err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "failed to encode session data", err)
		return
	}

	keyedState := exchangeState{
		AnonymousOAuthState: state,
		Key:                 flowKey,
	}

	oauthCfg := c.newOAuth2Config()
	oauthCfg.Endpoint = c.Endpoint
	oauthCfg.Scopes = keyedState.Scopes

	stateString, err = codec.Encode(&keyedState)
	if err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "failed to encode OAuth state", err)
		return
	}

	url := oauthCfg.AuthCodeURL(stateString)

	templateData := struct {
		Url string
	}{
		Url: url,
	}

	err = c.RedirectTemplate.Execute(w, templateData)
	if err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "failed to return redirect notice HTML page", err)
		return
	}
}

func (c commonController) Callback(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	exchange, err := c.finishOAuthExchange(ctx, r, c.Endpoint)
	if err != nil {
		logAndWriteResponse(w, http.StatusBadRequest, "error in Service Provider token exchange", err)
		return
	}

	if exchange.result == oauthFinishK8sAuthRequired {
		logAndWriteResponse(w, http.StatusUnauthorized, "could not authenticate to Kubernetes", err)
		return
	}

	err = c.syncTokenData(ctx, &exchange)
	if err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "failed to store token data to cluster", err)
		return
	}

	redirectLocation := r.FormValue("redirect_after_login")
	if redirectLocation == "" {
		redirectLocation = strings.TrimSuffix(c.BaseUrl, "/") + "/" + "callback_success"
	}
	http.Redirect(w, r, redirectLocation, http.StatusFound)
}

// finishOAuthExchange implements the bulk of the Callback function. It returns the token, if obtained, the decoded
// state from the oauth flow, if available, and the result of the authentication.
func (c commonController) finishOAuthExchange(ctx context.Context, r *http.Request, endpoint oauth2.Endpoint) (exchangeResult, error) {
	// TODO support the implicit flow here, too?

	// check that the state is correct
	stateString := r.FormValue("state")
	codec, err := oauthstate.NewCodec(c.JwtSigningSecret)
	if err != nil {
		return exchangeResult{result: oauthFinishError}, err
	}

	state := &exchangeState{}
	err = codec.ParseInto(stateString, state)
	if err != nil {
		return exchangeResult{result: oauthFinishError}, err
	}

	session := c.SessionManager.Load(r)
	flows := map[string]string{}
	if err = session.GetObject("flows", &flows); err != nil {
		return exchangeResult{result: oauthFinishError}, err
	}

	authHeader := flows[state.Key]
	if authHeader == "" {
		return exchangeResult{result: oauthFinishK8sAuthRequired}, fmt.Errorf("no active oauth flow found for the state key")
	}

	// the state is ok, let's retrieve the token from the service provider
	oauthCfg := c.newOAuth2Config()
	oauthCfg.Endpoint = endpoint

	code := r.FormValue("code")

	// adding scopes to code exchange request is little out of spec, but quay wants them,
	// while other providers will just ignore this parameter
	scopeOption := oauth2.SetAuthURLParam("scope", r.FormValue("scope"))
	token, err := oauthCfg.Exchange(ctx, code, scopeOption)
	if err != nil {
		return exchangeResult{result: oauthFinishError}, err
	}
	return exchangeResult{
		exchangeState:       *state,
		result:              oauthFinishAuthenticated,
		token:               token,
		authorizationHeader: authHeader,
	}, nil
}

// syncTokenData stores the data of the token to the configured TokenStorage.
func (c commonController) syncTokenData(ctx context.Context, exchange *exchangeResult) error {
	ctx = WithAuthIntoContext(exchange.authorizationHeader, ctx)

	accessToken := &v1beta1.SPIAccessToken{}
	if err := c.K8sClient.Get(ctx, client.ObjectKey{Name: exchange.TokenName, Namespace: exchange.TokenNamespace}, accessToken); err != nil {
		return err
	}

	apiToken := v1beta1.Token{
		AccessToken:  exchange.token.AccessToken,
		TokenType:    exchange.token.TokenType,
		RefreshToken: exchange.token.RefreshToken,
		Expiry:       uint64(exchange.token.Expiry.Unix()),
	}

	return c.TokenStorage.Store(ctx, accessToken, &apiToken)
}

func logAndWriteResponse(w http.ResponseWriter, status int, msg string, err error) {
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, msg+": ", err.Error())
	zap.L().Error(msg, zap.Error(err))
}

func (c *commonController) checkIdentityHasAccess(token string, req *http.Request, state oauthstate.AnonymousOAuthState) (bool, error) {
	review := v1.SelfSubjectAccessReview{
		Spec: v1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Namespace: state.TokenNamespace,
				Verb:      "create",
				Group:     v1beta1.GroupVersion.Group,
				Version:   v1beta1.GroupVersion.Version,
				Resource:  "spiaccesstokendataupdates",
			},
		},
	}

	ctx := WithAuthIntoContext(token, req.Context())

	if err := c.K8sClient.Create(ctx, &review); err != nil {
		return false, err
	}

	zap.L().Debug("self subject review result", zap.Stringer("review", &review))
	return review.Status.Allowed, nil
}

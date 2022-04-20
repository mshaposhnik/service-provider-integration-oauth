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
	"github.com/mshaposhnik/service-provider-integration-operator/pkg/spi-shared/config"
	"github.com/mshaposhnik/service-provider-integration-operator/pkg/spi-shared/tokenstorage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// Controller implements the OAuth flow. There are specific implementations for each service provider type. These
// are usually instances of the commonController with service-provider-specific configuration.
type Controller interface {
	// Authenticate handles the initial OAuth request. It should validate that the request is authenticated in Kubernetes
	// compose the authenticated OAuth state and return a redirect to the service-provider OAuth endpoint with the state.
	Authenticate(w http.ResponseWriter, r *http.Request)

	// Callback finishes the OAuth flow. It handles the final redirect from the OAuth flow of the service provider.
	Callback(ctx context.Context, w http.ResponseWriter, r *http.Request)
}

// oauthFinishResult is an enum listing the possible results of authentication during the commonController.finishOAuthExchange
// method.
type oauthFinishResult int

const (
	oauthFinishAuthenticated oauthFinishResult = iota
	oauthFinishK8sAuthRequired
	oauthFinishError
)

// FromConfiguration is a factory function to create instances of the Controller based on the service provider
// configuration.
func FromConfiguration(fullConfig config.Configuration, spConfig config.ServiceProviderConfiguration, sessionManager *scs.Manager, cl AuthenticatingClient, storage tokenstorage.TokenStorage, redirectTemplate *template.Template) (Controller, error) {
	// use the notifying token storage to automatically inform the cluster about changes in the token storage
	ts := &tokenstorage.NotifyingTokenStorage{
		Client:       cl,
		TokenStorage: storage,
	}

	var endpoint oauth2.Endpoint

	switch spConfig.ServiceProviderType {
	case config.ServiceProviderTypeGitHub:
		endpoint = github.Endpoint
	case config.ServiceProviderTypeQuay:
		endpoint = quayEndpoint
	default:
		return nil, fmt.Errorf("not implemented yet")
	}

	return &commonController{
		Config:           spConfig,
		JwtSigningSecret: fullConfig.SharedSecret,
		K8sClient:        cl,
		TokenStorage:     ts,
		Endpoint:         endpoint,
		BaseUrl:          fullConfig.BaseUrl,
		SessionManager:   sessionManager,
		RedirectTemplate: redirectTemplate,
	}, nil
}

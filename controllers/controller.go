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
	"net/http"
	"spi-oauth/config"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type Controller interface {
	Authenticate(w http.ResponseWriter, r *http.Request)
	Callback(ctx context.Context, w http.ResponseWriter, r *http.Request)
}

func FromConfiguration(configuration config.ServiceProviderConfiguration) (Controller, error) {
	switch configuration.ServiceProviderType {
	case config.ServiceProviderTypeGitHub:
		return &GitHubController{Config: configuration}, nil
	case config.ServiceProviderTypeQuay:
		return &QuayController{Config: configuration}, nil
	}
	return nil, fmt.Errorf("not implemented yet")
}

func newOAuth2Config(cfg *config.ServiceProviderConfiguration) oauth2.Config {
	return oauth2.Config{
		ClientID:     cfg.ClientId,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectUrl,
	}
}

func commonAuthenticate(w http.ResponseWriter, r *http.Request, cfg *config.ServiceProviderConfiguration, endpoint oauth2.Endpoint) {
	oauthCfg := newOAuth2Config(cfg)
	oauthCfg.Endpoint = endpoint
	oauthCfg.Scopes = strings.Split(r.FormValue("scopes"), ",")

	state := r.FormValue("state")
	url := oauthCfg.AuthCodeURL(state)

	http.Redirect(w, r, url, http.StatusFound)
}

func finishOAuthExchange(ctx context.Context, r *http.Request, cfg *config.ServiceProviderConfiguration, endpoint oauth2.Endpoint) (*oauth2.Token, error) {
	oauthCfg := newOAuth2Config(cfg)
	oauthCfg.Endpoint = endpoint

	code := r.FormValue("code")

	return oauthCfg.Exchange(ctx, code)
}

func logAndWriteResponse(w http.ResponseWriter, msg string, err error) {
	_, _ = fmt.Fprintf(w, msg+": ", err.Error())
	zap.L().Error(msg, zap.Error(err))
}

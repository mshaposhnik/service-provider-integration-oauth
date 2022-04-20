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
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	api "github.com/mshaposhnik/service-provider-integration-operator/api/v1beta1"
	"github.com/mshaposhnik/service-provider-integration-operator/pkg/spi-shared/tokenstorage"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type TokenUploader struct {
	K8sClient client.Client
	Storage   tokenstorage.TokenStorage
}

func (u *TokenUploader) Handle(r *http.Request) error {
	ctx, err := WithAuthFromRequestIntoContext(r, r.Context())
	if err != nil {
		return err
	}

	vars := mux.Vars(r)

	tokenObjectName := vars["name"]
	tokenObjectNamespace := vars["namespace"]

	token := &api.SPIAccessToken{}
	if err := u.K8sClient.Get(ctx, client.ObjectKey{Name: tokenObjectName, Namespace: tokenObjectNamespace}, token); err != nil {
		return err
	}

	data := &api.Token{}
	if err := json.NewDecoder(r.Body).Decode(data); err != nil {
		return err
	}

	return u.Storage.Store(ctx, token, data)
}

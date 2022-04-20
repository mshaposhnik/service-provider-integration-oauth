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
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/mshaposhnik/service-provider-integration-operator/api/v1beta1"
	"github.com/mshaposhnik/service-provider-integration-operator/pkg/spi-shared/tokenstorage"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestTokenUploader_Handle(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(v1beta1.AddToScheme(scheme))

	router := mux.NewRouter()

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&v1beta1.SPIAccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "token",
				Namespace: "default",
			},
		},
	).Build()

	strg := tokenstorage.NotifyingTokenStorage{
		Client: cl,
		TokenStorage: tokenstorage.TestTokenStorage{
			StoreImpl: func(ctx context.Context, token *v1beta1.SPIAccessToken, data *v1beta1.Token) error {
				return nil
			},
		},
	}

	uploader := TokenUploader{
		K8sClient: cl,
		Storage:   strg,
	}

	router.NewRoute().Path("/token/{namespace}/{name}").HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.NoError(t, uploader.Handle(request))
	}).Methods("POST")

	wrt := httptest.ResponseRecorder{}
	req, err := http.NewRequest("POST", "/token/default/token", bytes.NewBuffer([]byte(`{"access_token": "42"}`)))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer kachny")
	router.ServeHTTP(&wrt, req)

	token := &v1beta1.SPIAccessToken{}
	assert.NoError(t, cl.Get(context.TODO(), client.ObjectKey{Name: "token", Namespace: "default"}, token))
}

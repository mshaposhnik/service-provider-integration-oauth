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
	"fmt"
	"html"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/alexedwards/scs"
	"github.com/alexedwards/scs/stores/memstore"

	"github.com/mshaposhnik/service-provider-integration-operator/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/mshaposhnik/service-provider-integration-operator/pkg/spi-shared/oauthstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/go-jose/go-jose/v3/json"
	"github.com/mshaposhnik/service-provider-integration-operator/pkg/spi-shared/config"
	"golang.org/x/oauth2"
)

var _ = Describe("Controller", func() {

	prepareAnonymousState := func() string {
		codec, err := oauthstate.NewCodec([]byte("secret"))
		Expect(err).NotTo(HaveOccurred())

		ret, err := codec.Encode(&oauthstate.AnonymousOAuthState{
			TokenName:           "mytoken",
			TokenNamespace:      IT.Namespace,
			IssuedAt:            time.Now().Unix(),
			Scopes:              []string{"a", "b"},
			ServiceProviderType: "My_Special_SP",
			ServiceProviderUrl:  "https://special.sp",
		})
		Expect(err).NotTo(HaveOccurred())
		return ret
	}

	grabK8sToken := func(g Gomega) string {
		var secrets *corev1.SecretList

		g.Eventually(func(gg Gomega) {
			var err error
			secrets, err = IT.Clientset.CoreV1().Secrets(IT.Namespace).List(context.TODO(), metav1.ListOptions{})
			gg.Expect(err).NotTo(HaveOccurred())
			gg.Expect(secrets.Items).NotTo(BeEmpty())
		}).Should(Succeed())

		for _, s := range secrets.Items {
			if s.Annotations["kubernetes.io/service-account.name"] == "default" {
				return string(s.Data["token"])
			}
		}

		Fail("Could not find the token of the default service account in the test namespace", 1)
		return ""
	}

	prepareController := func(g Gomega) *commonController {
		tmpl, err := template.ParseFiles("../static/redirect_notice.html")
		g.Expect(err).NotTo(HaveOccurred())

		return &commonController{
			Config: config.ServiceProviderConfiguration{
				ClientId:            "clientId",
				ClientSecret:        "clientSecret",
				ServiceProviderType: config.ServiceProviderTypeGitHub,
			},
			JwtSigningSecret: []byte("secret"),
			K8sClient:        IT.Client,
			TokenStorage:     IT.TokenStorage,
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://special.sp/login",
				TokenURL:  "https://special.sp/toekn",
				AuthStyle: oauth2.AuthStyleAutoDetect,
			},
			BaseUrl:          "https://spi.on.my.machine",
			SessionManager:   scs.NewManager(memstore.New(1000000 * time.Hour)),
			RedirectTemplate: tmpl,
		}
	}

	authenticateFlow := func(g Gomega) (*commonController, *httptest.ResponseRecorder) {
		token := grabK8sToken(g)

		// This is the setup for the HTTP call to /github/authenticate
		req := httptest.NewRequest("GET", fmt.Sprintf("/?state=%s", prepareAnonymousState()), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		c := prepareController(g)

		c.Authenticate(res, req)

		return c, res
	}

	getRedirectUrlFromAuthenticateResponse := func(g Gomega, res *httptest.ResponseRecorder) *url.URL {
		body, err := ioutil.ReadAll(res.Result().Body)
		g.Expect(err).NotTo(HaveOccurred())
		re, err := regexp.Compile("<meta http-equiv = \"refresh\" content = \"2; url=([^\"]+)\"")
		g.Expect(err).NotTo(HaveOccurred())
		matches := re.FindSubmatch(body)
		g.Expect(matches).To(HaveLen(2))

		unescaped := html.UnescapeString(string(matches[1]))

		redirect, err := url.Parse(unescaped)
		g.Expect(err).NotTo(HaveOccurred())
		return redirect
	}

	It("additionally accepts data in POST", func() {
		token := grabK8sToken(Default)

		// This is the setup for the HTTP call to /github/authenticate
		req := httptest.NewRequest("POST", "/", nil)
		req.Form = url.Values{}
		req.Form.Set("state", prepareAnonymousState())
		req.Form.Set("k8s_token", token)
		res := httptest.NewRecorder()

		c := prepareController(Default)

		c.Authenticate(res, req)
		Expect(res.Code).To(Equal(http.StatusOK))
	})

	It("redirects to SP OAuth URL with state and scopes", func() {
		_, res := authenticateFlow(Default)

		Expect(res.Code).To(Equal(http.StatusOK))

		redirect := getRedirectUrlFromAuthenticateResponse(Default, res)

		Expect(redirect.Scheme).To(Equal("https"))
		Expect(redirect.Host).To(Equal("special.sp"))
		Expect(redirect.Path).To(Equal("/login"))
		Expect(redirect.Query().Get("client_id")).To(Equal("clientId"))
		Expect(redirect.Query().Get("redirect_uri")).To(Equal("https://spi.on.my.machine/github/callback"))
		Expect(redirect.Query().Get("response_type")).To(Equal("code"))
		Expect(redirect.Query().Get("state")).NotTo(BeEmpty())
		Expect(redirect.Query().Get("scope")).To(Equal("a b"))
		Expect(res.Result().Cookies()).NotTo(BeEmpty())
	})

	When("OAuth initiated", func() {
		BeforeEach(func() {
			Expect(IT.Client.Create(IT.Context, &v1beta1.SPIAccessToken{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "mytoken",
					Namespace: IT.Namespace,
				},
				Spec: v1beta1.SPIAccessTokenSpec{
					ServiceProviderUrl: "https://special.sp",
				},
			})).To(Succeed())

			t := &v1beta1.SPIAccessToken{}
			Eventually(func() error {
				return IT.Client.Get(IT.Context, client.ObjectKey{Name: "mytoken", Namespace: IT.Namespace}, t)
			}).Should(Succeed())
		})

		AfterEach(func() {
			t := &v1beta1.SPIAccessToken{}
			Expect(IT.Client.Get(IT.Context, client.ObjectKey{Name: "mytoken", Namespace: IT.Namespace}, t)).To(Succeed())
			Expect(IT.Client.Delete(IT.Context, t)).To(Succeed())
			Eventually(func() error {
				return IT.Client.Get(IT.Context, client.ObjectKey{Name: "mytoken", Namespace: IT.Namespace}, t)
			}).ShouldNot(Succeed())
		})

		It("exchanges the code for token", func() {
			// this may fail at times because we're updating the token during the flow and we may intersect with
			// operator's work. Wrapping it in an Eventually block makes sure we retry on such occurrences. Note that
			// the need for this will disappear once we don't update the token anymore from OAuth service (which is
			// the plan).
			Eventually(func(g Gomega) {
				controller, res := authenticateFlow(g)

				redirect := getRedirectUrlFromAuthenticateResponse(Default, res)

				state := redirect.Query().Get("state")

				// simulate github redirecting back to our callback endpoint...
				req := httptest.NewRequest("GET", fmt.Sprintf("/?state=%s&code=123", state), nil)
				req.Header.Set("Cookie", res.Result().Cookies()[0].String())
				res = httptest.NewRecorder()

				// The callback handler will be reaching out to github to exchange the code for the token.. let's fake that
				// response...
				bakedResponse, _ := json.Marshal(oauth2.Token{
					AccessToken:  "token",
					TokenType:    "jwt",
					RefreshToken: "refresh",
					Expiry:       time.Now(),
				})
				serviceProviderReached := false
				ctx := context.WithValue(context.TODO(), oauth2.HTTPClient, &http.Client{
					Transport: fakeRoundTrip(func(r *http.Request) (*http.Response, error) {
						if strings.HasPrefix(r.URL.String(), "https://special.sp") {
							serviceProviderReached = true
							return &http.Response{
								StatusCode: 200,
								Header:     http.Header{},
								Body:       ioutil.NopCloser(bytes.NewBuffer(bakedResponse)),
								Request:    r,
							}, nil
						}

						return nil, fmt.Errorf("unexpected request to: %s", r.URL.String())
					}),
				})

				controller.Callback(ctx, res, req)
				g.Expect(res.Code).To(Equal(http.StatusFound))
				Expect(serviceProviderReached).To(BeTrue())
			}).Should(Succeed())
		})

		It("redirects to specified url", func() {
			// this may fail at times because we're updating the token during the flow and we may intersect with
			// operator's work. Wrapping it in an Eventually block makes sure we retry on such occurrences. Note that
			// the need for this will disappear once we don't update the token anymore from OAuth service (which is
			// the plan).
			Eventually(func(g Gomega) {
				controller, res := authenticateFlow(g)

				redirect := getRedirectUrlFromAuthenticateResponse(Default, res)

				state := redirect.Query().Get("state")

				// simulate github redirecting back to our callback endpoint...
				req := httptest.NewRequest("GET", fmt.Sprintf("/?state=%s&code=123&redirect_after_login=https://redirect.to?foo=bar", state), nil)
				req.Header.Set("Cookie", res.Result().Cookies()[0].String())
				res = httptest.NewRecorder()

				// The callback handler will be reaching out to github to exchange the code for the token.. let's fake that
				// response...
				bakedResponse, _ := json.Marshal(oauth2.Token{
					AccessToken:  "token",
					TokenType:    "jwt",
					RefreshToken: "refresh",
					Expiry:       time.Now(),
				})
				ctx := context.WithValue(context.TODO(), oauth2.HTTPClient, &http.Client{
					Transport: fakeRoundTrip(func(r *http.Request) (*http.Response, error) {
						if strings.HasPrefix(r.URL.String(), "https://special.sp") {
							return &http.Response{
								StatusCode: 200,
								Header:     http.Header{},
								Body:       ioutil.NopCloser(bytes.NewBuffer(bakedResponse)),
								Request:    r,
							}, nil
						}

						return nil, fmt.Errorf("unexpected request to: %s", r.URL.String())
					}),
				})

				controller.Callback(ctx, res, req)

				g.Expect(res.Code).To(Equal(http.StatusFound))
				g.Expect(res.Result().Header.Get("Location")).To(Equal("https://redirect.to?foo=bar"))
			}).Should(Succeed())
		})
	})
})

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

package main

import (
	stderrors "errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mshaposhnik/service-provider-integration-operator/api/v1beta1"
	authz "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"

	certutil "k8s.io/client-go/util/cert"

	"github.com/alexedwards/scs"
	"github.com/alexedwards/scs/stores/memstore"
	"github.com/mshaposhnik/service-provider-integration-operator/pkg/spi-shared/tokenstorage"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/alexflint/go-arg"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/mshaposhnik/service-provider-integration-operator/pkg/spi-shared/config"
	"github.com/redhat-appstudio/service-provider-integration-oauth/controllers"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type cliArgs struct {
	ConfigFile string `arg:"-c, --config-file, env" default:"/etc/spi/config.yaml" help:"The location of the configuration file"`
	Port       int    `arg:"-p, --port, env" default:"8000" help:"The port to listen on"`
	DevMode    bool   `arg:"-d, --dev-mode, env" default:"false" help:"use dev-mode logging"`
	KubeConfig string `arg:"-k, --kubeconfig, env" default:"" help:""`
	// snake-case used because of environment variable naming (API_SERVER and API_SERVER_CA_PATH)
	Api_Server         string `arg:"-a, --api-server, env" default:"" help:"host:port of the Kubernetes API server to use when handling HTTP requests"`
	Api_Server_CA_Path string `arg:"-t, --ca-path, env" default:"" help:"the path to the CA certificate to use when connecting to the Kubernetes API server"`
}

type viewData struct {
	Title   string
	Message string
}

func OkHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func CallbackSuccessHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/callback_success.html")
}

func CallbackErrorHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	errorMsg := q.Get("error")
	errorDescription := q.Get("error_description")
	data := viewData{
		Title:   errorMsg,
		Message: errorDescription,
	}
	tmpl, _ := template.ParseFiles("static/callback_error.html")

	err := tmpl.Execute(w, data)
	if err == nil {
		w.WriteHeader(http.StatusOK)
	} else {
		zap.L().Error("failed to process template: %s", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf("Error response returned to OAuth callback: %s. Message: %s ", errorMsg, errorDescription)))
	}

}

func handleUpload(uploader *controllers.TokenUploader) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := uploader.Handle(r); err != nil {
			if status := errors.APIStatus(nil); stderrors.As(err, &status) {
				w.WriteHeader(int(status.Status().Code))
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
			zap.L().Error("error handling token upload", zap.Error(err))
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func main() {
	args := cliArgs{}
	arg.MustParse(&args)

	var loggerConfig zap.Config
	if args.DevMode {
		loggerConfig = zap.NewDevelopmentConfig()
	} else {
		loggerConfig = zap.NewProductionConfig()
	}
	loggerConfig.OutputPaths = []string{"stdout"}
	loggerConfig.ErrorOutputPaths = []string{"stdout"}
	logger, err := loggerConfig.Build()
	if err != nil {
		// there's nothing we can do about the error to print to stderr, but the linter requires us to at least pretend
		_, _ = fmt.Fprintf(os.Stderr, "failed to initialize logging: %s", err.Error())
		os.Exit(1)
	}
	defer func() {
		// linter says we need to handle the error from this call, but this is called after main with no way of us doing
		// anything about the error. So the anon func and this assignment is here purely to make the linter happy.
		_ = logger.Sync()
	}()

	undo := zap.ReplaceGlobals(logger)
	defer undo()

	cfg, err := config.LoadFrom(args.ConfigFile)
	if err != nil {
		zap.L().Error("failed to initialize the configuration", zap.Error(err))
		os.Exit(1)
	}

	kubeConfig, err := kubernetesConfig(&args)
	if err != nil {
		zap.L().Error("failed to create kubernetes configuration", zap.Error(err))
		os.Exit(1)
	}

	start(cfg, args.Port, kubeConfig, args.DevMode)
}

func start(cfg config.Configuration, port int, kubeConfig *rest.Config, devmode bool) {
	router := mux.NewRouter()

	if devmode {
		kubeConfig.Insecure = true
	}

	// we can't use the default dynamic rest mapper, because we don't have a token that would enable us to connect
	// to the cluster just yet. Therefore, we need to list all the resources that we are ever going to query using our
	// client here thus making the mapper not reach out to the target cluster at all.
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{})
	mapper.Add(authz.SchemeGroupVersion.WithKind("SelfSubjectAccessReview"), meta.RESTScopeRoot)
	mapper.Add(v1beta1.GroupVersion.WithKind("SPIAccessToken"), meta.RESTScopeNamespace)
	mapper.Add(v1beta1.GroupVersion.WithKind("SPIAccessTokenDataUpdate"), meta.RESTScopeNamespace)

	cl, err := controllers.CreateClient(kubeConfig, client.Options{
		Mapper: mapper,
	})

	if err != nil {
		zap.L().Error("failed to create kubernetes client", zap.Error(err))
		return
	}

	strg, err := tokenstorage.NewVaultStorage("spi-oauth", cfg.VaultHost, cfg.ServiceAccountTokenFilePath, devmode)
	if err != nil {
		zap.L().Error("failed to create token storage interface", zap.Error(err))
		return
	}

	tokenUploader := controllers.TokenUploader{
		K8sClient: cl,
		Storage: tokenstorage.NotifyingTokenStorage{
			Client:       cl,
			TokenStorage: strg,
		},
	}

	// the session has 15 minutes timeout and stale sessions are cleaned every 5 minutes
	sessionManager := scs.NewManager(memstore.New(5 * time.Minute))
	sessionManager.Name("appstudio_spi_session")
	sessionManager.IdleTimeout(15 * time.Minute)

	//static routes first
	router.HandleFunc("/health", OkHandler).Methods("GET")
	router.HandleFunc("/ready", OkHandler).Methods("GET")
	router.HandleFunc("/callback_success", CallbackSuccessHandler).Methods("GET")
	router.NewRoute().Path("/{type}/callback").Queries("error", "", "error_description", "").HandlerFunc(CallbackErrorHandler)
	router.NewRoute().Path("/token/{namespace}/{name}").HandlerFunc(handleUpload(&tokenUploader)).Methods("POST")

	redirectTpl, err := template.ParseFiles("static/redirect_notice.html")
	if err != nil {
		zap.L().Error("failed to parse the redirect notice HTML template", zap.Error(err))
		return
	}

	for _, sp := range cfg.ServiceProviders {
		controller, err := controllers.FromConfiguration(cfg, sp, sessionManager, cl, strg, redirectTpl)
		if err != nil {
			zap.L().Error("failed to initialize controller: %s", zap.Error(err))
		}

		prefix := strings.ToLower(string(sp.ServiceProviderType))

		router.Handle(fmt.Sprintf("/%s/authenticate", prefix), http.HandlerFunc(controller.Authenticate)).Methods("GET", "POST")
		router.Handle(fmt.Sprintf("/%s/callback", prefix), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			controller.Callback(r.Context(), w, r)
		})).Methods("GET")
	}

	zap.L().Info("Starting the server", zap.Int("port", port))
	err = http.ListenAndServe(fmt.Sprintf(":%d", port), router)
	if err != nil {
		zap.L().Error("failed to start the HTTP server", zap.Error(err))
	}
}

func kubernetesConfig(args *cliArgs) (*rest.Config, error) {
	if args.KubeConfig != "" {
		return clientcmd.BuildConfigFromFlags("", args.KubeConfig)
	} else if args.Api_Server != "" {
		// here we're essentially replicating what is done in rest.InClusterConfig() but we're using our own
		// configuration - this is to support going through an alternative API server to the one we're running with...
		// Note that we're NOT adding the Token or the TokenFile to the configuration here. This is supposed to be
		// handled on per-request basis...
		cfg := rest.Config{}

		apiServerUrl, err := url.Parse(args.Api_Server)
		if err != nil {
			return nil, err
		}

		cfg.Host = "https://" + net.JoinHostPort(apiServerUrl.Hostname(), apiServerUrl.Port())

		tlsConfig := rest.TLSClientConfig{}

		if args.Api_Server_CA_Path != "" {
			// rest.InClusterConfig is doing this most possibly only for early error handling so let's do the same
			if _, err := certutil.NewPool(args.Api_Server_CA_Path); err != nil {
				return nil, fmt.Errorf("expected to load root CA config from %s, but got err: %v", args.Api_Server_CA_Path, err)
			} else {
				tlsConfig.CAFile = args.Api_Server_CA_Path
			}
		}

		cfg.TLSClientConfig = tlsConfig

		return &cfg, nil
	} else {
		return rest.InClusterConfig()
	}
}

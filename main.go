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
	"context"
	stderrors "errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
	"github.com/alexflint/go-arg"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/redhat-appstudio/service-provider-integration-operator/api/v1beta1"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/config"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/tokenstorage"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zapio"
	authz "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/redhat-appstudio/service-provider-integration-oauth/controllers"
)

type cliArgs struct {
	ConfigFile      string `arg:"-c, --config-file, env" default:"/etc/spi/config.yaml" help:"The location of the configuration file"`
	Addr            string `arg:"-a, --addr, env" default:"0.0.0.0:8000" help:"Address to listen on"`
	AllowedOrigins  string `arg:"-o, --allowed-origins, env" default:"https://console.dev.redhat.com,https://prod.foo.redhat.com:1337" help:"Comma-separated list of domains allowed for cross-domain requests"`
	DevMode         bool   `arg:"-d, --dev-mode, env" default:"false" help:"use dev-mode logging"`
	KubeConfig      string `arg:"-k, --kubeconfig, env" default:"" help:""`
	ApiServer       string `arg:"-a, --api-server, env:API_SERVER" default:"" help:"host:port of the Kubernetes API server to use when handling HTTP requests"`
	ApiServerCAPath string `arg:"-t, --ca-path, env:API_SERVER_CA_PATH" default:"" help:"the path to the CA certificate to use when connecting to the Kubernetes API server"`
}

func (args *cliArgs) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("config-file", args.ConfigFile)
	enc.AddString("addr", args.Addr)
	enc.AddString("allowed-origins", args.AllowedOrigins)
	enc.AddBool("dev-mode", args.DevMode)
	enc.AddString("kubeconfig", args.KubeConfig)
	enc.AddString("api-server", args.ApiServer)
	enc.AddString("ca-path", args.ApiServerCAPath)
	return nil
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

	zap.L().Info("Starting OAuth service with environment", zap.Strings("env", os.Environ()), zap.Object("configuration", &args))

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

	start(cfg, args.Addr, strings.Split(args.AllowedOrigins, ","), kubeConfig, args.DevMode)
}

func MiddlewareHandler(allowedOrigins []string, h http.Handler) http.Handler {
	return handlers.LoggingHandler(&zapio.Writer{Log: zap.L(), Level: zap.InfoLevel},
		handlers.CORS(handlers.AllowedOrigins(allowedOrigins),
			handlers.AllowCredentials(),
			handlers.AllowedHeaders([]string{"Accept", "Accept-Language", "Content-Language", "Origin", "Authorization"}))(h))
}

func start(cfg config.Configuration, addr string, allowedOrigins []string, kubeConfig *rest.Config, devmode bool) {
	router := mux.NewRouter()

	// insecure mode only allowed when the trusted root certificate is not specified...
	if devmode && kubeConfig.TLSClientConfig.CAFile == "" {
		kubeConfig.Insecure = true
	}

	// we can't use the default dynamic rest mapper, because we don't have a token that would enable us to connect
	// to the cluster just yet. Therefore, we need to list all the resources that we are ever going to query using our
	// client here thus making the mapper not reach out to the target cluster at all.
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{})
	mapper.Add(authz.SchemeGroupVersion.WithKind("SelfSubjectAccessReview"), meta.RESTScopeRoot)
	//	mapper.Add(auth.SchemeGroupVersion.WithKind("TokenReview"), meta.RESTScopeRoot)
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
	sessionManager := scs.New()
	sessionManager.Store = memstore.NewWithCleanupInterval(5 * time.Minute)
	sessionManager.IdleTimeout = 15 * time.Minute
	sessionManager.Cookie.Name = "appstudio_spi_session"
	sessionManager.Cookie.SameSite = http.SameSiteNoneMode
	sessionManager.Cookie.Secure = true
	authenticator := controllers.NewAuthenticator(sessionManager, cl)
	//static routes first
	router.HandleFunc("/health", OkHandler).Methods("GET")
	router.HandleFunc("/ready", OkHandler).Methods("GET")
	router.HandleFunc("/callback_success", CallbackSuccessHandler).Methods("GET")
	router.HandleFunc("/login", authenticator.Login).Methods("POST")
	router.NewRoute().Path("/{type}/callback").Queries("error", "", "error_description", "").HandlerFunc(CallbackErrorHandler)
	router.NewRoute().Path("/token/{namespace}/{name}").HandlerFunc(handleUpload(&tokenUploader)).Methods("POST")

	redirectTpl, err := template.ParseFiles("static/redirect_notice.html")
	if err != nil {
		zap.L().Error("failed to parse the redirect notice HTML template", zap.Error(err))
		return
	}

	for _, sp := range cfg.ServiceProviders {
		if !sp.OAuthConfigured() {
			zap.L().Warn("provider OAuth configuration not found. only manual token upload will be available", zap.String("type", string(sp.ServiceProviderType)))
			continue
		}

		zap.L().Debug("initializing service provider controller", zap.String("type", string(sp.ServiceProviderType)), zap.String("url", sp.ServiceProviderBaseUrl))

		controller, err := controllers.FromConfiguration(cfg, sp, authenticator, cl, strg, redirectTpl)
		if err != nil {
			zap.L().Error("failed to initialize controller: %s", zap.Error(err))
		}

		prefix := strings.ToLower(string(sp.ServiceProviderType))

		router.Handle(fmt.Sprintf("/%s/authenticate", prefix), http.HandlerFunc(controller.Authenticate)).Methods("GET", "POST")
		router.Handle(fmt.Sprintf("/%s/callback", prefix), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			controller.Callback(r.Context(), w, r)
		})).Methods("GET")
	}

	zap.L().Info("Starting the server", zap.String("Addr", addr))
	server := &http.Server{
		Addr: addr,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      sessionManager.LoadAndSave(MiddlewareHandler(allowedOrigins, router)),
	}

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		if err := server.ListenAndServe(); err != nil {
			zap.L().Error("failed to start the HTTP server", zap.Error(err))
		}
	}()

	// Setting up signal capturing
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// Waiting for SIGINT (kill -2)
	<-stop

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	if err := server.Shutdown(ctx); err != nil {
		zap.L().Fatal("OAuth server shutdown failed", zap.Error(err))
	}
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	zap.L().Info("OAuth server exited properly")
	os.Exit(0)
}

func kubernetesConfig(args *cliArgs) (*rest.Config, error) {
	if args.KubeConfig != "" {
		return clientcmd.BuildConfigFromFlags("", args.KubeConfig)
	} else if args.ApiServer != "" {
		// here we're essentially replicating what is done in rest.InClusterConfig() but we're using our own
		// configuration - this is to support going through an alternative API server to the one we're running with...
		// Note that we're NOT adding the Token or the TokenFile to the configuration here. This is supposed to be
		// handled on per-request basis...
		cfg := rest.Config{}

		apiServerUrl, err := url.Parse(args.ApiServer)
		if err != nil {
			return nil, err
		}

		cfg.Host = "https://" + net.JoinHostPort(apiServerUrl.Hostname(), apiServerUrl.Port())

		tlsConfig := rest.TLSClientConfig{}

		if args.ApiServerCAPath != "" {
			// rest.InClusterConfig is doing this most possibly only for early error handling so let's do the same
			if _, err := certutil.NewPool(args.ApiServerCAPath); err != nil {
				return nil, fmt.Errorf("expected to load root CA config from %s, but got err: %v", args.ApiServerCAPath, err)
			} else {
				tlsConfig.CAFile = args.ApiServerCAPath
			}
		}

		cfg.TLSClientConfig = tlsConfig

		return &cfg, nil
	} else {
		return rest.InClusterConfig()
	}
}

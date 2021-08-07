package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cristalhq/aconfig"
	"github.com/xenitab/go-oidc-middleware/oidchttp"
	"golang.org/x/sync/errgroup"
)

func main() {
	cfg, err := newConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	err = run(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "application returned error: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	g, ctx := errgroup.WithContext(ctx)
	stopChan := make(chan os.Signal, 2)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGPIPE)

	h := getClaimsHandler()
	oidcHandler := oidchttp.New(h, &oidchttp.Options{
		Issuer:                     cfg.Issuer,
		FallbackSignatureAlgorithm: cfg.FallbackSignatureAlgorithm,
		RequiredClaims: map[string]interface{}{
			"cid": cfg.ClientID,
		},
	})

	addr := net.JoinHostPort(cfg.Address, fmt.Sprintf("%d", cfg.Port))

	srv := http.Server{
		Addr:    addr,
		Handler: oidcHandler,
	}

	g.Go(func() error {
		fmt.Printf("listening on: %s\n", addr)
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	})

	select {
	case <-stopChan:
	case <-ctx.Done():
	}

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	g.Go(func() error {
		err := srv.Shutdown(shutdownCtx)
		if err != nil {
			fmt.Println("failed to shutdown gracefully")
			return err
		}

		fmt.Println("succeeded to shutdown gracefully")
		return nil
	})

	return g.Wait()
}

func getClaimsHandler() http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(oidchttp.ClaimsContextKey).(map[string]interface{})
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(claims)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	return http.HandlerFunc(fn)
}

type config struct {
	Address                    string `flag:"address" env:"ADDRESS" default:"127.0.0.1" usage:"address webserver will listen to"`
	Port                       int    `flag:"port" env:"PORT" default:"8080" usage:"port webserver will listen to"`
	Issuer                     string `flag:"token-issuer" env:"TOKEN_ISSUER" usage:"the oidc issuer url for tokens"`
	ClientID                   string `flag:"client-id" env:"CLIENT_ID" usage:"the client id (cid) that tokens need to contain"`
	FallbackSignatureAlgorithm string `flag:"fallback-signature-algorithm" env:"FALLBACK_SIGNATURE_ALGORITHM" default:"RS256" usage:"if the issue jwks doesn't contain key alg, use the following signature algorithm to verify the signature of the tokens"`
}

func newConfig() (config, error) {
	var cfg config

	loader := aconfig.LoaderFor(&cfg, aconfig.Config{
		SkipDefaults: false,
		SkipFiles:    true,
		SkipEnv:      false,
		SkipFlags:    false,
		EnvPrefix:    "",
		FlagPrefix:   "",
		Files:        []string{},
		FileDecoders: map[string]aconfig.FileDecoder{},
	})

	err := loader.Load()
	if err != nil {
		return config{}, err
	}

	return cfg, nil
}

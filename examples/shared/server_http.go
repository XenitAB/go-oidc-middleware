package shared

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

	"github.com/xenitab/go-oidc-middleware/optest"
	"github.com/xenitab/go-oidc-middleware/options"
	"golang.org/x/sync/errgroup"
)

func NewHttpClaimsHandler() http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(options.DefaultClaimsContextKeyName).(*optest.TestUser)
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

func RunHttp(oidcHandler http.Handler, address string, port int) error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	g, ctx := errgroup.WithContext(ctx)
	stopChan := make(chan os.Signal, 2)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGPIPE)

	addr := net.JoinHostPort(address, fmt.Sprintf("%d", port))

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

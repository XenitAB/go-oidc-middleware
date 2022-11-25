package shared

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/sync/errgroup"
)

func newFiberClaimsHandler[T any]() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("claims").(T)
		if !ok {
			return c.SendStatus(fiber.StatusUnauthorized)
		}

		return c.JSON(claims)
	}
}

func RunFiber[T any](oidcHandler fiber.Handler, address string, port int) error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	g, ctx := errgroup.WithContext(ctx)
	stopChan := make(chan os.Signal, 2)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGPIPE)

	addr := net.JoinHostPort(address, fmt.Sprintf("%d", port))

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	app.Use(oidcHandler)

	claimsHandler := newFiberClaimsHandler[T]()
	app.Get("/", claimsHandler)

	g.Go(func() error {
		fmt.Printf("listening on: %s\n", addr)
		return app.Listen(addr)
	})

	select {
	case <-stopChan:
	case <-ctx.Done():
	}

	cancel()

	g.Go(func() error {
		err := app.Shutdown()
		if err != nil {
			fmt.Println("failed to shutdown gracefully")
			return err
		}

		fmt.Println("succeeded to shutdown gracefully")
		return nil
	})

	return g.Wait()
}

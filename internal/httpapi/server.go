package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/nsmithuk/local-kms/internal/kms"
)

type Server struct {
	ksmService *kms.KmsService
	kmsHanders map[string]kmsHandler
}

func NewServer(kmsService *kms.KmsService) *Server {
	s := &Server{
		ksmService: kmsService,
		kmsHanders: buildDispatcher(kmsService),
	}
	return s
}

func (s *Server) Start(ctx context.Context, port string) error {

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: s,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	slog.Info(fmt.Sprintf("Local KMS started on 0.0.0.0:%s", port))

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

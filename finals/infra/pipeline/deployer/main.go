package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// per COMMON.md: keep /tmp quota small
	if os.Getenv("GOTMPDIR") == "" {
		os.Setenv("GOTMPDIR", "/home/abu/.cache/go-tmp")
	}

	cfg := mustLoadConfig()
	st := mustLoadState(cfg.StateFile)

	hookMux := http.NewServeMux()
	hookMux.HandleFunc("/hook", makeWebhookHandler(cfg, st))
	hookMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})

	apiMux := http.NewServeMux()
	registerAPIRoutes(apiMux, cfg, st)

	hookSrv := &http.Server{
		Addr:        cfg.WebhookAddr,
		Handler:     hookMux,
		ReadTimeout: 15 * time.Second,
	}
	apiSrv := &http.Server{
		Addr:        cfg.APIAddr,
		Handler:     authMiddleware(apiMux, cfg.BoxToken),
		ReadTimeout: 60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go runPipelineWorker(cfg, st)
	go runAutoRevert(cfg, st)
	go runModePoller(cfg, st)

	go func() {
		if err := hookSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("webhook: %v", err)
		}
	}()
	go func() {
		if err := apiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("api: %v", err)
		}
	}()

	log.Printf("h7d ready team=%d webhook=%s api=%s", cfg.Team, cfg.WebhookAddr, cfg.APIAddr)
	<-ctx.Done()

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hookSrv.Shutdown(shutCtx)
	apiSrv.Shutdown(shutCtx)
	st.flush()
	log.Printf("h7d stopped")
}

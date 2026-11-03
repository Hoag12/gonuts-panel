// Command gonuts-panel serves the GoNuts self-hosted panel: the Discord
// sign-in pages, the dashboard API, the relayed client panel, and the mod's
// WebSocket, pairing, and credential-check endpoints.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"gonutspanel/internal/auth"
	"gonutspanel/internal/config"
	"gonutspanel/internal/relay"
	"gonutspanel/internal/store"
	"gonutspanel/internal/web"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hub := relay.NewHub(st, relay.Options{
		HeartbeatSeconds:     20,
		TelemetryMinInterval: time.Second,
		MaxMessageBytes:      32768,
		PanelTimeout:         15 * time.Second,
		MaxPanelInFlight:     8,
	})
	go hub.Start(ctx)
	defer hub.Stop()

	d := auth.NewDiscord(cfg)
	// The callback path is owned by the web layer; PUBLIC_BASE_URL is the only
	// place the externally visible origin comes from.
	d.RedirectURI = cfg.PublicBaseURL + "/auth/callback"

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           web.New(cfg, st, hub, d).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	log.Printf("gonuts-panel listening on %s", cfg.Addr)

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	// Stop the relay first so its last coalesced telemetry frame is flushed,
	// then persist the final state. Both calls are safe to repeat on the
	// deferred cleanup path above.
	hub.Stop()
	_ = st.SaveNow()
}

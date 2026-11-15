// Command gonuts-panel serves the GoNuts self-hosted panel: the Discord
// sign-in pages, the dashboard API, the relayed client panel, and the mod's
// WebSocket, pairing, and credential-check endpoints.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
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
	// -hash-password runs before config.Load so generating a hash needs no
	// valid panel configuration. Only the hash is printed; the password itself
	// is never echoed or logged.
	hashPassword := flag.String("hash-password", "", "print a PBKDF2 hash for this password for GONUTS_LOCAL_PASSWORD_HASH, then exit")
	flag.Parse()
	if *hashPassword != "" {
		hash, err := auth.HashPassword(*hashPassword, 0)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hash)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	// A malformed hash fails every sign-in without any other symptom, so treat
	// it as a startup error before the listener opens. The value itself is
	// never logged.
	if cfg.LocalPasswordHash != "" && !auth.ValidPasswordHash(cfg.LocalPasswordHash) {
		log.Fatal("gonuts-panel: GONUTS_LOCAL_PASSWORD_HASH is malformed; regenerate it with -hash-password")
	}
	var st *store.Store
	if cfg.RemoteStateURL != "" {
		sink, sinkErr := store.NewPostgresSink(cfg.RemoteStateURL)
		if sinkErr != nil {
			log.Printf("remote state unavailable, using local disk only: %v", sinkErr)
			st, err = store.Open(cfg.DataDir)
		} else {
			st, err = store.OpenWithSink(cfg.DataDir, sink)
		}
	} else {
		st, err = store.Open(cfg.DataDir)
	}
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

	var d *auth.Discord
	if cfg.DiscordEnabled {
		d = auth.NewDiscord(cfg)
		// The callback path is owned by the web layer; PUBLIC_BASE_URL is the
		// only place the externally visible origin comes from.
		d.RedirectURI = cfg.PublicBaseURL + "/auth/callback"
	}

	// Every request context descends from this one, so canceling it is what
	// ends the long-lived dashboard SSE streams. http.Server.Shutdown does not
	// close active connections, so without this a single open dashboard tab
	// would make shutdown wait out the whole deadline and then cut the stream
	// off at process exit.
	base, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           web.New(cfg, st, hub, d).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return base },
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	log.Printf("gonuts-panel listening on %s", cfg.Addr)

	<-ctx.Done()
	// Stop the streams before draining so Shutdown only has finite requests
	// left to wait on.
	cancelBase()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		// A request that never finishes must not keep the process alive; close
		// the remaining connections and persist what we have.
		log.Printf("gonuts-panel: graceful shutdown: %v", err)
		_ = srv.Close()
	}
	// Stop the relay first so its last coalesced telemetry frame is flushed,
	// then persist the final state. Both calls are safe to repeat on the
	// deferred cleanup path above.
	hub.Stop()
	_ = st.SaveNow()
}

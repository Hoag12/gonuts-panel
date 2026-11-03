package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"gonutspanel/internal/config"
)

func main() {
	flag.Parse()
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	srv := &http.Server{Addr: cfg.Addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("gonuts-panel listening on %s", cfg.Addr)
	log.Fatal(srv.ListenAndServe())
}

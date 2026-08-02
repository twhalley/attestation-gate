// Command gatedemo is a deliberately boring HTTP service.
//
// The service is not the point of this repository. It exists only so that
// there is a real artefact to build, sign, attest and then admit or reject.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	// Injected at build time via -ldflags so the two image variants
	// (baseline and hardened) are distinguishable at runtime.
	version = "dev"
	variant = "unknown"
)

type status struct {
	Version string    `json:"version"`
	Variant string    `json:"variant"`
	UID     int       `json:"uid"`
	Time    time.Time `json:"time"`
}

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		// Deliberately >1024: the hardened image runs as a non-root UID and
		// cannot bind a privileged port. See GOTCHAS.md.
		addr = ":8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status{
			Version: version,
			Variant: variant,
			UID:     os.Getuid(),
			Time:    time.Now().UTC(),
		})
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("gatedemo version=%s variant=%s uid=%d listening on %s", version, variant, os.Getuid(), addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

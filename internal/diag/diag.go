// SPDX-License-Identifier: AGPL-3.0-or-later

// Package diag serves the diagnostics surface every enterprise service needs:
// /metrics (Prometheus), /healthz (liveness), /readyz (readiness). Liveness is
// "the process is up"; readiness gates on a caller-supplied check (e.g. the
// grant store is reachable) so a load balancer / k8s only routes when serving.
package diag

import (
	"context"
	"net/http"
	"time"
)

// Handler builds the diagnostics mux. metricsHandler may be nil (no /metrics);
// ready may be nil (always ready).
func Handler(metricsHandler http.Handler, ready func(ctx context.Context) error) http.Handler {
	mux := http.NewServeMux()
	if metricsHandler != nil {
		mux.Handle("/metrics", metricsHandler)
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := ready(ctx); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("not ready: " + err.Error() + "\n"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	return mux
}

// Serve runs the diagnostics HTTP server until ctx is cancelled.
func Serve(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

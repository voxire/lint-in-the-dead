package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/voxire/lint-in-the-dead/pkg/models"
	"github.com/voxire/lint-in-the-dead/services/notification-service/notifier"
)

func main() {
	listenAddr := getEnv("LISTEN_ADDR", ":8084")

	slack := notifier.NewSlack(getEnv("SLACK_WEBHOOK_URL", ""))
	email := notifier.NewEmail(
		getEnv("SMTP_HOST", ""),
		getEnv("SMTP_PORT", "587"),
		getEnv("SMTP_USER", ""),
		getEnv("SMTP_PASS", ""),
		getEnv("SMTP_FROM", "litd@example.com"),
	)
	dispatcher := notifier.NewDispatcher(slack, email)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "ok",
			"slack_enabled": slack.Enabled(),
			"email_enabled": email.Enabled(),
		})
	})

	mux.HandleFunc("POST /api/v1/notify", func(w http.ResponseWriter, r *http.Request) {
		var req models.NotificationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		go dispatcher.Dispatch(r.Context(), req)
		w.WriteHeader(http.StatusAccepted)
	})

	log.Printf("notification-service listening on %s (slack=%v email=%v)",
		listenAddr, slack.Enabled(), email.Enabled())
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatalf("notification-service: %v", err)
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

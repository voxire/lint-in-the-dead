package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/voxire/lint-in-the-dead/pkg/metrics"
	"github.com/voxire/lint-in-the-dead/pkg/models"
	"github.com/voxire/lint-in-the-dead/services/audit-service/store"
)

func main() {
	listenAddr := getEnv("LISTEN_ADDR", ":8083")
	dsn := getEnv("DATABASE_URL", "")
	secret := getEnv("SIGNING_SECRET", "changeme-32-byte-secret-key!!")

	var s store.Store
	if dsn != "" {
		pg, err := store.NewPostgres(dsn, secret)
		if err != nil {
			log.Fatalf("audit-service: postgres: %v", err)
		}
		s = pg
		log.Println("audit-service: using PostgreSQL")
	} else {
		s = store.NewMemory(secret)
		log.Println("audit-service: using in-memory store (set DATABASE_URL for persistence)")
	}

	reg := metrics.NewRegistry("audit_service")
	entriesInserted := reg.Counter("entries_inserted_total")
	entriesVerified := reg.Counter("entries_verified_total")
	verifyFailed    := reg.Counter("entries_verify_failed_total")

	mux := http.NewServeMux()

	mux.HandleFunc("GET /metrics", reg.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /api/v1/entries", func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		raw, _ := json.Marshal(payload)
		jobID, _ := payload["job_id"].(string)
		eventType, _ := payload["event_type"].(string)
		actor, _ := payload["actor"].(string)

		entry := models.AuditEntry{
			ID:        newID(),
			JobID:     jobID,
			EventType: eventType,
			Actor:     actor,
			Payload:   string(raw),
			CreatedAt: time.Now().UTC(),
		}
		if err := s.Insert(r.Context(), entry); err != nil {
			log.Printf("audit insert: %v", err)
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		entriesInserted.Inc()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(entry)
	})

	mux.HandleFunc("GET /api/v1/entries", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))
		if limit == 0 {
			limit = 50
		}
		entries, err := s.Query(r.Context(), models.AuditQuery{
			JobID:     q.Get("job_id"),
			EventType: q.Get("event_type"),
			Actor:     q.Get("actor"),
			Limit:     limit,
			Offset:    offset,
		})
		if err != nil {
			http.Error(w, "query error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	})

	mux.HandleFunc("GET /api/v1/entries/{id}/verify", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		ok, err := s.Verify(r.Context(), id)
		if err != nil {
			http.Error(w, "verify error", http.StatusInternalServerError)
			return
		}
		entriesVerified.Inc()
		if !ok {
			verifyFailed.Inc()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"id": id, "valid": ok})
	})

	log.Printf("audit-service listening on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatalf("audit-service: %v", err)
	}
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

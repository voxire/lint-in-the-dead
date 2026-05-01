package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/voxire/lint-in-the-dead/pkg/metrics"
	"github.com/voxire/lint-in-the-dead/pkg/models"
	"github.com/voxire/lint-in-the-dead/pkg/queue"
	"github.com/voxire/lint-in-the-dead/services/analysis-service/analyzer"
)

func main() {
	listenAddr := getEnv("LISTEN_ADDR", ":8082")
	workerCount := getEnvInt("WORKER_COUNT", 4)
	policyURL := getEnv("POLICY_ENGINE_URL", "http://localhost:8081")
	auditURL := getEnv("AUDIT_SERVICE_URL", "http://localhost:8083")
	notifURL := getEnv("NOTIFICATION_SERVICE_URL", "http://localhost:8084")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := metrics.NewRegistry("analysis_service")
	jobsQueued    := reg.Counter("jobs_queued_total")
	jobsCompleted := reg.Counter("jobs_completed_total")
	jobsFailed    := reg.Counter("jobs_failed_total")
	queueDepth    := reg.Gauge("queue_depth")
	reg.Gauge("worker_count").Set(int64(workerCount))

	q := queue.NewInMemory(512)
	a := analyzer.New(policyURL, auditURL, notifURL)

	var (
		mu      sync.RWMutex
		results = make(map[string]models.AnalysisResult)
	)

	pool := analyzer.NewPool(ctx, workerCount, a)

	// Job consumer: drain queue and dispatch to pool.
	go func() {
		for {
			job, err := q.Dequeue(ctx)
			if err != nil {
				return
			}
			queueDepth.Dec()
			resultCh := make(chan models.AnalysisResult, 1)
			pool.Submit(analyzer.WorkItem{Job: job, ResultCh: resultCh})
			go func(id string) {
				r := <-resultCh
				if r.Summary.TotalFindings >= 0 {
					jobsCompleted.Inc()
				} else {
					jobsFailed.Inc()
				}
				mu.Lock()
				results[id] = r
				mu.Unlock()
			}(job.ID)
		}
	}()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /metrics", reg.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"workers": workerCount,
			"queued":  q.Len(),
		})
	})

	mux.HandleFunc("POST /api/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		var job models.Job
		if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		job.Status = models.JobStatusQueued
		if job.CreatedAt.IsZero() {
			job.CreatedAt = time.Now().UTC()
		}
		if err := q.Enqueue(r.Context(), job); err != nil {
			http.Error(w, "queue full", http.StatusServiceUnavailable)
			return
		}
		jobsQueued.Inc()
		queueDepth.Inc()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(job)
	})

	mux.HandleFunc("GET /api/v1/jobs", func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		list := make([]models.AnalysisResult, 0, len(results))
		for _, r := range results {
			list = append(list, r)
		}
		mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

	mux.HandleFunc("GET /api/v1/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		mu.RLock()
		result, ok := results[id]
		mu.RUnlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	srv := &http.Server{Addr: listenAddr, Handler: mux}

	go func() {
		log.Printf("analysis-service listening on %s (%d workers)", listenAddr, workerCount)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("analysis-service: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("analysis-service: shutting down…")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutCancel()
	srv.Shutdown(shutCtx)
	cancel()
	pool.Stop()
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

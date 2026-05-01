package config

import (
	"os"
	"strconv"
)

type Config struct {
	ListenAddr              string
	PolicyEngineURL         string
	AnalysisServiceURL      string
	AuditServiceURL         string
	NotificationServiceURL  string
	GitHubWebhookSecret     string
	WSReadBufferSize         int
	WSWriteBufferSize        int
}

func Load() Config {
	return Config{
		ListenAddr:             getEnv("LISTEN_ADDR", ":8080"),
		PolicyEngineURL:        getEnv("POLICY_ENGINE_URL", "http://localhost:8081"),
		AnalysisServiceURL:     getEnv("ANALYSIS_SERVICE_URL", "http://localhost:8082"),
		AuditServiceURL:        getEnv("AUDIT_SERVICE_URL", "http://localhost:8083"),
		NotificationServiceURL: getEnv("NOTIFICATION_SERVICE_URL", "http://localhost:8084"),
		GitHubWebhookSecret:    getEnv("GITHUB_WEBHOOK_SECRET", ""),
		WSReadBufferSize:       getEnvInt("WS_READ_BUF", 1024),
		WSWriteBufferSize:      getEnvInt("WS_WRITE_BUF", 1024),
	}
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

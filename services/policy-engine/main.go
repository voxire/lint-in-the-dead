package main

import (
	"log"
	"os"

	"github.com/voxire/lint-in-the-dead/services/policy-engine/engine"
)

func main() {
	addr := getEnv("LISTEN_ADDR", ":8081")
	rulesDir := getEnv("RULES_DIR", "./configs/rules")

	eng, err := engine.New(addr, rulesDir)
	if err != nil {
		log.Fatalf("policy-engine init: %v", err)
	}
	if err := eng.Start(); err != nil {
		log.Fatalf("policy-engine: %v", err)
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

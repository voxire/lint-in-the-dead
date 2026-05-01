package main

import (
	"log"

	"github.com/voxire/lint-in-the-dead/services/api-gateway/config"
	"github.com/voxire/lint-in-the-dead/services/api-gateway/server"
)

func main() {
	cfg := config.Load()
	srv := server.New(cfg)
	if err := srv.Start(); err != nil {
		log.Fatalf("api-gateway: %v", err)
	}
}

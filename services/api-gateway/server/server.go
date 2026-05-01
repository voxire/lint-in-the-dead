package server

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/voxire/lint-in-the-dead/services/api-gateway/config"
	"github.com/voxire/lint-in-the-dead/services/api-gateway/middleware"
)

// Server wires together all handlers, middleware, and the WebSocket hub.
type Server struct {
	cfg      config.Config
	hub      *Hub
	upgrader websocket.Upgrader
	mux      *http.ServeMux
	handler  http.Handler
}

func New(cfg config.Config) *Server {
	s := &Server{
		cfg: cfg,
		hub: NewHub(),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  cfg.WSReadBufferSize,
			WriteBufferSize: cfg.WSWriteBufferSize,
			CheckOrigin:     func(*http.Request) bool { return true },
		},
		mux: http.NewServeMux(),
	}
	s.routes()

	limiter := middleware.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)
	s.handler = middleware.Chain(
		middleware.Recovery,
		middleware.Logger,
		middleware.CORS("*"),
		limiter.Limit,
	)(s.mux)

	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", HealthHandler)
	s.mux.HandleFunc("POST /api/v1/jobs", s.SubmitJobHandler)
	s.mux.HandleFunc("GET /api/v1/jobs", s.ListJobsHandler)
	s.mux.HandleFunc("POST /webhooks/github", s.GitHubWebhookHandler)
	s.mux.HandleFunc("GET /ws", ServeWS(s.hub, s.upgrader))
}

func (s *Server) Start() error {
	go s.hub.Run()
	log.Printf("api-gateway listening on %s", s.cfg.ListenAddr)
	return http.ListenAndServe(s.cfg.ListenAddr, s.handler)
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

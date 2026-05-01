package middleware

import "net/http"

// CORS adds permissive cross-origin headers. Tighten AllowedOrigins in production.
func CORS(allowedOrigins ...string) func(http.Handler) http.Handler {
	origins := map[string]bool{}
	for _, o := range allowedOrigins {
		origins[o] = true
	}
	allowAll := len(allowedOrigins) == 0 || origins["*"]

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if allowAll || origins[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Hub-Signature-256")
			w.Header().Set("Access-Control-Max-Age", "3600")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

package main

import "net/http"

func requireAuth(next http.Handler) http.Handler { return next }

func me(w http.ResponseWriter, r *http.Request) {}

func main() {
	mux := http.NewServeMux()
	mux.Handle("GET /me", requireAuth(http.HandlerFunc(me)))
	mux.HandleFunc("GET /ping", me)
	http.ListenAndServe(":8080", mux)
}

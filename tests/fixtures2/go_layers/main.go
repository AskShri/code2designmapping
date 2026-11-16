package main

import (
	"net/http"

	"layers/store"
)

type Handler struct {
	users *store.UserStore
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	h.users.Get("1")
}

func main() {
	h := &Handler{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /me", h.me)
	http.ListenAndServe(":8080", mux)
}

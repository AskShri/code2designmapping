package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	r.Get("/health", health)
	r.Route("/articles", func(r chi.Router) {
		r.Get("/", list)
		r.Group(func(r chi.Router) {
			r.Use(AuthRequired)
			r.Post("/", create)
		})
		r.With(AdminOnly).Delete("/{id}", remove)
	})
	r.Get("/public", health)
	http.ListenAndServe(":8080", r)
}

func health(w http.ResponseWriter, r *http.Request) {}
func list(w http.ResponseWriter, r *http.Request)   {}
func create(w http.ResponseWriter, r *http.Request) {}
func remove(w http.ResponseWriter, r *http.Request) {}

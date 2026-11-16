package main

import (
	"database/sql"
	"net/http"
	_ "github.com/lib/pq"
)

var db *sql.DB

func getItem(w http.ResponseWriter, r *http.Request) {
	db.QueryRow("SELECT id, name FROM items WHERE id = $1", r.PathValue("id"))
}

func main() {
	db, _ = sql.Open("postgres", "postgres://db/items")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /items/{id}", getItem)
	mux.HandleFunc("POST /items", func(w http.ResponseWriter, r *http.Request) {
		db.Exec("INSERT INTO items (name) VALUES ($1)", r.FormValue("name"))
	})
	mux.HandleFunc("/files/{path...}", getItem)
	http.ListenAndServe(":8080", mux)
}

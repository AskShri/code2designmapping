package store

import "database/sql"

type UserStore struct{ db *sql.DB }

func (s *UserStore) Get(id string) {
	s.db.QueryRow("SELECT id, email FROM users WHERE id = $1", id)
}

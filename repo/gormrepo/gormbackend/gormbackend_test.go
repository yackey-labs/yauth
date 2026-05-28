package gormbackend

import "testing"

func TestDBNameFromDSN(t *testing.T) {
	tests := []struct {
		driver string
		dsn    string
		want   string
	}{
		{"pgx", "postgres://user:pass@localhost:5432/mydb?sslmode=disable", "mydb"},
		{"pgx", "postgresql://user:pass@host/authdb", "authdb"},
		{"pgx", "host=localhost port=5432 dbname=mydb user=u password=p", "mydb"},
		{"pgx", "host=localhost dbname='quoted_db' user=u", "quoted_db"},
		{"postgres", "postgres://user:pass@localhost/appdb?sslmode=require", "appdb"},
		{"postgres", "host=db.example.com dbname=prod user=app", "prod"},
		{"mysql", "user:pass@tcp(host:3306)/shopdb?parseTime=true", "shopdb"},
		{"mysql", "root@tcp(127.0.0.1:3306)/testdb", "testdb"},
		{"sqlite", ":memory:", ""},
		{"sqlite", "/var/data/app.db", ""},
		{"pgx", "postgres://user:pass@host/", ""},
	}
	for _, tt := range tests {
		got := dbNameFromDSN(tt.driver, tt.dsn)
		if got != tt.want {
			t.Errorf("dbNameFromDSN(%q, %q) = %q, want %q", tt.driver, tt.dsn, got, tt.want)
		}
	}
}

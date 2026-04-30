package gormrepo

import "testing"

func TestAddPostgresSchema_URLStyle(t *testing.T) {
	got := addPostgresSchema("postgres://u:p@host:5432/db?sslmode=disable", "tenant1")
	want := "postgres://u:p@host:5432/db?search_path=tenant1%2Cpublic&sslmode=disable"
	if got != want {
		t.Fatalf("URL DSN: got %q want %q", got, want)
	}
}

func TestAddPostgresSchema_KeywordStyle(t *testing.T) {
	got := addPostgresSchema("host=localhost user=u dbname=db sslmode=disable", "tenant1")
	want := "host=localhost user=u dbname=db sslmode=disable search_path=tenant1,public"
	if got != want {
		t.Fatalf("keyword DSN: got %q want %q", got, want)
	}
}

func TestAddPostgresSchema_PreservesExistingSearchPath(t *testing.T) {
	in := "postgres://u@host/db?search_path=already_set"
	if got := addPostgresSchema(in, "tenant1"); got != in {
		t.Fatalf("URL: existing search_path should win: got %q", got)
	}
	in2 := "host=localhost dbname=db search_path=already_set"
	if got := addPostgresSchema(in2, "tenant1"); got != in2 {
		t.Fatalf("keyword: existing search_path should win: got %q", got)
	}
}

func TestAddPostgresSchema_EmptySchemaIsNoop(t *testing.T) {
	in := "postgres://u@host/db"
	if got := addPostgresSchema(in, ""); got != in {
		t.Fatalf("empty schema should be noop: got %q", got)
	}
}

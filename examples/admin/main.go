// Command admin-example is a runnable demonstration of the status +
// admin plugins.
//
// It opens an in-memory SQLite database, runs migrations, seeds a single
// admin user via direct repo.CreateUser (so you don't need to register
// then PATCH the role), builds a YAuth instance with the email-password,
// status, and admin plugins, and serves it under /api/auth/* on :3000.
//
// Try it:
//
//	go run ./examples/admin
//
//	# in another shell, log in as the seeded admin to obtain a session cookie:
//	curl -i -c jar.txt -X POST http://localhost:3000/api/auth/login \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"admin@example.com","password":"correct horse battery staple"}'
//
//	# status:
//	curl -i -b jar.txt http://localhost:3000/api/auth/status
//
//	# list users:
//	curl -i -b jar.txt 'http://localhost:3000/api/auth/admin/users?limit=10'
//
//	# audit log:
//	curl -i -b jar.txt 'http://localhost:3000/api/auth/admin/audit?limit=10'
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/admin"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/status"
	"github.com/yackey-labs/yauth/repo/gormrepo"
	"github.com/yackey-labs/yauth/yautherr"
)

const (
	adminEmail    = "admin@example.com"
	adminPassword = "correct horse battery staple"
)

func main() {
	dsn := "file::memory:?cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	repo := gormrepo.New(db)

	if err := seedAdmin(context.Background(), repo); err != nil {
		log.Fatalf("seed admin: %v", err)
	}

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(status.New()).
		WithPlugin(admin.New()).
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))

	addr := ":3000"
	log.Printf("yauth-go admin example listening on %s", addr)
	log.Printf("seeded admin: email=%s password=%q", adminEmail, adminPassword)
	log.Printf("try:")
	log.Printf("  curl -i -c jar.txt -X POST http://localhost%s/api/auth/login \\", addr)
	log.Printf("    -H 'Content-Type: application/json' \\")
	log.Printf("    -d '{\"email\":\"%s\",\"password\":\"%s\"}'", adminEmail, adminPassword)
	log.Printf("  curl -i -b jar.txt http://localhost%s/api/auth/status", addr)
	log.Printf("  curl -i -b jar.txt 'http://localhost%s/api/auth/admin/users?limit=10'", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// seedAdmin creates the demo admin user via direct repo writes, bypassing
// any plugin handlers. It is idempotent — re-running the example reuses
// the existing admin row.
func seedAdmin(ctx context.Context, repo *gormrepo.Repo) error {
	if existing, err := repo.GetUserByEmail(ctx, adminEmail); err == nil && existing != nil {
		return nil
	} else if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
		return err
	}

	now := time.Now().UTC()
	user, err := repo.CreateUser(ctx, domain.NewUser{
		ID:            uuid.NewString(),
		Email:         adminEmail,
		Role:          "admin",
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(adminPassword)
	if err != nil {
		return err
	}
	return repo.UpsertPassword(ctx, domain.NewPassword{
		UserID:       user.ID,
		PasswordHash: hash,
	})
}

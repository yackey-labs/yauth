// Command vue-example-server is the Go backend for the Vue example
// frontend in examples/vue.
//
// It boots an in-memory SQLite database, wires up the email-password +
// status + admin plugins, seeds a demo admin, and serves /api/auth/*
// on :3000. The Vue dev server (port 5173) proxies /api/* to this
// process so register/login/dashboard/logout work out of the box.
//
// Run side-by-side:
//
//	go run ./examples/vue/server   # backend on :3000
//	cd examples/vue && bun dev     # frontend on :5173
//
// Demo admin: admin@example.com / correct horse battery staple
// New users register via the Vue UI and land in the in-memory DB.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugins/admin"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	"github.com/yackey-labs/yauth-go/plugins/status"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
	"github.com/yackey-labs/yauth-go/yautherr"
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
	log.Printf("yauth-go Vue example backend listening on %s", addr)
	log.Printf("seeded admin: email=%s password=%q", adminEmail, adminPassword)
	log.Printf("frontend: cd examples/vue && bun dev   (proxies /api -> :3000)")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

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

package yauth

import (
	"embed"
	"io/fs"
)

// docsFS embeds the human-readable documentation tree (the top-level
// README plus everything under docs/) directly into the compiled binary.
//
// This is what makes `yauth docs` / `yauth context` version-exact: the docs
// an operator or AI agent reads are the docs that shipped in the same
// artifact as the running code, so they cannot drift from the binary's
// behavior — no network fetch, no separate doc site to keep in sync. It
// mirrors the existing pattern in migrate/ which embeds the SQL migrations.
//
//go:embed README.md
//go:embed docs
var docsFS embed.FS

// DocsFS is the embedded documentation tree, exposed as an fs.FS so the
// yauth CLI (and any consumer) can serve version-exact docs offline.
var DocsFS fs.FS = docsFS

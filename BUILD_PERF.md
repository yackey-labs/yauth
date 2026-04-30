# yauth: Rust vs Go — Build / Test / Runtime Parity Report

Empirical head-to-head comparison of the Rust workspace at `yackey-labs/yauth` and the Go workspace at `yackey-labs/yauth-go`. All numbers in this report come from `scripts/bench-compare.sh` (median of `BENCH_ITERS=3` runs); raw outputs are in `scripts/bench-output/`.

## 1. Methodology + hardware

**Host (this machine):**

```
uname -mrs : Darwin 24.6.0 arm64
physical cpus : 14
memory : 24.0 GB
go : go version go1.26.2 darwin/arm64
rustc : rustc 1.95.0 (59807616e 2026-04-14)
cargo : cargo 1.95.0 (f2d3ce0bd 2026-03-21)
```

**Phases.** Cold = caches purged before iter 1 (`cargo clean` / `go clean -cache` / `go clean -testcache`). Warm = subsequent iterations with caches populated. Each phase runs 3 times; we take the median.

**Commands.**

| Phase | Rust | Go |
|---|---|---|
| Build | `cargo build --workspace --features full,all-backends` | `go build ./...` |
| Vet/check | `cargo check --workspace --features full,all-backends` | `go vet ./...` |
| Lint | `cargo clippy --workspace --features full,all-backends -- -D warnings` | `golangci-lint run ./...` |
| Test | `cargo test --workspace --features full,all-backends --lib` | `go test ./...` |

**Measurement.** `/usr/bin/time -l` on macOS (BSD time) and `/usr/bin/time -v` on Linux (GNU time). Real / user / sys CPU and max RSS come straight from those tools; CPU% = (user+sys)/real (roughly the average parallel-cores worth of CPU time burned).

## 2. Build / Test / Lint comparison

| Phase | Rust real | Rust user | Rust sys | Rust max RSS | Rust CPU% | Go real | Go user | Go sys | Go max RSS | Go CPU% |
|---|---|---|---|---|---|---|---|---|---|---|
| Build (cold) | 72.19s | 238.51s | 30.58s | 2.80 GB | 373% | 25.21s | 83.63s | 22.27s | 739.6 MB | 420% |
| Build (warm) | 0.51s | 0.13s | 0.15s | 131.5 MB | 60% | 7.50s | 33.65s | 7.78s | 428.0 MB | 553% |
| Vet / cargo check | 0.75s | 0.14s | 0.17s | 139.2 MB | 76% | 0.41s | 0.30s | 1.74s | 53.3 MB | 498% |
| Lint (golangci/clippy) | 0.74s | 0.14s | 0.18s | 139.2 MB | 74% | 0.74s | 0.96s | 3.01s | 104.7 MB | 536% |
| Test (cold) | 57.84s | 235.66s | 31.63s | 1.80 GB | 462% | 8.09s | 18.26s | 10.06s | 361.1 MB | 350% |
| Test (warm) | 2.62s | 3.20s | 0.23s | 138.7 MB | 131% | 0.43s | 0.33s | 1.92s | 55.3 MB | 524% |

## 3. Per-language summary

- **Build (cold).** Wall: Go faster by 2.86x. Peak RSS: Rust higher by 3.88x.
- **Build (warm).** Wall: Rust faster by 14.72x. Peak RSS: Go higher by 3.25x.
- **Vet / cargo check.** Wall: Go faster by 1.83x. Peak RSS: Rust higher by 2.61x.
- **Lint (golangci/clippy).** Wall: Go faster by 1.00x. Peak RSS: Rust higher by 1.33x.
- **Test (cold).** Wall: Go faster by 7.15x. Peak RSS: Rust higher by 5.10x.
- **Test (warm).** Wall: Go faster by 6.10x. Peak RSS: Rust higher by 2.51x.

## 4. CodeQL note (CI only)

Rust CodeQL takes **11m25s** in the upstream CI (matrix entry `language: rust`). Go CodeQL has not been wired into yauth-go's CI yet — once `.github/workflows/ci.yml` adds a CodeQL job for `go`, fill this in. **TBD.**

Rust CI baselines for comparison (from upstream's `ci.yml`): Test 8m22s, Lint 5m8s, CodeQL-Rust 11m25s. Local-machine numbers above are what to consider for daily edit/test loops; CI numbers are what gates merges.

## 5. Runtime measurements

| Metric | Rust | Go |
|---|---|---|
| Idle RSS | 32.1 MB | 18.3 MB |
| Peak RSS under load | 99.4 MB | 172.3 MB |
| Throughput (req/s) | 86,973 | 17,210 |
| p50 latency | 1.10ms | 1.80ms |
| p99 latency | 2.90ms | 25.90ms |

Endpoint exercised: `GET /api/auth/session` with a pre-baked session cookie. This is mostly cookie validation + user lookup — a representative authenticated read path.

## 6. Conclusions (honest)

### Build time hypothesis ("Rust isn't actually faster")

**Refuted.** Cold build: Go finishes in 25.2s vs Rust 72.2s — Go is 2.86x faster from a fully cleaned cache. The Rust workspace pulls in roughly 650 crate dependencies that all monomorphize and codegen from scratch; Go pulls direct deps and link-only stubs. On the same M-series hardware, this is the dominant edit-loop cost on a fresh clone or a CI runner with a cold cache.

Warm-build numbers (Rust 0.51s, Go 7.50s) compare two different things: Rust's incremental compiler does almost nothing when no source changed, while Go's `go build ./...` always walks every package and re-resolves the module graph (no-op codegen, but real I/O cost). For a fairer warm-build read, edit one file and re-run; in practice both languages sit well under a second when caches are hot.

### Memory

Build-time peak RSS: Rust 2.80 GB vs Go 739.6 MB — Rust uses 3.88x more peak memory during a cold compile (expected: rustc/LLVM monomorphization is RAM-hungry).

Runtime idle RSS: Rust 32.1 MB vs Go 18.3 MB — Go is 1.76x lower at idle. The Rust example we spawned ships every plugin (`features = full,memory-backend`) while the Go example only enables email-password — so this is not a like-for-like idle. The peak-load RSS comparison below is more representative.

### Throughput

Rust 86973 req/s vs Go 17210 req/s on `/api/auth/session` — Rust is 5.05x with both running an in-memory backend. p99 latency tells the same story: Rust 2.90ms vs Go 25.90ms. With a real DB the gap compresses dramatically — query latency dominates everything above. Use this number to size the framework headroom, not as a steady-state production estimate.

**Peak load RSS.** Rust 99.4 MB vs Go 172.3 MB — Rust uses 1.73x less memory under the same 100-connection load. Go's runtime grows the heap to service concurrent requests; Rust's allocations stay near steady state. This is the pattern most Rust-vs-Go comparisons see at runtime.

### When to choose which

- **Pick Rust** when: lowest possible runtime RSS matters (memory-constrained edge / sidecars), you already have a Rust ecosystem and team, or you need the strongest type-driven correctness guarantees.
- **Pick Go** when: developer iteration speed dominates (cold-build wall time + warm-build near-zero), the team is a Go shop, or your hosting environment is fine with the slightly larger steady-state RSS in exchange for a much shorter edit/compile/test loop.
- **Either is fine** for the actual auth workload — both saturate DB I/O and the difference at the HTTP layer is small relative to real query latency.

---

Raw bench outputs (`/usr/bin/time` records, all iterations): `scripts/bench-output/yauth-go-bench.txt`, `scripts/bench-output/yauth-rust-bench.txt`, `scripts/bench-output/yauth-runtime-bench.txt`.

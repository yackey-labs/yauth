# yauth-go on Kubernetes

A reference for the migrate-as-Job + app-as-Deployment pattern. **The
app deployment never runs migrations**: `yauth.NewFromConfig` will fail
loudly via `SchemaCheck` if the DB isn't migrated. Run the Job first.

## Layout

- `Dockerfile` — multi-stage build that produces both `yauth-app` and
  `yauth-cli` images from this repo.
- `migrate-job.yaml` — one-shot Job that runs `yauth migrate`. Wire it
  as a Helm `pre-upgrade,pre-install` hook, an Argo `Sync` step, or a
  CI step that waits with `kubectl wait --for=condition=complete`.
- `deployment.yaml` — the app Deployment + ConfigMap. Multiple replicas
  are safe because the app does not migrate; only the Job does.

## Why a Job, not an initContainer?

Multi-replica Deployments would each run their own initContainer. If
the initContainer ran AutoMigrate, replicas would race on the same
DDL. A single-shot Job runs migrations exactly once, regardless of
replica count.

## Required secrets

```bash
kubectl create secret generic yauth-secrets \
  --from-literal=DATABASE_URL='postgres://...' \
  --from-literal=JWT_SECRET="$(openssl rand -hex 32)"
```

## Order of operations

```bash
kubectl apply -f migrate-job.yaml
kubectl wait --for=condition=complete job/yauth-migrate --timeout=120s
kubectl apply -f deployment.yaml
```

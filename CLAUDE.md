# TunnelDeck

Go 1.27 backend + React 19/TypeScript/Vite frontend (`web/`), shipped as one Docker image. Spec: `docs/SPEC.md`. Tasks: `docs/PLAN.md`. Navigation: `filemap.md`. OpenVPN specifics: `docs/openvpn-notes.md`.

## Commands

- Backend: `go build ./...` · `go test ./...` · `golangci-lint run`
- Frontend (in `web/`): `npm ci` · `npm run lint` · `npm test` · `npm run build`
- Run locally: `npm --prefix web run build` then `go run ./cmd/tunneldeck`
- Image: `docker build -t tunneldeck .`

## Rules

- Code, comments, commits and docs in English. UI strings only via i18n keys, always in both `de` and `en`.
- Dependency direction: `internal/domain` imports no internal package; only `cmd/tunneldeck` wires concrete types. Interfaces are declared by the consumer.
- Nothing outside `internal/vpn/openvpn` may know OpenVPN. Other code uses `vpn.Driver`.
- All `iptables`/`ip` calls go through `netguard.CommandRunner`; never `exec.Command` elsewhere. The host's main routing table is never modified.
- Secrets never appear in API responses, logs, errors or files outside `/data` (encrypted) — use `hasValue`. Sole exception: key material inside the rendered OpenVPN config in the tmpfs runtime dir (SPEC §5).
- Clean code: small functions, intention-revealing names, no dead code, no commented-out code, errors wrapped with context (`fmt.Errorf("...: %w", err)`), table-driven tests next to the code.
- Dev machine is Windows: Linux-only code needs build tags or interfaces so `go build ./...` and `go test ./...` pass on Windows.
- Versioning: SemVer from git tags, Conventional Commits, `CHANGELOG.md` (`Unreleased`) updated with every user-visible change, `schemaVersion` in data files — see SPEC §13.
- Follow the RFCs listed in SPEC §14 (e.g. API errors are RFC 9457 problem details, timestamps RFC 3339 UTC).
- Every change ships with tests; `go test -race ./...` must pass where the race detector is available.
- Update `filemap.md` when adding or moving files. Do not commit; the orchestrator commits.

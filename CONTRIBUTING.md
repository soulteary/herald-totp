# Contributing to herald-totp

Thank you for your interest in contributing to herald-totp.

## Development

- **Go version**: 1.27.3+ (see [go.mod](go.mod)).
- **Tests**: Run on Linux with `go test -race -count=1 -coverprofile=coverage.out ./...`, then `go tool cover -func=coverage.out`. Total statement coverage must stay at least 98%. Lifecycle tests execute real child processes and forward the standard Go coverage directory so their production execution is measured. Tests cover configuration, persistence, encryption, enrollment, verification, replay protection, startup and shutdown.
- **Code style**: Follow standard Go formatting. Run `gofmt -s -w .` before committing. The CI runs `gofmt -s -l .` and fails if there are unformatted files.
- **Static analysis**: CI runs `go vet ./...`. Run `golangci-lint run` locally before submitting.

## Submitting changes

1. Fork the repository and create a branch from `main` (or `master`).
2. Make your changes; keep commits focused and messages clear.
3. Ensure tests pass: `go test ./...`.
4. Open a Pull Request with a short description of the change and reference any related issues.

## Documentation

- English docs: [docs/enUS/](docs/enUS/).
- Chinese docs: [docs/zhCN/](docs/zhCN/).
- When adding or changing API or configuration, update the relevant docs (API.md, DEPLOYMENT.md, README, SECURITY, TROUBLESHOOTING) in both enUS and zhCN if applicable.

## Questions

Open an [Issue](https://github.com/soulteary/herald-totp/issues) for questions or bug reports.

# Development

[← README](../README.md)

GitHub Actions runs the same gate on every push to master and every pull request (`.github/workflows/ci.yml`). A `v*` tag also builds the release binaries with `scripts/release.sh`, attests where they were built and publishes the release with notes from `docs/releases/`.

```sh
go build ./... && go vet ./... && go test -race ./...
scripts/release.sh dist               # release binaries and SHA256SUMS
ES_BIN=/usr/local/bin scripts/demo.sh # the demo on installed binaries instead of a fresh build
python3 scripts/mutate.py keyring     # mutation testing: every injected bug must fail a test
                                      # sets: keyring, evlog, tsa, store, edge, auditchain, gateway, config, ship, cosign,
                                      # and the rest in scripts/mutations/
PGINPUT_TEST_DSN="host=… port=… dbname=…" go test ./internal/pginput -run Live -v  # the PostgreSQL input on a live database:
                                      # PostgreSQL 14+ with wal_level=logical, a throwaway cluster where the test
                                      # makes roles, a table and a slot; no user in the DSN, roles log in by trust
```

The simulations and how to replay a failing scenario: [docs/testing.md](testing.md#simulations).

Code comments, commit messages and the notes in [`docs/dev/`](dev/) are in Russian: a code map, the design decisions and open questions, and the log of every finding of the code review. Everything a user of the product sees is in English.

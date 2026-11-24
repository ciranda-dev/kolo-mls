#!/bin/sh
# Release gate: fetches and checks the official MLS test vectors, then runs
# the checks with the vectors required, so a missing file fails instead of
# skipping. Usage: scripts/release-check.sh
set -eu

cd "$(dirname "$0")/.."
export GOWORK=off
export KOLO_MLS_REQUIRE_VECTORS=1

scripts/fetch-vectors.sh

out=$(gofmt -l .)
if [ -n "$out" ]; then
	echo "gofmt: unformatted files:" >&2
	echo "$out" >&2
	exit 1
fi
go vet ./...
GOOS=windows go vet ./...
GOOS=linux GOARCH=386 go vet ./...
if command -v staticcheck >/dev/null 2>&1; then
	staticcheck ./...
else
	echo "staticcheck not installed: install it with go install honnef.co/go/tools/cmd/staticcheck@latest" >&2
	exit 1
fi
go test -count=1 ./...
go test -race -count=1 ./...
echo "release-check: all checks passed"

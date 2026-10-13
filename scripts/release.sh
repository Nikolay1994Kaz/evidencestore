#!/usr/bin/env bash
# Бинарники релиза и SHA256SUMS:
#
#   scripts/release.sh OUTDIR
#
# Хранилище и сборщик — только linux (flock, statx); esverify — ещё macOS и
# Windows: проверяющему не обязательно сидеть на Linux. Версию и коммит
# go build кладёт в бинарник сам (evidencestore version, esverify -version).
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:?usage: scripts/release.sh OUTDIR}
mkdir -p "$out"

build() { # ос арх команда
	local ext=""
	[ "$1" = windows ] && ext=.exe
	CGO_ENABLED=0 GOOS=$1 GOARCH=$2 go build -trimpath -ldflags "-s -w" -o "$out/$3-$1-$2$ext" "./cmd/$3"
}

for arch in amd64 arm64; do
	for cmd in evidencestore escollect esverify; do
		build linux "$arch" "$cmd"
	done
done
build darwin amd64 esverify
build darwin arm64 esverify
build windows amd64 esverify
(cd "$out" && sha256sum -- * >SHA256SUMS)

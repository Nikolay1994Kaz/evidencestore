#!/usr/bin/env bash
# Бинарники релиза и SHA256SUMS:
#
#   scripts/release.sh OUTDIR
#
# Хранилище, сборщик и свидетель — только linux (flock, statx); esverify — ещё
# macOS и Windows: проверяющему не обязательно сидеть на Linux. Версию и коммит
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
	for cmd in evidencestore escollect eswitness esverify esreceipt; do
		build linux "$arch" "$cmd"
	done
done
# esverify — у аудитора, esreceipt — у шлюза: оба бывают не на Linux.
for cmd in esverify esreceipt; do
	build darwin amd64 "$cmd"
	build darwin arm64 "$cmd"
done
build windows amd64 esverify

# Бинарник из изменённого дерева помечен +dirty (vcs.modified): релиз
# обязан быть ровно коммитом тега. На GitHub Actions это отказ, локально —
# предупреждение.
for f in "$out"/*; do
	if go version -m "$f" | grep -q 'vcs.modified=true'; then
		echo "release.sh: $f собран из изменённого дерева (+dirty)" >&2
		[ -z "${GITHUB_ACTIONS:-}" ] || exit 1
	fi
done
(cd "$out" && sha256sum -- * >SHA256SUMS)

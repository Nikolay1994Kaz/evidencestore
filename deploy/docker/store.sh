#!/bin/sh
# Хранилище в compose: evidencestore serve и корень службы меток для esundo.
# Корень выдаёт только работающее хранилище (tsa-root), поэтому — здесь, а не в
# первом запуске.
set -eu
C=/state/store/store.json
evidencestore serve -config "$C" &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null; wait "$pid"' TERM INT
until [ -f /state/store/tsa-root.crt ] || evidencestore tsa-root -config "$C" -out /state/store/tsa-root.crt >/dev/null 2>&1; do
	kill -0 "$pid" 2>/dev/null || break
	sleep 0.2
done
wait "$pid"

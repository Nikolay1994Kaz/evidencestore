#!/bin/sh
# Хранилище в Docker (deploy/docker/store/compose.yaml): при первом запуске —
# evidencestore docker init (УЦ сборщиков, сертификат сервера на ES_HOST,
# конфиг, init), затем serve. Есть конфиг — установка закончена, и ES_HOST
# больше не нужен.
#
# serve — дочерний процесс: по SIGHUP (его шлёт add-collector) вход
# перезапускает его, и новый источник принимается без перезапуска контейнера
# (serve читает источники при запуске). TERM и INT — serve, и выход с его кодом.
set -eu
C=/etc/evidencestore/evidencestore.json
if [ ! -f "$C" ]; then
	evidencestore docker init -host "${ES_HOST:-}" -tsa "${ES_TSA:-digicert}"
fi
reload=0
pid=
trap 'reload=1; [ -z "$pid" ] || kill -TERM "$pid" 2>/dev/null || true' HUP
trap '[ -z "$pid" ] || kill -TERM "$pid" 2>/dev/null || true' TERM INT
set +e
while :; do
	evidencestore serve -config "$C" &
	pid=$!
	# wait прерывается сигналом раньше, чем serve выйдет: ждать, пока выйдет.
	while :; do
		wait "$pid"
		st=$?
		kill -0 "$pid" 2>/dev/null || break
	done
	if [ "$reload" = 1 ]; then
		reload=0
		echo "es-docker-store: the sources changed: serve starts again" >&2
		continue
	fi
	exit "$st"
done

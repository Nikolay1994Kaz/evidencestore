#!/bin/sh
# Сборщик для хранилища в Docker — одной командой на хосте хранилища:
#
#   docker compose exec -T store add-collector web1 > web1.tgz
#   docker compose exec -T store add-collector db1 -file /var/log/postgresql/postgresql-17-main.log > db1.tgz
#
# evidencestore docker add-source с -reload: сертификат, запись в конфиге,
# архив в стандартный вывод, и serve перезапускается сам (entry.sh).
set -eu
if [ $# -lt 1 ] || [ "${1#-}" != "$1" ]; then
	echo "usage: docker compose exec -T store add-collector NAME [-file /var/log/auth.log] [-content-type T] [-retention-months N] > NAME.tgz" >&2
	exit 2
fi
name=$1
shift
exec evidencestore docker add-source -reload -name "$name" "$@"

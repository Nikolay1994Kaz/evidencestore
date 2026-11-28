# Образ стенда: PostgreSQL с Patroni, etcd, HAProxy и PgBouncer из пакетов
# Debian и PGDG. Один образ на все роли стенда (compose.yaml).
ARG PG_VERSION=17
FROM postgres:${PG_VERSION}
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends patroni etcd-server etcd-client haproxy pgbouncer curl python3-etcd python3-psycopg2 \
 && rm -rf /var/lib/apt/lists/*

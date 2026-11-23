# Образ всех программ: evidencestore, escollect, esverify, esmcp, esundo, eswitness.
# Сборка — статическая (CGO_ENABLED=0), образ — alpine: оболочка нужна первому
# запуску compose (deploy/docker/init.sh), больше ничего.
#
#   docker build -t evidencestore .
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# .git в образ не идёт (.dockerignore): версию и коммит go build взять неоткуда.
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/ ./cmd/...

FROM alpine:3.22
RUN adduser -D -H -u 10001 es
COPY --from=build /out/ /usr/local/bin/
COPY deploy/docker/init.sh /usr/local/bin/es-init
COPY deploy/docker/store.sh /usr/local/bin/es-store
USER es
WORKDIR /state

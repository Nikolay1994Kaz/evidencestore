# Образ выпуска: ровно те бинарники, что на странице выпуска (scripts/release.sh
# dist в CI), — без сборки и без RUN, поэтому собирается под amd64 и arm64 без
# эмуляции. Из клона без выпуска — корневой Dockerfile (сборка из исходников).
#
#   scripts/release.sh dist && docker buildx build -f deploy/docker/release.Dockerfile --platform linux/amd64,linux/arm64 .
# База закреплена по digest: метку 3.22 можно передвинуть, digest — нет.
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
ARG TARGETARCH
COPY dist/evidencestore-linux-${TARGETARCH} /usr/local/bin/evidencestore
COPY dist/escollect-linux-${TARGETARCH} /usr/local/bin/escollect
COPY dist/esverify-linux-${TARGETARCH} /usr/local/bin/esverify
COPY dist/eswitness-linux-${TARGETARCH} /usr/local/bin/eswitness
COPY dist/esreceipt-linux-${TARGETARCH} /usr/local/bin/esreceipt
COPY dist/esmcp-linux-${TARGETARCH} /usr/local/bin/esmcp
COPY dist/esundo-linux-${TARGETARCH} /usr/local/bin/esundo
COPY configs/tsa /usr/local/share/evidencestore/tsa
COPY deploy/docker/store/entry.sh /usr/local/bin/es-docker-store
COPY deploy/docker/store/add-collector.sh /usr/local/bin/add-collector
LABEL org.opencontainers.image.source="https://github.com/Nikolay1994Kaz/evidencestore" \
      org.opencontainers.image.description="evidencestore: an independent witness for logs" \
      org.opencontainers.image.licenses="Apache-2.0"

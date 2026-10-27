ARG RUNTIME_IMAGE=debian:trixie-slim
FROM node:22-bookworm-slim AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
COPY contracts/ /src/contracts/
RUN npm run build

FROM node:22-bookworm-slim AS piworker
WORKDIR /src/runtime/pi-worker
COPY runtime/pi-worker/package.json runtime/pi-worker/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY runtime/pi-worker/tsconfig.json ./
COPY runtime/pi-worker/src ./src
RUN npm run build && npm prune --omit=dev

FROM golang:1.26-bookworm AS backend
ARG BUILD_FLAVOR=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -tags "embedui,${BUILD_FLAVOR}" -ldflags="-s -w" -o /out/server ./cmd/server \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/scanner ./cmd/scanner \
    && mkdir -p "/out/plugin-packages/codexploit.static-patterns@1.0.15" \
    && cp /out/scanner "/out/plugin-packages/codexploit.static-patterns@1.0.15/scanner" \
    && cp internal/scanner/manifest.json "/out/plugin-packages/codexploit.static-patterns@1.0.15/manifest.json" \
    && chmod 0755 "/out/plugin-packages/codexploit.static-patterns@1.0.15/scanner" \
    && chmod 0644 "/out/plugin-packages/codexploit.static-patterns@1.0.15/manifest.json"

# The formal default chain includes one sealed, offline Joern release.
FROM golang:1.26-bookworm AS joern-package
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates build-essential pkg-config bison flex && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
# Package inputs are independent of Web/API changes. A frontend rebuild should
# reuse the sealed three-GiB engine instead of recompiling its native helpers.
COPY cmd/joern-adapter/ ./cmd/joern-adapter/
COPY cmd/pluginpack/ ./cmd/pluginpack/
COPY pkg/pluginsdk/ ./pkg/pluginsdk/
COPY contracts/ ./contracts/
COPY internal/repository/ ./internal/repository/
COPY internal/artifact/ ./internal/artifact/
COPY internal/analysis/ ./internal/analysis/
COPY internal/scg/ ./internal/scg/
COPY internal/asg/ ./internal/asg/
COPY internal/path/ ./internal/path/
COPY internal/plugin/ ./internal/plugin/
COPY plugins/joern/ ./plugins/joern/
COPY scripts/package-joern.py ./scripts/package-joern.py
RUN --mount=type=cache,target=/downloads python3 scripts/package-joern.py --cache /downloads --output /joern/codexploit.joern@2.3.0 > /joern-release.json

FROM ${RUNTIME_IMAGE} AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client ca-certificates curl libstdc++6 && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 codexploit && useradd --uid 10001 --gid 10001 --no-create-home codexploit \
    && mkdir -p /data /repos && chown 10001:10001 /data /repos
WORKDIR /app
COPY --from=backend /out/server ./server
COPY --from=backend /out/plugin-packages ./plugin-packages
COPY --chown=10001:10001 --from=joern-package /joern/ ./plugin-packages/
COPY --from=piworker /usr/local/bin/node /usr/local/bin/node
COPY --from=piworker /src/runtime/pi-worker /app/pi-worker
USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["curl", "--fail", "--silent", "http://127.0.0.1:8080/healthz"]
ENTRYPOINT ["/app/server"]
CMD ["--addr=:8080", "--workspace=/data", "--db=/data/codexploit.db", "--web-auth", "--agent-runtime=llm", "--scheduler"]

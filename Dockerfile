FROM node:22-bookworm-slim AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
COPY contracts/ /src/contracts/
RUN npm run build

FROM golang:1.26-bookworm AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -tags embedui -ldflags="-s -w" -o /out/server ./cmd/server

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client ca-certificates curl && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 codexploit && useradd --uid 10001 --gid 10001 --no-create-home codexploit \
    && mkdir -p /data /repos && chown 10001:10001 /data /repos
WORKDIR /app
COPY --from=backend /out/server ./server
USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["curl", "--fail", "--silent", "http://127.0.0.1:8080/healthz"]
ENTRYPOINT ["/app/server"]
CMD ["--addr=:8080", "--workspace=/data", "--db=/data/codexploit.db", "--web-auth", "--agent-runtime=llm", "--scheduler"]

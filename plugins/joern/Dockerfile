# Build a Linux package on Docker's native architecture. The exported directory
# is mounted into an existing application; no database or runtime is started.
FROM golang:1.26-bookworm AS package
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates build-essential pkg-config bison flex && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/downloads python3 scripts/package-joern.py --cache /downloads --output /out/codexploit.joern@2.3.4 > /out-release.json

FROM scratch
COPY --from=package /out/ /
COPY --from=package /out-release.json /release.json

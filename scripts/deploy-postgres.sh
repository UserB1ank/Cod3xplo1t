#!/usr/bin/env bash
# One-command PostgreSQL deployment for Codexploit.
#
# Usage:
#   scripts/deploy-postgres.sh [up|down|status|logs] [SOURCE_ROOT]
#   SOURCE_ROOT may also be set with CODEXPLOIT_SOURCE_ROOT.
#
# The database password, DSN and installation key are generated outside the
# repository on first use and reused later. Existing data volumes are never
# re-initialised with different secrets.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

COMMAND="up"
SOURCE_ARG=""
case "${1:-}" in
	up|down|status|logs)
		COMMAND="$1"
		SOURCE_ARG="${2:-}"
		;;
	"") ;;
	*)
		# A bare path is treated as `up <path>`.
		SOURCE_ARG="${1:-}"
		;;
esac

PROJECT="${CODEXPLOIT_PG_PROJECT:-codexploit-catalog}"
PORT="${CODEXPLOIT_PG_PORT:-18095}"
SECRETS_DIR="${CODEXPLOIT_PG_SECRETS_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/codexploit/postgres}"
SOURCE_ROOT="${SOURCE_ARG:-${CODEXPLOIT_SOURCE_ROOT:-$PWD}}"

if [[ ! "$PROJECT" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
	echo "error: CODEXPLOIT_PG_PROJECT must use lowercase letters, digits, '_' or '-'" >&2
	exit 1
fi
if [[ ! "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
	echo "error: CODEXPLOIT_PG_PORT must be a port number" >&2
	exit 1
fi

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "error: $1 is required" >&2
		exit 1
	fi
}

need docker
if ! docker compose version >/dev/null 2>&1; then
	echo "error: Docker Compose v2 is required (docker compose)" >&2
	exit 1
fi
if ! docker info >/dev/null 2>&1; then
	echo "error: the Docker daemon is not available" >&2
	exit 1
fi

absolute_dir() {
	local path="$1"
	if [[ ! -d "$path" ]]; then
		echo "error: directory does not exist: $path" >&2
		exit 1
	fi
	(cd "$path" && pwd -P)
}

PASSWORD_FILE="$SECRETS_DIR/postgres-password"
DSN_FILE="$SECRETS_DIR/postgres-dsn"
SETTINGS_KEY_FILE="$SECRETS_DIR/settings-key"
VOLUME="${PROJECT}_postgres-catalog"

volume_exists() {
	docker volume inspect "$VOLUME" >/dev/null 2>&1
}

require_secrets() {
	local name
	for name in "$PASSWORD_FILE" "$DSN_FILE" "$SETTINGS_KEY_FILE"; do
		if [[ ! -s "$name" ]]; then
			echo "error: missing deployment secret: $name" >&2
			echo "       restore the secrets used by the existing data, or remove the PostgreSQL volume to start fresh" >&2
			exit 1
		fi
	done
	chmod 444 "$PASSWORD_FILE" "$DSN_FILE" "$SETTINGS_KEY_FILE"
}

generate_secrets() {
	need openssl
	umask 077

	if [[ ! -s "$PASSWORD_FILE" && ! -s "$DSN_FILE" ]]; then
		local password
		password="$(openssl rand -hex 24)"
		printf '%s\n' "$password" >"$PASSWORD_FILE"
		printf 'postgres://catalog:%s@postgres:5432/codexploit?sslmode=disable\n' "$password" >"$DSN_FILE"
	elif [[ -s "$PASSWORD_FILE" && ! -s "$DSN_FILE" ]]; then
		printf 'postgres://catalog:%s@postgres:5432/codexploit?sslmode=disable\n' \
			"$(tr -d '\r\n' <"$PASSWORD_FILE")" >"$DSN_FILE"
	elif [[ ! -s "$PASSWORD_FILE" && -s "$DSN_FILE" ]]; then
		echo "error: $DSN_FILE exists but $PASSWORD_FILE is missing" >&2
		echo "       restore the matching password file; do not generate a new one for an existing volume" >&2
		exit 1
	fi

	if [[ ! -s "$SETTINGS_KEY_FILE" ]]; then
		openssl rand -hex 32 >"$SETTINGS_KEY_FILE"
	fi
}

if [[ "$COMMAND" == "up" ]]; then
	SOURCE_ROOT="$(absolute_dir "$SOURCE_ROOT")"
	mkdir -p "$SECRETS_DIR"
	chmod 700 "$SECRETS_DIR"
	SECRETS_DIR="$(cd "$SECRETS_DIR" && pwd -P)"
	case "$SECRETS_DIR" in
		"$ROOT"|"$ROOT"/*)
			rmdir "$SECRETS_DIR" 2>/dev/null || true
			echo "error: the secrets directory must be outside the repository: $SECRETS_DIR" >&2
			exit 1
			;;
	esac
	PASSWORD_FILE="$SECRETS_DIR/postgres-password"
	DSN_FILE="$SECRETS_DIR/postgres-dsn"
	SETTINGS_KEY_FILE="$SECRETS_DIR/settings-key"
	if volume_exists; then
		# Never silently replace secrets for a database that already contains data.
		require_secrets
	else
		generate_secrets
		require_secrets
	fi
else
	# Stopping, inspecting or reading logs must not require the secret contents.
	if [[ -d "$SECRETS_DIR" ]]; then
		SECRETS_DIR="$(cd "$SECRETS_DIR" && pwd -P)"
	fi
	if [[ -d "$SOURCE_ROOT" ]]; then
		SOURCE_ROOT="$(cd "$SOURCE_ROOT" && pwd -P)"
	fi
	PASSWORD_FILE="$SECRETS_DIR/postgres-password"
	DSN_FILE="$SECRETS_DIR/postgres-dsn"
	SETTINGS_KEY_FILE="$SECRETS_DIR/settings-key"
fi

export CODEXPLOIT_POSTGRES_PASSWORD_FILE="$PASSWORD_FILE"
export CODEXPLOIT_POSTGRES_DSN_FILE="$DSN_FILE"
export CODEXPLOIT_SETTINGS_KEY_FILE="$SETTINGS_KEY_FILE"
export CODEXPLOIT_SOURCE_ROOT="$SOURCE_ROOT"
export CODEXPLOIT_PG_PORT="$PORT"

compose() {
	docker compose --project-name "$PROJECT" --file "$ROOT/compose.postgres.yaml" "$@"
}

url="http://127.0.0.1:${PORT}"

case "$COMMAND" in
	up)
		compose up -d --build
		ready=0
		if command -v curl >/dev/null 2>&1; then
			printf 'Waiting for %s/healthz ' "$url"
			for ((attempt = 0; attempt < 90; attempt++)); do
				if curl -fsS --max-time 2 "$url/healthz" >/dev/null 2>&1; then
					ready=1
					break
				fi
				printf '.'
				sleep 1
			done
			printf '\n'
		else
			# No curl: do not claim health, but do not fail a started stack either.
			ready=1
		fi
		compose ps
		if [[ "$ready" -ne 1 ]]; then
			echo "error: the application did not become healthy at $url/healthz" >&2
			compose logs --tail=80 codexploit >&2 || true
			exit 1
		fi
		echo
		echo "PostgreSQL deployment is running."
		echo "  URL:      $url"
		echo "  project:  $PROJECT"
		echo "  database: internal postgres:5432 (no host port)"
		echo "  source:   $SOURCE_ROOT -> /repos"
		echo "  secrets:  $SECRETS_DIR"
		echo
		echo "Open the URL and create the administrator account on first use."
		echo "Back up the PostgreSQL volume and the secrets directory together."
		;;
	down)
		compose down
		echo "Stopped $PROJECT; data volumes were retained."
		;;
	status)
		compose ps
		echo "URL: $url"
		echo "Secrets: $SECRETS_DIR"
		;;
	logs)
		compose logs --tail=200 --follow codexploit
		;;
	*)
		echo "usage: $0 [up|down|status|logs] [SOURCE_ROOT]" >&2
		exit 2
		;;
esac

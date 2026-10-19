#!/bin/sh
# Generates the deployment secrets for the default Compose stack, once.
#
# The database password, its DSN and the installation key are written into the
# `pg-secrets` volume. They never appear in the Compose file, in the repository or
# in the environment: postgres and the application read them as files. A second
# start reuses them, which is what keeps the database and the stored ciphertext
# readable across restarts.
set -eu

dir=/run/codexploit-secrets
mkdir -p "$dir"
umask 077

# 64 hexadecimal characters: a 32-byte password that needs no URL escaping, and a
# 64-character installation key (the format the application accepts).
hex() {
	od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
}

if [ ! -s "$dir/postgres_password" ]; then
	password=$(hex)
	printf '%s' "$password" > "$dir/postgres_password"
	printf 'postgres://catalog:%s@postgres:5432/codexploit?sslmode=disable' "$password" > "$dir/postgres_dsn"
	printf '%s' "$(hex)" > "$dir/settings_key"
fi

chmod 0444 "$dir/postgres_password" "$dir/postgres_dsn" "$dir/settings_key"

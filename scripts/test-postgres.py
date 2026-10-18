#!/usr/bin/env python3
"""Run catalog acceptance in an isolated Compose project, without a DB host port."""
import os
from pathlib import Path
import secrets
import subprocess
import tempfile


def main():
    project = "codexploit-pg-test-" + secrets.token_hex(6)
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="codexploit-pg-test-") as temporary:
        fixture = Path(temporary)
        password = secrets.token_urlsafe(32)
        (fixture / "password").write_text(password)
        (fixture / "dsn").write_text(
            "postgres://catalog:" + password + "@postgres:5432/codexploit?sslmode=disable"
        )
        # Compose file-backed secrets are bind mounts. Container users need
        # read access; the host's temporary parent directory remains private.
        for name in ("password", "dsn"):
            (fixture / name).chmod(0o444)
        (fixture / "sources").mkdir()
        environment = dict(os.environ)
        environment.update({
            "CODEXPLOIT_POSTGRES_PASSWORD_FILE": str(fixture / "password"),
            "CODEXPLOIT_POSTGRES_DSN_FILE": str(fixture / "dsn"),
            "CODEXPLOIT_SOURCE_ROOT": str(fixture / "sources"),
        })
        command = ["docker", "compose", "--project-name", project,
                   "--file", str(root / "compose.postgres.yaml"), "--profile", "acceptance"]
        try:
            subprocess.run(command + ["run", "--rm", "tests"], cwd=root,
                           env=environment, check=True)
        finally:
            subprocess.run(command + ["down", "--volumes", "--remove-orphans"],
                           cwd=root, env=environment, check=True)


if __name__ == "__main__":
    main()

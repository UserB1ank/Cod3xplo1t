#!/usr/bin/env python3
"""Build a native, offline Joern package from pinned upstream archives.

PHP is built from a pinned upstream source archive; no installer or target build is executed. Deployment packages and
caches are build artifacts; only the recipe, queries and digest lock are source.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "plugins" / "joern"


def verify(path, expected):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != expected["bytes"]:
        raise ValueError("integrity_mismatch")
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected["sha256"]:
            raise ValueError("integrity_mismatch")


def fetch(cache, name, expected):
    path = cache / name
    if path.exists() or path.is_symlink():
        verify(path, expected)
        return path
    print("Downloading pinned " + name, file=sys.stderr)
    fd, temporary = tempfile.mkstemp(prefix=".download-", dir=cache)
    try:
        request = urllib.request.Request(expected["url"], headers={"User-Agent": "Codexploit-Joern-Packager"})
        with os.fdopen(fd, "wb") as target, urllib.request.urlopen(request, timeout=60) as source:
            total = 0
            while block := source.read(1 << 20):
                total += len(block)
                if total > expected["bytes"]:
                    raise ValueError("integrity_mismatch")
                target.write(block)
        verify(Path(temporary), expected)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return path


def safe(name):
    return (name and not name.startswith("/") and "\\" not in name and ":" not in name
            and not any(x in name for x in ["\x00", "\r", "\n"])
            and all(p not in ("", ".", "..") for p in name.split("/")))


def unpack_joern(archive, destination):
    with zipfile.ZipFile(archive) as bundle:
        selected = []
        for entry in bundle.infolist():
            name = entry.filename
            if not (name.startswith("joern-cli/")) or entry.is_dir():
                continue
            mode = entry.external_attr >> 16
            if not safe(name) or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                raise ValueError("unsafe_distribution_entry")
            selected.append(entry)
        if len(selected) > 50000 or sum(e.file_size for e in selected) > 3 << 30:
            raise ValueError("distribution_budget_exceeded")
        seen = set()
        for entry in selected:
            if entry.filename.casefold() in seen:
                raise ValueError("duplicate_distribution_entry")
            seen.add(entry.filename.casefold())
            target = destination / "vendor" / PurePosixPath(entry.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(entry) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755 if entry.external_attr >> 16 & 0o111 else 0o644)


def unpack_jdk(archive, destination):
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        homes = [m.name[:-len("bin/java")] for m in members if m.name.endswith("/bin/java") and m.isfile()]
        if len(homes) != 1:
            raise ValueError("unsupported_jdk_layout")
        home = homes[0]
        index = {m.name: m for m in members}
        seen = set()
        total = 0
        for member in members:
            if not member.name.startswith(home) or member.isdir():
                continue
            name = member.name[len(home):]
            if name == "lib/src.zip":
                continue
            if not safe(name) or name.casefold() in seen:
                raise ValueError("unsafe_distribution_entry")
            seen.add(name.casefold())
            resolved = member
            links = set()
            # Materialize only in-archive links within JAVA_HOME as regular
            # files; the installed package itself contains no symlinks.
            while resolved.issym() or resolved.islnk():
                if resolved.name in links:
                    raise ValueError("cyclic_distribution_link")
                links.add(resolved.name)
                target = (posixpath.join(posixpath.dirname(resolved.name), resolved.linkname)
                          if resolved.issym() else resolved.linkname)
                target = posixpath.normpath(target)
                if not target.startswith(home) or target not in index:
                    raise ValueError("escaping_distribution_link")
                resolved = index[target]
            if not resolved.isfile():
                raise ValueError("unsafe_distribution_entry")
            total += resolved.size
            if total > 1 << 30 or len(seen) > 20000:
                raise ValueError("distribution_budget_exceeded")
            target = destination / "vendor" / "jdk" / PurePosixPath(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.extractfile(resolved) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755 if resolved.mode & 0o111 else 0o644)


def unpack_rust(archives, destination):
    # Materialize compiler components directly; upstream install.sh is not run.
    for component, archive in archives.items():
        with tarfile.open(archive) as bundle:
            members = bundle.getmembers()
            total = 0
            for member in members:
                parts = member.name.split("/", 2)
                if len(parts) == 2 and member.isfile() and parts[1] in ["LICENSE-APACHE", "LICENSE-MIT", "LICENSE-THIRD-PARTY", "COPYRIGHT"]:
                    license_target = destination / "vendor/rust/licenses" / component / parts[1]
                    license_target.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.extractfile(member) as source:
                        license_target.write_bytes(source.read())
                if len(parts) != 3 or not (parts[1] == component or parts[1].startswith(component + "-")) or member.isdir():
                    continue
                name = parts[2]
                if name in ["manifest.in"]:
                    continue
                if not safe(name) or not member.isfile():
                    raise ValueError("unsafe_distribution_entry")
                total += member.size
                if total > 1 << 30:
                    raise ValueError("distribution_budget_exceeded")
                target = destination / "vendor/rust" / PurePosixPath(name)
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as source:
                    data = source.read()
                if target.exists():
                    if target.read_bytes() != data:
                        raise ValueError("duplicate_distribution_entry")
                else:
                    target.write_bytes(data)
                    target.chmod(0o755 if member.mode & 0o111 else 0o644)


def build_php(archive, destination):
    with tempfile.TemporaryDirectory(prefix="joern-php-") as temporary:
        source_root = Path(temporary)
        with tarfile.open(archive) as bundle:
            members = bundle.getmembers()
            if len(members) > 64000 or sum(m.size for m in members) > 256 << 20:
                raise ValueError("distribution_budget_exceeded")
            for member in members:
                name = member.name.rstrip("/")
                if not safe(name) or not (member.isfile() or member.isdir()):
                    raise ValueError("unsafe_distribution_entry")
            # Manual extraction also works with Python 3.11 before the
            # tarfile filter backport. All members were validated above.
            for member in members:
                target = source_root / PurePosixPath(member.name.rstrip("/"))
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.extractfile(member) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)
                    target.chmod(0o755 if member.mode & 0o111 else 0o644)
        roots = list(source_root.iterdir())
        if len(roots) != 1:
            raise ValueError("unsupported_php_layout")
        source = roots[0]
        arguments = ["./configure", "--disable-all", "--enable-cli", "--enable-tokenizer", "--enable-phar", "--enable-ctype", "--enable-filter", "--disable-cgi", "--disable-phpdbg", "--without-pear", "--without-iconv"]
        # Compiler diagnostics can contain absolute build paths; never stream
        # those into package metadata or the product UI.
        with (source_root / "build.log").open("wb") as log:
            subprocess.run(arguments, cwd=source, stdout=log, stderr=log, check=True)
            subprocess.run(["make", "-j" + str(min(os.cpu_count() or 2, 8))], cwd=source, stdout=log, stderr=log, check=True)
        target = destination / "vendor/php/bin/php"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / "sapi/cli/php", target)
        target.chmod(0o755)
        (destination / "vendor/php/LICENSE").write_bytes((source / "LICENSE").read_bytes())


def build_ghidra_arm(archive, destination):
    # The upstream shaded Ghidra JAR omits Linux ARM64's decompiler.
    # Compile exactly the source commit named by that JAR, then add only the
    # missing native resource. All resulting bytes are sealed in files.lock.
    with tempfile.TemporaryDirectory(prefix="joern-ghidra-") as temporary:
        root = Path(temporary)
        with tarfile.open(archive) as bundle:
            prefix = None
            members = bundle.getmembers()
            for member in members:
                if member.name.endswith("/Ghidra/Features/Decompiler/src/decompile/cpp/Makefile"):
                    prefix = member.name[:-len("Makefile")]
                    break
            if prefix is None:
                raise ValueError("unsupported_ghidra_layout")
            for member in members:
                if not member.name.startswith(prefix) or member.isdir():
                    continue
                name = member.name[len(prefix):]
                if not safe(name) or not member.isfile() or member.size > 16 << 20:
                    raise ValueError("unsafe_distribution_entry")
                target = root / PurePosixPath(name)
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
            license_member = next(m for m in members if m.name.count("/") == 1 and m.name.endswith("/LICENSE"))
            license_target = destination / "vendor/ghidra-native/LICENSE"
            license_target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.extractfile(license_member) as source:
                license_target.write_bytes(source.read())
        with (root / "build.log").open("wb") as log:
            subprocess.run(["make", "-j" + str(min(os.cpu_count() or 2, 8)), "ARCH_TYPE=", "OSDIR=linux_arm_64", "ghidra_opt"], cwd=root, stdout=log, stderr=log, check=True)
        jars = list((destination / "vendor/joern-cli/frontends/ghidra2cpg/lib").glob("io.joern.ghidra-*.jar"))
        if len(jars) != 1:
            raise ValueError("unsupported_ghidra_layout")
        name = "_Root/Ghidra/Features/Decompiler/os/linux_arm_64/decompile"
        with zipfile.ZipFile(jars[0], "a", compression=zipfile.ZIP_DEFLATED) as jar:
            if name in jar.namelist():
                raise ValueError("duplicate_distribution_entry")
            info = zipfile.ZipInfo(name, date_time=(2026, 5, 28, 0, 0, 0))
            info.external_attr = (stat.S_IFREG | 0o755) << 16
            jar.writestr(info, (root / "ghidra_opt").read_bytes(), compress_type=zipfile.ZIP_DEFLATED)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache/codexploit/joern")
    parser.add_argument("--output", type=Path, default=REPO / "bin/plugin-packages/codexploit.joern@2.3.4")
    args = parser.parse_args()
    args.output = args.output.absolute()
    args.cache = args.cache.absolute()
    os_name = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "AMD64": "amd64"}.get(platform.machine())
    lock = json.loads((SPEC / "sources.lock.json").read_text())
    selected = lock["platforms"].get(str(os_name) + "/" + str(arch))
    if selected is None:
        raise ValueError("unsupported_platform")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("immutable_package_exists")
    args.cache.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    distribution = fetch(args.cache, f"joern-{os_name}-{arch}.zip", selected["joern"])
    jdk = fetch(args.cache, f"jdk-{os_name}-{arch}.tar.gz", selected["jdk"])
    license_file = fetch(args.cache, "joern-LICENSE", lock["license"])
    php = fetch(args.cache, "php-" + lock["php_version"] + ".tar.xz", lock["php"])
    rust = {name: fetch(args.cache, "rust-" + name + "-" + os_name + "-" + arch + ".tar.xz", item) for name, item in selected["rust"].items()}
    with tempfile.TemporaryDirectory(prefix=".joern-package-", dir=args.output.parent) as temporary:
        package = Path(temporary) / "package"
        package.mkdir()
        unpack_joern(distribution, package)
        unpack_jdk(jdk, package)
        unpack_rust(rust, package)
        build_php(php, package)
        if os_name == "linux" and arch == "arm64":
            ghidra_lock = json.loads((SPEC / "ghidra.lock.json").read_text())
            ghidra_source = fetch(args.cache, "ghidra-" + ghidra_lock["commit"] + ".tar.gz", ghidra_lock["source"])
            build_ghidra_arm(ghidra_source, package)
            shutil.copyfile(SPEC / "ghidra.lock.json", package / "ghidra.lock.json")
        java = subprocess.run([str(package / "vendor/jdk/bin/java"), "-version"], check=True, capture_output=True, text=True)
        if '"21.0.9"' not in java.stderr:
            raise ValueError("tool_version_mismatch")
        for tool, expected in [("php/bin/php", "PHP 8.5.12"), ("rust/bin/rustc", "rustc 1.95.0"), ("rust/bin/cargo", "cargo 1.95.0")]:
            probe = subprocess.run([str(package / "vendor" / tool), "--version"], check=True, capture_output=True, text=True)
            if not probe.stdout.startswith(expected):
                raise ValueError("tool_version_mismatch")
        (package / "bin").mkdir()
        (package / "scripts").mkdir()
        (package / "licenses").mkdir()
        for name in ["manifest.json", "sources.lock.json", "frontends.json", "rules.json", "java-sinks.json"]:
            shutil.copyfile(SPEC / name, package / name)
        for query in ["export.sc", "taint.sc"]:
            shutil.copyfile(SPEC / query, package / "scripts" / query)
        shutil.copyfile(license_file, package / "licenses/JOERN-LICENSE")
        subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(package / "bin/joern-adapter"), "./cmd/joern-adapter"], cwd=REPO, check=True)
        result = subprocess.run(["go", "run", "./cmd/pluginpack", "--directory", str(package), "--seal"], cwd=REPO, check=True, capture_output=True, text=True)
        release = json.loads(result.stdout)
        os.rename(package, args.output)
    print(json.dumps(release))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        # Avoid echoing arbitrary paths, command output, or host environment.
        code = str(error) if isinstance(error, ValueError) else type(error).__name__
        print("Joern packaging failed: " + code, file=sys.stderr)
        sys.exit(1)

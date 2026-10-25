#!/usr/bin/env python3
"""Check proposal fixtures locally; no tool execution or production API calls."""

import hashlib
import json
import re
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def safe_path(value):
    path = PurePosixPath(value)
    return (
        bool(value)
        and not path.is_absolute()
        and str(path) == value
        and all(part not in (".", "..") for part in path.parts)
        and not any(char in value for char in "\\:\x00\n\r")
    )


def check_ports(ports):
    names = [port["name"] for port in ports]
    require(len(names) == len(set(names)), "duplicate port name")
    for port in ports:
        require(port["cardinality"] in ("one", "many"), "invalid cardinality")
        require(isinstance(port["required"], bool), "invalid port required flag")
        require(re.fullmatch(r"[a-z][a-z0-9_-]*", port["name"]), "invalid port name")


def main():
    documents = {path: read(path) for path in ROOT.rglob("*.json")}
    registry = read(ROOT / "stages.json")
    stages = {entry["stage"]: entry for entry in registry["stages"]}
    require(len(stages) == len(registry["stages"]) == 10, "expected ten unique stages")
    require(len({entry["capability"] for entry in stages.values()}) == 9, "expected nine capabilities")
    manifests = sorted((ROOT / "manifests").glob("*.json"))
    require(len(manifests) == len(stages), "expected one manifest per stage")
    seen = set()
    for path in manifests:
        manifest = read(path)
        require(manifest["api_version"] == "codexploit/plugin/v2", "wrong manifest API")
        require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", manifest["version"]), "invalid version")
        for operation in manifest["operations"]:
            stage = operation["stage"]
            require(stage in stages and stage not in seen, "missing or duplicate stage")
            seen.add(stage)
            standard = stages[stage]
            require(operation["capability"] == standard["capability"], "capability mismatch")
            require(operation["profile"] == "standard", "wrong profile")
            for direction in ("inputs", "outputs"):
                require(operation[direction] == standard[direction], f"{stage}: wrong {direction}")
                check_ports(operation[direction])
            runtime = manifest["runtime"]
            if standard["transport"] == "plugin_execute":
                require(runtime["kind"] == "process", "wrong runtime")
                require(runtime["protocol"] in ("codexploit/process-plugin/v2", "codexploit/file-job/v1"), "wrong protocol")
                require(safe_path(runtime["entrypoint"]), "unsafe entrypoint")
            else:
                require(runtime["kind"] == standard["transport"], "domain transport mismatch")
    require(seen == set(stages), "uncovered stage")

    request = read(ROOT / "file-job.request.json")
    result = read(ROOT / "file-job.result.json")
    require(request["api_version"] == result["api_version"] == "codexploit/file-job/v1", "wrong file-job API")
    require(request["invocation_id"] == result["invocation_id"], "invocation mismatch")
    require(safe_path(request["output_directory"]), "unsafe output directory")
    require(result["status"] == "SUCCEEDED" and result["outputs"], "missing fixture output")
    standard = stages[request["stage"]]
    for direction, key, name in (("inputs", "inputs", "report.input.json"), ("outputs", "outputs", "report.md")):
        records = request[key] if direction == "inputs" else result[key]
        require(len(records) == len(standard[direction]) == 1, "fixture cardinality mismatch")
        record = records[0]
        port = standard[direction][0]
        require(record["port"] == port["name"], "wrong fixture port")
        require(record["kind"] == port["kind"] and record["schema_id"] == port["schema_id"], "fixture contract mismatch")
        require(safe_path(record["path"]), "unsafe artifact path")
        content = (ROOT / "fixtures" / name).read_bytes()
        require(record["bytes"] == len(content), "fixture size mismatch")
        require(record["sha256"] == hashlib.sha256(content).hexdigest(), "fixture digest mismatch")
    coverage = result["coverage"]
    require(coverage["seen"] == coverage["analyzed"] + coverage["skipped"] + coverage["failed"], "invalid coverage")

    recipe = read(ROOT / "joern.recipe.json")
    production = ROOT.parents[3] / recipe["manifest"]
    require(production.exists(), "missing production Joern manifest")
    joern = read(production)
    require(joern["id"] == recipe["plugin_id"] == "codexploit.joern", "incorrect production plugin")
    require(joern["version"] == recipe["version"], "incorrect Joern version")
    require({op["stage"]: op["id"] for op in joern["operations"]} == recipe["stage_operations"], "incorrect Joern operations")
    require(all(op["profile"] == "standard" for op in joern["operations"]), "Joern must provide standard facts")
    require(joern["runtime"]["protocol"] == recipe["transport"], "incorrect Joern transport")
    for key in ["dependency_lock", "frontend_catalog", "rules", "workflow"]:
        require((ROOT.parents[3] / recipe[key]).exists(), "missing production recipe input")

    schema = read(ROOT / "manifest.schema.json")
    require(schema["$schema"].endswith("/draft/2020-12/schema"), "wrong draft")
    for markdown in ROOT.parent.rglob("*.md"):
        for target in re.findall(r"\]\(([^)]+)\)", markdown.read_text(encoding="utf-8")):
            if "://" in target or target.startswith("#"):
                continue
            require((markdown.parent / target.split("#", 1)[0]).exists(), f"broken link in {markdown.name}: {target}")
    print(f"PASS: {len(documents)} JSON files, ten stage manifests, fixture hashes, Joern integration recipe and local links")
    print("This check does not certify production schema validation or tool readiness.")


if __name__ == "__main__":
    main()

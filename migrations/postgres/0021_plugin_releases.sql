CREATE TABLE plugin_releases (
    plugin_id TEXT NOT NULL,
    version TEXT NOT NULL,
    os TEXT NOT NULL,
    arch TEXT NOT NULL,
    build_id TEXT NOT NULL DEFAULT '',
    package_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (plugin_id, version, os, arch, build_id)
);
CREATE TABLE plugin_installations (
    installation_id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    version TEXT NOT NULL,
    package_digest TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    record_version BIGINT NOT NULL,
    enabled BOOLEAN NOT NULL,
    installed BOOLEAN NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX plugin_installations_release ON plugin_installations(plugin_id,version,package_digest);

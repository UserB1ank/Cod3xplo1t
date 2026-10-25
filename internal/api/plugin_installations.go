package api

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin"
)

func WithPluginPackageRoot(root string) Option { return func(s *Server) { s.PluginPackageRoot = root } }

func (s *Server) installationRepository(w http.ResponseWriter) (plugin.InstallationRepository, bool) {
	if s.PluginCatalog == nil {
		writePluginError(w, plugin.ErrUnsupported)
		return nil, false
	}
	repo, ok := s.PluginCatalog.Repository.(plugin.InstallationRepository)
	if !ok {
		writePluginError(w, plugin.ErrUnsupported)
	}
	return repo, ok
}

func (s *Server) handlePluginReleasesV2(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.installationRepository(w)
	if !ok {
		return
	}
	rows, err := repo.ListPluginReleases(r.Context(), r.PathValue("pluginID"), r.PathValue("pluginVersion"))
	if err != nil {
		writePluginError(w, err)
		return
	}
	writePluginV2JSON(w, 200, map[string]any{"api_version": "codexploit/v2", "releases": rows})
}

func (s *Server) handleRegisterReleaseV2(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.installationRepository(w)
	if !ok {
		return
	}
	var release plugin.Release
	if !s.decode(w, r, &release) {
		return
	}
	if (release.BuildID != "" && release.BuildID != release.PackageDigest) || release.PluginID != r.PathValue("pluginID") || release.PluginVersion != r.PathValue("pluginVersion") || (release.OS != "linux" && release.OS != "darwin" && release.OS != "windows") || (release.Arch != "amd64" && release.Arch != "arm64") {
		writePluginError(w, plugin.ErrInvalid)
		return
	}
	definition, err := s.PluginCatalog.Get(r.Context(), release.PluginID, release.PluginVersion)
	if err != nil {
		writePluginError(w, err)
		return
	}
	if definition.Manifest.APIVersion != plugin.DefinitionVersion || release.ManifestDigest != definition.ManifestDigest || len(release.PackageDigest) != 64 {
		writePluginError(w, plugin.ErrInvalid)
		return
	}
	if err = repo.PutPluginRelease(r.Context(), release); err != nil {
		writePluginError(w, err)
		return
	}
	writePluginV2JSON(w, 201, map[string]any{"api_version": "codexploit/v2", "releases": []plugin.Release{release}})
}

func (s *Server) handleListInstallationsV2(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.installationRepository(w)
	if !ok {
		return
	}
	rows, err := repo.ListPluginInstallations(r.Context())
	if err != nil {
		writePluginError(w, err)
		return
	}
	writePluginV2JSON(w, 200, map[string]any{"api_version": "codexploit/v2", "installations": rows})
}

func installationTag(row plugin.Installation) string {
	return fmt.Sprintf(`"installation-%s-v%d"`, row.ID, row.Version)
}

func (s *Server) installation(w http.ResponseWriter, r *http.Request) (plugin.Installation, plugin.InstallationRepository, bool) {
	repo, ok := s.installationRepository(w)
	if !ok {
		return plugin.Installation{}, nil, false
	}
	rows, err := repo.ListPluginInstallations(r.Context())
	if err != nil {
		writePluginError(w, err)
		return plugin.Installation{}, nil, false
	}
	for _, row := range rows {
		if row.ID == r.PathValue("installationID") {
			return row, repo, true
		}
	}
	writePluginError(w, plugin.ErrNotFound)
	return plugin.Installation{}, nil, false
}

func (s *Server) findDeployedPackage(release plugin.Release) (plugin.Package, error) {
	if s.PluginPackageRoot == "" {
		return plugin.Package{}, plugin.ErrUnsupported
	}
	if release.OS != runtime.GOOS || release.Arch != runtime.GOARCH {
		return plugin.Package{}, plugin.ErrUnsupported
	}
	packages, err := plugin.DiscoverPackages(s.PluginPackageRoot)
	if err != nil {
		return plugin.Package{}, err
	}
	for _, pkg := range packages {
		if pkg.Manifest.ID == release.PluginID && pkg.Manifest.Version == release.PluginVersion && pkg.PackageDigest == release.PackageDigest && pkg.ManifestDigest == release.ManifestDigest {
			return pkg, nil
		}
	}
	return plugin.Package{}, plugin.ErrNotFound
}

func (s *Server) handleInstallPluginV2(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.installationRepository(w)
	if !ok {
		return
	}
	var release plugin.Release
	if !s.decode(w, r, &release) {
		return
	}
	definition, err := s.PluginCatalog.Get(r.Context(), release.PluginID, release.PluginVersion)
	if err != nil {
		writePluginError(w, err)
		return
	}
	if definition.Manifest.APIVersion != plugin.DefinitionVersion || release.ManifestDigest != definition.ManifestDigest {
		writePluginError(w, plugin.ErrConflict)
		return
	}
	pkg, err := s.findDeployedPackage(release)
	if err != nil {
		writePluginError(w, err)
		return
	}
	if s.Plugins == nil {
		writePluginError(w, plugin.ErrUnsupported)
		return
	}
	executors, err := processplugin.PackageExecutors(pkg)
	if err != nil {
		writePluginError(w, err)
		return
	}
	if err = s.Plugins.AddExecutors(r.Context(), executors); err != nil {
		writePluginError(w, err)
		return
	}
	rows, err := repo.ListPluginInstallations(r.Context())
	if err != nil {
		writePluginError(w, err)
		return
	}
	id := plugin.InstallationID(release, s.PluginCatalog.WorkerID)
	for _, row := range rows {
		if row.ID == id {
			if !row.Installed {
				expected := row.Version
				row.Version++
				row.Installed = true
				row.Integrity = "verified"
				row.Probe = "not_run"
				row, err = repo.SavePluginInstallation(r.Context(), row, expected)
				if err != nil {
					writePluginError(w, err)
					return
				}
			}
			w.Header().Set("ETag", installationTag(row))
			writePluginV2JSON(w, 201, map[string]any{"api_version": "codexploit/v2", "installation": row})
			return
		}
	}
	writePluginError(w, plugin.ErrNotFound)
}

func (s *Server) handleCheckInstallationV2(w http.ResponseWriter, r *http.Request) {
	row, repo, ok := s.installation(w, r)
	if !ok {
		return
	}
	if !requireEntityVersion(w, r, installationTag(row)) {
		return
	}
	if row.WorkerID != s.PluginCatalog.WorkerID {
		writePluginError(w, plugin.ErrUnsupported)
		return
	}
	_, checkErr := s.findDeployedPackage(row.Release)
	if row.Release.BuildID != "" {
		record, err := s.PluginCatalog.Get(r.Context(), row.Release.PluginID, row.Release.PluginVersion)
		checkErr = err
		if err == nil && record.PackageDigest != row.Release.PackageDigest {
			checkErr = plugin.ErrConflict
		}
	}
	expected := row.Version
	row.Version++
	row.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	row.Integrity = "verified"
	row.Reason = ""
	if checkErr != nil {
		row.Integrity = "failed"
		row.Reason = "Deployed package missing or integrity check failed"
	}
	row, err := repo.SavePluginInstallation(r.Context(), row, expected)
	if err != nil {
		writePluginError(w, err)
		return
	}
	w.Header().Set("ETag", installationTag(row))
	writePluginV2JSON(w, 200, map[string]any{"api_version": "codexploit/v2", "installation": row})
}

func (s *Server) handleInstallationPolicyV2(w http.ResponseWriter, r *http.Request) {
	row, repo, ok := s.installation(w, r)
	if !ok {
		return
	}
	if !requireEntityVersion(w, r, installationTag(row)) {
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	if body.Enabled == nil || (*body.Enabled && (!row.Installed || row.Integrity != "verified")) {
		writePluginError(w, plugin.ErrInvalid)
		return
	}
	expected := row.Version
	row.Version++
	row.Enabled = *body.Enabled
	row, err := repo.SavePluginInstallation(r.Context(), row, expected)
	if err != nil {
		if errors.Is(err, plugin.ErrConflict) {
			writeError(w, 412, "precondition_failed", plugin.ErrConflict)
		} else {
			writePluginError(w, err)
		}
		return
	}
	w.Header().Set("ETag", installationTag(row))
	writePluginV2JSON(w, 200, map[string]any{"api_version": "codexploit/v2", "installation": row})
}

func (s *Server) handleUninstallPluginV2(w http.ResponseWriter, r *http.Request) {
	row, repo, ok := s.installation(w, r)
	if !ok {
		return
	}
	if !requireEntityVersion(w, r, installationTag(row)) {
		return
	}
	expected := row.Version
	row.Version++
	row.Enabled = false
	row.Installed = false
	row, err := repo.SavePluginInstallation(r.Context(), row, expected)
	if err != nil {
		writePluginError(w, err)
		return
	}
	w.Header().Set("ETag", installationTag(row))
	writePluginV2JSON(w, 200, map[string]any{"api_version": "codexploit/v2", "installation": row})
}

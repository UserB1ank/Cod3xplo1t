package processplugin

import (
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

// Executors discovers verified process packages below root and returns the
// compiled adapters for the supported v1 surface. A package that declares a
// capability this host cannot enforce is rejected instead of advertised.
func Executors(root string) ([]plugin.Executor, error) {
	packages, err := plugin.DiscoverPackages(root)
	if err != nil {
		return nil, err
	}
	executors := make([]plugin.Executor, 0, len(packages))
	for _, pkg := range packages {
		loaded, err := PackageExecutors(pkg)
		if err != nil {
			return nil, err
		}
		executors = append(executors, loaded...)
	}
	return executors, nil
}

// PackageExecutors builds adapters only for protocols this host implements.
func PackageExecutors(pkg plugin.Package) ([]plugin.Executor, error) {
	executors := []plugin.Executor{}
	if pkg.Manifest.APIVersion == plugin.DefinitionVersion {
		if pkg.Manifest.Runtime.Protocol != plugin.FileJobProtocol && pkg.Manifest.Runtime.Protocol != plugin.FileJobProtocolV2 && pkg.Manifest.Runtime.Protocol != plugin.ProcessProtocolV2 {
			return nil, plugin.ErrUnsupported
		}
		for _, op := range pkg.Manifest.Operations {
			if pkg.Manifest.Runtime.Protocol == plugin.FileJobProtocol || pkg.Manifest.Runtime.Protocol == plugin.FileJobProtocolV2 {
				executors = append(executors, fileJobExecutor(pkg, op))
			} else {
				executors = append(executors, streamExecutor(pkg, op))
			}
		}
		return executors, nil
	}
	if pkg.Manifest.Kind != "analyzer" ||
		len(pkg.Manifest.Consumes) != 1 || pkg.Manifest.Consumes[0] != "source.snapshot" ||
		len(pkg.Manifest.Produces) != 2 || !contains(pkg.Manifest.Produces, "scanner.alerts") || !contains(pkg.Manifest.Produces, "security.facts") ||
		!contains(pkg.Manifest.Languages, "Go") {
		return nil, plugin.ErrUnsupported
	}
	adapter := Adapter{
		Package:          &pkg,
		Executable:       pkg.Executable,
		Directory:        pkg.Directory,
		Manifest:         pkg.Manifest,
		ManifestDigest:   pkg.ManifestDigest,
		PackageDigest:    pkg.PackageDigest,
		ExecutableSHA256: pkg.ExecutableSHA256,
		ExecutableBytes:  pkg.ExecutableBytes,
	}
	executors = append(executors, plugin.Executor{
		Manifest:       pkg.RawManifest,
		PackageDigest:  pkg.PackageDigest,
		ManifestDigest: pkg.ManifestDigest,
		Source:         "compiled package " + pkg.Manifest.ID + "@" + pkg.Manifest.Version,
		InputSchemas:   []string{"codexploit/source-tar/v1"},
		InputPlugins:   []string{""},
		Run:            adapter.Run,
		Normalize:      Normalize,
		NativeKind:     "scanner.alerts",
		NativeSchema:   "codexploit/scanner-alerts/v1",
	})
	return executors, nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

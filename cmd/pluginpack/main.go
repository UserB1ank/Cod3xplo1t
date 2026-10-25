// pluginpack seals and verifies an offline plugin package without executing it.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("pluginpack", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "package directory")
	seal := flags.Bool("seal", false, "create a new immutable files.lock.json")
	if err := flags.Parse(args); err != nil {
		return errors.New("usage: pluginpack --directory <package> [--seal]")
	}
	if *directory == "" || flags.NArg() != 0 {
		return plugin.ErrInvalid
	}
	if *seal {
		lock, err := plugin.BuildFilesLock(*directory)
		if err != nil {
			return err
		}
		path := filepath.Join(*directory, "files.lock.json")
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			prior, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(prior, lock) {
				return plugin.ErrConflict
			}
		} else if err != nil {
			return err
		} else {
			_, writeErr := file.Write(lock)
			closeErr := file.Close()
			if writeErr != nil {
				return writeErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
	pkg, err := plugin.LoadPackage(*directory)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(plugin.Release{BuildID: pkg.PackageDigest, PluginID: pkg.Manifest.ID, PluginVersion: pkg.Manifest.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, PackageDigest: pkg.PackageDigest, ManifestDigest: pkg.ManifestDigest})
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "plugin package verification failed")
		os.Exit(1)
	}
}

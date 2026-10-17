//go:build !embedui

package webui

import (
	"errors"
	"io/fs"
)

func assets() (fs.FS, error) { return nil, errors.New("web UI is not embedded; run make build") }

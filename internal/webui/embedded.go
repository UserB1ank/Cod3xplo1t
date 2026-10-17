//go:build embedui

package webui

import (
	"github.com/open-mcp-ai/Codexploit/web"
	"io/fs"
)

func assets() (fs.FS, error) { return fs.Sub(web.Assets, "dist") }

//go:build embedui

// Package web contains the frontend bundled by make build.
package web

import "embed"

// Assets is populated only after the frontend build has succeeded.
//
//go:embed dist
var Assets embed.FS

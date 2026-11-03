// Package webassets holds the dashboard HTML and its same-origin assets. The
// panel/web directory is the embed root so the files sit next to this package
// rather than under internal/web.
package webassets

import (
	"embed"
	"io/fs"
)

// FS is the raw embedded filesystem: the dashboard and login shells plus the
// assets subtree.
//
//go:embed dashboard.html login.html assets
var FS embed.FS

// Assets is the filesystem served under /assets/.
var Assets, _ = fs.Sub(FS, "assets")

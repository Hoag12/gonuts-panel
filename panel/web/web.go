// Package webassets holds the embedded dashboard files. Task 9 adds the
// embed directives and the actual HTML/CSS/JS assets.
package webassets

import (
	"embed"
	"io/fs"
)

// FS is the raw embedded filesystem.
var FS embed.FS

// Assets is the filesystem served under /assets/ and read for dashboard
// templates.
var Assets fs.FS

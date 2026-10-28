// Package web embeds the browser UI.
package web

import "embed"

// Static holds index.html, styles and ES modules under static/.
//
//go:embed static
var Static embed.FS

// Package web embeds the built SPA (web/dist) into the server binary.
package web

import "embed"

// Dist holds the Vite build output. `make web` populates it; a placeholder
// keeps the package buildable without Node.
//
//go:embed all:dist
var Dist embed.FS

//go:build webapp

package webassets

import "embed"

//go:embed all:dist
var files embed.FS

const root = "dist"

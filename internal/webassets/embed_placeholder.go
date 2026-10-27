//go:build !webapp

package webassets

import "embed"

//go:embed placeholder
var files embed.FS

const root = "placeholder"

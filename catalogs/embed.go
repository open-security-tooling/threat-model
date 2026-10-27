// Package catalogs holds the built-in threat library. Each .yaml file is
// one catalog; see docs/threat-library.md for the format and writing rules.
package catalogs

import "embed"

//go:embed *.yaml
var FS embed.FS

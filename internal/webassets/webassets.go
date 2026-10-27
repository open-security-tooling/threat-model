// Package webassets embeds the built web app for `threat serve`.
//
// Release builds use `-tags webapp` and embed dist/, which `make web-release`
// fills and git ignores completely. Other builds (including `go install`) embed
// placeholder/, a page that explains how to get the web app. Keeping build output
// out of tracked paths means release binaries aren't stamped vcs.modified=true.
package webassets

import "io/fs"

// FS returns the web app's files, rooted at index.html.
func FS() fs.FS {
	sub, err := fs.Sub(files, root)
	if err != nil {
		panic(err)
	}
	return sub
}

package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-security-tooling/threat-model/internal/model"
)

// ReadCustom reads the custom catalog files a model refers to. Paths are
// relative to root and must stay inside it, even through symlinks: model
// files arrive in pull requests.
func ReadCustom(root string, refs []model.CatalogRef) (map[string]string, error) {
	out := map[string]string{}
	absRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("repository root %s not found", root)
	}
	for _, ref := range refs {
		if ref.Path == "" {
			continue
		}
		clean := filepath.Clean(filepath.FromSlash(ref.Path))
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("catalog %s must be inside the repository", ref.Path)
		}
		real, err := filepath.EvalSymlinks(filepath.Join(absRoot, clean))
		if err != nil {
			return nil, fmt.Errorf("catalog %s doesn't exist", ref.Path)
		}
		if rel, err := filepath.Rel(absRoot, real); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("catalog %s points outside the repository", ref.Path)
		}
		info, err := os.Stat(real)
		if err != nil || info.IsDir() || info.Size() > int64(model.DefaultLimits.MaxBytes) {
			return nil, fmt.Errorf("catalog %s isn't a readable file under the size limit", ref.Path)
		}
		b, err := os.ReadFile(real)
		if err != nil {
			return nil, err
		}
		out[ref.Path] = string(b)
	}
	return out, nil
}

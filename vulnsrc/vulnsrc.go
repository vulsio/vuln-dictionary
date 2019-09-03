package vulnsrc

import (
	"log"
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/vulsio/vuln-dictionary/util"
	"github.com/vulsio/vuln-dictionary/vulnsrc/nvd"
	"github.com/vulsio/vuln-dictionary/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

const (
	repoURL = "https://github.com/vulsio/vuln-list.git"
)

type updateFunc func(dir string, updatedFiles map[string]struct{}) error

var (
	// UpdateList has list of update distributions
	UpdateList []string
	updateMap  = map[string]updateFunc{
		vulnerability.Nvd: nvd.Update,
		//	vulnerability.Alpine:     alpine.Update,
		//	vulnerability.RedHat:     redhat.Update,
		//	vulnerability.Debian:     debian.Update,
		//	vulnerability.DebianOVAL: debianoval.Update,
		//	vulnerability.Ubuntu:     ubuntu.Update,
	}
)

func init() {
	UpdateList = make([]string, 0, len(updateMap))
	for distribution := range updateMap {
		UpdateList = append(UpdateList, distribution)
	}
}

// Update :
func Update(names []string) error {
	log.Println("Updating vulnerability database...")

	// Clone vuln-list repository
	dir := filepath.Join(util.CacheDir(), "vuln-list")
	updatedFiles, err := git.CloneOrPull(repoURL, dir)
	if err != nil {
		return xerrors.Errorf("error in vulnsrc clone or pull: %w", err)
	}
	log.Println("total updated files: %d", len(updatedFiles))

	// Only last_updated.json
	if len(updatedFiles) <= 1 {
		return nil
	}

	for _, distribution := range names {
		updateFunc, ok := updateMap[distribution]
		if !ok {
			return xerrors.Errorf("%s does not supported yet", distribution)
		}
		log.Printf("Updating %s data...", distribution)
		if err := updateFunc(dir, updatedFiles); err != nil {
			return xerrors.Errorf("error in %s update: %w", distribution, err)
		}
	}
	return nil
}

package nvd

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"path/filepath"

	bolt "github.com/etcd-io/bbolt"
	"github.com/vulsio/vuln-dictionary/db"
	"github.com/vulsio/vuln-dictionary/util"
	"github.com/vulsio/vuln-dictionary/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

const (
	nvdDir = "nvd"
)

// Update :
func Update(dir string, updatedFiles map[string]struct{}) error {
	rootDir := filepath.Join(dir, nvdDir)
	targets, err := util.FilterTargets(nvdDir, updatedFiles)
	if err != nil {
		return xerrors.Errorf("failed to filter target files: %w", err)
	} else if len(targets) == 0 {
		log.Println("NVD: no updated file")
		return nil
	}
	log.Printf("NVD updated files: %d", len(targets))

	var items []RawCveItem
	bar := util.PbStartNew(len(targets))
	{
		defer bar.Finish()
		buffer := &bytes.Buffer{}
		err = util.FileWalk(rootDir, targets, func(r io.Reader, _ string) error {
			item := RawCveItem{}
			if _, err := buffer.ReadFrom(r); err != nil {
				return xerrors.Errorf("failed to read file: %w", err)
			}
			if err := json.Unmarshal(buffer.Bytes(), &item); err != nil {
				return xerrors.Errorf("failed to decode NVD JSON: %w", err)
			}
			buffer.Reset()
			items = append(items, item)
			bar.Increment()
			return nil
		})
		if err != nil {
			return xerrors.Errorf("error in NVD walk: %w", err)
		}
	}
	if err = save(items); err != nil {
		return xerrors.Errorf("error in NVD save: %w", err)
	}

	return nil
}

func save(items []RawCveItem) error {
	log.Println("NVD batch update")
	err := vulnerability.BatchUpdate(func(b *bolt.Bucket) (err error) {
		for _, item := range items {
			cveID := item.Cve.CveDataMeta.ID
			var vuln *Nvd
			if vuln, err = ConvertToModel(&item); err != nil {
				return err
			}
			if err := db.Put(b, cveID, vulnerability.Nvd, vuln); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

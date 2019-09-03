package vulnsrc

import (
	"path/filepath"
	"testing"

	"github.com/vulsio/vuln-dictionary/db"
	"github.com/vulsio/vuln-dictionary/git"
	"github.com/vulsio/vuln-dictionary/util"
	"github.com/vulsio/vuln-dictionary/vulnsrc/vulnerability"
)

func BenchmarkUpdate(b *testing.B) {
	util.Quiet = true
	if err := db.Init(); err != nil {
		b.Fatal(err)
	}
	dir := filepath.Join(util.CacheDir(), "vuln-list")
	if _, err := git.CloneOrPull(repoURL, dir); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	b.Run("NVD", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := db.SetVersion(""); err != nil {
				b.Fatal(err)
			}
			if err := Update([]string{vulnerability.Nvd}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

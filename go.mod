module github.com/vulsio/vuln-dictionary

go 1.12

require (
	cloud.google.com/go v0.41.0 // indirect
	github.com/aquasecurity/vuln-list-update v0.0.0-20190819085415-c2e78f32795d
	github.com/briandowns/spinner v0.0.0-20190319032542-ac46072a5a91
	github.com/elazarl/goproxy v0.0.0-20190703090003-6125c262ffb0 // indirect
	github.com/elazarl/goproxy/ext v0.0.0-20190703090003-6125c262ffb0 // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/etcd-io/bbolt v1.3.3
	github.com/fatih/color v1.7.0
	github.com/gliderlabs/ssh v0.1.3 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20190430165422-3e4dfb77656c // indirect
	github.com/jinzhu/gorm v1.9.10
	github.com/k0kubun/colorstring v0.0.0-20150214042306-9440f1994b88 // indirect
	github.com/k0kubun/pp v3.0.1+incompatible
	github.com/knqyf263/go-cpe v0.0.0-20180327054844-659663f6eca2
	github.com/knqyf263/go-version v1.1.1
	github.com/mattn/go-colorable v0.1.2 // indirect
	github.com/mattn/go-isatty v0.0.9 // indirect
	github.com/mattn/go-sqlite3 v1.11.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/smartystreets/assertions v1.0.0 // indirect
	github.com/stretchr/testify v1.3.0 // indirect
	github.com/xanzy/ssh-agent v0.2.1 // indirect
	go.etcd.io/bbolt v1.3.3 // indirect
	golang.org/x/crypto v0.0.0-20190701094942-4def268fd1a4 // indirect
	golang.org/x/net v0.0.0-20190628185345-da137c7871d7 // indirect
	golang.org/x/xerrors v0.0.0-20190717185122-a985d3407aa7
	gopkg.in/cheggaaa/pb.v1 v1.0.28
	gopkg.in/src-d/go-billy.v4 v4.3.0 // indirect
	gopkg.in/src-d/go-git-fixtures.v3 v3.4.0 // indirect
	gopkg.in/src-d/go-git.v4 v4.10.0
)

replace (
	github.com/genuinetools/reg => github.com/tomoyamachi/reg v0.16.1-0.20190706172545-2a2250fd7c00
	gopkg.in/mattn/go-colorable.v0 => github.com/mattn/go-colorable v0.1.0
	gopkg.in/mattn/go-isatty.v0 => github.com/mattn/go-isatty v0.0.6
)

module github.com/NakliTechie/crate-agent

go 1.26.2

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/NakliTechie/private-mesh/fabric-sdk-go v0.0.0-00010101000000-000000000000
	github.com/fsnotify/fsnotify v1.10.1
	github.com/oklog/ulid/v2 v2.1.1
	github.com/spf13/cobra v1.10.2
	golang.org/x/crypto v0.51.0
	golang.org/x/term v0.43.0
	modernc.org/sqlite v1.50.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	golang.org/x/sys v0.44.0 // indirect
	gopkg.in/macaroon.v2 v2.1.0 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// Local-dev replace for the sibling private-mesh repo. Migration path:
// when fabric-sdk-go publishes a tagged version, drop this `replace` and
// pin the version in `require`.
replace github.com/NakliTechie/private-mesh/fabric-sdk-go => ../private-mesh/fabric-sdk-go

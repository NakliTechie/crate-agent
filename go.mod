module github.com/NakliTechie/crate-agent

go 1.26.2

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/NakliTechie/private-mesh/fabric-sdk-go v0.0.0-00010101000000-000000000000
	github.com/oklog/ulid/v2 v2.1.1
	github.com/spf13/cobra v1.10.2
	golang.org/x/crypto v0.51.0
	golang.org/x/term v0.43.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	golang.org/x/sys v0.44.0 // indirect
)

// Local-dev replace for the sibling private-mesh repo. Migration path:
// when fabric-sdk-go publishes a tagged version, drop this `replace` and
// pin the version in `require`.
replace github.com/NakliTechie/private-mesh/fabric-sdk-go => ../private-mesh/fabric-sdk-go

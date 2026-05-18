// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"fmt"
	"os"

	"github.com/NakliTechie/crate-agent/cmd"
)

var version = "0.0.0-m0"

func main() {
	cmd.SetVersion(version)
	if err := cmd.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

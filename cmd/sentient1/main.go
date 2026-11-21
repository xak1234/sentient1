// Command sentient1 catches infostealers in the act: it plants decoy files and
// fake app data, watches them with Windows file auditing, and freezes and
// cuts off anything suspicious that reads them.
package main

import (
	"os"

	"github.com/xak1234/sentient1/internal/cli"
)

// Set by the release build: -ldflags "-X main.version=v0.1.0"
var version = "dev"

func main() {
	cli.Version = version
	os.Exit(cli.Execute())
}

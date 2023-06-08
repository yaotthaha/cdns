package constant

import (
	"fmt"
)

var Version = "unknown"

var Commit = ""

func GetVersion() string {
	if Commit != "" {
		return fmt.Sprintf("cdns version %s, commit: %s", Version, Commit)
	}
	return fmt.Sprintf("cdns version %s", Version)
}

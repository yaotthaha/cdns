package constant

import "fmt"

const Version = "v0.0.1-alpha-2"

var Commit = ""

func GetVersion() string {
	if Commit != "" {
		return fmt.Sprintf("cdns version %s, commit: %s", Version, Commit)
	}
	return fmt.Sprintf("cdns version %s", Version)
}

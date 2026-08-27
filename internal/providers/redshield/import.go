package redshield

import "github.com/vsevo/home-gateway/internal/providers/configfile"

type Config = configfile.Config

func ImportFile(path string) (Config, error) {
	return configfile.ImportFile(path, "redshield")
}

func ImportFilePinned(path, expectedSHA256 string) (Config, error) {
	return configfile.ImportFilePinned(path, expectedSHA256, "redshield")
}

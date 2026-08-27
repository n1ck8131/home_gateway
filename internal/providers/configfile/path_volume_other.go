//go:build !windows

package configfile

func validateLocalConfigVolume(string) error {
	return nil
}

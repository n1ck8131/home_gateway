//go:build !windows

package redshield

func validateLocalConfigVolume(string) error {
	return nil
}

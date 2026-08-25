//go:build windows

package windows

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	xwindows "golang.org/x/sys/windows"
)

const canaryInstalledExecutableName = "hgctl.exe"

// ProductionCanaryStateRoot resolves the only privileged state location that
// P3.5 accepts. It does not trust ProgramData from the process environment.
func ProductionCanaryStateRoot() (string, error) {
	programData, err := xwindows.KnownFolderPath(xwindows.FOLDERID_ProgramData, xwindows.KF_FLAG_DEFAULT)
	if err != nil || programData == "" {
		return "", errors.New("resolve trusted ProgramData known folder")
	}
	return filepath.Join(programData, "HomeGateway", "P35"), nil
}

// ValidateProductionCanaryStateRoot rejects UNC, device, alternate and
// user-chosen roots. Privileged P3.5 state is deliberately fixed to one local
// dedicated directory so parent ownership can be validated and recovered.
func ValidateProductionCanaryStateRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Dir(root) == root || strings.HasPrefix(root, `\\`) {
		return errors.New("P3.5 state root must be the clean local production path")
	}
	want, err := ProductionCanaryStateRoot()
	if err != nil {
		return err
	}
	if !strings.EqualFold(root, want) {
		return errors.New("P3.5 state root differs from the dedicated ProgramData path")
	}
	return nil
}

// ValidateProductionCanaryPlanRoot performs no filesystem access. Planning is
// intentionally supported from a UAC-filtered non-elevated token even after
// the SYSTEM/Administrators-only production root has been staged. Every live
// action revalidates the same fixed path and its protected ACL before I/O.
func ValidateProductionCanaryPlanRoot(root string) error {
	return ValidateProductionCanaryStateRoot(root)
}

// ValidateProductionCanaryStateAccessRoot is the fail-fast validator used by
// every privileged CLI action before journal or revision I/O. An absent root
// is valid for read-only plan/status, but every existing ancestor must remain
// local and non-reparse; an existing root must also satisfy the protected
// SYSTEM/Administrators ownership contract.
func ValidateProductionCanaryStateAccessRoot(root string) error {
	if err := ValidateProductionCanaryStateRoot(root); err != nil {
		return err
	}
	volume := filepath.VolumeName(root)
	current := volume + string(filepath.Separator)
	components := strings.FieldsFunc(strings.TrimPrefix(root, volume), func(character rune) bool {
		return character == '\\' || character == '/'
	})
	for _, component := range components {
		current = filepath.Join(current, component)
		pointer, err := xwindows.UTF16PtrFromString(current)
		if err != nil {
			return errors.New("P3.5 state root ancestor is invalid")
		}
		attributes, err := xwindows.GetFileAttributes(pointer)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || attributes&xwindows.FILE_ATTRIBUTE_DIRECTORY == 0 || attributes&xwindows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("P3.5 state root ancestor is unsafe")
		}
	}
	return validateProtectedNativeRoot(root)
}

func canaryInstalledExecutable(root string) string {
	return filepath.Join(root, "bin", canaryInstalledExecutableName)
}

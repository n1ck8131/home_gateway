//go:build windows

package windows

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	xwindows "golang.org/x/sys/windows"
)

func configACLIdentity(path string) (string, error) {
	descriptor, err := xwindows.GetNamedSecurityInfo(path, xwindows.SE_FILE_OBJECT, xwindows.OWNER_SECURITY_INFORMATION|xwindows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return "", errors.New("inspect protected config ACL")
	}
	sddl := descriptor.String()
	if sddl == "" {
		return "", errors.New("inspect protected config ACL")
	}
	digest := sha256.Sum256([]byte(sddl))
	return fmt.Sprintf("%x", digest[:]), nil
}

const canaryInstalledConfigPinName = "tunnel.sha256"

func ValidateProductionCanaryInstalledConfigSource(path, expectedSHA256 string) error {
	root, err := ProductionCanaryStateRoot()
	if err != nil {
		return err
	}
	installed := filepath.Join(root, "secrets", "tunnel.conf")
	if !strings.EqualFold(path, installed) {
		return errors.New("live P3 requires the protected installed tunnel config")
	}
	if len(expectedSHA256) != 64 {
		return errors.New("installed P3.5 config SHA-256 is invalid")
	}
	for _, character := range expectedSHA256 {
		if character < '0' || character > '9' && (character < 'a' || character > 'f') {
			return errors.New("installed P3.5 config SHA-256 is invalid")
		}
	}
	if err := ValidateProductionCanaryConfigSource(path); err != nil {
		return err
	}
	pin := filepath.Join(root, "secrets", canaryInstalledConfigPinName)
	if err := validateCanaryConfigPath(pin); err != nil {
		return errors.New("installed P3.5 config pin is unsafe")
	}
	descriptor, err := xwindows.GetNamedSecurityInfo(pin, xwindows.SE_FILE_OBJECT, xwindows.OWNER_SECURITY_INFORMATION|xwindows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return errors.New("read installed P3.5 config pin security descriptor")
	}
	if err := validateInstalledCanaryConfigSecurityDescriptor(descriptor); err != nil {
		return errors.New("installed P3.5 config pin ACL differs")
	}
	// #nosec G304 -- pin path is derived from the validated production canary state root and fixed filename.
	data, err := os.ReadFile(pin)
	if err != nil || len(data) != 64 || subtle.ConstantTimeCompare(data, []byte(expectedSHA256)) != 1 {
		return errors.New("installed P3.5 config pin differs")
	}
	return nil
}

// ValidateProductionCanaryConfigSource ensures privileged live commands never
// read provider key material from a broad, inherited, remote, or reparse-backed
// ACL. Read-only development callers may still inspect such a source, but it is
// not eligible for the production canary gate.
func ValidateProductionCanaryConfigSource(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, `\\`) {
		return errors.New("P3.5 config source must be one clean local absolute path")
	}
	if err := validateCanaryConfigPath(path); err != nil {
		return err
	}
	root, rootErr := ProductionCanaryStateRoot()
	installed := rootErr == nil && strings.EqualFold(path, filepath.Join(root, "secrets", "tunnel.conf"))
	if installed {
		if err := ValidateProductionCanaryStateAccessRoot(root); err != nil {
			return err
		}
	}
	descriptor, err := xwindows.GetNamedSecurityInfo(path, xwindows.SE_FILE_OBJECT, xwindows.OWNER_SECURITY_INFORMATION|xwindows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return errors.New("read P3.5 config source security descriptor")
	}
	if installed {
		return validateInstalledCanaryConfigSecurityDescriptor(descriptor)
	}
	user, err := xwindows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return errors.New("resolve P3.5 config source caller identity")
	}
	return validateCanaryConfigSecurityDescriptor(descriptor, user.User.Sid.String())
}

func validateInstalledCanaryConfigSecurityDescriptor(descriptor *xwindows.SECURITY_DESCRIPTOR) error {
	if descriptor == nil {
		return errors.New("installed P3.5 config security descriptor is missing")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !nativePrivilegedSID(owner) {
		return errors.New("installed P3.5 config owner is not privileged")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("installed P3.5 config has no restrictive DACL")
	}
	// #nosec G103 -- DACL memory is returned by the Windows security descriptor API and size-checked before iteration.
	header := (*nativeACLHeader)(unsafe.Pointer(dacl))
	if header.ACECount > 4096 || header.Size < uint16(unsafe.Sizeof(nativeACLHeader{})) {
		return errors.New("installed P3.5 config DACL is invalid")
	}
	privilegedRead := false
	for index := uint32(0); index < uint32(header.ACECount); index++ {
		var ace *xwindows.ACCESS_ALLOWED_ACE
		if err := xwindows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return errors.New("inspect installed P3.5 config DACL")
		}
		switch ace.Header.AceType {
		case xwindows.ACCESS_DENIED_ACE_TYPE:
			continue
		case xwindows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return errors.New("installed P3.5 config DACL uses an unsupported ACE type")
		}
		// #nosec G103 -- ACE SID pointer is provided by GetAce and validated before use.
		sid := (*xwindows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !nativePrivilegedSID(sid) {
			return errors.New("installed P3.5 config grants non-privileged access")
		}
		if ace.Mask&(xwindows.GENERIC_READ|xwindows.FILE_READ_DATA) != 0 {
			privilegedRead = true
		}
	}
	if !privilegedRead {
		return errors.New("installed P3.5 config lacks privileged read access")
	}
	return nil
}

func validateCanaryConfigSecurityDescriptor(descriptor *xwindows.SECURITY_DESCRIPTOR, currentSID string) error {
	if descriptor == nil || currentSID == "" {
		return errors.New("P3.5 config source security identity is missing")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&xwindows.SE_DACL_PROTECTED == 0 {
		return errors.New("P3.5 config source inherits its DACL")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !canaryConfigSIDAllowed(owner, currentSID) {
		return errors.New("P3.5 config source owner is not trusted")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("P3.5 config source has no restrictive DACL")
	}
	// #nosec G103 -- DACL memory is returned by the Windows security descriptor API and size-checked before iteration.
	header := (*nativeACLHeader)(unsafe.Pointer(dacl))
	if header.ACECount > 4096 || header.Size < uint16(unsafe.Sizeof(nativeACLHeader{})) {
		return errors.New("P3.5 config source DACL is invalid")
	}
	currentUserCanRead := false
	for index := uint32(0); index < uint32(header.ACECount); index++ {
		var ace *xwindows.ACCESS_ALLOWED_ACE
		if err := xwindows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return errors.New("inspect P3.5 config source DACL")
		}
		switch ace.Header.AceType {
		case xwindows.ACCESS_DENIED_ACE_TYPE:
			continue
		case xwindows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return errors.New("P3.5 config source DACL uses an unsupported ACE type")
		}
		// #nosec G103 -- ACE SID pointer is provided by GetAce and validated before use.
		sid := (*xwindows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !canaryConfigSIDAllowed(sid, currentSID) {
			return errors.New("P3.5 config source grants an unauthorized principal")
		}
		if sid.String() == currentSID && ace.Mask&(xwindows.GENERIC_READ|xwindows.FILE_READ_DATA) != 0 {
			currentUserCanRead = true
		}
	}
	if !currentUserCanRead {
		return errors.New("P3.5 config source lacks explicit caller read access")
	}
	return nil
}

func validateCanaryConfigPath(path string) error {
	volume := filepath.VolumeName(path)
	if volume == "" {
		return errors.New("P3.5 config source volume is invalid")
	}
	current := volume + string(filepath.Separator)
	components := strings.FieldsFunc(strings.TrimPrefix(path, volume), func(character rune) bool {
		return character == '\\' || character == '/'
	})
	for index, component := range components {
		current = filepath.Join(current, component)
		pointer, err := xwindows.UTF16PtrFromString(current)
		if err != nil {
			return errors.New("P3.5 config source path is invalid")
		}
		attributes, err := xwindows.GetFileAttributes(pointer)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return errors.New("P3.5 config source is missing")
			}
			return errors.New("inspect P3.5 config source path")
		}
		if attributes&xwindows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("P3.5 config source path contains a reparse point")
		}
		last := index == len(components)-1
		if last && attributes&xwindows.FILE_ATTRIBUTE_DIRECTORY != 0 || !last && attributes&xwindows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return errors.New("P3.5 config source is not one regular file")
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("P3.5 config source is not one regular file")
	}
	return nil
}

func canaryConfigSIDAllowed(sid *xwindows.SID, currentSID string) bool {
	return sid != nil && (sid.String() == currentSID || nativePrivilegedSID(sid))
}

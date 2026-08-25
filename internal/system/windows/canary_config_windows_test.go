//go:build windows

package windows

import (
	"strings"
	"testing"

	xwindows "golang.org/x/sys/windows"
)

func TestCanaryConfigSecurityDescriptorRequiresExplicitCallerOnlyAccess(t *testing.T) {
	const currentSID = "S-1-5-32-545"
	tests := []struct {
		name    string
		sddl    string
		wantErr string
	}{
		{name: "restricted", sddl: `O:BUD:P(A;;FR;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)`},
		{name: "inherited", sddl: `O:BUD:(A;;FR;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)`, wantErr: "inherits"},
		{name: "broad read", sddl: `O:BUD:P(A;;FR;;;BU)(A;;FR;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)`, wantErr: "unauthorized principal"},
		{name: "missing caller read", sddl: `O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`, wantErr: "caller read"},
		{name: "untrusted owner", sddl: `O:WDD:P(A;;FR;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)`, wantErr: "owner"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := xwindows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			err = validateCanaryConfigSecurityDescriptor(descriptor, currentSID)
			if test.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestInstalledCanaryConfigAllowsOnlyPrivilegedInheritedAccess(t *testing.T) {
	for _, test := range []struct {
		name    string
		sddl    string
		wantErr string
	}{
		{name: "inherited SYSTEM and administrators", sddl: `O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)`},
		{name: "protected SYSTEM and administrators", sddl: `O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`},
		{name: "standard user read", sddl: `O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)`, wantErr: "non-privileged"},
		{name: "standard user owner", sddl: `O:BUD:(A;;FA;;;SY)(A;;FA;;;BA)`, wantErr: "owner"},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := xwindows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			err = validateInstalledCanaryConfigSecurityDescriptor(descriptor)
			if test.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

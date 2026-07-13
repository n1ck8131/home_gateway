package lists

import (
	"testing"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

func FuzzNormalizeDomain(f *testing.F) {
	for _, seed := range []string{"example.com", "HTTPS://BÜCHER.Example/path", "*.example.com", "co.uk"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := NormalizeDomain(raw, contracts.DomainMatchSuffix)
		if err != nil {
			return
		}
		gotAgain, err := NormalizeDomain(got, contracts.DomainMatchSuffix)
		if err != nil || gotAgain != got {
			t.Fatalf("normalization is not idempotent: %q -> %q, %v", got, gotAgain, err)
		}
	})
}

func FuzzNormalizeCIDR(f *testing.F) {
	for _, seed := range []string{"192.0.2.42/24", "2001:db8::1/64", "bad"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := NormalizeCIDR(raw)
		if err != nil {
			return
		}
		gotAgain, err := NormalizeCIDR(got)
		if err != nil || gotAgain != got {
			t.Fatalf("normalization is not idempotent: %q -> %q, %v", got, gotAgain, err)
		}
	})
}

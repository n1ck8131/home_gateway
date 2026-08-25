//go:build windows

package windows

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestNativeCollectorLiveReadOnly(t *testing.T) {
	if os.Getenv("HOME_GATEWAY_LIVE_WINDOWS_INVENTORY") != "1" {
		t.Skip("set HOME_GATEWAY_LIVE_WINDOWS_INVENTORY=1 to run the read-only Windows inventory smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	inventory, err := (NativeCollector{}).Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !inventory.RouteSnapshotAuthoritative || !inventory.DNSPolicyObserved {
		t.Fatalf("live inventory overstated no authoritative capability: %#v", inventory)
	}
	if len(inventory.Adapters) == 0 || len(inventory.Routes) == 0 || len(inventory.DNSPolicy.ServerSets) == 0 {
		t.Fatalf(
			"live inventory is incomplete: adapters=%d routes=%d DNS sets=%d",
			len(inventory.Adapters),
			len(inventory.Routes),
			len(inventory.DNSPolicy.ServerSets),
		)
	}
}

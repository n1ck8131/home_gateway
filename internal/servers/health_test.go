package servers

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateAWGHealthSuccessAndRedaction(t *testing.T) {
	report := EvaluateAWGHealth(healthySample(), AWGHealthOptions{MaxHandshakeAge: time.Minute})
	if report.Status != "healthy" || report.SchemaVersion != AWGHealthSchemaVersion || report.Scope != "awg" {
		t.Fatalf("report = %+v", report)
	}
	data, err := report.RedactedJSON()
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(data)
	for _, forbidden := range []string{"PRIVATE KEY", "PrivateKey", "secret", "config"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("health report leaked %q: %s", forbidden, serialized)
		}
	}
}

func TestEvaluateAWGHealthFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AWGHealthSample)
		check  string
	}{
		{name: "service", mutate: func(s *AWGHealthSample) { s.ServiceRunning = false }, check: "service"},
		{name: "interface", mutate: func(s *AWGHealthSample) { s.InterfaceUp = false }, check: "interface"},
		{name: "forwarding", mutate: func(s *AWGHealthSample) { s.ForwardingEnabled = false }, check: "forwarding"},
		{name: "nat", mutate: func(s *AWGHealthSample) { s.NATEnabled = false }, check: "nat"},
		{name: "listener", mutate: func(s *AWGHealthSample) { s.ListenerOpen = false }, check: "listener"},
		{name: "handshake missing", mutate: func(s *AWGHealthSample) { s.HandshakeObserved = false; s.LastHandshakeAge = 0 }, check: "fresh_handshake"},
		{name: "handshake stale", mutate: func(s *AWGHealthSample) { s.LastHandshakeAge = 10 * time.Minute }, check: "fresh_handshake"},
		{name: "dns", mutate: func(s *AWGHealthSample) { s.DNSOK = false }, check: "dns"},
		{name: "tls", mutate: func(s *AWGHealthSample) { s.TLSOK = false }, check: "tls"},
		{name: "admin http", mutate: func(s *AWGHealthSample) { s.PublicAdminHTTPDetected = true }, check: "admin_http"},
		{name: "egress wan", mutate: func(s *AWGHealthSample) { s.EgressIP = s.WANIP }, check: "egress"},
		{name: "missing wan baseline", mutate: func(s *AWGHealthSample) { s.WANIP = "" }, check: "egress"},
		{name: "invalid wan baseline", mutate: func(s *AWGHealthSample) { s.WANIP = "not-an-ip" }, check: "egress"},
		{name: "egress wan mapped", mutate: func(s *AWGHealthSample) { s.WANIP = "::ffff:1.1.1.1"; s.EgressIP = "1.1.1.1" }, check: "egress"},
		{name: "country", mutate: func(s *AWGHealthSample) { s.Country = "DE" }, check: "country"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sample := healthySample()
			test.mutate(&sample)
			report := EvaluateAWGHealth(sample, AWGHealthOptions{MaxHandshakeAge: time.Minute})
			if report.Status != "unhealthy" {
				t.Fatalf("status = %q", report.Status)
			}
			for _, check := range report.Checks {
				if check.Name == test.check && check.Status == "fail" {
					return
				}
			}
			t.Fatalf("failed check %q not found in %+v", test.check, report.Checks)
		})
	}
}

func TestHealthTrackerAppliesTwoSuccessThreeFailureHysteresis(t *testing.T) {
	tracker := HealthTracker{}
	healthy := AWGHealthReport{Status: "healthy"}
	unhealthy := AWGHealthReport{Status: "unhealthy"}

	tracker = tracker.Observe(healthy)
	if tracker.State != "unknown" {
		t.Fatalf("state after one success = %q", tracker.State)
	}
	tracker = tracker.Observe(healthy)
	if tracker.State != "healthy" || tracker.ConsecutiveSuccess != 2 {
		t.Fatalf("state after two successes = %+v", tracker)
	}
	tracker = tracker.Observe(unhealthy)
	tracker = tracker.Observe(unhealthy)
	if tracker.State != "healthy" {
		t.Fatalf("state before third failure = %+v", tracker)
	}
	tracker = tracker.Observe(unhealthy)
	if tracker.State != "unhealthy" || tracker.ConsecutiveFailure != 3 {
		t.Fatalf("state after three failures = %+v", tracker)
	}
}

func healthySample() AWGHealthSample {
	return AWGHealthSample{
		ServiceRunning:    true,
		InterfaceUp:       true,
		ForwardingEnabled: true,
		NATEnabled:        true,
		ListenerOpen:      true,
		HandshakeObserved: true,
		LastHandshakeAge:  20 * time.Second,
		DNSOK:             true,
		TLSOK:             true,
		WANIP:             "1.1.1.1",
		EgressIP:          "9.9.9.9",
		Country:           "NL",
		ExpectedCountry:   "NL",
		InterfaceName:     "awg0",
	}
}

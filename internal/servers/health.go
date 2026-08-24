package servers

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"
)

const AWGHealthSchemaVersion = 1

type AWGHealthSample struct {
	ServiceRunning          bool
	InterfaceUp             bool
	ForwardingEnabled       bool
	NATEnabled              bool
	ListenerOpen            bool
	HandshakeObserved       bool
	LastHandshakeAge        time.Duration
	DNSOK                   bool
	TLSOK                   bool
	PublicAdminHTTPDetected bool
	WANIP                   string
	EgressIP                string
	Country                 string
	ExpectedCountry         string
	InterfaceName           string
}

type AWGHealthOptions struct {
	MaxHandshakeAge time.Duration
}

type AWGHealthReport struct {
	SchemaVersion int                  `json:"schema_version"`
	Scope         string               `json:"scope"`
	Status        string               `json:"status"`
	Checks        []AWGHealthCheck     `json:"checks"`
	PublicDetails AWGHealthPublicFacts `json:"public_details"`
}

type AWGHealthCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type AWGHealthPublicFacts struct {
	InterfaceName  string `json:"interface_name,omitempty"`
	EgressIP       string `json:"egress_ip,omitempty"`
	Country        string `json:"country,omitempty"`
	HandshakeFresh bool   `json:"handshake_fresh"`
}

type HealthTracker struct {
	State              string
	ConsecutiveSuccess int
	ConsecutiveFailure int
}

func EvaluateAWGHealth(sample AWGHealthSample, options AWGHealthOptions) AWGHealthReport {
	maxAge := options.MaxHandshakeAge
	if maxAge <= 0 {
		maxAge = 3 * time.Minute
	}
	handshakeFresh := sample.HandshakeObserved && sample.LastHandshakeAge >= 0 && sample.LastHandshakeAge <= maxAge
	checks := []AWGHealthCheck{
		boolCheck("service", sample.ServiceRunning, "service is not running"),
		boolCheck("interface", sample.InterfaceUp, "AWG interface is down"),
		boolCheck("forwarding", sample.ForwardingEnabled, "IP forwarding is disabled"),
		boolCheck("nat", sample.NATEnabled, "NAT is not active"),
		boolCheck("listener", sample.ListenerOpen, "AWG listener is not reachable"),
		boolCheck("fresh_handshake", handshakeFresh, "last handshake is missing or stale"),
		boolCheck("dns", sample.DNSOK, "DNS check failed"),
		boolCheck("tls", sample.TLSOK, "TLS check failed"),
		boolCheck("admin_http", !sample.PublicAdminHTTPDetected, "public admin HTTP listener detected"),
	}
	egressOK := concreteIP(sample.EgressIP) && concreteIP(sample.WANIP) && !sameCanonicalIP(sample.EgressIP, sample.WANIP)
	checks = append(checks, boolCheck("egress", egressOK, "egress IP is missing or still equals WAN"))
	if sample.ExpectedCountry != "" {
		checks = append(checks, boolCheck("country", strings.EqualFold(sample.Country, sample.ExpectedCountry), "egress country mismatch"))
	}
	status := "healthy"
	for _, check := range checks {
		if check.Status != "ok" {
			status = "unhealthy"
			break
		}
	}
	return AWGHealthReport{
		SchemaVersion: AWGHealthSchemaVersion,
		Scope:         "awg",
		Status:        status,
		Checks:        checks,
		PublicDetails: AWGHealthPublicFacts{
			InterfaceName:  publicIdentifier(sample.InterfaceName),
			EgressIP:       publicIP(sample.EgressIP),
			Country:        publicIdentifier(sample.Country),
			HandshakeFresh: handshakeFresh,
		},
	}
}

func (tracker HealthTracker) Observe(report AWGHealthReport) HealthTracker {
	next := tracker
	if next.State == "" {
		next.State = "unknown"
	}
	if report.Status == "healthy" {
		next.ConsecutiveSuccess++
		next.ConsecutiveFailure = 0
		if next.ConsecutiveSuccess >= 2 {
			next.State = "healthy"
		}
		return next
	}
	next.ConsecutiveFailure++
	next.ConsecutiveSuccess = 0
	if next.ConsecutiveFailure >= 3 {
		next.State = "unhealthy"
	}
	return next
}

func (report AWGHealthReport) RedactedJSON() ([]byte, error) {
	return json.Marshal(report)
}

func boolCheck(name string, ok bool, reason string) AWGHealthCheck {
	if ok {
		return AWGHealthCheck{Name: name, Status: "ok"}
	}
	return AWGHealthCheck{Name: name, Status: "fail", Reason: reason}
}

func sameCanonicalIP(left, right string) bool {
	leftAddr, leftErr := netip.ParseAddr(left)
	rightAddr, rightErr := netip.ParseAddr(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return leftAddr.Unmap() == rightAddr.Unmap()
}

func concreteIP(value string) bool {
	addr, err := netip.ParseAddr(value)
	return err == nil && deployablePublicIP(addr)
}

func publicIP(value string) string {
	addr, err := netip.ParseAddr(value)
	if err == nil && deployablePublicIP(addr) {
		return addr.Unmap().String()
	}
	return ""
}

func publicIdentifier(value string) string {
	if containsSecretMaterial(value) || strings.ContainsAny(value, "\r\n\t") {
		return ""
	}
	return value
}

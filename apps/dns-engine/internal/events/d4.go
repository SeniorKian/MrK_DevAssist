package events

// D4 event types (docs/40 §3).
const (
	DNSSECTrustAnchorUpdated = "dnssec.trust_anchor_updated"
	DNSSECTrustAnchorFailed  = "dnssec.trust_anchor_failed"
	DNSSECBogusSpike         = "dnssec.bogus_spike"
	ResolutionPrimingFailed  = "resolution.priming_failed"
)

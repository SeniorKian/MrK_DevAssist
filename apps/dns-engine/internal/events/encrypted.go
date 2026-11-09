package events

// D4 part B event types (docs/40 §3).
const (
	TLSCertificateExpiring = "tls.certificate_expiring"
	TLSCertificateExpired  = "tls.certificate_expired"
	ListenerFailed         = "listener.failed"
)

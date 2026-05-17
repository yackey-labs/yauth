// Package domain — audit-export entities (issue #96 / yauth Rust #106 port).
//
// These types are the cross-component contract for the audit-export plugin.
// Memory-backend semantics are canonical; SQL backends are stubbed pending a
// follow-up issue per the same precedent as Phase A/B / SAML / SCIM.
package domain

import "time"

// AuditExportFormat names the wire format used to render an AuditLog for a
// destination. JSON is the default and most universally consumable. CEF
// (ArcSight Common Event Format) targets Splunk/ArcSight. RFC 5424 is the
// canonical syslog framing.
type AuditExportFormat string

const (
	AuditExportFormatJSON    AuditExportFormat = "json"
	AuditExportFormatCEF     AuditExportFormat = "cef"
	AuditExportFormatRFC5424 AuditExportFormat = "rfc5424"
)

// SyslogTransport is the wire transport for a Syslog destination.
//
// UdpUnsecured is unauthenticated and lossy — not recommended.
// Tcp is plaintext RFC 6587 octet-counted framing.
// TcpTls is the conventional secure path on port 6514; deferred to a
// follow-up issue, the dispatcher returns ErrNotImplemented for it.
type SyslogTransport string

const (
	SyslogTransportUDP    SyslogTransport = "udp_unsecured"
	SyslogTransportTCP    SyslogTransport = "tcp"
	SyslogTransportTCPTLS SyslogTransport = "tcp_tls"
)

// S3Partition picks the object-key layout for S3-flavoured destinations.
type S3Partition string

const (
	S3PartitionByDate       S3Partition = "by_date"
	S3PartitionByOrg        S3Partition = "by_org"
	S3PartitionByDateAndOrg S3Partition = "by_date_and_org"
)

// DestinationStatus is the lifecycle state of a destination row.
type DestinationStatus string

const (
	DestinationStatusActive   DestinationStatus = "active"
	DestinationStatusDisabled DestinationStatus = "disabled"
)

// OutboxStatus is the lifecycle state of an AuditOutboxEntry row.
type OutboxStatus string

const (
	OutboxStatusPending    OutboxStatus = "pending"
	OutboxStatusSent       OutboxStatus = "sent"
	OutboxStatusFailed     OutboxStatus = "failed"
	OutboxStatusDeadLetter OutboxStatus = "dead_letter"
)

// AuditExportDestinationKind names the destination type. The detailed
// configuration lives in AuditExportDestination.Config (a free-form
// map) so wire-format compatibility is preserved across feature gates.
type AuditExportDestinationKind string

const (
	DestinationKindWebhook AuditExportDestinationKind = "webhook"
	DestinationKindSyslog  AuditExportDestinationKind = "syslog"
	DestinationKindS3      AuditExportDestinationKind = "s3"
	DestinationKindSplunk  AuditExportDestinationKind = "splunk"
	DestinationKindDatadog AuditExportDestinationKind = "datadog"
)

// AuditExportDestination is a single SIEM/syslog/object-store endpoint.
//
// OrganizationID == nil means a deployment-wide destination — every
// audit event routes here. OrganizationID non-nil means only that org's
// events route to it, in addition to deployment-wide rows. The
// "cross-org leakage" pentest asserts this contract.
//
// Secrets (HMAC keys, HEC tokens, Datadog API keys) live in Config but
// MUST NEVER be returned by the admin list/get endpoints — see
// (de)sanitizeKind helpers in routes.go.
type AuditExportDestination struct {
	ID             string
	OrganizationID *string
	Name           string
	Kind           AuditExportDestinationKind
	Format         AuditExportFormat
	// Config carries kind-specific options. Webhook: url, hmac_secret,
	// headers. Syslog: host, port, transport, facility. S3: bucket,
	// prefix, region, partition. Splunk: hec_url, hec_token. Datadog:
	// site, api_key.
	Config         map[string]string
	Status         DestinationStatus
	LastSuccessAt  *time.Time
	LastFailureAt  *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// NewAuditExportDestination is the insert input.
type NewAuditExportDestination struct {
	ID             string
	OrganizationID *string
	Name           string
	Kind           AuditExportDestinationKind
	Format         AuditExportFormat
	Config         map[string]string
	Status         DestinationStatus
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// UpdateAuditExportDestination is a partial update. Nil fields are left
// unchanged. LastSuccessAt / LastFailureAt take **pointer-to-pointer
// semantics**: nil means "no change", non-nil pointer to nil means "clear",
// non-nil pointer to non-nil time means "set".
type UpdateAuditExportDestination struct {
	Name          *string
	Format        *AuditExportFormat
	Config        map[string]string
	Status        *DestinationStatus
	LastSuccessAt **time.Time
	LastFailureAt **time.Time
	UpdatedAt     *time.Time
}

// AuditOutboxEntry is one row per (audit event, destination). Inserted in
// the same critical section as the audit row.
type AuditOutboxEntry struct {
	ID            string
	AuditLogID    string
	DestinationID string
	Status        OutboxStatus
	Attempts      int32
	LastAttemptAt *time.Time
	LastError     *string
	CreatedAt     time.Time
}

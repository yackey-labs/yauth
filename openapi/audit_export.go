package openapi

import (
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

// ── Audit export types ────────────────────────────────────────────────────

type auditDestinationResponse struct {
	ID             string    `json:"id" format:"uuid"`
	Name           string    `json:"name"`
	Kind           any       `json:"kind"` // sanitised — secrets stripped
	KindTag        string    `json:"kind_tag"`
	Status         string    `json:"status"`
	OrganizationID *string   `json:"organization_id,omitempty" format:"uuid"`
	LastSuccessAt  *string   `json:"last_success_at,omitempty"`
	LastFailureAt  *string   `json:"last_failure_at,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type createAuditDestinationRequest struct {
	Name           string  `json:"name"`
	Kind           any     `json:"kind"`
	OrganizationID *string `json:"organization_id,omitempty" doc:"nil => deployment-wide destination."`
}

type updateAuditDestinationRequest struct {
	Name   *string `json:"name,omitempty"`
	Kind   any     `json:"kind,omitempty"`
	Status *string `json:"status,omitempty"`
}

type outboxEntryResponse struct {
	ID            string    `json:"id" format:"uuid"`
	AuditLogID    string    `json:"audit_log_id" format:"uuid"`
	DestinationID string    `json:"destination_id" format:"uuid"`
	Status        string    `json:"status"`
	Attempts      int       `json:"attempts"`
	LastAttemptAt *string   `json:"last_attempt_at,omitempty"`
	LastError     *string   `json:"last_error,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type replayRequest struct {
	AuditLogIDs    []string `json:"audit_log_ids"`
	DestinationIDs []string `json:"destination_ids"`
}

type replayResponse struct {
	Enqueued int      `json:"enqueued"`
	Gone     []string `json:"gone"`
}

// addAuditExport declares the audit-export routes introduced in yauth (Rust) #96.
//
// All routes are admin-only:
//
//	POST   /audit/destinations
//	GET    /audit/destinations
//	GET    /audit/destinations/{id}
//	PATCH  /audit/destinations/{id}
//	DELETE /audit/destinations/{id}
//	GET    /audit/destinations/{id}/outbox
//	POST   /audit/replay
func addAuditExport(api *huma.OpenAPI) {
	idParam := pathParam("id", "Destination id (UUID).")

	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/audit/destinations",
		Tags: []string{"audit-export"}, OperationID: "auditExport_createDestination",
		Summary:     "Create an audit export destination",
		Security:    secAny(),
		RequestBody: jsonRequestBody(createAuditDestinationRequest{}, "Destination to create."),
		Responses: map[string]*huma.Response{
			"201": jsonResponse("Created destination.", auditDestinationResponse{}),
			"400": errorResponse("Invalid configuration."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Admin only."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/audit/destinations",
		Tags: []string{"audit-export"}, OperationID: "auditExport_listDestinations",
		Summary:  "List audit export destinations",
		Security: secAny(),
		Parameters: []*huma.Param{
			queryStringParam("organization_id", "Filter by organization id."),
			queryStringParam("scope", "Filter scope (org or global)."),
		},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Destination list.", []auditDestinationResponse{}),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Admin only."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/audit/destinations/{id}",
		Tags: []string{"audit-export"}, OperationID: "auditExport_getDestination",
		Summary:    "Get an audit export destination",
		Security:   secAny(),
		Parameters: []*huma.Param{idParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Destination.", auditDestinationResponse{}),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Admin only."),
			"404": errorResponse("Destination not found."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodPatch, Path: "/audit/destinations/{id}",
		Tags: []string{"audit-export"}, OperationID: "auditExport_updateDestination",
		Summary:     "Update an audit export destination",
		Security:    secAny(),
		Parameters:  []*huma.Param{idParam},
		RequestBody: jsonRequestBody(updateAuditDestinationRequest{}, "Fields to update."),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Updated destination.", auditDestinationResponse{}),
			"400": errorResponse("Invalid field value."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Admin only."),
			"404": errorResponse("Destination not found."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/audit/destinations/{id}",
		Tags: []string{"audit-export"}, OperationID: "auditExport_deleteDestination",
		Summary:    "Delete an audit export destination",
		Security:   secAny(),
		Parameters: []*huma.Param{idParam},
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Destination deleted."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Admin only."),
			"404": errorResponse("Destination not found."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/audit/destinations/{id}/outbox",
		Tags: []string{"audit-export"}, OperationID: "auditExport_listDestinationOutbox",
		Summary:  "List pending outbox entries for a destination",
		Security: secAny(),
		Parameters: []*huma.Param{
			idParam,
			queryStringParam("limit", "Maximum entries to return."),
		},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Outbox entries.", []outboxEntryResponse{}),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Admin only."),
			"404": errorResponse("Destination not found."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/audit/replay",
		Tags: []string{"audit-export"}, OperationID: "auditExport_replay",
		Summary:     "Re-enqueue audit log entries for a set of destinations",
		Security:    secAny(),
		RequestBody: jsonRequestBody(replayRequest{}, "Audit log and destination IDs to replay."),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Replay result.", replayResponse{}),
			"400": errorResponse("Invalid request."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Admin only."),
		},
	})
}

// Package scim implements SCIM 2.0 provisioning endpoints (yauth Rust #95
// / yauth-go #27). Mounts a tree of endpoints under
// /scim/v2/organizations/{org_id}/... that IdPs (Okta, Entra,
// OneLogin) use to provision users into yauth.
//
// types.go: hand-rolled SCIM wire types (RFC 7643 Core User + Group,
// RFC 7644 envelopes). The type surface yauth-go actually needs is small
// (Core User, Core Group, ListResponse, Error, PatchOp); hand-rolled
// keeps the dependency surface flat and avoids an unmaintained upstream
// risk.
//
// What's modelled:
//
//   - urn:ietf:params:scim:schemas:core:2.0:User (Core User)
//   - urn:ietf:params:scim:schemas:core:2.0:Group (Core Group)
//   - urn:ietf:params:scim:api:messages:2.0:ListResponse
//   - urn:ietf:params:scim:api:messages:2.0:Error
//   - urn:ietf:params:scim:api:messages:2.0:PatchOp
//
// Enterprise extension (urn:ietf:params:scim:schemas:extension:enterprise:2.0:User)
// is recognised as a known schema URN but its fields are NOT persisted.
//
// Schema URN validation: ValidateSchemas is the gate handlers MUST call
// before treating a payload as Core User / Core Group. Unknown schema
// URNs are rejected with invalidSyntax rather than silently passed
// through.
package scim

import (
	"encoding/json"
	"fmt"
)

// Schema URN constants.
const (
	CoreUserSchema              = "urn:ietf:params:scim:schemas:core:2.0:User"
	CoreGroupSchema             = "urn:ietf:params:scim:schemas:core:2.0:Group"
	EnterpriseUserSchema        = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	ListResponseSchema          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	ErrorSchema                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	PatchOpSchema               = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	ServiceProviderConfigSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	ResourceTypeSchema          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema                = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// knownRequestSchemas is the closed set of schema URNs an incoming
// request payload may declare. Unknown URNs in schemas[] are rejected
// with invalidSyntax per RFC 7644 §3.3 — this prevents arbitrary
// extension data from being passed through to storage.
var knownRequestSchemas = map[string]struct{}{
	CoreUserSchema:       {},
	CoreGroupSchema:      {},
	EnterpriseUserSchema: {},
	PatchOpSchema:        {},
}

// ResourceMeta is the RFC 7643 §3.1 common meta block returned on every
// resource.
type ResourceMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified"`
	Location     string `json:"location"`
}

// ScimEmail is a single entry in a User's emails[] array.
type ScimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary *bool  `json:"primary,omitempty"`
	Display string `json:"display,omitempty"`
}

// ScimName is the structured name block on a SCIM User.
type ScimName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	MiddleName string `json:"middleName,omitempty"`
}

// ScimGroupRef is a group reference inside a User.groups[] block.
type ScimGroupRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// ScimUser is the SCIM Core User resource (RFC 7643 §4.1).
//
// On input we accept any subset; unknown attributes are silently dropped
// by Go's JSON decoder (we do NOT echo them back on the response). The
// handler MUST still validate schemas[] via ValidateSchemas.
type ScimUser struct {
	ID          string         `json:"id,omitempty"`
	ExternalID  string         `json:"externalId,omitempty"`
	Schemas     []string       `json:"schemas"`
	UserName    string         `json:"userName,omitempty"`
	DisplayName string         `json:"displayName,omitempty"`
	Name        *ScimName      `json:"name,omitempty"`
	Emails      []ScimEmail    `json:"emails,omitempty"`
	Active      *bool          `json:"active,omitempty"`
	Groups      []ScimGroupRef `json:"groups,omitempty"`
	Meta        *ResourceMeta  `json:"meta,omitempty"`
}

// CanonicalEmail returns the user's canonical email address. Prefers
// the entry marked primary:true, then the first entry, then userName.
func (u *ScimUser) CanonicalEmail() string {
	for _, e := range u.Emails {
		if e.Primary != nil && *e.Primary {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return u.UserName
}

// PickDisplayName returns the best display name. Prefers DisplayName,
// then Name.Formatted, then "GivenName FamilyName".
func (u *ScimUser) PickDisplayName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if u.Name != nil {
		if u.Name.Formatted != "" {
			return u.Name.Formatted
		}
		switch {
		case u.Name.GivenName != "" && u.Name.FamilyName != "":
			return u.Name.GivenName + " " + u.Name.FamilyName
		case u.Name.GivenName != "":
			return u.Name.GivenName
		case u.Name.FamilyName != "":
			return u.Name.FamilyName
		}
	}
	return ""
}

// ScimGroupMember is a single entry on a Group's members[] array.
type ScimGroupMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// ScimGroup is the SCIM Core Group resource (RFC 7643 §4.2).
type ScimGroup struct {
	ID          string            `json:"id,omitempty"`
	Schemas     []string          `json:"schemas"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName,omitempty"`
	Members     []ScimGroupMember `json:"members"`
	Meta        *ResourceMeta     `json:"meta,omitempty"`
}

// PatchOp is the RFC 7644 §3.5.2 PATCH envelope.
type PatchOp struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is one entry in a PATCH Operations[] array.
type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// ListResponse is the RFC 7644 §3.4.2 paginated list envelope.
type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    any      `json:"Resources"`
}

// NewListResponse constructs a ListResponse with the messages:ListResponse
// schema URN set.
func NewListResponse(total, startIndex, itemsPerPage int, resources any) ListResponse {
	return ListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: itemsPerPage,
		Resources:    resources,
	}
}

// ScimErrorBody is the RFC 7644 §3.12 error envelope. The status field
// is a string by the RFC's choice — IdPs parse it as a string, NOT as
// an integer.
type ScimErrorBody struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// NewScimErrorBody builds a SCIM error envelope with the messages:Error
// schema URN set.
func NewScimErrorBody(status int, scimType, detail string) ScimErrorBody {
	return ScimErrorBody{
		Schemas:  []string{ErrorSchema},
		Status:   fmt.Sprintf("%d", status),
		ScimType: scimType,
		Detail:   detail,
	}
}

// ValidateSchemas validates the schemas[] array on an incoming request
// payload.
//
//   - MUST contain the expected primary URN.
//   - MAY contain additional URNs, but they must all appear in the
//     closed knownRequestSchemas set. Unknown URNs are rejected with
//     scimType=invalidSyntax so a bad IdP can't smuggle arbitrary
//     extension data through and rely on us passing it untouched.
//
// On rejection returns an error body the handler maps to a 400.
func ValidateSchemas(schemas []string, primary string) (*ScimErrorBody, bool) {
	primaryFound := false
	for _, s := range schemas {
		if s == primary {
			primaryFound = true
		}
	}
	if !primaryFound {
		e := NewScimErrorBody(400, "invalidSyntax", "schemas[] must include "+primary)
		return &e, false
	}
	for _, s := range schemas {
		if _, ok := knownRequestSchemas[s]; !ok {
			e := NewScimErrorBody(400, "invalidSyntax", "unknown schema urn: "+s)
			return &e, false
		}
	}
	return nil, true
}

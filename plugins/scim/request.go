package scim

// request.go — huma-native REQUEST schemas for the SCIM write routes
// (POST/PUT Users & Groups, PATCH Users & Groups).
//
// Why this is RawBody-only, not a JSON-parsed huma Body:
//
// A typed huma `Body` field would make huma unmarshal + validate the request
// body BEFORE the operation handler runs. For malformed JSON, an empty body, or
// a type-mismatched value (e.g. `active:"true"`), that pre-handler parse FAILS
// and huma emits an RFC 9457 application/problem+json error — the legacy SCIM
// handler never runs, so the RFC 7644 §3.12 SCIM error envelope and the
// application/scim+json content type are LOST for those inputs. SCIM is an
// externally-specified wire contract where every error MUST be scim+json, so
// that regression is unacceptable.
//
// Instead each write route declares only a `RawBody []byte` (tagged with the
// SCIM content type). huma copies the verbatim request bytes into RawBody WITHOUT
// structurally unmarshaling them (processRegularMsgBody short-circuits when no
// typed Body field is present), so a malformed/empty/mismatched body flows
// untouched to the legacy handler, which decodes it itself and returns its own
// SCIM-shaped error. The bridge resets r.Body from RawBody so the unchanged
// handler re-reads the exact original bytes — extension attributes intact.
//
// The request *schema* is still derived from the SCIM resource shapes below and
// attached to each write operation's RequestBody (see scimRegisterBody): huma's
// huma.SchemaFromType turns scimUserBody / scimGroupBody / scimPatchBody into a
// JSON Schema documenting the accepted payload. This is documentation-only — it
// does NOT gate the request (the handler owns validation) — so a permissive,
// open-ended schema is correct: additionalProperties stays open (SCIM extension
// schemas, RFC 7644 §3.3) and nothing is marked required.

// The blank `_ struct{}` field carrying additionalProperties:"true" is huma's
// sentinel for emitting additionalProperties:true on the struct's schema (huma
// reads it via reflection — see schema.go FieldByName("_")). EVERY SCIM body
// struct carries it: SCIM is open-ended — IdPs send extension-schema keys (the
// enterprise URN) plus attributes we don't model (addresses/phoneNumbers) — and
// additionalProperties:false would mis-document the contract. The task forbids
// additionalProperties:false here.

// scimNameBody mirrors the SCIM User `name` sub-object (RFC 7643 §4.1.1).
type scimNameBody struct {
	_          struct{} `additionalProperties:"true"`
	Formatted  string   `json:"formatted,omitempty"`
	FamilyName string   `json:"familyName,omitempty"`
	GivenName  string   `json:"givenName,omitempty"`
	MiddleName string   `json:"middleName,omitempty"`
}

// scimEmailBody mirrors one entry in a SCIM User `emails[]` array.
type scimEmailBody struct {
	_       struct{} `additionalProperties:"true"`
	Value   string   `json:"value,omitempty"`
	Type    string   `json:"type,omitempty"`
	Primary *bool    `json:"primary,omitempty"`
	Display string   `json:"display,omitempty"`
}

// scimUserBody is the request schema for POST/PUT /Users — the SCIM Core User
// resource shape (RFC 7643 §4.1). Permissive: every field optional, since the
// schema documents (does not enforce) the payload; the handler validates.
type scimUserBody struct {
	_           struct{}        `additionalProperties:"true"`
	Schemas     []string        `json:"schemas,omitempty"`
	ExternalID  string          `json:"externalId,omitempty"`
	UserName    string          `json:"userName,omitempty"`
	DisplayName string          `json:"displayName,omitempty"`
	Name        *scimNameBody   `json:"name,omitempty"`
	Emails      []scimEmailBody `json:"emails,omitempty"`
	Active      *bool           `json:"active,omitempty"`
}

// scimGroupMemberBody mirrors one entry in a SCIM Group `members[]` array.
type scimGroupMemberBody struct {
	_       struct{} `additionalProperties:"true"`
	Value   string   `json:"value,omitempty"`
	Display string   `json:"display,omitempty"`
	Type    string   `json:"type,omitempty"`
	Ref     string   `json:"$ref,omitempty"`
}

// scimGroupBody is the request schema for POST/PUT /Groups — the SCIM Core
// Group resource shape (RFC 7643 §4.2).
type scimGroupBody struct {
	_           struct{}              `additionalProperties:"true"`
	Schemas     []string              `json:"schemas,omitempty"`
	ExternalID  string                `json:"externalId,omitempty"`
	DisplayName string                `json:"displayName,omitempty"`
	Members     []scimGroupMemberBody `json:"members,omitempty"`
}

// scimPatchOperationBody mirrors one entry in a PATCH Operations[] array.
// `value` is `any` (empty schema) so the documented shape admits every legal
// SCIM PATCH value — a bare bool, an object, or an array.
type scimPatchOperationBody struct {
	_     struct{} `additionalProperties:"true"`
	Op    string   `json:"op,omitempty"`
	Path  string   `json:"path,omitempty"`
	Value any      `json:"value,omitempty"`
}

// scimPatchBody is the request schema for PATCH /Users & /Groups — the RFC 7644
// §3.5.2 PatchOp envelope.
type scimPatchBody struct {
	_          struct{}                 `additionalProperties:"true"`
	Schemas    []string                 `json:"schemas,omitempty"`
	Operations []scimPatchOperationBody `json:"Operations,omitempty"`
}

// ---------------------------------------------------------------------------
// Per-route huma input structs: path params + RawBody (the verbatim request
// bytes huma copies in without unmarshaling). The contentType tag makes huma
// register the request body under application/scim+json; scimRegisterBody then
// overrides that media type's schema with the SCIM-derived one above.

// scimUserCreateInput: POST .../{org_id}/Users.
type scimUserCreateInput struct {
	OrgID   string `path:"org_id"`
	RawBody []byte `contentType:"application/scim+json"`
}

func (i *scimUserCreateInput) raw() []byte { return i.RawBody }

// scimUserPutInput: PUT .../{org_id}/Users/{user_id}.
type scimUserPutInput struct {
	OrgID   string `path:"org_id"`
	UserID  string `path:"user_id"`
	RawBody []byte `contentType:"application/scim+json"`
}

func (i *scimUserPutInput) raw() []byte { return i.RawBody }

// scimUserPatchInput: PATCH .../{org_id}/Users/{user_id}.
type scimUserPatchInput struct {
	OrgID   string `path:"org_id"`
	UserID  string `path:"user_id"`
	RawBody []byte `contentType:"application/scim+json"`
}

func (i *scimUserPatchInput) raw() []byte { return i.RawBody }

// scimGroupCreateInput: POST .../{org_id}/Groups.
type scimGroupCreateInput struct {
	OrgID   string `path:"org_id"`
	RawBody []byte `contentType:"application/scim+json"`
}

func (i *scimGroupCreateInput) raw() []byte { return i.RawBody }

// scimGroupPutInput: PUT .../{org_id}/Groups/{group_id}.
type scimGroupPutInput struct {
	OrgID   string `path:"org_id"`
	GroupID string `path:"group_id"`
	RawBody []byte `contentType:"application/scim+json"`
}

func (i *scimGroupPutInput) raw() []byte { return i.RawBody }

// scimGroupPatchInput: PATCH .../{org_id}/Groups/{group_id}.
type scimGroupPatchInput struct {
	OrgID   string `path:"org_id"`
	GroupID string `path:"group_id"`
	RawBody []byte `contentType:"application/scim+json"`
}

func (i *scimGroupPatchInput) raw() []byte { return i.RawBody }

// rawBodyer is implemented by every body-bearing SCIM input so the generic
// bridge (scimRegisterBody) can recover the verbatim RawBody bytes.
type rawBodyer interface {
	raw() []byte
}

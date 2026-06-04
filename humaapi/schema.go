package humaapi

import (
	"reflect"

	"github.com/danielgtaylor/huma/v2"
)

// ReqBody builds an explicit JSON request-body schema from a Go type and is
// used to DOCUMENT the body of routes that parse the request manually (the
// StashHTTPHuma bridge) — huma can't auto-derive a schema for those because the
// input struct carries no `Body` field. Attach it on the operation:
//
//	huma.Register(api, huma.Operation{
//	    Method: http.MethodPost, Path: ...,
//	    RequestBody: humaapi.ReqBody[CreateThingRequest](api),
//	}, handler)
//
// The handler still parses the body itself; this only makes the generated
// OpenAPI (and the TS client) carry the typed request body.
func ReqBody[T any](api huma.API) *huma.RequestBody {
	reg := api.OpenAPI().Components.Schemas
	t := reflect.TypeOf((*T)(nil)).Elem()
	return &huma.RequestBody{
		Required: true,
		Content: map[string]*huma.MediaType{
			"application/json": {Schema: reg.Schema(t, true, t.Name())},
		},
	}
}

// JSONResponse builds an explicit JSON response schema from a Go type, for
// routes whose handler writes the body manually (raw-writer / streaming
// outputs) so huma has no typed Output to derive from. Use it to populate an
// operation's Responses entry, e.g.:
//
//	Responses: map[string]*huma.Response{
//	    "200": humaapi.JSONResponse[TokenResponse](api, "OAuth2 token"),
//	}
func JSONResponse[T any](api huma.API, desc string) *huma.Response {
	reg := api.OpenAPI().Components.Schemas
	t := reflect.TypeOf((*T)(nil)).Elem()
	return &huma.Response{
		Description: desc,
		Content: map[string]*huma.MediaType{
			"application/json": {Schema: reg.Schema(t, true, t.Name())},
		},
	}
}

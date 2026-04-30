// Package openapi exposes a `go generate` directive that writes the
// fully-marshaled spec to <repo>/openapi.json. The generator program
// itself lives in cmd/openapigen so this package can be imported by the
// runtime without dragging in a main() entry point.
package openapi

//go:generate go run github.com/yackey-labs/yauth-go/cmd/openapigen -out ../openapi.json

package asymjwt

import (
	"encoding/json"
)

// jsonMarshalIndent marshals v with the encoding/json package using a
// stable two-space indent. It is a small helper used to keep the JWKS
// doc readable when inspected by humans.
func jsonMarshalIndent(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

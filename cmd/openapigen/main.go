// Command openapigen is the `go generate` target for openapi.json.
// It builds the spec via openapi.Build and writes it to -out, defaulting
// to ../openapi.json (relative to the openapi package).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/yackey-labs/yauth-go/openapi"
)

func main() {
	out := flag.String("out", "../openapi.json", "path of the openapi.json file to write")
	flag.Parse()

	body, err := json.MarshalIndent(openapi.Build(), "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "openapigen: marshal failed:", err)
		os.Exit(1)
	}
	body = append(body, '\n')
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "openapigen: write failed:", err)
		os.Exit(1)
	}
	fmt.Println("openapigen: wrote", *out, "(", len(body), "bytes )")
}

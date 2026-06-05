package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/yackey-labs/yauth/yauthcfg"
)

var durationType = reflect.TypeOf(time.Duration(0))

func newSchemaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schema",
		Short: "Emit machine-readable schemas for agents and tooling",
	}
	cmd.AddCommand(newSchemaConfigCmd())
	return cmd
}

func newSchemaConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Emit the yauth.yaml config schema as JSON Schema (Draft 2020-12)",
		Long: "Reflects the config schema from yauthcfg.Config in this exact binary, " +
			"so the schema always matches what this version parses. Key fields carry " +
			"inline descriptions/enums; fuller prose lives in `yauth docs`.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			schema := structSchema(reflect.TypeOf(yauthcfg.Config{}), reflect.ValueOf(*yauthcfg.Default()))
			schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
			schema["title"] = "yauth.yaml"
			schema["x-source"] = "reflected from yauthcfg.Config in this binary — version-exact"
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(schema)
		},
	}
}

// fieldSchema builds a JSON Schema node for type t. v is the corresponding
// value from yauthcfg.Default() (used to populate "default"); it may be the
// zero reflect.Value when no default is available (map/slice elements, nil
// pointers), in which case no default is emitted.
func fieldSchema(t reflect.Type, v reflect.Value) map[string]any {
	if t.Kind() == reflect.Pointer {
		var ev reflect.Value
		if v.IsValid() && !v.IsNil() {
			ev = v.Elem()
		}
		return fieldSchema(t.Elem(), ev)
	}

	// time.Duration is an int64 under the hood but is configured as a string
	// like "30m" / "24h", so it must be schematized as a string, not integer.
	if t == durationType {
		s := map[string]any{"type": "string", "format": "duration", "examples": []string{"30m", "24h"}}
		if v.IsValid() && v.Int() != 0 {
			s["default"] = time.Duration(v.Int()).String()
		}
		return s
	}

	switch t.Kind() {
	case reflect.Struct:
		return structSchema(t, v)
	case reflect.Map:
		return map[string]any{
			"type":                 "object",
			"additionalProperties": fieldSchema(t.Elem(), reflect.Value{}),
		}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": fieldSchema(t.Elem(), reflect.Value{})}
	case reflect.String:
		s := map[string]any{"type": "string"}
		if v.IsValid() && v.String() != "" {
			s["default"] = v.String()
		}
		return s
	case reflect.Bool:
		s := map[string]any{"type": "boolean"}
		if v.IsValid() && v.Bool() {
			s["default"] = true
		}
		return s
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		s := map[string]any{"type": "integer"}
		if v.IsValid() && v.Int() != 0 {
			s["default"] = v.Int()
		}
		return s
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		s := map[string]any{"type": "integer"}
		if v.IsValid() && v.Uint() != 0 {
			s["default"] = v.Uint()
		}
		return s
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	default:
		return map[string]any{}
	}
}

func structSchema(t reflect.Type, v reflect.Value) map[string]any {
	props := map[string]any{}
	var required []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, opts := parseYAMLTag(f.Tag.Get("yaml"), f.Name)
		if name == "-" {
			continue
		}
		var fv reflect.Value
		if v.IsValid() {
			fv = v.Field(i)
		}
		node := fieldSchema(f.Type, fv)
		// Optional self-documentation: a `doc:"..."` tag becomes the JSON
		// Schema description and an `enum:"a,b,c"` tag becomes the allowed
		// value set, so `yauth schema config` is informative on its own (Go
		// reflection cannot read source comments at runtime).
		if doc := f.Tag.Get("doc"); doc != "" {
			node["description"] = doc
		}
		if enum := f.Tag.Get("enum"); enum != "" {
			vals := strings.Split(enum, ",")
			anyVals := make([]any, len(vals))
			for j, e := range vals {
				anyVals[j] = strings.TrimSpace(e)
			}
			node["enum"] = anyVals
		}
		props[name] = node
		// A field is "required" only if it has no natural empty form: pointer
		// fields and omitempty fields are optional by construction.
		if f.Type.Kind() != reflect.Pointer && !opts["omitempty"] {
			required = append(required, name)
		}
	}
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// parseYAMLTag splits a struct yaml tag into its name and option set, falling
// back to the Go field name when the tag has no explicit name.
func parseYAMLTag(tag, fieldName string) (string, map[string]bool) {
	opts := map[string]bool{}
	parts := strings.Split(tag, ",")
	name := parts[0]
	for _, o := range parts[1:] {
		opts[o] = true
	}
	if name == "" {
		name = fieldName
	}
	return name, opts
}

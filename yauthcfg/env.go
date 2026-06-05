package yauthcfg

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// envPrefix is prepended to every config-override environment variable.
const envPrefix = "YAUTH"

var durationType = reflect.TypeOf(time.Duration(0))

// applyEnvOverrides overlays YAUTH_* environment variables onto cfg, so env
// wins over the config file. The variable name for a field is envPrefix plus
// the uppercased YAML path joined by "_": e.g. server.addr → YAUTH_SERVER_ADDR,
// session.ttl → YAUTH_SESSION_TTL, plugins.bearer.enabled →
// YAUTH_PLUGINS_BEARER_ENABLED.
//
// Only scalar fields (string, bool, int kinds, time.Duration, []string) and the
// structs containing them are bound; maps (e.g. oauth.providers) are not
// env-overridable and must be set in the file. A present-but-unparseable value
// is a hard error so a typo'd override fails loudly rather than being ignored.
func applyEnvOverrides(c *Config) error {
	return bindEnv(reflect.ValueOf(c).Elem(), envPrefix)
}

func bindEnv(v reflect.Value, prefix string) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := yamlFieldName(f)
		if name == "-" {
			continue
		}
		envName := prefix + "_" + strings.ToUpper(name)
		fv := v.Field(i)

		// Recurse into nested config structs (but not time.Duration, which is a
		// struct-free named int64, nor pointers — handled as scalars below).
		if fv.Kind() == reflect.Struct && fv.Type() != durationType {
			if err := bindEnv(fv, envName); err != nil {
				return err
			}
			continue
		}

		raw, ok := os.LookupEnv(envName)
		if !ok {
			continue
		}
		if err := setScalar(fv, raw); err != nil {
			return fmt.Errorf("%s: %w", envName, err)
		}
	}
	return nil
}

// setScalar parses raw into dst according to its kind. Pointer fields are
// allocated as needed so a tri-state *bool can be set from env.
func setScalar(dst reflect.Value, raw string) error {
	if dst.Kind() == reflect.Pointer {
		if dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		return setScalar(dst.Elem(), raw)
	}

	if dst.Type() == durationType {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("invalid duration %q", raw)
		}
		dst.SetInt(int64(d))
		return nil
	}

	switch dst.Kind() {
	case reflect.String:
		dst.SetString(raw)
	case reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("invalid bool %q", raw)
		}
		dst.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid integer %q", raw)
		}
		dst.SetInt(n)
	case reflect.Slice:
		if dst.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("unsupported slice type for env override")
		}
		parts := strings.Split(raw, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		dst.Set(reflect.ValueOf(parts))
	default:
		return fmt.Errorf("field type %s is not env-overridable", dst.Kind())
	}
	return nil
}

// yamlFieldName extracts the YAML key for a struct field (the name before any
// comma options), falling back to the Go field name.
func yamlFieldName(f reflect.StructField) string {
	tag := f.Tag.Get("yaml")
	if tag == "" {
		return f.Name
	}
	name := strings.SplitN(tag, ",", 2)[0]
	if name == "" {
		return f.Name
	}
	return name
}

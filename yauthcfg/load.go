package yauthcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// Load reads a config file from disk, decodes it according to the file
// extension (.yaml/.yml → YAML, .toml → TOML), validates it, and
// returns the populated Config. Database DSNs prefixed with `env:` are
// resolved from the environment.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	cfg, err := Decode(b, formatFor(path))
	if err != nil {
		return nil, fmt.Errorf("decode %q: %w", path, err)
	}

	// YAUTH_* env vars override file values (env wins). Applied before DSN
	// env: resolution and validation.
	if err := applyEnvOverrides(cfg); err != nil {
		return nil, fmt.Errorf("apply env overrides for %q: %w", path, err)
	}

	if err := cfg.resolveEnv(); err != nil {
		return nil, fmt.Errorf("resolve env in %q: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate %q: %w", path, err)
	}

	return cfg, nil
}

// Format identifies a config encoding.
type Format int

const (
	FormatYAML Format = iota
	FormatTOML
)

func formatFor(path string) Format {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		return FormatTOML
	default:
		return FormatYAML
	}
}

// Decode parses raw config bytes in the given format. Validation is
// not performed here so callers can decode partial configs in tests.
func Decode(data []byte, format Format) (*Config, error) {
	cfg := &Config{}
	switch format {
	case FormatTOML:
		if err := toml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	default:
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// Encode renders cfg back to YAML bytes. Used by `yauth init`.
func Encode(cfg *Config) ([]byte, error) {
	return yaml.Marshal(cfg)
}

// resolveEnv expands `env:VAR` indirections on the database DSN. We
// limit env: resolution to DSN; secret-bearing fields use *_env names
// and are looked up by their respective plugin wiring at construction
// time.
func (c *Config) resolveEnv() error {
	if v, ok := strings.CutPrefix(c.Database.DSN, "env:"); ok {
		got := os.Getenv(v)
		if got == "" {
			return fmt.Errorf("database.dsn references env %q which is unset", v)
		}
		c.Database.DSN = got
	}
	return nil
}

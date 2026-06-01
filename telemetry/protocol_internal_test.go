package telemetry

import "testing"

func TestResolveProtocol(t *testing.T) {
	// Ensure the env fallback is read from a clean slate.
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "")

	cases := []struct {
		name string
		cfg  string
		env  string
		want string
	}{
		{"default is grpc", "", "", "grpc"},
		{"explicit grpc", "grpc", "", "grpc"},
		{"explicit http", "http", "", "http"},
		{"http/protobuf alias", "http/protobuf", "", "http"},
		{"http/json alias", "http/json", "", "http"},
		{"case/space insensitive", "  HTTP ", "", "http"},
		{"env grpc", "", "grpc", "grpc"},
		{"env http/protobuf", "", "http/protobuf", "http"},
		{"cfg overrides env", "http", "grpc", "http"},
		{"unknown falls back to grpc", "carrier-pigeon", "", "grpc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", tc.env)
			if got := resolveProtocol(tc.cfg); got != tc.want {
				t.Errorf("resolveProtocol(%q) with env %q = %q, want %q", tc.cfg, tc.env, got, tc.want)
			}
		})
	}
}

func TestDefaultEndpoint(t *testing.T) {
	if got, want := defaultEndpoint("http"), "http://localhost:4318"; got != want {
		t.Errorf("defaultEndpoint(http) = %q, want %q", got, want)
	}
	if got, want := defaultEndpoint("grpc"), "http://localhost:4317"; got != want {
		t.Errorf("defaultEndpoint(grpc) = %q, want %q", got, want)
	}
}

#![cfg(feature = "openapi")]

use std::path::Path;

fn openapi_output_path() -> &'static str {
    "../../openapi.json"
}

#[test]
#[ignore] // Run explicitly via `bun generate`, not during `cargo test`
fn generate_openapi_spec() {
    let spec = yauth::routes_meta::build_openapi_spec();
    let json = serde_json::to_string_pretty(&spec).expect("Failed to serialize OpenAPI spec");
    std::fs::write(openapi_output_path(), &json).expect("Failed to write openapi.json");
    println!("OpenAPI spec written to {}", openapi_output_path());
}

#[test]
fn check_openapi_spec_up_to_date() {
    let spec = yauth::routes_meta::build_openapi_spec();
    let expected = serde_json::to_string_pretty(&spec).expect("Failed to serialize OpenAPI spec");

    let path = Path::new(openapi_output_path());
    let current = std::fs::read_to_string(path).expect("openapi.json not found! Run: bun generate");

    assert_eq!(
        current.trim(),
        expected.trim(),
        "OpenAPI spec is out of date! Run: bun generate"
    );
}

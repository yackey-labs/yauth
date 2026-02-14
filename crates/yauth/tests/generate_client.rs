use axum_ts_client::GeneratorConfig;

fn config() -> GeneratorConfig {
    // Paths are relative to the crate root (crates/yauth/)
    // ts-rs generates bindings to ./bindings (crates/yauth/bindings/)
    // Import prefix: from packages/client/src/ to crates/yauth/bindings/
    GeneratorConfig {
        bindings_dir: "../../packages/client/src/bindings".into(),
        output_path: "../../packages/client/src/generated.ts".into(),
        factory_name: "createYAuthClient".into(),
        enable_groups: true,
        error_class_name: "YAuthError".into(),
        options_interface_name: "YAuthClientOptions".into(),
        default_credentials: "include".into(),
        type_import_prefix: "./bindings".into(),
        format_command: Some("bun biome check --write --unsafe".into()),
    }
}

#[test]
fn generate_ts_client() {
    let routes = yauth::routes_meta::all_route_meta();
    axum_ts_client::generate_to_file(&routes, &config()).unwrap();
}

#[test]
fn check_ts_client_up_to_date() {
    let routes = yauth::routes_meta::all_route_meta();
    axum_ts_client::check(&routes, &config())
        .expect("Generated TypeScript client is out of date! Run: bun generate");
}

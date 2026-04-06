//! Schema collector -- merges core + plugin schemas, topologically sorted.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use super::types::TableDef;

/// Merged schema: all tables topologically sorted by FK dependencies.
#[derive(Debug, Clone)]
pub struct YAuthSchema {
    pub tables: Vec<TableDef>,
}

impl YAuthSchema {
    /// Get a table definition by name.
    pub fn table(&self, name: &str) -> Option<&TableDef> {
        self.tables.iter().find(|t| t.name == name)
    }
}

/// Error during schema collection.
#[derive(Debug)]
pub enum SchemaError {
    DuplicateTable(String),
    MissingDependency { table: String, references: String },
    Cycle(Vec<String>),
    UnknownPlugin(String),
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaError::DuplicateTable(name) => {
                write!(
                    f,
                    "duplicate table definition: '{name}' -- each table must be defined exactly once"
                )
            }
            SchemaError::MissingDependency { table, references } => {
                write!(
                    f,
                    "table '{table}' references '{references}' which is not in the schema -- ensure the referenced table's plugin is enabled"
                )
            }
            SchemaError::Cycle(tables) => {
                write!(
                    f,
                    "cycle detected in FK dependencies among tables: {tables:?}"
                )
            }
            SchemaError::UnknownPlugin(name) => {
                write!(f, "unknown plugin: '{name}'")
            }
        }
    }
}

impl std::error::Error for SchemaError {}

/// Collect and merge core + plugin schemas, then topologically sort by FK deps.
///
/// The sort preserves input order among tables with the same dependency depth,
/// ensuring deterministic output that matches the order plugins declare tables.
pub fn collect_schema(table_lists: Vec<Vec<TableDef>>) -> Result<YAuthSchema, SchemaError> {
    // Preserve insertion order using a Vec of names
    let mut ordered_names: Vec<String> = Vec::new();
    let mut tables_by_name: HashMap<String, TableDef> = HashMap::new();

    for tables in &table_lists {
        for table in tables {
            if tables_by_name.contains_key(&table.name) {
                return Err(SchemaError::DuplicateTable(table.name.clone()));
            }
            ordered_names.push(table.name.clone());
            tables_by_name.insert(table.name.clone(), table.clone());
        }
    }

    // Topological sort (Kahn's algorithm) preserving input order for ties
    let table_names: HashSet<String> = tables_by_name.keys().cloned().collect();

    // Build in-degree count and dependents map
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut dependents: HashMap<String, Vec<String>> = HashMap::new();

    for name in &table_names {
        in_degree.entry(name.clone()).or_insert(0);
    }

    for (name, table) in &tables_by_name {
        for dep in table.dependencies() {
            if !table_names.contains(dep) {
                return Err(SchemaError::MissingDependency {
                    table: name.clone(),
                    references: dep.to_string(),
                });
            }
            *in_degree.entry(name.clone()).or_insert(0) += 1;
            dependents
                .entry(dep.to_string())
                .or_default()
                .push(name.clone());
        }
    }

    // Initialize queue with zero-degree tables in input order
    let mut queue: VecDeque<String> = VecDeque::new();
    for name in &ordered_names {
        if in_degree[name] == 0 {
            queue.push_back(name.clone());
        }
    }

    let mut sorted: Vec<TableDef> = Vec::new();
    while let Some(name) = queue.pop_front() {
        sorted.push(
            tables_by_name
                .remove(&name)
                .expect("invariant: name came from tables_by_name keys"),
        );
        if let Some(deps) = dependents.get(&name) {
            // Add newly-freed tables in their original input order
            let mut freed: Vec<String> = Vec::new();
            for dep in deps {
                let d = in_degree
                    .get_mut(dep)
                    .expect("invariant: all table names have in_degree entries");
                *d -= 1;
                if *d == 0 {
                    freed.push(dep.clone());
                }
            }
            // Sort freed tables by their position in ordered_names for stability
            freed.sort_by_key(|n| ordered_names.iter().position(|on| on == n));
            for n in freed {
                queue.push_back(n);
            }
        }
    }

    if sorted.len() != table_names.len() {
        let remaining: Vec<String> = tables_by_name.keys().cloned().collect();
        return Err(SchemaError::Cycle(remaining));
    }

    Ok(YAuthSchema { tables: sorted })
}

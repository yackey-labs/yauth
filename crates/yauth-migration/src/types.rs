//! Core types for declarative schema definitions.

/// Supported SQL dialects for DDL generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Postgres,
    Sqlite,
    Mysql,
}

impl std::fmt::Display for Dialect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dialect::Postgres => write!(f, "postgres"),
            Dialect::Sqlite => write!(f, "sqlite"),
            Dialect::Mysql => write!(f, "mysql"),
        }
    }
}

impl std::str::FromStr for Dialect {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "postgres" | "postgresql" | "pg" => Ok(Dialect::Postgres),
            "sqlite" => Ok(Dialect::Sqlite),
            "mysql" | "mariadb" => Ok(Dialect::Mysql),
            _ => Err(format!("unknown dialect: '{s}'")),
        }
    }
}

/// Supported ORM formats for migration file generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Orm {
    Diesel,
    Sqlx,
}

impl std::fmt::Display for Orm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Orm::Diesel => write!(f, "diesel"),
            Orm::Sqlx => write!(f, "sqlx"),
        }
    }
}

impl std::str::FromStr for Orm {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "diesel" => Ok(Orm::Diesel),
            "sqlx" => Ok(Orm::Sqlx),
            _ => Err(format!("unknown orm: '{s}'")),
        }
    }
}

/// Abstract column type -- each dialect maps this to a concrete SQL type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ColumnType {
    /// UUID type. Postgres: UUID.
    Uuid,
    /// Variable-length string. Postgres: VARCHAR.
    Varchar,
    /// Variable-length string with max length. Postgres: VARCHAR(n).
    VarcharN(u32),
    /// Boolean. Postgres: BOOLEAN.
    Boolean,
    /// Timestamp with timezone. Postgres: TIMESTAMPTZ.
    DateTime,
    /// JSON binary. Postgres: JSONB.
    Json,
    /// 32-bit integer. Postgres: INT.
    Int,
    /// 16-bit integer. Postgres: SMALLINT.
    SmallInt,
    /// Text (unbounded). Postgres: TEXT.
    Text,
}

/// ON DELETE action for foreign keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OnDelete {
    Cascade,
    SetNull,
    Restrict,
    NoAction,
}

/// Foreign key reference from a column to another table's column.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ForeignKey {
    pub references_table: String,
    pub references_column: String,
    pub on_delete: OnDelete,
}

/// Definition of a single column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnDef {
    pub name: String,
    pub col_type: ColumnType,
    pub nullable: bool,
    pub primary_key: bool,
    pub unique: bool,
    pub default: Option<String>,
    pub foreign_key: Option<ForeignKey>,
}

impl ColumnDef {
    /// Create a new non-null column with no constraints.
    pub fn new(name: &str, col_type: ColumnType) -> Self {
        Self {
            name: name.to_string(),
            col_type,
            nullable: false,
            primary_key: false,
            unique: false,
            default: None,
            foreign_key: None,
        }
    }

    pub fn nullable(mut self) -> Self {
        self.nullable = true;
        self
    }

    pub fn primary_key(mut self) -> Self {
        self.primary_key = true;
        self
    }

    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }

    pub fn default(mut self, val: &str) -> Self {
        self.default = Some(val.to_string());
        self
    }

    pub fn references(mut self, table: &str, column: &str, on_delete: OnDelete) -> Self {
        self.foreign_key = Some(ForeignKey {
            references_table: table.to_string(),
            references_column: column.to_string(),
            on_delete,
        });
        self
    }
}

/// Index definition for a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDef {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

/// Definition of a single table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDef {
    pub name: String,
    pub columns: Vec<ColumnDef>,
    pub indices: Vec<IndexDef>,
}

impl TableDef {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            columns: Vec::new(),
            indices: Vec::new(),
        }
    }

    pub fn column(mut self, col: ColumnDef) -> Self {
        self.columns.push(col);
        self
    }

    pub fn index(mut self, idx: IndexDef) -> Self {
        self.indices.push(idx);
        self
    }

    /// Get the names of tables this table depends on (via foreign keys).
    pub fn dependencies(&self) -> Vec<&str> {
        self.columns
            .iter()
            .filter_map(|c| {
                c.foreign_key
                    .as_ref()
                    .map(|fk| fk.references_table.as_str())
            })
            .filter(|t| *t != self.name)
            .collect()
    }

    /// Replace `old_prefix` with `new_prefix` in the table name and all FK references.
    pub fn apply_prefix(&mut self, old_prefix: &str, new_prefix: &str) {
        if self.name.starts_with(old_prefix) {
            self.name = format!("{}{}", new_prefix, &self.name[old_prefix.len()..]);
        }
        for col in &mut self.columns {
            if let Some(ref mut fk) = col.foreign_key
                && fk.references_table.starts_with(old_prefix)
            {
                fk.references_table =
                    format!("{}{}", new_prefix, &fk.references_table[old_prefix.len()..]);
            }
        }
        for idx in &mut self.indices {
            if idx.name.starts_with(old_prefix) {
                idx.name = format!("{}{}", new_prefix, &idx.name[old_prefix.len()..]);
            }
        }
    }
}

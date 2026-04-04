//! Core types for declarative schema definitions.

/// Supported SQL dialects for DDL generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Postgres,
    Sqlite,
    Mysql,
}

/// Abstract column type — each dialect maps this to a concrete SQL type.
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
    pub references_table: &'static str,
    pub references_column: &'static str,
    pub on_delete: OnDelete,
}

/// Definition of a single column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnDef {
    pub name: &'static str,
    pub col_type: ColumnType,
    pub nullable: bool,
    pub primary_key: bool,
    pub unique: bool,
    pub default: Option<&'static str>,
    pub foreign_key: Option<ForeignKey>,
}

impl ColumnDef {
    /// Create a new non-null column with no constraints.
    pub fn new(name: &'static str, col_type: ColumnType) -> Self {
        Self {
            name,
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

    pub fn default(mut self, val: &'static str) -> Self {
        self.default = Some(val);
        self
    }

    pub fn references(
        mut self,
        table: &'static str,
        column: &'static str,
        on_delete: OnDelete,
    ) -> Self {
        self.foreign_key = Some(ForeignKey {
            references_table: table,
            references_column: column,
            on_delete,
        });
        self
    }
}

/// Index definition for a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDef {
    pub name: &'static str,
    pub columns: Vec<&'static str>,
    pub unique: bool,
}

/// Definition of a single table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDef {
    pub name: &'static str,
    pub columns: Vec<ColumnDef>,
    pub indices: Vec<IndexDef>,
}

impl TableDef {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
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
    pub fn dependencies(&self) -> Vec<&'static str> {
        self.columns
            .iter()
            .filter_map(|c| c.foreign_key.as_ref().map(|fk| fk.references_table))
            .filter(|t| *t != self.name) // self-references don't count
            .collect()
    }
}

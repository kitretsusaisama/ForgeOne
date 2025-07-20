//! # Database Schema Module
//!
//! This module provides schema management for the database system, including:
//! - Schema definition and validation
//! - Schema migration and versioning
//! - Schema integrity checking
//! - Schema documentation generation

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Once};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use semver::Version;
use crate::error::{ForgeError, Result};
//use base64::engine::general_purpose::STANDARD;
use base64::Engine;

// Static initialization
static INIT: Once = Once::new();
static mut SCHEMA_MANAGER: Option<Arc<RwLock<SchemaManager>>> = None;

/// Schema manager
pub struct SchemaManager {
    /// Base directory for schema storage
    base_dir: PathBuf,
    /// Schemas by name
    schemas: HashMap<String, Schema>,
    /// Whether schema validation is enabled
    validation_enabled: bool,
}

/// Schema definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    /// Schema name
    pub name: String,
    /// Schema version
    pub version: Version,
    /// Schema description
    pub description: String,
    /// Tables in the schema
    pub tables: Vec<TableSchema>,
    /// Schema creation timestamp
    pub created_at: DateTime<Utc>,
    /// Schema last updated timestamp
    pub updated_at: DateTime<Utc>,
    /// Schema author
    pub author: String,
    /// Migration history
    pub migrations: Vec<Migration>,
}

/// Table schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableSchema {
    /// Table name
    pub name: String,
    /// Table description
    pub description: String,
    /// Fields in the table
    pub fields: Vec<FieldSchema>,
    /// Indexes for the table
    pub indexes: Vec<IndexSchema>,
    /// Foreign keys
    pub foreign_keys: Vec<ForeignKeySchema>,
    /// Whether the table is encrypted
    pub encrypted: bool,
    /// Whether the table tracks changes
    pub track_changes: bool,
    /// Whether the table supports TTL
    pub ttl_enabled: bool,
    /// Default TTL in seconds (if TTL is enabled)
    pub default_ttl_seconds: Option<u64>,
}

/// Field schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSchema {
    /// Field name
    pub name: String,
    /// Field description
    pub description: String,
    /// Field type
    pub field_type: FieldType,
    /// Whether the field is required
    pub required: bool,
    /// Default value
    pub default_value: Option<String>,
    /// Validation rules
    pub validation: Vec<ValidationRule>,
    /// Whether the field is encrypted
    pub encrypted: bool,
    /// Whether the field is indexed
    pub indexed: bool,
    /// Whether the field is unique
    pub unique: bool,
}

/// Field type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FieldType {
    /// String type
    String,
    /// Integer type
    Integer,
    /// Float type
    Float,
    /// Boolean type
    Boolean,
    /// Date type
    Date,
    /// DateTime type
    DateTime,
    /// Binary type
    Binary,
    /// JSON type
    Json,
    /// Array type
    Array(Box<FieldType>),
    /// Map type
    Map(Box<FieldType>, Box<FieldType>),
    /// Reference type
    Reference(String),
    /// Enum type
    Enum(Vec<String>),
    /// UUID type
    Uuid,
}

/// Validation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationRule {
    /// Minimum length
    MinLength(usize),
    /// Maximum length
    MaxLength(usize),
    /// Minimum value
    MinValue(f64),
    /// Maximum value
    MaxValue(f64),
    /// Regular expression pattern
    Pattern(String),
    /// Enumeration of allowed values
    Enum(Vec<String>),
    /// Custom validation function
    Custom(String),
}

/// Index schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexSchema {
    /// Index name
    pub name: String,
    /// Fields in the index
    pub fields: Vec<String>,
    /// Whether the index is unique
    pub unique: bool,
    /// Index type
    pub index_type: IndexType,
}

/// Index type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndexType {
    /// B-tree index
    BTree,
    /// Hash index
    Hash,
    /// Full-text search index
    FullText,
    /// Spatial index
    Spatial,
}

/// Foreign key schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForeignKeySchema {
    /// Foreign key name
    pub name: String,
    /// Fields in the foreign key
    pub fields: Vec<String>,
    /// Referenced table
    pub referenced_table: String,
    /// Referenced fields
    pub referenced_fields: Vec<String>,
    /// On delete action
    pub on_delete: ForeignKeyAction,
    /// On update action
    pub on_update: ForeignKeyAction,
}

/// Foreign key action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForeignKeyAction {
    /// Cascade
    Cascade,
    /// Set null
    SetNull,
    /// Set default
    SetDefault,
    /// Restrict
    Restrict,
    /// No action
    NoAction,
}

/// Migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Migration {
    /// Migration ID
    pub id: String,
    /// Migration name
    pub name: String,
    /// Migration description
    pub description: String,
    /// Migration timestamp
    pub timestamp: DateTime<Utc>,
    /// Migration author
    pub author: String,
    /// Migration script
    pub script: String,
    /// Migration status
    pub status: MigrationStatus,
    /// Migration applied timestamp
    pub applied_at: Option<DateTime<Utc>>,
    /// Migration duration in milliseconds
    pub duration_ms: Option<u64>,
    /// Migration checksum
    pub checksum: String,
}

/// Migration status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MigrationStatus {
    /// Pending
    Pending,
    /// Applied
    Applied,
    /// Failed
    Failed(String),
    /// Rolled back
    RolledBack,
}

/// Initialize schema manager
pub fn init_schema_manager(base_dir: &PathBuf, validation_enabled: bool) -> Result<()> {
    INIT.call_once(|| {
        // Create base directory if it doesn't exist
        let schemas_dir = base_dir.join("schemas");
        if !schemas_dir.exists() {
            if let Err(e) = std::fs::create_dir_all(&schemas_dir) {
                eprintln!("Failed to create schemas directory: {}", e);
                return;
            }
        }
        
        // Create manager
        let manager = SchemaManager {
            base_dir: base_dir.clone(),
            schemas: HashMap::new(),
            validation_enabled,
        };
        
        // Load existing schemas
        if let Err(e) = load_schemas(&manager) {
            eprintln!("Failed to load schemas: {}", e);
        }
        
        // Store manager
        unsafe {
            SCHEMA_MANAGER = Some(Arc::new(RwLock::new(manager)));
        }
    });
    
    Ok(())
}

/// Get schema manager
pub fn get_schema_manager() -> Result<Arc<RwLock<SchemaManager>>> {
    unsafe {
        match &SCHEMA_MANAGER {
            Some(manager) => Ok(manager.clone()),
            None => Err(ForgeError::DatabaseQueryError("Schema manager not initialized".to_string())),
        }
    }
}

/// Load schemas from disk
fn load_schemas(manager: &SchemaManager) -> Result<()> {
    let schemas_dir = manager.base_dir.join("schemas");
    
    if !schemas_dir.exists() {
        return Ok(());
    }
    
    for entry in std::fs::read_dir(&schemas_dir).map_err(|e| {
        ForgeError::DatabaseQueryError(format!("Failed to read schemas directory: {}", e))
    })? {
        let entry = entry.map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to read directory entry: {}", e))
        })?;
        
        let path = entry.path();
        
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            let schema_json = std::fs::read_to_string(&path).map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to read schema file: {}", e))
            })?;
            
            let schema: Schema = serde_json::from_str(&schema_json).map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to parse schema: {}", e))
            })?;
            
            let manager = get_schema_manager()?;
            let mut manager_write = manager.write().unwrap();
            manager_write.schemas.insert(schema.name.clone(), schema);
        }
    }
    
    Ok(())
}

impl SchemaManager {
    /// Register a schema
    pub fn register_schema(&mut self, schema: Schema) -> Result<()> {
        // Validate schema
        if self.validation_enabled {
            self.validate_schema(&schema)?;
        }
        
        // Save schema to disk
        let schemas_dir = self.base_dir.join("schemas");
        if !schemas_dir.exists() {
            std::fs::create_dir_all(&schemas_dir).map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to create schemas directory: {}", e))
            })?;
        }
        
        let schema_path = schemas_dir.join(format!("{}.json", schema.name));
        let schema_json = serde_json::to_string_pretty(&schema).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to serialize schema: {}", e))
        })?;
        
        std::fs::write(&schema_path, schema_json).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to write schema file: {}", e))
        })?;
        
        // Add schema to manager
        self.schemas.insert(schema.name.clone(), schema);
        
        Ok(())
    }
    
    /// Get a schema
    pub fn get_schema(&self, name: &str) -> Option<&Schema> {
        self.schemas.get(name)
    }
    
    /// Validate a schema
    pub fn validate_schema(&self, schema: &Schema) -> Result<()> {
        // Check for duplicate table names
        let mut table_names = std::collections::HashSet::new();
        for table in &schema.tables {
            if !table_names.insert(table.name.clone()) {
                return Err(ForgeError::DatabaseQueryError(format!("Duplicate table name: {}", table.name)));
            }
            
            // Check for duplicate field names
            let mut field_names = std::collections::HashSet::new();
            for field in &table.fields {
                if !field_names.insert(field.name.clone()) {
                    return Err(ForgeError::DatabaseQueryError(format!("Duplicate field name: {} in table {}", field.name, table.name)));
                }
            }
            
            // Check for duplicate index names
            let mut index_names = std::collections::HashSet::new();
            for index in &table.indexes {
                if !index_names.insert(index.name.clone()) {
                    return Err(ForgeError::DatabaseQueryError(format!("Duplicate index name: {} in table {}", index.name, table.name)));
                }
                
                // Check that index fields exist
                for field_name in &index.fields {
                    if !table.fields.iter().any(|f| &f.name == field_name) {
                        return Err(ForgeError::DatabaseQueryError(
                            format!("Index {} references non-existent field {} in table {}", 
                                   index.name, field_name, table.name),
                        ));
                    }
                }
            }
            
            // Check foreign keys
            for fk in &table.foreign_keys {
                // Check that foreign key fields exist
                for field_name in &fk.fields {
                    if !table.fields.iter().any(|f| &f.name == field_name) {
                        return Err(ForgeError::DatabaseQueryError(
                            format!("Foreign key {} references non-existent field {} in table {}", 
                                   fk.name, field_name, table.name),
                        ));
                    }
                }
                
                // Check that referenced table exists
                if !schema.tables.iter().any(|t| t.name == fk.referenced_table) {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Foreign key {} references non-existent table {}", 
                               fk.name, fk.referenced_table),
                    ));
                }
                
                // Check that referenced fields exist
                let referenced_table = schema.tables.iter()
                    .find(|t| t.name == fk.referenced_table)
                    .unwrap();
                
                for field_name in &fk.referenced_fields {
                    if !referenced_table.fields.iter().any(|f| &f.name == field_name) {
                        return Err(ForgeError::DatabaseQueryError(
                            format!("Foreign key {} references non-existent field {} in table {}", 
                                   fk.name, field_name, fk.referenced_table),
                        ));
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Validate data against schema
    pub fn validate_data(&self, table_name: &str, data: &serde_json::Value) -> Result<()> {
        if !self.validation_enabled {
            return Ok(());
        }
        
        // Find the table schema
        let table_schema = self.find_table_schema(table_name)?;
        
        // Validate data against schema
        self.validate_object(data, &table_schema)
    }
    
    /// Find a table schema
    fn find_table_schema(&self, table_name: &str) -> Result<&TableSchema> {
        for schema in self.schemas.values() {
            for table in &schema.tables {
                if table.name == table_name {
                    return Ok(table);
                }
            }
        }
        
        Err(ForgeError::DatabaseQueryError(
            format!("Table schema not found: {}", table_name),
        ))
    }
    
    /// Validate an object against a table schema
    fn validate_object(&self, data: &serde_json::Value, table_schema: &TableSchema) -> Result<()> {
        // Check that data is an object
        if !data.is_object() {
            return Err(ForgeError::DatabaseQueryError(
                format!("Data is not an object for table {}", table_schema.name),
            ));
        }
        
        let data_obj = data.as_object().unwrap();
        
        // Check required fields
        for field in &table_schema.fields {
            if field.required && !data_obj.contains_key(&field.name) {
                return Err(ForgeError::DatabaseQueryError(
                    format!("Required field {} missing in table {}", field.name, table_schema.name),
                ));
            }
        }
        
        // Validate each field
        for (field_name, field_value) in data_obj {
            // Find field schema
            let field_schema = table_schema.fields.iter()
                .find(|f| f.name == *field_name);
            
            if let Some(field_schema) = field_schema {
                self.validate_field(field_value, field_schema)?;
            }
        }
        
        Ok(())
    }
    
    /// Validate a field against a field schema
    fn validate_field(&self, value: &serde_json::Value, field_schema: &FieldSchema) -> Result<()> {
        // Check field type
        match &field_schema.field_type {
            FieldType::String => {
                if !value.is_string() {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be a string", field_schema.name),
                    ));
                }
                
                let string_value = value.as_str().unwrap();
                
                // Apply validation rules
                for rule in &field_schema.validation {
                    match rule {
                        ValidationRule::MinLength(min) => {
                            if string_value.len() < *min {
                                return Err(ForgeError::DatabaseQueryError(
                                    format!("Field {} should have minimum length {}", field_schema.name, min),
                                ));
                            }
                        },
                        ValidationRule::MaxLength(max) => {
                            if string_value.len() > *max {
                                return Err(ForgeError::DatabaseQueryError(
                                    format!("Field {} should have maximum length {}", field_schema.name, max),
                                ));
                            }
                        },
                        ValidationRule::Pattern(pattern) => {
                            let regex = regex::Regex::new(pattern).map_err(|e| {
                                ForgeError::DatabaseQueryError(
                                    format!("Invalid regex pattern: {}", e),
                                )
                            })?;
                            
                            if !regex.is_match(string_value) {
                                return Err(ForgeError::DatabaseQueryError(
                                    format!("Field {} should match pattern {}", field_schema.name, pattern),
                                ));
                            }
                        },
                        ValidationRule::Enum(allowed_values) => {
                            if !allowed_values.contains(&string_value.to_string()) {
                                return Err(ForgeError::DatabaseQueryError(
                                    format!("Field {} should be one of {:?}", field_schema.name, allowed_values),
                                ));
                            }
                        },
                        _ => {}
                    }
                }
            },
            FieldType::Integer => {
                if !value.is_i64() && !value.is_u64() {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be an integer", field_schema.name),
                    ));
                }
                
                let num_value = if value.is_i64() {
                    value.as_i64().unwrap() as f64
                } else {
                    value.as_u64().unwrap() as f64
                };
                
                // Apply validation rules
                for rule in &field_schema.validation {
                    match rule {
                        ValidationRule::MinValue(min) => {
                            if num_value < *min {
                                return Err(ForgeError::DatabaseQueryError(
                                    format!("Field {} should be at least {}", field_schema.name, min),
                                ));
                            }
                        },
                        ValidationRule::MaxValue(max) => {
                            if num_value > *max {
                                return Err(ForgeError::DatabaseQueryError(
                                    format!("Field {} should be at most {}", field_schema.name, max),
                                ));
                            }
                        },
                        _ => {}
                    }
                }
            },
            FieldType::Float => {
                if !value.is_f64() && !value.is_i64() && !value.is_u64() {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be a number", field_schema.name),
                    ));
                }
                
                let num_value = if value.is_f64() {
                    value.as_f64().unwrap()
                } else if value.is_i64() {
                    value.as_i64().unwrap() as f64
                } else {
                    value.as_u64().unwrap() as f64
                };
                
                // Apply validation rules
                for rule in &field_schema.validation {
                    match rule {
                        ValidationRule::MinValue(min) => {
                            if num_value < *min {
                                return Err(ForgeError::DatabaseQueryError(
                                    format!("Field {} should be at least {}", field_schema.name, min),
                                ));
                            }
                        },
                        ValidationRule::MaxValue(max) => {
                            if num_value > *max {
                                return Err(ForgeError::DatabaseQueryError(
                                    format!("Field {} should be at most {}", field_schema.name, max),
                                ));
                            }
                        },
                        _ => {}
                    }
                }
            },
            FieldType::Boolean => {
                if !value.is_boolean() {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be a boolean", field_schema.name),
                    ));
                }
            },
            FieldType::Date | FieldType::DateTime => {
                if !value.is_string() {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be a date string", field_schema.name),
                    ));
                }
                
                let date_str = value.as_str().unwrap();
                
                // Try to parse as DateTime
                if let Err(_) = chrono::DateTime::parse_from_rfc3339(date_str) {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be a valid date/time string", field_schema.name),
                    ));
                }
            },
            FieldType::Binary => {
                if !value.is_string() {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be a base64 string", field_schema.name),
                    ));
                }
                
                let base64_str = value.as_str().unwrap();
                
                // Try to decode as base64
                if let Err(_) = base64::engine::general_purpose::STANDARD.decode(base64_str) {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be a valid base64 string", field_schema.name),
                    ));
                }
            },
            FieldType::Json => {
                // Any JSON value is valid
            },
            FieldType::Array(item_type) => {
                if !value.is_array() {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be an array", field_schema.name),
                    ));
                }
                
                let array_value = value.as_array().unwrap();
                
                // Validate each item
                for item in array_value {
                    let item_field = FieldSchema {
                        name: format!("{}.item", field_schema.name),
                        description: "Array item".to_string(),
                        field_type: (**item_type).clone(), // clone the FieldType
                        required: true,
                        default_value: None,
                        validation: Vec::new(),
                        encrypted: false,
                        indexed: false,
                        unique: false,
                    };
                    
                    self.validate_field(item, &item_field)?;
                }
            },
            FieldType::Map(key_type, value_type) => {
                if !value.is_object() {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be an object", field_schema.name),
                    ));
                }
                
                let map_value = value.as_object().unwrap();
                
                // Validate each key and value
                for (key, val) in map_value {
                    let key_field = FieldSchema {
                        name: format!("{}.key", field_schema.name),
                        description: "Map key".to_string(),
                        field_type: (**key_type).clone(),
                        required: true,
                        default_value: None,
                        validation: Vec::new(),
                        encrypted: false,
                        indexed: false,
                        unique: false,
                    };
                    
                    let value_field = FieldSchema {
                        name: format!("{}.value", field_schema.name),
                        description: "Map value".to_string(),
                        field_type: (**value_type).clone(),
                        required: true,
                        default_value: None,
                        validation: Vec::new(),
                        encrypted: false,
                        indexed: false,
                        unique: false,
                    };
                    
                    self.validate_field(&serde_json::Value::String(key.clone()), &key_field)?;
                    self.validate_field(val, &value_field)?;
                }
            },
            FieldType::Reference(referenced_table) => {
                if !value.is_string() {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be a reference ID string", field_schema.name),
                    ));
                }
            },
            FieldType::Enum(allowed_values) => {
                if !value.is_string() {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be a string enum value", field_schema.name),
                    ));
                }
                
                let enum_value = value.as_str().unwrap();
                
                if !allowed_values.contains(&enum_value.to_string()) {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be one of {:?}", field_schema.name, allowed_values),
                    ));
                }
            },
            FieldType::Uuid => {
                if !value.is_string() {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be a UUID string", field_schema.name),
                    ));
                }
                
                let uuid_str = value.as_str().unwrap();
                
                // Try to parse as UUID
                if let Err(_) = Uuid::parse_str(uuid_str) {
                    return Err(ForgeError::DatabaseQueryError(
                        format!("Field {} should be a valid UUID", field_schema.name),
                    ));
                }
            },
        }
        
        Ok(())
    }
    
    /// Apply a migration
    pub fn apply_migration(&mut self, schema_name: &str, migration: Migration) -> Result<()> {
        // Find the schema
        let schema = self.schemas.get_mut(schema_name).ok_or_else(|| {
            ForgeError::DatabaseQueryError(
                format!("Schema not found: {}", schema_name),
            )
        })?;
        
        // Apply the migration
        let start_time = std::time::Instant::now();
        
        // TODO: Execute migration script
        
        let duration = start_time.elapsed();
        
        // Update migration status
        let mut migration = migration;
        migration.status = MigrationStatus::Applied;
        migration.applied_at = Some(Utc::now());
        migration.duration_ms = Some(duration.as_millis() as u64);
        
        // Add migration to schema
        schema.migrations.push(migration);
        
        // Update schema version
        schema.version = semver::Version::parse(&format!("{}.{}.{}", 
                                                      schema.version.major, 
                                                      schema.version.minor + 1, 
                                                      0)).unwrap();
        schema.updated_at = Utc::now();
        
        // Remove schema from map, update, then re-insert and register
        let updated_schema = schema.clone();
        drop(schema); // End the mutable borrow

        self.register_schema(updated_schema)?;
        
        Ok(())
    }
    
    /// Generate schema documentation
    pub fn generate_documentation(&self, schema_name: &str) -> Result<String> {
        // Find the schema
        let schema = self.schemas.get(schema_name).ok_or_else(|| {
            ForgeError::DatabaseQueryError(
                format!("Schema not found: {}", schema_name),
            )
        })?;
        
        // Generate markdown documentation
        let mut doc = String::new();
        
        doc.push_str(&format!("# {} Schema Documentation\n\n", schema.name));
        doc.push_str(&format!("Version: {}\n\n", schema.version));
        doc.push_str(&format!("{}\n\n", schema.description));
        doc.push_str(&format!("Created: {}\n\n", schema.created_at));
        doc.push_str(&format!("Last Updated: {}\n\n", schema.updated_at));
        doc.push_str(&format!("Author: {}\n\n", schema.author));
        
        doc.push_str("## Tables\n\n");
        
        for table in &schema.tables {
            doc.push_str(&format!("### {}\n\n", table.name));
            doc.push_str(&format!("{}\n\n", table.description));
            
            // Table properties
            doc.push_str("**Properties:**\n\n");
            doc.push_str(&format!("- Encrypted: {}\n", table.encrypted));
            doc.push_str(&format!("- Track Changes: {}\n", table.track_changes));
            doc.push_str(&format!("- TTL Enabled: {}\n", table.ttl_enabled));
            if let Some(ttl) = table.default_ttl_seconds {
                doc.push_str(&format!("- Default TTL: {} seconds\n", ttl));
            }
            doc.push_str("\n");
            
            // Fields
            doc.push_str("**Fields:**\n\n");
            doc.push_str("| Name | Type | Required | Encrypted | Indexed | Unique | Description |\n");
            doc.push_str("|------|------|----------|-----------|---------|--------|-------------|\n");
            
            for field in &table.fields {
                let field_type = match &field.field_type {
                    FieldType::String => "String".to_string(),
                    FieldType::Integer => "Integer".to_string(),
                    FieldType::Float => "Float".to_string(),
                    FieldType::Boolean => "Boolean".to_string(),
                    FieldType::Date => "Date".to_string(),
                    FieldType::DateTime => "DateTime".to_string(),
                    FieldType::Binary => "Binary".to_string(),
                    FieldType::Json => "JSON".to_string(),
                    FieldType::Array(item_type) => format!("Array<{}>", field_type_to_string(&*item_type)),
                    FieldType::Map(key_type, value_type) => {
                        format!("Map<{}, {}>", field_type_to_string(&*key_type), field_type_to_string(&*value_type))
                    },
                    FieldType::Reference(table) => format!("Reference<{}>", table),
                    FieldType::Enum(values) => format!("Enum<{}>", values.join(", ")),
                    FieldType::Uuid => "UUID".to_string(),
                };
                
                doc.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} | {} |\n",
                    field.name,
                    field_type,
                    field.required,
                    field.encrypted,
                    field.indexed,
                    field.unique,
                    field.description
                ));
            }
            
            doc.push_str("\n");
            
            // Indexes
            if !table.indexes.is_empty() {
                doc.push_str("**Indexes:**\n\n");
                doc.push_str("| Name | Fields | Unique | Type |\n");
                doc.push_str("|------|--------|--------|------|\n");
                
                for index in &table.indexes {
                    let index_type = match &index.index_type {
                        IndexType::BTree => "B-Tree",
                        IndexType::Hash => "Hash",
                        IndexType::FullText => "Full-Text",
                        IndexType::Spatial => "Spatial",
                    };
                    
                    doc.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        index.name,
                        index.fields.join(", "),
                        index.unique,
                        index_type
                    ));
                }
                
                doc.push_str("\n");
            }
            
            // Foreign Keys
            if !table.foreign_keys.is_empty() {
                doc.push_str("**Foreign Keys:**\n\n");
                doc.push_str("| Name | Fields | Referenced Table | Referenced Fields | On Delete | On Update |\n");
                doc.push_str("|------|--------|-----------------|-------------------|-----------|-----------|\n");
                
                for fk in &table.foreign_keys {
                    let on_delete = match &fk.on_delete {
                        ForeignKeyAction::Cascade => "CASCADE",
                        ForeignKeyAction::SetNull => "SET NULL",
                        ForeignKeyAction::SetDefault => "SET DEFAULT",
                        ForeignKeyAction::Restrict => "RESTRICT",
                        ForeignKeyAction::NoAction => "NO ACTION",
                    };
                    
                    let on_update = match &fk.on_update {
                        ForeignKeyAction::Cascade => "CASCADE",
                        ForeignKeyAction::SetNull => "SET NULL",
                        ForeignKeyAction::SetDefault => "SET DEFAULT",
                        ForeignKeyAction::Restrict => "RESTRICT",
                        ForeignKeyAction::NoAction => "NO ACTION",
                    };
                    
                    doc.push_str(&format!(
                        "| {} | {} | {} | {} | {} | {} |\n",
                        fk.name,
                        fk.fields.join(", "),
                        fk.referenced_table,
                        fk.referenced_fields.join(", "),
                        on_delete,
                        on_update
                    ));
                }
                
                doc.push_str("\n");
            }
        }
        
        // Migrations
        if !schema.migrations.is_empty() {
            doc.push_str("## Migration History\n\n");
            doc.push_str("| ID | Name | Description | Status | Applied At | Duration |\n");
            doc.push_str("|----|----|-------------|--------|------------|----------|\n");
            
            for migration in &schema.migrations {
                let status = match &migration.status {
                    MigrationStatus::Pending => "Pending",
                    MigrationStatus::Applied => "Applied",
                    MigrationStatus::Failed(reason) => &reason,
                    MigrationStatus::RolledBack => "Rolled Back",
                };
                
                let applied_at = migration.applied_at
                    .map(|dt| dt.to_string())
                    .unwrap_or_else(|| "-".to_string());
                
                let duration = migration.duration_ms
                    .map(|ms| format!("{} ms", ms))
                    .unwrap_or_else(|| "-".to_string());
                
                doc.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} |\n",
                    migration.id,
                    migration.name,
                    migration.description,
                    status,
                    applied_at,
                    duration
                ));
            }
        }
        
        Ok(doc)
    }
}

/// Convert field type to string
fn field_type_to_string(field_type: &FieldType) -> String {
    match field_type {
        FieldType::String => "String".to_string(),
        FieldType::Integer => "Integer".to_string(),
        FieldType::Float => "Float".to_string(),
        FieldType::Boolean => "Boolean".to_string(),
        FieldType::Date => "Date".to_string(),
        FieldType::DateTime => "DateTime".to_string(),
        FieldType::Binary => "Binary".to_string(),
        FieldType::Json => "JSON".to_string(),
        FieldType::Array(item_type) => format!("Array<{}>", field_type_to_string(&*item_type)),
        FieldType::Map(key_type, value_type) => {
            format!("Map<{}, {}>", field_type_to_string(&*key_type), field_type_to_string(&*value_type))
        },
        FieldType::Reference(table) => format!("Reference<{}>", table),
        FieldType::Enum(values) => format!("Enum<{}>", values.join(", ")),
        FieldType::Uuid => "UUID".to_string(),
    }
}
//! # Database Integrity Module
//!
//! This module provides integrity checking and verification for the database system, including:
//! - Checksum verification
//! - Corruption detection
//! - Data consistency checks
//! - Integrity reports

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Once};
use std::path::PathBuf;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::error::{ForgeError, Result};
use crate::db::metrics::{get_metrics_manager, OperationType};
use crate::db::DbOptions;

// Static initialization
static INIT: Once = Once::new();
static mut INTEGRITY_MANAGER: Option<Arc<RwLock<IntegrityManager>>> = None;

/// Database integrity manager
pub struct IntegrityManager {
    /// Base directory for integrity reports
    base_dir: PathBuf,
    /// Whether integrity checking is enabled
    enabled: bool,
    /// Integrity check interval in hours
    check_interval_hours: u32,
    /// Last check time
    last_check_time: Option<DateTime<Utc>>,
    /// Integrity reports
    reports: HashMap<String, IntegrityReport>,
}

/// Integrity check level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityCheckLevel {
    /// Basic check (fast)
    Basic,
    /// Standard check
    Standard,
    /// Thorough check (slow)
    Thorough,
}

/// Integrity report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// Report ID
    pub id: String,
    /// Database name
    pub database: String,
    /// Check level
    pub check_level: IntegrityCheckLevel,
    /// Start time
    pub start_time: DateTime<Utc>,
    /// End time
    pub end_time: DateTime<Utc>,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Whether the check passed
    pub passed: bool,
    /// Issues found
    pub issues: Vec<IntegrityIssue>,
    /// Tables checked
    pub tables_checked: Vec<String>,
    /// Records checked
    pub records_checked: u64,
    /// Bytes checked
    pub bytes_checked: u64,
}

/// Integrity issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityIssue {
    /// Issue ID
    pub id: String,
    /// Issue type
    pub issue_type: IntegrityIssueType,
    /// Severity
    pub severity: IssueSeverity,
    /// Table name
    pub table: Option<String>,
    /// Record ID
    pub record_id: Option<String>,
    /// Field name
    pub field: Option<String>,
    /// Description
    pub description: String,
    /// Repair action
    pub repair_action: Option<RepairAction>,
    /// Whether the issue was repaired
    pub repaired: bool,
}

/// Integrity issue type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityIssueType {
    /// Checksum mismatch
    ChecksumMismatch,
    /// Missing record
    MissingRecord,
    /// Corrupt data
    CorruptData,
    /// Schema violation
    SchemaViolation,
    /// Index inconsistency
    IndexInconsistency,
    /// Foreign key violation
    ForeignKeyViolation,
    /// Duplicate key
    DuplicateKey,
    /// Orphaned record
    OrphanedRecord,
    /// File system error
    FileSystemError,
    /// Encryption error
    EncryptionError,
    /// Other issue
    Other(String),
}

/// Issue severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueSeverity {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Repair action
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairAction {
    /// Delete record
    DeleteRecord,
    /// Rebuild index
    RebuildIndex,
    /// Restore from backup
    RestoreFromBackup,
    /// Recalculate checksum
    RecalculateChecksum,
    /// Fix schema
    FixSchema,
    /// Custom action
    Custom(String),
}

/// Initialize integrity manager
pub fn init_integrity_manager(
    base_dir: &PathBuf,
    enabled: bool,
    check_interval_hours: u32,
) -> Result<()> {
    INIT.call_once(|| {
        // Create base directory if it doesn't exist
        let integrity_dir = base_dir.join("integrity");
        if !integrity_dir.exists() {
            if let Err(e) = std::fs::create_dir_all(&integrity_dir) {
                eprintln!("Failed to create integrity directory: {}", e);
                return;
            }
        }
        
        let manager = IntegrityManager {
            base_dir: base_dir.clone(),
            enabled,
            check_interval_hours,
            last_check_time: None,
            reports: HashMap::new(),
        };
        
        // Load existing reports
        if let Err(e) = load_reports(&manager) {
            eprintln!("Failed to load integrity reports: {}", e);
        }
        
        unsafe {
            INTEGRITY_MANAGER = Some(Arc::new(RwLock::new(manager)));
        }
    });
    
    Ok(())
}

/// Get integrity manager
pub fn get_integrity_manager() -> Result<Arc<RwLock<IntegrityManager>>> {
    unsafe {
        match &INTEGRITY_MANAGER {
            Some(manager) => Ok(manager.clone()),
            None => Err(ForgeError::DatabaseQueryError("Integrity manager not initialized".to_string())),
        }
    }
}

/// Load integrity reports from disk
fn load_reports(manager: &IntegrityManager) -> Result<()> {
    let reports_dir = manager.base_dir.join("integrity").join("reports");
    
    if !reports_dir.exists() {
        return Ok(());
    }
    
    for entry in std::fs::read_dir(&reports_dir).map_err(|e| {
        ForgeError::DatabaseQueryError(format!("Failed to read reports directory: {}", e))
    })? {
        let entry = entry.map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to read directory entry: {}", e))
        })?;
        
        let path = entry.path();
        
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            let report_json = std::fs::read_to_string(&path).map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to read report file: {}", e))
            })?;
            
            let report: IntegrityReport = serde_json::from_str(&report_json).map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to parse report: {}", e))
            })?;
            
            let integrity_manager = get_integrity_manager()?;
            let mut manager_write = integrity_manager.write().unwrap();
            manager_write.reports.insert(report.id.clone(), report);
        }
    }
    
    Ok(())
}

impl IntegrityManager {
    /// Check if an integrity check is due
    pub fn is_check_due(&self) -> bool {
        if !self.enabled {
            return false;
        }
        
        match self.last_check_time {
            Some(last_check) => {
                let hours_since_last_check = Utc::now()
                    .signed_duration_since(last_check)
                    .num_hours();
                
                hours_since_last_check >= self.check_interval_hours as i64
            },
            None => true,
        }
    }
    
    /// Run an integrity check
    pub fn run_integrity_check(
        &mut self,
        database: &str,
        level: IntegrityCheckLevel,
        repair: bool,
    ) -> Result<IntegrityReport> {
        if !self.enabled {
            return Err(ForgeError::DatabaseQueryError("Integrity checking is disabled".to_string()));
        }
        
        let start_time = Utc::now();
        let start_instant = std::time::Instant::now();
        
        let report_id = uuid::Uuid::new_v4().to_string();
        
        // Record operation start in metrics
        if let Ok(metrics_manager) = get_metrics_manager() {
            let mut metrics_manager = metrics_manager.write().unwrap();
            let _ = metrics_manager.record_operation_metric(
                OperationType::Validation,
                database,
                None,
                1,
                0,
                1.0,
            );
        }
        
        // Placeholder for actual integrity check implementation
        // In a real implementation, this would check the database integrity
        // based on the specified level
        
        // For now, we'll create a mock report
        let mut issues = Vec::new();
        let tables_checked = vec!["users".to_string(), "settings".to_string(), "documents".to_string()];
        let records_checked = 1000;
        let bytes_checked = 1024 * 1024 * 10; // 10 MB
        
        // Add some mock issues for demonstration
        if level == IntegrityCheckLevel::Thorough {
            issues.push(IntegrityIssue {
                id: uuid::Uuid::new_v4().to_string(),
                issue_type: IntegrityIssueType::ChecksumMismatch,
                severity: IssueSeverity::Medium,
                table: Some("documents".to_string()),
                record_id: Some("doc123".to_string()),
                field: Some("content".to_string()),
                description: "Checksum mismatch in document content".to_string(),
                repair_action: Some(RepairAction::RecalculateChecksum),
                repaired: repair,
            });
        }
        
        // Create the report
        let end_time = Utc::now();
        let duration_ms = start_instant.elapsed().as_millis() as u64;
        
        let report = IntegrityReport {
            id: report_id.clone(),
            database: database.to_string(),
            check_level: level,
            start_time,
            end_time,
            duration_ms,
            passed: issues.is_empty(),
            issues,
            tables_checked,
            records_checked,
            bytes_checked,
        };
        
        // Save the report
        self.save_report(&report)?;
        
        // Update last check time
        self.last_check_time = Some(end_time);
        
        // Record operation completion in metrics
        if let Ok(metrics_manager) = get_metrics_manager() {
            let mut metrics_manager = metrics_manager.write().unwrap();
            let _ = metrics_manager.record_operation_metric(
                OperationType::Validation,
                database,
                None,
                1,
                duration_ms,
                if report.passed { 1.0 } else { 0.0 },
            );
        }
        
        Ok(report)
    }
    
    /// Save an integrity report
    fn save_report(&mut self, report: &IntegrityReport) -> Result<()> {
        // Add to in-memory reports
        self.reports.insert(report.id.clone(), report.clone());
        
        // Save to disk
        let reports_dir = self.base_dir.join("integrity").join("reports");
        if !reports_dir.exists() {
            std::fs::create_dir_all(&reports_dir).map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to create reports directory: {}", e))
            })?;
        }
        
        let report_path = reports_dir.join(format!("{}.json", report.id));
        let report_json = serde_json::to_string_pretty(report).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to serialize report: {}", e))
        })?;
        
        std::fs::write(&report_path, report_json).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to write report file: {}", e))
        })?;
        
        Ok(())
    }
    
    /// Get an integrity report by ID
    pub fn get_report(&self, report_id: &str) -> Option<&IntegrityReport> {
        self.reports.get(report_id)
    }
    
    /// Get all integrity reports
    pub fn get_all_reports(&self) -> Vec<&IntegrityReport> {
        self.reports.values().collect()
    }
    
    /// Get reports for a specific database
    pub fn get_reports_for_database(&self, database: &str) -> Vec<&IntegrityReport> {
        self.reports
            .values()
            .filter(|r| r.database == database)
            .collect()
    }
    
    /// Get the latest report for a database
    pub fn get_latest_report_for_database(&self, database: &str) -> Option<&IntegrityReport> {
        self.reports
            .values()
            .filter(|r| r.database == database)
            .max_by_key(|r| r.end_time)
    }
    
    /// Verify a record's integrity
    pub fn verify_record_integrity(
        &self,
        database: &str,
        table: &str,
        record_id: &str,
        data: &[u8],
        expected_checksum: &str,
    ) -> Result<bool> {
        if !self.enabled {
            return Ok(true); // Skip verification if disabled
        }
        
        // Calculate checksum
        let calculated_checksum = calculate_checksum(data)?;
        
        // Compare checksums
        let integrity_ok = calculated_checksum == expected_checksum;
        
        // Log verification result if not ok
        if !integrity_ok {
            if let Ok(metrics_manager) = get_metrics_manager() {
                let mut metrics_manager = metrics_manager.write().unwrap();
                let _ = metrics_manager.record_error_metric(
                    crate::db::metrics::ErrorType::Validation,
                    database,
                    Some(table),
                    &format!("Integrity check failed for record {}", record_id),
                    None,
                    Some(serde_json::json!({
                        "record_id": record_id,
                        "expected_checksum": expected_checksum,
                        "calculated_checksum": calculated_checksum,
                    })),
                );
            }
        }
        
        Ok(integrity_ok)
    }
    
    /// Generate an integrity summary report
    pub fn generate_summary_report(&self, database: &str) -> Result<String> {
        let reports = self.get_reports_for_database(database);
        
        if reports.is_empty() {
            return Ok(format!("No integrity reports found for database {}", database));
        }
        
        let latest_report = self.get_latest_report_for_database(database).unwrap();
        
        let mut summary = String::new();
        
        summary.push_str(&format!("# Integrity Summary for Database '{}'\n\n", database));
        summary.push_str(&format!("Last check: {}\n\n", latest_report.end_time));
        summary.push_str(&format!("Check level: {:?}\n\n", latest_report.check_level));
        summary.push_str(&format!("Status: {}\n\n", if latest_report.passed { "PASSED" } else { "FAILED" }));
        
        summary.push_str("## Statistics\n\n");
        summary.push_str(&format!("- Total reports: {}\n", reports.len()));
        summary.push_str(&format!("- Tables checked: {}\n", latest_report.tables_checked.join(", ")));
        summary.push_str(&format!("- Records checked: {}\n", latest_report.records_checked));
        summary.push_str(&format!("- Data checked: {} bytes\n", latest_report.bytes_checked));
        summary.push_str(&format!("- Check duration: {} ms\n\n", latest_report.duration_ms));
        
        let total_issues: usize = reports.iter().map(|r| r.issues.len()).sum();
        summary.push_str(&format!("- Total issues found: {}\n\n", total_issues));
        
        if !latest_report.issues.is_empty() {
            summary.push_str("## Issues in Latest Check\n\n");
            summary.push_str("| Type | Severity | Table | Record ID | Description | Repaired |\n");
            summary.push_str("|------|----------|-------|-----------|-------------|----------|\n");
            
            for issue in &latest_report.issues {
                let issue_type = match &issue.issue_type {
                    IntegrityIssueType::ChecksumMismatch => "Checksum Mismatch",
                    IntegrityIssueType::MissingRecord => "Missing Record",
                    IntegrityIssueType::CorruptData => "Corrupt Data",
                    IntegrityIssueType::SchemaViolation => "Schema Violation",
                    IntegrityIssueType::IndexInconsistency => "Index Inconsistency",
                    IntegrityIssueType::ForeignKeyViolation => "Foreign Key Violation",
                    IntegrityIssueType::DuplicateKey => "Duplicate Key",
                    IntegrityIssueType::OrphanedRecord => "Orphaned Record",
                    IntegrityIssueType::FileSystemError => "File System Error",
                    IntegrityIssueType::EncryptionError => "Encryption Error",
                    IntegrityIssueType::Other(s) => s,
                };
                
                let severity = match issue.severity {
                    IssueSeverity::Low => "Low",
                    IssueSeverity::Medium => "Medium",
                    IssueSeverity::High => "High",
                    IssueSeverity::Critical => "Critical",
                };
                
                let table = issue.table.as_deref().unwrap_or("-");
                let record_id = issue.record_id.as_deref().unwrap_or("-");
                
                summary.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} |\n",
                    issue_type,
                    severity,
                    table,
                    record_id,
                    issue.description,
                    if issue.repaired { "Yes" } else { "No" }
                ));
            }
        }
        
        Ok(summary)
    }
}

/// Calculate checksum for data
fn calculate_checksum(data: &[u8]) -> Result<String> {
    // Use BLAKE3 for checksums
    let hash = blake3::hash(data);
    Ok(hash.to_hex().to_string())
}

/// Verify data integrity
pub fn verify_data_integrity(
    database: &str,
    table: &str,
    record_id: &str,
    data: &[u8],
    expected_checksum: &str,
) -> Result<bool> {
    let integrity_manager = get_integrity_manager()?;
    let manager = integrity_manager.read().unwrap();
    
    manager.verify_record_integrity(database, table, record_id, data, expected_checksum)
}

/// Run a database integrity check
pub fn run_database_integrity_check(
    database: &str,
    level: IntegrityCheckLevel,
    repair: bool,
) -> Result<IntegrityReport> {
    let integrity_manager = get_integrity_manager()?;
    let mut manager = integrity_manager.write().unwrap();
    
    manager.run_integrity_check(database, level, repair)
}

/// Check if an integrity check is due
pub fn is_integrity_check_due() -> Result<bool> {
    let integrity_manager = get_integrity_manager()?;
    let manager = integrity_manager.read().unwrap();
    
    Ok(manager.is_check_due())
}

/// Get the latest integrity report for a database
pub fn get_latest_integrity_report(database: &str) -> Result<Option<IntegrityReport>> {
    let integrity_manager = get_integrity_manager()?;
    let manager = integrity_manager.read().unwrap();
    
    Ok(manager.get_latest_report_for_database(database).cloned())
}

/// Generate an integrity summary report
pub fn generate_integrity_summary(database: &str) -> Result<String> {
    let integrity_manager = get_integrity_manager()?;
    let manager = integrity_manager.read().unwrap();
    
    manager.generate_summary_report(database)
}

pub fn init_integrity_system(options: &DbOptions) -> Result<()> {
    let base_dir = &options.base_dir;
    let enabled = true; // Or map from options if you add an option for integrity
    let check_interval_hours = 24; // Default, or make configurable

    if let Err(e) = init_integrity_manager(base_dir, enabled, check_interval_hours) {
        log::error!("Failed to initialize integrity manager: {}", e);
        return Err(e);
    }
    log::info!("Integrity system initialized (enabled: {}, check_interval_hours: {})", enabled, check_interval_hours);
    Ok(())
}
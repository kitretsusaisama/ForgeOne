//! # Database Metrics Module
//!
//! This module provides metrics collection and reporting for the database system, including:
//! - Query performance metrics
//! - Storage usage metrics
//! - Operation counts
//! - Error rates
//! - Connection statistics

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Once};
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::error::{ForgeError, Result};
use crate::db::DbOptions;

// Static initialization
static INIT: Once = Once::new();
static mut METRICS_MANAGER: Option<Arc<RwLock<MetricsManager>>> = None;

/// Database metrics manager
pub struct MetricsManager {
    /// Whether metrics collection is enabled
    enabled: bool,
    /// Metrics retention period in days
    retention_days: u32,
    /// Query metrics
    query_metrics: HashMap<String, Vec<QueryMetric>>,
    /// Storage metrics
    storage_metrics: HashMap<String, Vec<StorageMetric>>,
    /// Operation metrics
    operation_metrics: HashMap<String, Vec<OperationMetric>>,
    /// Error metrics
    error_metrics: HashMap<String, Vec<ErrorMetric>>,
    /// Connection metrics
    connection_metrics: HashMap<String, Vec<ConnectionMetric>>,
}

/// Query metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryMetric {
    /// Query ID
    pub id: String,
    /// Query type
    pub query_type: QueryType,
    /// Database name
    pub database: String,
    /// Table name
    pub table: String,
    /// Query execution time in milliseconds
    pub execution_time_ms: u64,
    /// Query result count
    pub result_count: u64,
    /// Query timestamp
    pub timestamp: DateTime<Utc>,
    /// Query parameters (sanitized)
    pub parameters: Option<serde_json::Value>,
    /// Whether the query used an index
    pub used_index: bool,
    /// Index name if used
    pub index_name: Option<String>,
    /// Query plan if available
    pub query_plan: Option<String>,
}

/// Query type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum QueryType {
    /// Select query
    Select,
    /// Insert query
    Insert,
    /// Update query
    Update,
    /// Delete query
    Delete,
    /// Count query
    Count,
    /// Aggregate query
    Aggregate,
    /// Join query
    Join,
    /// Transaction
    Transaction,
    /// Schema operation
    Schema,
    /// Index operation
    Index,
    /// Custom query
    Custom(String),
}

/// Storage metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetric {
    /// Database name
    pub database: String,
    /// Table name (optional)
    pub table: Option<String>,
    /// Storage size in bytes
    pub size_bytes: u64,
    /// Number of records
    pub record_count: u64,
    /// Index size in bytes
    pub index_size_bytes: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Compression ratio if compressed
    pub compression_ratio: Option<f64>,
    /// Storage growth rate (bytes per day)
    pub growth_rate_bytes_per_day: Option<f64>,
}

/// Operation metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationMetric {
    /// Operation type
    pub operation_type: OperationType,
    /// Database name
    pub database: String,
    /// Table name (optional)
    pub table: Option<String>,
    /// Operation count
    pub count: u64,
    /// Operation execution time in milliseconds
    pub execution_time_ms: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Operation success rate (0.0 - 1.0)
    pub success_rate: f64,
}

/// Operation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OperationType {
    /// Read operation
    Read,
    /// Write operation
    Write,
    /// Backup operation
    Backup,
    /// Restore operation
    Restore,
    /// Vacuum operation
    Vacuum,
    /// Checkpoint operation
    Checkpoint,
    /// Encryption operation
    Encryption,
    /// Compression operation
    Compression,
    /// Migration operation
    Migration,
    /// Validation operation
    Validation,
    /// Custom operation
    Custom(String),
}

/// Error metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMetric {
    /// Error type
    pub error_type: ErrorType,
    /// Database name
    pub database: String,
    /// Table name (optional)
    pub table: Option<String>,
    /// Error count
    pub count: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Error message (sanitized)
    pub message: String,
    /// Error stack trace (sanitized)
    pub stack_trace: Option<String>,
    /// Error context
    pub context: Option<serde_json::Value>,
}

/// Error type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ErrorType {
    /// Connection error
    Connection,
    /// Query error
    Query,
    /// Transaction error
    Transaction,
    /// Schema error
    Schema,
    /// Constraint error
    Constraint,
    /// Encryption error
    Encryption,
    /// Compression error
    Compression,
    /// Migration error
    Migration,
    /// Validation error
    Validation,
    /// IO error
    IO,
    /// Custom error
    Custom(String),
}

/// Connection metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetric {
    /// Database name
    pub database: String,
    /// Connection count
    pub connection_count: u64,
    /// Active connection count
    pub active_connection_count: u64,
    /// Idle connection count
    pub idle_connection_count: u64,
    /// Connection duration in seconds
    pub connection_duration_seconds: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Connection source (e.g., application name)
    pub source: Option<String>,
}

/// Metric query filter
#[derive(Debug, Clone)]
pub struct MetricFilter {
    /// Start time
    pub start_time: Option<DateTime<Utc>>,
    /// End time
    pub end_time: Option<DateTime<Utc>>,
    /// Database name
    pub database: Option<String>,
    /// Table name
    pub table: Option<String>,
    /// Limit
    pub limit: Option<usize>,
    /// Offset
    pub offset: Option<usize>,
    /// Sort by field
    pub sort_by: Option<String>,
    /// Sort direction
    pub sort_direction: Option<SortDirection>,
}

/// Sort direction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SortDirection {
    /// Ascending
    Asc,
    /// Descending
    Desc,
}

/// Metric summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSummary {
    /// Total query count
    pub total_query_count: u64,
    /// Average query execution time in milliseconds
    pub avg_query_execution_time_ms: f64,
    /// Total storage size in bytes
    pub total_storage_size_bytes: u64,
    /// Total record count
    pub total_record_count: u64,
    /// Total operation count
    pub total_operation_count: u64,
    /// Total error count
    pub total_error_count: u64,
    /// Error rate (0.0 - 1.0)
    pub error_rate: f64,
    /// Total connection count
    pub total_connection_count: u64,
    /// Average active connections
    pub avg_active_connections: f64,
    /// Time period start
    pub period_start: DateTime<Utc>,
    /// Time period end
    pub period_end: DateTime<Utc>,
}

/// Initialize metrics manager
pub fn init_metrics_manager(enabled: bool, retention_days: u32) -> Result<()> {
    INIT.call_once(|| {
        let manager = MetricsManager {
            enabled,
            retention_days,
            query_metrics: HashMap::new(),
            storage_metrics: HashMap::new(),
            operation_metrics: HashMap::new(),
            error_metrics: HashMap::new(),
            connection_metrics: HashMap::new(),
        };
        
        unsafe {
            METRICS_MANAGER = Some(Arc::new(RwLock::new(manager)));
        }
    });
    
    Ok(())
}

/// Get metrics manager
pub fn get_metrics_manager() -> Result<Arc<RwLock<MetricsManager>>> {
    unsafe {
        match &METRICS_MANAGER {
            Some(manager) => Ok(manager.clone()),
            None => Err(ForgeError::DatabaseError(crate::error::DatabaseErrorKind::DatabaseQueryError)),
        }
    }
}

/// Query timer for measuring query execution time
pub struct QueryTimer {
    /// Query ID
    id: String,
    /// Query type
    query_type: QueryType,
    /// Database name
    database: String,
    /// Table name
    table: String,
    /// Start time
    start_time: Instant,
    /// Parameters
    parameters: Option<serde_json::Value>,
}

impl QueryTimer {
    /// Create a new query timer
    pub fn new(
        query_type: QueryType,
        database: &str,
        table: &str,
        parameters: Option<serde_json::Value>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            query_type,
            database: database.to_string(),
            table: table.to_string(),
            start_time: Instant::now(),
            parameters,
        }
    }
    
    /// Stop the timer and record the query metric
    pub fn stop(
        self,
        result_count: u64,
        used_index: bool,
        index_name: Option<String>,
        query_plan: Option<String>,
    ) -> Result<Duration> {
        let duration = self.start_time.elapsed();
        
        if let Ok(manager) = get_metrics_manager() {
            let mut manager = manager.write().unwrap();
            
            if manager.enabled {
                let metric = QueryMetric {
                    id: self.id,
                    query_type: self.query_type,
                    database: self.database.clone(),
                    table: self.table,
                    execution_time_ms: duration.as_millis() as u64,
                    result_count,
                    timestamp: Utc::now(),
                    parameters: self.parameters,
                    used_index,
                    index_name,
                    query_plan,
                };
                
                let key = self.database;
                manager.query_metrics.entry(key).or_insert_with(Vec::new).push(metric);
                
                // Clean up old metrics
                manager.cleanup_old_metrics();
            }
        }
        
        Ok(duration)
    }
}

impl MetricsManager {
    /// Record a storage metric
    pub fn record_storage_metric(
        &mut self,
        database: &str,
        table: Option<&str>,
        size_bytes: u64,
        record_count: u64,
        index_size_bytes: u64,
        compression_ratio: Option<f64>,
        growth_rate_bytes_per_day: Option<f64>,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        
        let metric = StorageMetric {
            database: database.to_string(),
            table: table.map(|t| t.to_string()),
            size_bytes,
            record_count,
            index_size_bytes,
            timestamp: Utc::now(),
            compression_ratio,
            growth_rate_bytes_per_day,
        };
        
        self.storage_metrics.entry(database.to_string())
            .or_insert_with(Vec::new)
            .push(metric);
        
        self.cleanup_old_metrics();
        
        Ok(())
    }
    
    /// Record an operation metric
    pub fn record_operation_metric(
        &mut self,
        operation_type: OperationType,
        database: &str,
        table: Option<&str>,
        count: u64,
        execution_time_ms: u64,
        success_rate: f64,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        
        let metric = OperationMetric {
            operation_type,
            database: database.to_string(),
            table: table.map(|t| t.to_string()),
            count,
            execution_time_ms,
            timestamp: Utc::now(),
            success_rate,
        };
        
        self.operation_metrics.entry(database.to_string())
            .or_insert_with(Vec::new)
            .push(metric);
        
        self.cleanup_old_metrics();
        
        Ok(())
    }
    
    /// Record an error metric
    pub fn record_error_metric(
        &mut self,
        error_type: ErrorType,
        database: &str,
        table: Option<&str>,
        message: &str,
        stack_trace: Option<&str>,
        context: Option<serde_json::Value>,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        
        let metric = ErrorMetric {
            error_type,
            database: database.to_string(),
            table: table.map(|t| t.to_string()),
            count: 1,
            timestamp: Utc::now(),
            message: message.to_string(),
            stack_trace: stack_trace.map(|s| s.to_string()),
            context,
        };
        
        self.error_metrics.entry(database.to_string())
            .or_insert_with(Vec::new)
            .push(metric);
        
        self.cleanup_old_metrics();
        
        Ok(())
    }
    
    /// Record a connection metric
    pub fn record_connection_metric(
        &mut self,
        database: &str,
        connection_count: u64,
        active_connection_count: u64,
        idle_connection_count: u64,
        connection_duration_seconds: u64,
        source: Option<&str>,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        
        let metric = ConnectionMetric {
            database: database.to_string(),
            connection_count,
            active_connection_count,
            idle_connection_count,
            connection_duration_seconds,
            timestamp: Utc::now(),
            source: source.map(|s| s.to_string()),
        };
        
        self.connection_metrics.entry(database.to_string())
            .or_insert_with(Vec::new)
            .push(metric);
        
        self.cleanup_old_metrics();
        
        Ok(())
    }
    
    /// Clean up old metrics
    fn cleanup_old_metrics(&mut self) {
        if self.retention_days == 0 {
            return;
        }
        
        let cutoff = Utc::now() - chrono::Duration::days(self.retention_days as i64);
        
        // Clean up query metrics
        for metrics in self.query_metrics.values_mut() {
            metrics.retain(|m| m.timestamp > cutoff);
        }
        
        // Clean up storage metrics
        for metrics in self.storage_metrics.values_mut() {
            metrics.retain(|m| m.timestamp > cutoff);
        }
        
        // Clean up operation metrics
        for metrics in self.operation_metrics.values_mut() {
            metrics.retain(|m| m.timestamp > cutoff);
        }
        
        // Clean up error metrics
        for metrics in self.error_metrics.values_mut() {
            metrics.retain(|m| m.timestamp > cutoff);
        }
        
        // Clean up connection metrics
        for metrics in self.connection_metrics.values_mut() {
            metrics.retain(|m| m.timestamp > cutoff);
        }
    }
    
    /// Get query metrics
    pub fn get_query_metrics(&self, filter: &MetricFilter) -> Vec<QueryMetric> {
        if !self.enabled {
            return Vec::new();
        }
        
        let mut result = Vec::new();
        
        for metrics in self.query_metrics.values() {
            for metric in metrics {
                if self.matches_filter(metric, filter) {
                    result.push(metric.clone());
                }
            }
        }
        
        self.apply_sort_and_limit(&mut result, filter)
    }
    
    /// Get storage metrics
    pub fn get_storage_metrics(&self, filter: &MetricFilter) -> Vec<StorageMetric> {
        if !self.enabled {
            return Vec::new();
        }
        
        let mut result = Vec::new();
        
        for metrics in self.storage_metrics.values() {
            for metric in metrics {
                if self.matches_filter(metric, filter) {
                    result.push(metric.clone());
                }
            }
        }
        
        self.apply_sort_and_limit(&mut result, filter)
    }
    
    /// Get operation metrics
    pub fn get_operation_metrics(&self, filter: &MetricFilter) -> Vec<OperationMetric> {
        if !self.enabled {
            return Vec::new();
        }
        
        let mut result = Vec::new();
        
        for metrics in self.operation_metrics.values() {
            for metric in metrics {
                if self.matches_filter(metric, filter) {
                    result.push(metric.clone());
                }
            }
        }
        
        self.apply_sort_and_limit(&mut result, filter)
    }
    
    /// Get error metrics
    pub fn get_error_metrics(&self, filter: &MetricFilter) -> Vec<ErrorMetric> {
        if !self.enabled {
            return Vec::new();
        }
        
        let mut result = Vec::new();
        
        for metrics in self.error_metrics.values() {
            for metric in metrics {
                if self.matches_filter(metric, filter) {
                    result.push(metric.clone());
                }
            }
        }
        
        self.apply_sort_and_limit(&mut result, filter)
    }
    
    /// Get connection metrics
    pub fn get_connection_metrics(&self, filter: &MetricFilter) -> Vec<ConnectionMetric> {
        if !self.enabled {
            return Vec::new();
        }
        
        let mut result = Vec::new();
        
        for metrics in self.connection_metrics.values() {
            for metric in metrics {
                if self.matches_filter(metric, filter) {
                    result.push(metric.clone());
                }
            }
        }
        
        self.apply_sort_and_limit(&mut result, filter)
    }
    
    /// Get metric summary
    pub fn get_metric_summary(&self, filter: &MetricFilter) -> MetricSummary {
        let query_metrics = self.get_query_metrics(filter);
        let storage_metrics = self.get_storage_metrics(filter);
        let operation_metrics = self.get_operation_metrics(filter);
        let error_metrics = self.get_error_metrics(filter);
        let connection_metrics = self.get_connection_metrics(filter);
        
        let total_query_count = query_metrics.len() as u64;
        let avg_query_execution_time_ms = if !query_metrics.is_empty() {
            query_metrics.iter().map(|m| m.execution_time_ms as f64).sum::<f64>() / total_query_count as f64
        } else {
            0.0
        };
        
        let total_storage_size_bytes = storage_metrics.iter().map(|m| m.size_bytes).sum();
        let total_record_count = storage_metrics.iter().map(|m| m.record_count).sum();
        
        let total_operation_count = operation_metrics.iter().map(|m| m.count).sum();
        let total_error_count = error_metrics.iter().map(|m| m.count).sum();
        
        let error_rate = if total_operation_count > 0 {
            total_error_count as f64 / total_operation_count as f64
        } else {
            0.0
        };
        
        let total_connection_count = connection_metrics.iter().map(|m| m.connection_count).sum();
        let avg_active_connections = if !connection_metrics.is_empty() {
            connection_metrics.iter().map(|m| m.active_connection_count as f64).sum::<f64>() / connection_metrics.len() as f64
        } else {
            0.0
        };
        
        let period_start = filter.start_time.unwrap_or_else(|| {
            let mut min_time = Utc::now();
            
            if let Some(time) = query_metrics.iter().map(|m| m.timestamp).min() {
                if time < min_time {
                    min_time = time;
                }
            }
            
            if let Some(time) = storage_metrics.iter().map(|m| m.timestamp).min() {
                if time < min_time {
                    min_time = time;
                }
            }
            
            if let Some(time) = operation_metrics.iter().map(|m| m.timestamp).min() {
                if time < min_time {
                    min_time = time;
                }
            }
            
            if let Some(time) = error_metrics.iter().map(|m| m.timestamp).min() {
                if time < min_time {
                    min_time = time;
                }
            }
            
            if let Some(time) = connection_metrics.iter().map(|m| m.timestamp).min() {
                if time < min_time {
                    min_time = time;
                }
            }
            
            min_time
        });
        
        let period_end = filter.end_time.unwrap_or_else(|| Utc::now());
        
        MetricSummary {
            total_query_count,
            avg_query_execution_time_ms,
            total_storage_size_bytes,
            total_record_count,
            total_operation_count,
            total_error_count,
            error_rate,
            total_connection_count,
            avg_active_connections,
            period_start,
            period_end,
        }
    }
    
    /// Check if a metric matches a filter
    fn matches_filter<T>(&self, metric: &T, filter: &MetricFilter) -> bool
    where
        T: HasTimestamp + HasDatabase + HasTable,
    {
        // Check time range
        if let Some(start_time) = filter.start_time {
            if metric.timestamp() < start_time {
                return false;
            }
        }
        
        if let Some(end_time) = filter.end_time {
            if metric.timestamp() > end_time {
                return false;
            }
        }
        
        // Check database
        if let Some(database) = &filter.database {
            if metric.database() != database {
                return false;
            }
        }
        
        // Check table
        if let Some(table) = &filter.table {
            match metric.table() {
                Some(metric_table) => {
                    if metric_table != table {
                        return false;
                    }
                },
                None => return false,
            }
        }
        
        true
    }
    
    /// Apply sort and limit to results
    fn apply_sort_and_limit<T>(&self, results: &mut Vec<T>, filter: &MetricFilter) -> Vec<T>
    where
        T: Clone + HasTimestamp,
    {
        // Sort results
        if let Some(sort_by) = &filter.sort_by {
            // For now, we only support sorting by timestamp
            if sort_by == "timestamp" {
                results.sort_by(|a, b| {
                    let ordering = a.timestamp().cmp(&b.timestamp());
                    
                    match filter.sort_direction {
                        Some(SortDirection::Desc) => ordering.reverse(),
                        _ => ordering,
                    }
                });
            }
        } else {
            // Default sort by timestamp descending
            results.sort_by(|a, b| b.timestamp().cmp(&a.timestamp()));
        }
        
        // Apply offset and limit
        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(usize::MAX);
        
        if offset >= results.len() {
            return Vec::new();
        }
        
        let end = std::cmp::min(offset + limit, results.len());
        results[offset..end].to_vec()
    }
    
    /// Export metrics to JSON
    pub fn export_metrics_to_json(&self, filter: &MetricFilter) -> Result<String> {
        let query_metrics = self.get_query_metrics(filter);
        let storage_metrics = self.get_storage_metrics(filter);
        let operation_metrics = self.get_operation_metrics(filter);
        let error_metrics = self.get_error_metrics(filter);
        let connection_metrics = self.get_connection_metrics(filter);
        let summary = self.get_metric_summary(filter);
        
        let export = serde_json::json!({
            "summary": summary,
            "query_metrics": query_metrics,
            "storage_metrics": storage_metrics,
            "operation_metrics": operation_metrics,
            "error_metrics": error_metrics,
            "connection_metrics": connection_metrics,
        });
        
        serde_json::to_string_pretty(&export).map_err(|e| {
            ForgeError::DatabaseError(crate::error::DatabaseErrorKind::DatabaseQueryError)
        })
    }
}

/// Trait for types that have a timestamp
trait HasTimestamp {
    /// Get the timestamp
    fn timestamp(&self) -> DateTime<Utc>;
}

/// Trait for types that have a database
trait HasDatabase {
    /// Get the database
    fn database(&self) -> &str;
}

/// Trait for types that have a table
trait HasTable {
    /// Get the table
    fn table(&self) -> Option<&str>;
}

impl HasTimestamp for QueryMetric {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
}

impl HasDatabase for QueryMetric {
    fn database(&self) -> &str {
        &self.database
    }
}

impl HasTable for QueryMetric {
    fn table(&self) -> Option<&str> {
        Some(&self.table)
    }
}

impl HasTimestamp for StorageMetric {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
}

impl HasDatabase for StorageMetric {
    fn database(&self) -> &str {
        &self.database
    }
}

impl HasTable for StorageMetric {
    fn table(&self) -> Option<&str> {
        self.table.as_deref()
    }
}

impl HasTimestamp for OperationMetric {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
}

impl HasDatabase for OperationMetric {
    fn database(&self) -> &str {
        &self.database
    }
}

impl HasTable for OperationMetric {
    fn table(&self) -> Option<&str> {
        self.table.as_deref()
    }
}

impl HasTimestamp for ErrorMetric {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
}

impl HasDatabase for ErrorMetric {
    fn database(&self) -> &str {
        &self.database
    }
}

impl HasTable for ErrorMetric {
    fn table(&self) -> Option<&str> {
        self.table.as_deref()
    }
}

impl HasTimestamp for ConnectionMetric {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
}

impl HasDatabase for ConnectionMetric {
    fn database(&self) -> &str {
        &self.database
    }
}

impl HasTable for ConnectionMetric {
    fn table(&self) -> Option<&str> {
        None
    }
}

pub fn init_metrics_system(options: &DbOptions) -> Result<()> {
    // Determine if metrics are enabled and retention period
    let enabled = options.enable_metrics;
    let retention_days = 30; // Default retention, or make configurable via options if needed

    if let Err(e) = init_metrics_manager(enabled, retention_days) {
        log::error!("Failed to initialize metrics manager: {}", e);
        return Err(e);
    }
    log::info!("Metrics system initialized (enabled: {}, retention_days: {})", enabled, retention_days);
    Ok(())
}
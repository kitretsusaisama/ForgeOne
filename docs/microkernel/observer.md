# Microkernel Observer Module

## Overview
The Observer module provides comprehensive monitoring, tracing, and forensic capabilities for the ForgeOne microkernel. It records execution traces, enables forensic replay of container executions, and exports memory and state information for analysis. This module ensures that all activities within the microkernel are observable, explainable, and auditable.

## Key Features

### Trace Recording
- **OTEL Integration**: Exports traces in OpenTelemetry format
- **LLM-Digestible Summaries**: Generates human and AI-readable execution summaries
- **Comprehensive Syscall Logging**: Records all syscall attempts and outcomes
- **DNA-Style Container Traces**: Maintains identity, entropy, and outcome information

### Forensic Replay
- **Execution Replay**: Recreates container executions for analysis
- **Deterministic Reproduction**: Ensures consistent replay results
- **Controlled Environment**: Executes replays in isolated environments
- **Differential Analysis**: Compares original and replay executions

### Memory and State Export
- **Memory Snapshots**: Captures memory state at configurable intervals
- **State Serialization**: Exports container and kernel state
- **Secure Export**: Ensures exported data is encrypted and integrity-protected
- **Selective Capture**: Targets specific memory regions or state components

## Core Components

### Trace Module
```rust
pub struct TraceContext {
    pub trace_id: Uuid,
    pub container_id: Option<Uuid>,
    pub plugin_id: Option<Uuid>,
    pub identity: IdentityContext,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub syscalls: Vec<SyscallTrace>,
    pub events: Vec<TraceEvent>,
    pub status: TraceStatus,
}

pub struct TraceEvent {
    pub event_type: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub data: HashMap<String, String>,
    pub severity: EventSeverity,
}

pub enum EventSeverity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

pub enum TraceStatus {
    Active,
    Completed,
    Failed(String),
}

pub struct LlmSummary {
    pub trace_id: Uuid,
    pub container_id: Option<Uuid>,
    pub identity: String,
    pub duration: std::time::Duration,
    pub syscall_count: usize,
    pub allowed_syscalls: usize,
    pub denied_syscalls: usize,
    pub key_events: Vec<String>,
    pub integrity_assessment: String,
    pub risk_factors: Vec<String>,
}
```

### Forensic Module
```rust
pub struct ForensicContext {
    pub replay_id: Uuid,
    pub original_trace_id: Uuid,
    pub environment: ReplayEnvironment,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub status: ReplayStatus,
    pub comparison: Option<ReplayComparison>,
}

pub struct ReplayEnvironment {
    pub isolation_level: IsolationLevel,
    pub resource_limits: ResourceLimits,
    pub simulated_inputs: HashMap<String, Vec<u8>>,
    pub breakpoints: Vec<Breakpoint>,
}

pub struct Breakpoint {
    pub syscall: String,
    pub condition: Option<String>,
    pub action: BreakpointAction,
}

pub enum BreakpointAction {
    Pause,
    Log,
    Modify(HashMap<String, String>),
    Abort,
}

pub enum ReplayStatus {
    Preparing,
    Running,
    Paused,
    Completed,
    Failed(String),
    Aborted,
}

pub struct ReplayComparison {
    pub match_percentage: f64,
    pub syscall_differences: Vec<SyscallDifference>,
    pub timing_differences: Vec<TimingDifference>,
    pub outcome_differences: Vec<OutcomeDifference>,
}
```

### Snapshot Module
```rust
pub struct SnapshotContext {
    pub snapshot_id: Uuid,
    pub container_id: Option<Uuid>,
    pub plugin_id: Option<Uuid>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub memory_regions: Vec<MemoryRegion>,
    pub state_components: Vec<StateComponent>,
    pub metadata: HashMap<String, String>,
}

pub struct MemoryRegion {
    pub address: usize,
    pub size: usize,
    pub permissions: MemoryPermissions,
    pub content_hash: String,
    pub content: Option<Vec<u8>>,
}

pub struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

pub struct StateComponent {
    pub component_type: String,
    pub name: String,
    pub data: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

pub enum SnapshotFormat {
    Raw,
    Compressed,
    Encrypted,
    CompressedAndEncrypted,
}
```

## Usage Examples

### Recording and Analyzing Traces
```rust
use microkernel::observer::trace;

// Create a new trace context
let trace_context = trace::TraceContext::new(
    Some(container_id),
    None, // plugin_id
    identity_context,
);

// Record a syscall trace
trace::record_syscall(
    &trace_context.trace_id,
    "open_file",
    &identity_context,
    &["path/to/file", "r"],
    true, // allowed
);

// Record an event
trace::record_event(
    &trace_context.trace_id,
    "container_started",
    trace::EventSeverity::Info,
    hashmap!{
        "container_id".to_string() => container_id.to_string(),
        "image".to_string() => "alpine:latest".to_string(),
    },
);

// Complete the trace
trace::complete_trace(&trace_context.trace_id);

// Generate an LLM summary
let summary = trace::generate_llm_summary(&trace_context.trace_id);
println!("Trace summary: {}", summary.integrity_assessment);
for risk in &summary.risk_factors {
    println!("Risk factor: {}", risk);
}
```

### Performing Forensic Replay
```rust
use microkernel::observer::forensic;

// Create a replay environment
let environment = forensic::ReplayEnvironment {
    isolation_level: forensic::IsolationLevel::Full,
    resource_limits: ResourceLimits::default(),
    simulated_inputs: HashMap::new(),
    breakpoints: vec![
        forensic::Breakpoint {
            syscall: "open_file".to_string(),
            condition: Some("args[0].contains('passwd')".to_string()),
            action: forensic::BreakpointAction::Log,
        },
    ],
};

// Start a replay
let replay_id = forensic::start_replay(trace_id, environment)?;

// Wait for replay to complete
forensic::wait_for_replay(replay_id)?;

// Get replay results
let context = forensic::get_replay_context(replay_id)?;
if let Some(comparison) = &context.comparison {
    println!("Match percentage: {}%", comparison.match_percentage * 100.0);
    for diff in &comparison.syscall_differences {
        println!("Syscall difference: {:?}", diff);
    }
}
```

### Creating and Using Snapshots
```rust
use microkernel::observer::snapshot;

// Create a snapshot
let snapshot_id = snapshot::create_snapshot(
    Some(container_id),
    None, // plugin_id
    snapshot::SnapshotFormat::CompressedAndEncrypted,
)?;

// Get snapshot information
let snapshot = snapshot::get_snapshot(snapshot_id)?;
println!("Snapshot created at: {}", snapshot.timestamp);
println!("Memory regions: {}", snapshot.memory_regions.len());

// Export a snapshot
let export_path = snapshot::export_snapshot(
    snapshot_id,
    "/path/to/export",
    snapshot::SnapshotFormat::CompressedAndEncrypted,
)?;
println!("Snapshot exported to: {}", export_path);

// Import a snapshot
let imported_id = snapshot::import_snapshot("/path/to/export")?;

// Restore from a snapshot (for forensic analysis only)
snapshot::restore_for_analysis(imported_id)?;
```

## Related Modules
- [Core Module](./core.md) - Provides the runtime context observed by the Observer module
- [Execution Module](./execution.md) - Generates the syscalls and events recorded by the Observer module
- [Trust Module](./trust.md) - Supplies policy decisions recorded by the Observer module
- [Common Telemetry Module](../common/telemetry.md) - Integrates with the Observer module for telemetry
- [Common Audit Module](../common/audit.md) - Uses Observer data for audit records
# LLM-Explainable Observation System

## Overview
The Observer module provides an LLM-explainable observation system for the ForgeOne platform. It handles creating and formatting observations for LLM consumption, making system behavior transparent and interpretable.

## Key Features
- LLM-friendly observation formatting
- Categorized observation types
- Severity-based classification
- Timestamped observations
- Identity context integration

## Core Components

### ObservationType
The type of observation:
- `Info` - Informational observation
- `Warning` - Warning observation
- `Error` - Error observation
- `Debug` - Debug observation
- `Trace` - Trace observation
- `Security` - Security observation
- `Performance` - Performance observation
- `Policy` - Policy observation

### ObservationSeverity
The severity of an observation:
- `Info` - Informational severity
- `Warning` - Warning severity
- `Error` - Error severity
- `Critical` - Critical severity

### Observation
An observation for LLM consumption:
- `identity` - The identity context of this observation
- `observation_type` - The type of this observation
- `content` - The content of this observation
- `severity` - The severity of this observation
- `timestamp` - The timestamp of this observation

## Helper Methods
- `new()` - Create a new observation
- `to_llm_string()` - Convert this observation to a string for LLM consumption

## Usage Example
```rust
// Create a new observation
let identity = IdentityContext::root();
let observation = Observation::new(
    identity,
    ObservationType::Security,
    "Unauthorized access attempt detected".to_string(),
    ObservationSeverity::Warning
);

// Convert to LLM-friendly string
let llm_string = observation.to_llm_string();
println!("{}", llm_string);
```

## LLM Output Format
Observations are formatted for LLM consumption as follows:
```
[TIMESTAMP] [SEVERITY] [TYPE] [USER_ID] [REQUEST_ID]: CONTENT
```

## Related Modules
- [Telemetry](./telemetry.md)
- [Diagnostics](./diagnostics.md)
- [Audit](./audit.md)
# ForgeOne Plugin Developer Guide (Atomic Plugin-Manager, DMCOA, MNC-Grade)

*This guide provides advanced, actionable, MNC-grade, production-ready, and compliance-driven instructions for ForgeOne plugin development. All procedures are mapped to SOC2, ISO 27001, GDPR, and enterprise SLAs. Audit, security, and evidence generation are integral to every step.*

---

## 1. Atomic Module Reference
- [modules/plugin-manager-l3.txt]: Plugin lifecycle, hooks, security
- [examples/sample-plugin/src/lib.rs]: Minimal working plugin example

## 2. Plugin Architecture & Compliance
- WASM-based, ABI-mapped, sandboxed (see plugin-manager-l3.txt)
- Hot-swappable, versioned, signed for production deployment [SOC2 CC6, ISO 27001 A.9, GDPR Art.32]
- Secure hooks for external providers (cloud, storage, auth, observability), all RBAC/ABAC enforced and audited [SOC2 CC6, ISO 27001 A.9]
- All plugin lifecycle events (install, upgrade, remove, failure) are logged, versioned, and exportable for audit [SOC2 CC7, ISO 27001 A.12, GDPR Art.30]
- **Integration:** Plugins interact with the host via defined ABI. All host calls (logging, syscalls, env) are mediated and logged. See [sample-plugin/src/lib.rs] for usage.

## 3. Development & Lifecycle (Production Best Practices)
- Target `wasm32-unknown-unknown` for all plugins. Use `cargo build --target wasm32-unknown-unknown --release`.
- Export required ABI functions: `init`, `start`, `stop`, `pause`, `resume`, `unload` (see sample plugin).
- **Error Handling:** All exported functions must return `i32` status codes. Use `0` for success, nonzero for error. Log all errors using the host `log` ABI.
- Sign plugin for production deployment; unsigned plugins are rejected in production [SOC2 CC6, ISO 27001 A.9]. Use your organization's signing process.
- Install/update/remove via CLI/API or `plugins/` directory; all actions are logged and auditable.
- Test all plugins in staging before production deployment; validate for compliance and operational impact.
- Review and update plugins quarterly or after every major incident or regulatory change.

## 4. Security, Audit, & Evidence Generation
- Plugins run in sandboxed WASM VM; all actions are RBAC/ABAC enforced and logged [SOC2 CC6, ISO 27001 A.9, GDPR Art.32].
- All plugin actions (calls, failures, upgrades) are logged, versioned, and exportable for audit [SOC2 CC7, ISO 27001 A.12, GDPR Art.30].
- Plugin signature events, sandbox enforcement, and lifecycle changes are available for audit and regulatory review.
- Automated compliance reporting and evidence generation for SOC2, ISO 27001, GDPR, and enterprise audits.
- **Security Note:** Never embed secrets or credentials in plugin code. Use environment variables and host-provided secure storage only.

## 5. Compliance & Operational Guarantees
- All plugin management and development procedures are reviewed quarterly and after every major incident or regulatory change [SOC2, ISO 27001, GDPR].
- Immutable logs, plugin signature events, install/upgrade/remove events, and sandbox enforcement are available for audit and regulatory review.
- Integrate with SIEM/SOC for real-time monitoring and compliance reporting.

## 6. Troubleshooting & Error Handling
- **Plugin Load Failure:** Ensure the plugin is signed, targets `wasm32-unknown-unknown`, and exports all required ABI functions.
- **Syscall/Host Call Failure:** Check host logs for error details. All errors should be logged by the plugin using the `log` ABI.
- **Compliance Failure:** Review audit logs and ensure all lifecycle events are properly logged and versioned.
- **Upgrade/Remove Issues:** Ensure no running instances before upgrade/remove. All actions are atomic and logged.

## 7. Minimal Working Example
See [examples/sample-plugin/src/lib.rs] for a complete, production-ready plugin implementation. This example demonstrates:
- ABI function exports
- Logging, environment variable access, and syscalls
- Error handling and status codes
- Compliance with all lifecycle and audit requirements

---

**For further details, see:**
- [modules/plugin-manager-l3.txt]
- [examples/sample-plugin/src/lib.rs]
- [docs/plugins/README.md]
- [docs/plugins/developer-guide.md] (this file)

*This document is reviewed quarterly and after every major incident or regulatory change. For questions, contact the ForgeOne compliance or platform engineering team.* 
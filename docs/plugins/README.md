# ForgeOne Plugins (Atomic Plugin-Manager, DMCOA, MNC-Grade)

*This document provides an MNC-grade, production-ready, and compliance-focused overview of ForgeOne plugin management. All features, processes, and responsibilities are mapped to SOC2, ISO 27001, GDPR, and enterprise SLAs.*

---

## 1. Atomic Module Mapping
- **Plugin Manager**: See [modules/plugin-manager-l3.txt]
- **Sample Plugin**: See [examples/sample-plugin/src/lib.rs] for a minimal, production-ready implementation

## 2. Responsibilities & MNC-Grade Guarantees
- **Modular, WASM-based, hot-swappable, sandboxed plugins:** All plugins are versioned, signed, and run in a sandboxed WASM VM. [SOC2 CC6, ISO 27001 A.9, GDPR Art.32]
- **Secure hooks for cloud, storage, auth, observability:** All external integrations are RBAC/ABAC enforced and audited. [SOC2 CC6, ISO 27001 A.9]
- **RBAC/ABAC enforced, all actions audited:** All plugin actions are logged, versioned, and exportable for audit and regulatory review. [SOC2 CC7, ISO 27001 A.12, GDPR Art.30]
- **Compliance:** All plugin management procedures are reviewed quarterly and after every major incident or regulatory change. [SOC2, ISO 27001, GDPR]
- **Audit Evidence:** Immutable logs, plugin signature events, install/upgrade/remove events, and sandbox enforcement are available for audit and regulatory review.
- **Production Best Practices:** All plugins are tested in staging, signed for production, and reviewed for compliance and operational impact before deployment. Quarterly reviews ensure alignment with regulatory and business requirements.
- **Integration:** Plugins interact with the host via a defined ABI. All host calls (logging, syscalls, env) are mediated and logged. See [examples/sample-plugin/src/lib.rs] for usage.
- **Error Handling:** All exported plugin functions must return `i32` status codes. Use `0` for success, nonzero for error. All errors must be logged using the host `log` ABI.
- **Security Note:** Never embed secrets or credentials in plugin code. Use environment variables and host-provided secure storage only.

## 3. Operational Notes
- **Install/Update/Remove:** Use CLI/API or the `plugins/` directory. All actions are atomic, logged, and auditable.
- **Lifecycle Management:** All plugin lifecycle events (install, upgrade, remove, failure) are logged, versioned, and exportable for audit.
- **Troubleshooting:**
  - Plugin load failure: Ensure plugin is signed, targets `wasm32-unknown-unknown`, and exports all required ABI functions.
  - Syscall/host call failure: Check host logs for error details. All errors should be logged by the plugin using the `log` ABI.
  - Compliance failure: Review audit logs and ensure all lifecycle events are properly logged and versioned.

## 4. Key Docs
- [Developer Guide](./developer-guide.md)
- [Plugin-Manager Module](../../modules/plugin-manager-l3.txt)
- [Sample Plugin](../../plugin-manager/examples/sample-plugin/src/lib.rs)

---

*This document is reviewed quarterly and after every major incident or regulatory change. For questions, contact the ForgeOne compliance or platform engineering team.* 
# ForgeOne GUI User Manual

## 1. Overview
The ForgeOne Web GUI provides a modern, secure dashboard for managing all aspects of the platform: containers, images, networks, volumes, plugins, observability, DSM, and more.

## 2. Authentication & Security
- Login with MFA, RBAC, SSO, or API keys
- All actions require proper authorization (RBAC/ABAC)

## 3. Dashboard Navigation
- **Home**: System status, alerts, quick actions
- **Containers**: List, create, start/stop, logs, metrics, exec shell
- **Images**: Browse, pull, build, scan, delete
- **Networks**: Create, view, manage connections
- **Volumes**: Create, attach, snapshot, restore
- **Plugins**: List, install, update, sandbox status
- **Observability**: Metrics, logs, traces, live dashboards
- **DSM**: Health status, rollback, anomaly detection
- **Forgefile**: Visual builder, validate, deploy
- **Settings**: User profile, API keys, security settings

## 4. Key Workflows
- **Create a container**: Containers → Create → Fill form → Launch
- **View logs/metrics**: Containers → Select → Logs/Metrics tab
- **Install a plugin**: Plugins → Install → Upload WASM file
- **Trigger rollback**: DSM → Select resource → Rollback
- **Validate Forgefile**: Forgefile → Upload/Build → Validate

## 5. Troubleshooting & Support
- System/component status: Home → Status/Alerts
- Error details: Click error icon for logs/traces
- Help: Help menu, tooltips, and https://docs.forgeone.io

## 6. Security & Compliance
- All actions logged and auditable
- Compliance dashboard: Settings → Compliance

## 7. Best Practices
- Use RBAC roles for least privilege
- Enable MFA for all users
- Regularly review audit logs and compliance status

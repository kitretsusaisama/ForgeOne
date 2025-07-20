# ForgeOne CLI User Manual

## 1. Overview
The ForgeOne CLI provides a powerful, secure, and user-friendly interface for managing containers, images, networks, volumes, plugins, observability, and more in a modular, MNC-scale environment.

## 2. Authentication & Security
- Login with MFA, RBAC, and API keys:
  ```sh
  forgeone login --user alice --mfa 123456
  ```
- Token-based and mTLS authentication for all commands

## 3. Core Workflows & Commands

### 3.1 Container Management
- Create a container:
  ```sh
  forgeone container create --name web --image nginx:latest --network prod-net --volume data-vol:/data
  ```
- List containers:
  ```sh
  forgeone container list
  ```
- Start/stop/remove:
  ```sh
  forgeone container start web
  forgeone container stop web
  forgeone container remove web
  ```

### 3.2 Image Management
- Pull/build images:
  ```sh
  forgeone image pull alpine:latest
  forgeone image build --file Dockerfile .
  ```
- Scan for vulnerabilities:
  ```sh
  forgeone image scan nginx:latest
  ```

### 3.3 Network Management
- Create/list networks:
  ```sh
  forgeone network create --name prod-net --subnet 10.0.0.0/24
  forgeone network list
  ```

### 3.4 Volume Management
- Create/list volumes:
  ```sh
  forgeone volume create data-vol
  forgeone volume list
  ```

### 3.5 Plugin Management
- List/install plugins:
  ```sh
  forgeone plugin list
  forgeone plugin install ./my_plugin.wasm
  ```

### 3.6 Observability & Logs
- View metrics/logs:
  ```sh
  forgeone metrics
  forgeone logs --container web
  ```

### 3.7 DSM & Self-Healing
- Check system health, trigger rollback:
  ```sh
  forgeone dsm status
  forgeone dsm rollback --container web
  ```

## 4. Advanced Workflows
- Multi-tenant namespace management
- GitOps deployment: `forgeone deploy --git https://repo.git`
- Forgefile validation: `forgeone forgefile validate ./Forgefile`

## 5. Troubleshooting
- View system/component status: `forgeone status`
- Debug mode: `forgeone --debug <command>`
- Common issues and resolutions (see Operational Playbook)

## 6. Help & Documentation
- Command help: `forgeone <command> --help`
- Full docs: https://docs.forgeone.io

# Windows Operations

This document describes the repository's recommended local Windows operating model for `CLIProxyAPI`.

## Layout

When running from a Git checkout, the expected working files are:

- `bin/cli-proxy-api.exe`
- `config.yaml`
- `auths/`
- `.runtime/`

`auths/` and `config.yaml` are the runtime data you typically preserve or migrate.
`.runtime/` is disposable and is recreated on each start.

## Start And Stop

Use the PowerShell scripts under `scripts/` as the normal entrypoints:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start-local.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\stop-local.ps1
```

`start-local.ps1` will:

- locate `bin\cli-proxy-api.exe`
- start it with `--config <repo>\config.yaml`
- redirect stdout/stderr into `.runtime\`
- write `.runtime\cli-proxy-api.pid`
- return the listening URL

`stop-local.ps1` will:

- read `.runtime\cli-proxy-api.pid`
- stop the matching process if it is alive
- remove the PID file

## Hidden Startup Task

For silent background startup after Windows login:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\register-hidden-startup-task.ps1
```

This registers a Scheduled Task named:

- `CLIProxyAPI Hidden Startup`

The task launches:

- `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File <repo>\scripts\start-local.ps1`

Related helpers:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\disable-hidden-startup-task.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\enable-hidden-startup-task.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\unregister-hidden-startup-task.ps1
```

## Runtime Validation

Typical local checks:

```powershell
Get-Content .\.runtime\cli-proxy-api.pid
Get-NetTCPConnection -State Listen -LocalPort 8317
Invoke-WebRequest http://127.0.0.1:8317/
```

If management is enabled and you have the correct management key:

```powershell
Invoke-WebRequest `
  -Headers @{ Authorization = 'Bearer <management-key>' } `
  http://127.0.0.1:8317/v0/management/auth-files
```

## Management Key Notes

Management endpoints do **not** use the normal top-level `api-keys` from `config.yaml`.

They require one of:

- `remote-management.secret-key` from `config.yaml`
- `MANAGEMENT_PASSWORD` from the environment
- an optional runtime-only local management password injected by the launcher

For localhost requests, the launcher may set a local-only management password that is accepted by `/v0/management/*` even when it differs from your normal client API key.

## Local Desktop Workflows

The repository currently includes two desktop-facing management flows:

- `POST /v0/management/codex/switch-auth`
  - refresh one managed Codex auth if requested
  - write it into the active local Codex auth path
  - optionally launch `codex app`
- `GET /v0/management/health-report`
  - return a static or live diagnostics report for one or all managed auths
  - `?deep=true` performs live refresh validation

## Migration Notes

If you move an installation from one checkout to another:

1. Stop the old instance.
2. Move `auths/` and `config.yaml`.
3. Copy or rebuild `bin/`.
4. Start the new checkout.
5. Re-register `CLIProxyAPI Hidden Startup` so it points to the new checkout.

Do not migrate `.runtime/`; let the new checkout recreate it.

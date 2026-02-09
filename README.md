# nox-plugin-threat-model

**STRIDE-based threat pattern detection in source code for automated threat modeling.**

## Overview

`nox-plugin-threat-model` is a Nox security scanner plugin that performs automated threat modeling using the STRIDE methodology. It detects code patterns that correspond to each STRIDE category -- Spoofing, Tampering, Repudiation, Information Disclosure, and Elevation of Privilege -- giving security teams a structured threat model derived directly from the codebase.

Traditional threat modeling is a manual, whiteboard-driven process that happens once (if ever) and quickly becomes stale. This plugin makes threat modeling continuous by scanning every commit for patterns that indicate spoofing risks (weak authentication), tampering risks (missing integrity checks), repudiation risks (insufficient audit logging), information disclosure (sensitive data in logs and error messages), and privilege escalation (unauthorized role assignment, setuid calls).

The plugin scans Go, Python, JavaScript, and TypeScript source files. It includes intelligent context awareness -- for example, repudiation findings (THREAT-003) are only emitted when security-critical functions lack corresponding audit logging in the same file. All analysis is deterministic, offline, and read-only.

## Use Cases

### Continuous Threat Modeling in CI/CD

Your security architecture team performs annual threat model reviews, but the codebase evolves daily. The plugin runs on every pull request, flagging new code that introduces STRIDE threat patterns. This keeps the threat model current without scheduling manual review sessions.

### Security Architecture Review

Your team is reviewing the architecture of a microservice before production launch. The plugin scans the entire codebase and produces a categorized inventory of threat patterns -- which services have weak authentication, which lack integrity checks, which perform privileged operations -- giving architects a data-driven starting point for the threat model.

### Audit Logging Compliance

Your compliance framework requires that all security-critical operations (login, permission changes, data deletion) produce audit log entries. The THREAT-003 (Repudiation) rule detects security-critical function signatures and only flags them when the file lacks audit logging, identifying gaps in your audit trail.

### Privilege Escalation Prevention

Your application includes role assignment, sudo invocations, or setuid calls. The THREAT-005 (Elevation of Privilege) rule detects these patterns and flags them as high-severity threats, ensuring that every privilege escalation path receives security review.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-threat-model
   ```

2. **Create test files with STRIDE threat patterns**

   ```bash
   mkdir -p demo-stride && cd demo-stride

   cat > auth.py <<'EOF'
   import json
   import subprocess
   from flask import Flask, request

   app = Flask(__name__)

   def handle_login():
       password = request.form["password"]
       if password == "admin":
           return "Welcome"

   def delete_user(user_id):
       db.execute("DELETE FROM users WHERE id = ?", (user_id,))

   def grant_admin(user_id):
       user = db.get(user_id)
       user.set_role("admin")

   def get_user_data(user_id):
       try:
           user = db.get(user_id)
           return json.dumps(user.__dict__)
       except Exception as e:
           return str(e)
   EOF

   cat > deploy.js <<'EOF'
   const { exec } = require("child_process");
   const fs = require("fs");

   function deployService(req, res) {
       const config = JSON.parse(req.body.config);
       fetch("https://api.internal.com/deploy");

       child_process.exec("sudo systemctl restart " + config.service);
       process.setuid(0);
   }
   EOF
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/threat-model demo-stride/
   ```

4. **Review findings**

   ```
   nox/threat-model scan completed: 7 findings

   THREAT-001 [MEDIUM] Spoofing risk: authentication bypass pattern detected:
       if password == "admin":
     Location: demo-stride/auth.py:9
     Category: spoofing
     Language: python

   THREAT-003 [MEDIUM] Repudiation risk: security action without audit logging:
       def delete_user(user_id):
     Location: demo-stride/auth.py:12
     Category: repudiation
     Language: python

   THREAT-003 [MEDIUM] Repudiation risk: security action without audit logging:
       def grant_admin(user_id):
     Location: demo-stride/auth.py:15
     Category: repudiation
     Language: python

   THREAT-005 [HIGH] Elevation of privilege: privilege escalation pattern detected:
       user.set_role("admin")
     Location: demo-stride/auth.py:17
     Category: elevation-of-privilege
     Language: python

   THREAT-002 [MEDIUM] Tampering risk: missing integrity check detected:
       fetch("https://api.internal.com/deploy");
     Location: demo-stride/deploy.js:6
     Category: tampering
     Language: javascript

   THREAT-005 [HIGH] Elevation of privilege: privilege escalation pattern detected:
       child_process.exec("sudo systemctl restart " + config.service);
     Location: demo-stride/deploy.js:8
     Category: elevation-of-privilege
     Language: javascript

   THREAT-005 [HIGH] Elevation of privilege: privilege escalation pattern detected:
       process.setuid(0);
     Location: demo-stride/deploy.js:9
     Category: elevation-of-privilege
     Language: javascript
   ```

## Rules

| Rule ID    | Description | Severity | Confidence | CWE | STRIDE Category |
|------------|-------------|----------|------------|-----|-----------------|
| THREAT-001 | Spoofing: authentication bypass patterns -- hardcoded/weak passwords, disabled auth flags, token comparison against string literals | Medium | Medium | CWE-287 | Spoofing |
| THREAT-002 | Tampering: missing integrity checks -- HTTP responses consumed without verification, JSON parsing without validation, `eval()` usage | Medium | Medium | CWE-345 | Tampering |
| THREAT-003 | Repudiation: security-critical functions (delete/create/grant/revoke user/role/permission, handle login/payment) without audit logging in the same file | Medium | High | CWE-778 | Repudiation |
| THREAT-004 | Information Disclosure: sensitive data in error responses, stack traces exposed to clients, verbose debug output, secrets in log statements | High | Medium | CWE-200 | Information Disclosure |
| THREAT-005 | Elevation of Privilege: setuid/setgid calls, sudo/chmod/chown in exec, admin role assignment, direct privilege escalation patterns | High | High | CWE-269 | Elevation of Privilege |

## Supported Languages / File Types

| Language | Extensions |
|----------|-----------|
| Go | `.go` |
| Python | `.py` |
| JavaScript | `.js` |
| TypeScript | `.ts` |

## Configuration

The plugin operates with sensible defaults and requires no configuration. It scans the entire workspace recursively, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, `.venv`, `dist`, and `build` directories.

Pass `workspace_root` as input to override the default scan directory:

```bash
nox scan --plugin nox/threat-model --input workspace_root=/path/to/project
```

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-threat-model
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-threat-model.git
cd nox-plugin-threat-model
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run tests with race detection
make test

# Run linter
make lint

# Clean build artifacts
make clean

# Build Docker image
docker build -t nox-plugin-threat-model .
```

## Architecture

The plugin follows the standard Nox plugin architecture, communicating via the Nox Plugin SDK over stdio.

1. **File Discovery**: Recursively walks the workspace, filtering for supported source file extensions (`.go`, `.py`, `.js`, `.ts`).

2. **Two-Pass File Analysis**: Each file is processed in two passes:
   - **First pass**: Reads all lines and checks for logging patterns (log.Info, logger, audit_log, console.log, etc.) to determine whether the file has audit logging.
   - **Second pass**: Checks each line against all STRIDE threat rule patterns. Each rule can have multiple regex patterns per language extension. A match on any single pattern triggers the finding.

3. **Context-Aware Repudiation Detection (THREAT-003)**: Security-critical function signatures (delete_user, grant_admin, handle_login, etc.) only generate repudiation findings when the file lacks audit logging. This reduces false positives in files that already have proper logging infrastructure.

4. **STRIDE Categorization**: Each finding includes a `category` metadata field mapping to the STRIDE model (spoofing, tampering, repudiation, information-disclosure, elevation-of-privilege), enabling downstream tooling to group and filter findings by threat category.

All analysis is deterministic, offline, and read-only.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request on the [GitHub repository](https://github.com/Nox-HQ/nox-plugin-threat-model).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure `make test` and `make lint` pass
5. Submit a pull request

## License

Apache-2.0

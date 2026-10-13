# UEFI Secure Boot PK / KEK Simulator

An **educational Python simulation** of UEFI Secure Boot concepts: platform key (PK), key-exchange keys (KEK), allowed image signers (db), and revoked hashes / certificates (dbx). It models a three-component boot chain (shim → GRUB → kernel) with simplified HMAC-SHA256 test signatures.

**Scope and limitations:** This repository does not parse real UEFI authenticated variables, validate X.509 chains, verify PE/COFF Authenticode, inspect your firmware, or perform secure enrollment. Simulation output must not be used as a security audit or compliance attestation.

## Features

- Enroll toy PK, KEK, and db entries and simulate revocation using dbx.
- Check a signed chain under full, deployed, audit, or setup policies.
- Exercise unsigned, forged, untrusted, modified and revoked image scenarios.
- Run the same Python simulation directly in the browser through Pyodide (WebAssembly).
- Use the stdlib CLI and optional FastAPI service; a separate legacy numeric task evaluator is retained for compatibility.
- Run regression tests covering signature enforcement, content hashing and audit-log tampering.

## Use the browser simulator

The static application is in `web/` and is deployed by `.github/workflows/pages.yml`. It runs Python locally in the tab after loading the Pyodide runtime from jsDelivr. No firmware access, uploads, account, or backend is required. An internet connection is needed for the runtime on first load.

To run locally, serve a directory containing `index.html`, `style.css`, `app.js`, `browser_bridge.py` and `simulator.py`. For example:

```bash
mkdir -p /tmp/secure-boot-demo
cp web/index.html web/style.css web/app.js web/browser_bridge.py simulator.py /tmp/secure-boot-demo/
cd /tmp/secure-boot-demo
python -m http.server 8000
```

Open `http://localhost:8000`. Do not open `index.html` directly via `file://`, because the browser must fetch the Python sources.

## Python CLI

Python 3.10+ (standard library only for the simulator):

```bash
python cli.py demo
python cli.py verify --name test.efi --data example
python cli.py verify --unsigned
python cli.py chain --policy full
python cli.py chain --policy audit --revoke-kernel
python cli.py setup --policy full
python cli.py status
```

Each command creates an isolated simulated environment and does not read or modify system keys. The `setup` command prints a new toy environment; it does not persist state between invocations.

## Install, tests and API

```bash
python -m pip install -e ".[test]"
python -m pytest -q
python -m pip check
```

Optional API mode:

```bash
python -m pip install -e ".[api]"
uvicorn agents.api:app --host 127.0.0.1 --port 8000
```

`/health`, `/metrics`, `/api/audit`, `/api/chat` and `/api/audit/logs` belong to the **legacy generic task-evaluation service**, not to the toy boot-chain verifier. The `secure_boot_uefi` package similarly exposes the legacy numeric threshold engine. Neither should be mistaken for real Secure Boot inspection.

To run the API using Docker:

```bash
docker build -t secure-boot-simulator .
docker run --rm -p 127.0.0.1:8000:8000 secure-boot-simulator
```

For a consistent audit HMAC key across restarts, supply an `AUDIT_SECRET_KEY` through a secret manager; otherwise the service generates a fresh random key on startup. Audit logs remain in memory and are **not** persisted across restarts. The API has no authentication and should not be exposed to an untrusted network.

## Technical notes

- The HMAC simulator uses temporary, randomly generated keys, not actual asymmetric signatures.
- db signing trust is modeled by enrollment. A KEK is used to represent update authority, **not** an image-signing certificate issuer. It does not cryptographically authenticate actual UEFI variable updates.
- Browser evaluation is local; an external CDN provides Pyodide runtime assets.
- The browser application is static and compatible with modern browsers that support WebAssembly and JavaScript.
- Optional API dependencies: FastAPI, Uvicorn, Pydantic. Tests use pytest.
- Source code and supporting assets are distributed under the [MIT License](LICENSE).

Repository: https://github.com/abusuraihsakhri/secure-boot-uefi-pk-kek-agent

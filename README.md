# UEFI Secure Boot Verification Simulator

A Python simulator for UEFI Secure Boot verification. Implements the PK/KEK/db/dbx certificate hierarchy, signature verification, certificate chain validation, and boot policy enforcement.

## What This Actually Does

This is a **simulation** of UEFI Secure Boot using HMAC-SHA256 for signatures (a real system uses RSA-2048/SHA-256 or ECDSA). It faithfully models the certificate hierarchy, verification logic, and boot policies defined in the UEFI Specification.

## Secure Boot Hierarchy

```
PK (Platform Key)          ← Root of trust, one per platform
  └── KEK (Key Exchange Key)  ← Intermediate keys (OS vendors)
        └── db (Signature Database)  ← Allowed signing certificates
        └── dbx (Forbidden Database) ← Revoked hashes/certificates
```

## Features

- **PK/KEK/db/dbx Management**: Enroll and manage the full certificate hierarchy
- **Signature Verification**: Sign boot components and verify signatures
- **Certificate Chain Validation**: Verify cert → KEK → PK chain
- **Boot Policy Enforcement**: Full (strict), Audit (log-only), Deployed (production)
- **dbx Revocation**: Block specific component hashes
- **Boot Chain Verification**: Verify entire boot sequences (Shim → GRUB → Kernel)
- **Setup Mode**: Platform starts in setup mode until PK is enrolled

## Quick Start

```bash
# Run full demonstration
python cli.py demo

# Set up Secure Boot environment
python cli.py setup --policy full

# Verify a single component
python cli.py verify --name grub.efi --data "grub2-2.06"

# Verify a boot chain
python cli.py chain

# Verify with revoked kernel
python cli.py chain --revoke-kernel

# Show status
python cli.py status
```

## Python API

```python
from simulator import SecureBootVerifier, PrivateKey, BootComponent, BootComponentType

# Set up
verifier = SecureBootVerifier()
pk_key = PrivateKey("PK")
verifier.enroll_pk(pk_key, "Platform Owner")

kek_key = PrivateKey("KEK")
verifier.enroll_kek(kek_key, "OS Vendor")

signer_key = PrivateKey("Signer")
signer_cert = signer_key.get_certificate("Boot Signer")
verifier.enroll_db_cert(signer_cert)

# Sign and verify a component
component = BootComponent("grub.efi", BootComponentType.GRUB, b"grub-data")
verifier.sign_component(component, signer_key, signer_cert)
valid, reason = verifier.verify_component(component)
```

## Boot Policies

| Policy | Behavior |
|--------|----------|
| `full` | All components must be signed and verified |
| `audit` | Log failures but allow unsigned components |
| `deployed` | Production mode, strict enforcement, stop on first failure |
| `setup` | PK not enrolled, all components allowed |

## Requirements

Python 3.10+ stdlib only (no external dependencies).

## License

MIT

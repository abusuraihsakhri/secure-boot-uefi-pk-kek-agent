"""
UEFI Secure Boot Verification Simulator.

Implements realistic simulations of UEFI Secure Boot concepts:
- PK (Platform Key): root of trust for the platform
- KEK (Key Exchange Key): intermediate keys for signature management
- db (Signature Database): allowed signatures for boot components
- dbx (Forbidden Signatures): revoked/blocked signatures
- Certificate chain verification
- Signature verification (simplified RSA-like using HMAC for simulation)
- Boot policy: authenticate all boot components in the boot chain

Uses only Python stdlib (hashlib, hmac, secrets, struct, json, time, enum).
"""
import hashlib
import hmac
import secrets
import struct
import json
import time
from typing import List, Dict, Optional, Tuple, Any, Set
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class SignatureType(Enum):
    """UEFI signature types."""
    RSA2048_SHA256 = "RSA2048_SHA256"
    RSA2048_SHA1 = "RSA2048_SHA1"
    ECDSA_P256_SHA256 = "ECDSA_P256_SHA256"
    X509_CERT = "X509"
    # Simulation type
    HMAC_SHA256 = "HMAC_SHA256"


class BootComponentType(Enum):
    """Types of boot components that can be verified."""
    PLATFORM_KEY = "PK"
    KEY_EXCHANGE_KEY = "KEK"
    SIGNATURE_DATABASE = "db"
    FORBIDDEN_DATABASE = "dbx"
    BOOT_APPLICATION = "boot_app"
    BOOT_DRIVER = "boot_driver"
    OPTION_ROM = "option_rom"
    SHIM = "shim"
    GRUB = "grub"
    KERNEL = "kernel"


class BootPolicy(Enum):
    """Secure Boot enforcement policy."""
    FULL = "full"           # All components must be signed
    AUDIT = "audit"         # Log failures but allow boot
    DEPLOYED = "deployed"   # Production mode, strict enforcement
    SETUP = "setup"         # Setup mode, PK not enrolled


# ---------------------------------------------------------------------------
# Certificate / Key simulation
# ---------------------------------------------------------------------------

@dataclass
class Certificate:
    """
    Simulated certificate for Secure Boot.

    In a real UEFI system this would be an X.509 certificate with RSA/ECDSA
    public key.  Here we use a hash-based identity for simulation.
    """
    subject: str
    issuer: str
    serial_number: bytes
    not_before: float
    not_after: float
    public_key_hash: bytes   # Simulated public key fingerprint
    signature_type: SignatureType = SignatureType.HMAC_SHA256
    is_ca: bool = False
    cert_id: str = ""

    def __post_init__(self):
        if not self.cert_id:
            self.cert_id = hashlib.sha256(
                self.subject.encode() + self.serial_number
            ).hexdigest()[:16]

    def is_valid_at(self, timestamp: float) -> bool:
        """Check if certificate is valid at the given timestamp."""
        return self.not_before <= timestamp <= self.not_after

    def to_dict(self) -> Dict[str, Any]:
        return {
            'cert_id': self.cert_id,
            'subject': self.subject,
            'issuer': self.issuer,
            'serial': self.serial_number.hex(),
            'is_ca': self.is_ca,
            'valid_from': self.not_before,
            'valid_to': self.not_after,
            'public_key_hash': self.public_key_hash.hex()[:32],
        }


@dataclass
class PrivateKey:
    """
    Simulated private key.  In a real system this would be RSA/ECDSA.
    Here we use a random secret for HMAC-based signing.
    """
    key_id: str
    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    algorithm: SignatureType = SignatureType.HMAC_SHA256

    def sign(self, data: bytes) -> bytes:
        """Sign data using HMAC-SHA256."""
        return hmac.new(self.secret, data, hashlib.sha256).digest()

    def get_certificate(self, subject: str, issuer: str = "",
                        is_ca: bool = False, valid_years: int = 10) -> Certificate:
        """Create a self-signed certificate for this key."""
        now = time.time()
        return Certificate(
            subject=subject,
            issuer=issuer or subject,
            serial_number=secrets.token_bytes(16),
            not_before=now,
            not_after=now + valid_years * 365.25 * 86400,
            public_key_hash=hashlib.sha256(self.secret).digest(),
            is_ca=is_ca,
        )


@dataclass
class Signature:
    """A signature over a boot component."""
    signature_type: SignatureType
    signer_cert_id: str
    value: bytes
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Boot Component
# ---------------------------------------------------------------------------

@dataclass
class BootComponent:
    """A component in the boot chain."""
    name: str
    component_type: BootComponentType
    data: bytes
    hash_value: bytes = b""
    signature: Optional[Signature] = None
    verified: bool = False
    verification_error: str = ""

    def __post_init__(self):
        if not self.hash_value:
            self.hash_value = hashlib.sha256(self.data).digest()


# ---------------------------------------------------------------------------
# Signature Database
# ---------------------------------------------------------------------------

class SignatureDatabase:
    """
    Manages a signature database (db or dbx).

    Contains certificates and hash entries that are used to verify
    boot component signatures.
    """

    def __init__(self, name: str = "db"):
        self.name = name
        self._certificates: Dict[str, Certificate] = {}  # cert_id -> Certificate
        self._hash_entries: Dict[bytes, str] = {}  # hash -> description
        self._owner_guid = secrets.token_bytes(16)

    def add_certificate(self, cert: Certificate) -> str:
        """Add a certificate to the database."""
        self._certificates[cert.cert_id] = cert
        return cert.cert_id

    def remove_certificate(self, cert_id: str) -> bool:
        """Remove a certificate from the database."""
        if cert_id in self._certificates:
            del self._certificates[cert_id]
            return True
        return False

    def add_hash_entry(self, hash_value: bytes, description: str = "") -> None:
        """Add a hash entry (for dbx revocation)."""
        self._hash_entries[hash_value] = description

    def contains_certificate(self, cert_id: str) -> bool:
        return cert_id in self._certificates

    def contains_hash(self, hash_value: bytes) -> bool:
        return hash_value in self._hash_entries

    def get_certificate(self, cert_id: str) -> Optional[Certificate]:
        return self._certificates.get(cert_id)

    def get_all_certificates(self) -> List[Certificate]:
        return list(self._certificates.values())

    def get_all_hashes(self) -> Dict[bytes, str]:
        return dict(self._hash_entries)

    @property
    def size(self) -> int:
        return len(self._certificates) + len(self._hash_entries)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'certificates': [c.to_dict() for c in self._certificates.values()],
            'hash_entries': len(self._hash_entries),
        }


# ---------------------------------------------------------------------------
# Secure Boot Verifier
# ---------------------------------------------------------------------------

class SecureBootVerifier:
    """
    Implements UEFI Secure Boot verification logic.

    Verification chain:
    1. Check if component hash is in dbx (forbidden) → REJECT
    2. Verify component signature against db (allowed) certificates
    3. Verify certificate chain up to KEK
    4. Verify KEK chain up to PK (root of trust)
    5. Apply boot policy
    """

    def __init__(self, policy: BootPolicy = BootPolicy.FULL):
        self.policy = policy
        self._pk: Optional[Certificate] = None
        self._pk_key: Optional[PrivateKey] = None
        self._kek_certs: Dict[str, Certificate] = {}
        self._kek_keys: Dict[str, PrivateKey] = {}
        # Test-only HMAC keys for explicitly enrolled db certificates.
        # Real UEFI verifies public-key signatures; this is not a firmware verifier.
        self._db_signing_keys: Dict[str, PrivateKey] = {}
        self.db = SignatureDatabase("db")
        self.dbx = SignatureDatabase("dbx")
        self._verification_log: List[Dict[str, Any]] = []
        self._setup_mode = True

    @property
    def is_setup_mode(self) -> bool:
        return self._setup_mode

    @property
    def pk_enrolled(self) -> bool:
        return self._pk is not None

    # -- Key enrollment --

    def enroll_pk(self, key: PrivateKey, subject: str = "Platform Owner") -> Certificate:
        """
        Enroll a Platform Key (PK).  This exits setup mode.

        In a real system, PK enrollment is a one-time operation that
        establishes the root of trust.
        """
        cert = key.get_certificate(subject, issuer=subject, is_ca=True)
        self._pk = cert
        self._pk_key = key
        self._setup_mode = False
        return cert

    def enroll_kek(self, key: PrivateKey, subject: str = "OS Vendor KEK",
                   signed_by_pk: bool = True) -> Certificate:
        """
        Enroll a Key Exchange Key (KEK).

        In a real system, the KEK must be signed by the PK.
        """
        if not self._setup_mode and not signed_by_pk:
            raise ValueError("Cannot enroll unsigned KEK after PK enrollment")
        if signed_by_pk and not self._pk_key:
            raise ValueError("PK must be enrolled before an authorized KEK")
        # Issuer association only; no real X.509 or authenticated UEFI updates.
        cert = key.get_certificate(
            subject,
            issuer=self._pk.subject if signed_by_pk else subject,
            is_ca=True,
        )
        self._kek_certs[cert.cert_id] = cert
        self._kek_keys[cert.cert_id] = key
        return cert

    def enroll_db_cert(self, cert: Certificate,
                       signing_key: Optional[PrivateKey] = None) -> str:
        """Allowlist a simulated signer, optionally registering its HMAC test key.

        An enrolled certificate without a matching simulation key cannot
        authenticate a signature. No real private keys should be used here.
        """
        if signing_key is not None:
            if hashlib.sha256(signing_key.secret).digest() != cert.public_key_hash:
                raise ValueError("Signing key does not match enrolled certificate")
            if signing_key.algorithm != SignatureType.HMAC_SHA256:
                raise ValueError("Only HMAC_SHA256 is implemented in this simulation")
            self._db_signing_keys[cert.cert_id] = signing_key
        return self.db.add_certificate(cert)

    def enroll_dbx_hash(self, hash_value: bytes, description: str = "") -> None:
        """Add a hash to the forbidden database (dbx)."""
        self.dbx.add_hash_entry(hash_value, description)

    # -- Signing --

    def sign_component(self, component: BootComponent,
                       signing_key: PrivateKey,
                       signer_cert: Certificate) -> BootComponent:
        """Sign a boot component."""
        if signing_key.algorithm != SignatureType.HMAC_SHA256:
            raise ValueError("Only HMAC_SHA256 is implemented in this simulation")
        enrolled_cert = self.db.get_certificate(signer_cert.cert_id)
        if (enrolled_cert is not None
                and enrolled_cert.public_key_hash == hashlib.sha256(signing_key.secret).digest()
                and enrolled_cert.public_key_hash == signer_cert.public_key_hash):
            # Backward-compatible test fixture registration for local signing.
            # A mismatched or unenrolled key is never made trusted.
            self._db_signing_keys[signer_cert.cert_id] = signing_key
        sig_value = signing_key.sign(component.data)
        component.signature = Signature(
            signature_type=SignatureType.HMAC_SHA256,
            signer_cert_id=signer_cert.cert_id,
            value=sig_value,
        )
        return component

    # -- Verification --

    def verify_component(self, component: BootComponent,
                         timestamp: Optional[float] = None) -> Tuple[bool, str]:
        """
        Verify a boot component against the Secure Boot policy.

        Returns (valid: bool, reason: str).
        """
        if timestamp is None:
            timestamp = time.time()

        self._verification_log.append({
            'component': component.name,
            'type': component.component_type.value,
            'timestamp': timestamp,
        })

        # Always hash the current bytes. A cached digest is not an authority.
        current_hash = hashlib.sha256(component.data).digest()
        if component.hash_value != current_hash:
            reason = f"REJECTED: {component.name} content hash mismatch"
            component.verified = False
            component.verification_error = reason
            self._log_result(component, False, reason)
            return False, reason

        # Step 1: Check dbx (forbidden hashes)
        if self.dbx.contains_hash(current_hash):
            reason = f"REJECTED: {component.name} hash found in dbx (forbidden)"
            component.verified = False
            component.verification_error = reason
            self._log_result(component, False, reason)
            return False, reason

        # Step 2: Check if we're in setup mode
        if self._setup_mode:
            reason = f"ALLOWED: {component.name} - setup mode (no PK enrolled)"
            component.verified = True
            component.verification_error = ""
            self._log_result(component, True, reason)
            return True, reason

        # Step 3: Verify signature exists
        if component.signature is None:
            if self.policy == BootPolicy.AUDIT:
                reason = f"AUDIT: {component.name} has no signature (audit mode)"
                component.verified = True
                component.verification_error = ""
                self._log_result(component, True, reason)
                return True, reason
            reason = f"REJECTED: {component.name} has no signature"
            component.verified = False
            component.verification_error = reason
            self._log_result(component, False, reason)
            return False, reason

        # Step 4: Verify signer certificate is in db
        sig = component.signature
        if not self.db.contains_certificate(sig.signer_cert_id):
            reason = f"REJECTED: {component.name} signer cert {sig.signer_cert_id} not in db"
            component.verified = False
            component.verification_error = reason
            self._log_result(component, False, reason)
            return False, reason

        if self.dbx.contains_certificate(sig.signer_cert_id):
            reason = f"REJECTED: {component.name} signer certificate revoked in dbx"
            component.verified = False
            component.verification_error = reason
            self._log_result(component, False, reason)
            return False, reason

        signer_cert = self.db.get_certificate(sig.signer_cert_id)

        # Step 5: Verify certificate is valid (not expired)
        if not signer_cert.is_valid_at(timestamp):
            reason = f"REJECTED: {component.name} signer cert expired"
            component.verified = False
            component.verification_error = reason
            self._log_result(component, False, reason)
            return False, reason

        # Step 6: Verify signature value
        if not self._verify_signature_value(component, sig, signer_cert):
            reason = f"REJECTED: {component.name} signature verification failed"
            component.verified = False
            component.verification_error = reason
            self._log_result(component, False, reason)
            return False, reason

        # Step 7: Verify certificate chain (signer -> KEK -> PK)
        chain_valid, chain_reason = self._verify_certificate_chain(signer_cert)
        if not chain_valid:
            reason = f"REJECTED: {component.name} cert chain: {chain_reason}"
            component.verified = False
            component.verification_error = reason
            self._log_result(component, False, reason)
            return False, reason

        reason = f"ACCEPTED: {component.name} verified successfully"
        component.verified = True
        component.verification_error = ""
        self._log_result(component, True, reason)
        return True, reason

    def _verify_signature_value(self, component: BootComponent,
                                sig: Signature, cert: Certificate) -> bool:
        """Check an enrolled simulated HMAC signer and its signed content."""
        if sig.signature_type != SignatureType.HMAC_SHA256 or len(sig.value) != 32:
            return False
        key = self._db_signing_keys.get(cert.cert_id)
        if key is None or key.algorithm != SignatureType.HMAC_SHA256:
            return False
        if hashlib.sha256(key.secret).digest() != cert.public_key_hash:
            return False
        return hmac.compare_digest(key.sign(component.data), sig.value)

    def _verify_certificate_chain(self, cert: Certificate) -> Tuple[bool, str]:
        """Model db enrollment authority, not cryptographic X.509 chains.

        KEK authorizes db updates in UEFI; it is not a certificate-chain
        issuer for executable image validation.
        """
        if not self._pk or not self.db.contains_certificate(cert.cert_id):
            return False, "No PK or db enrollment"
        if not any(kek.issuer == self._pk.subject
                   and kek.is_valid_at(time.time())
                   for kek in self._kek_certs.values()):
            return False, "No authorized KEK enrolled"
        return True, "Simulated db trust with PK/KEK enrolled"

    def _log_result(self, component: BootComponent, valid: bool, reason: str):
        """Log verification result."""
        if self._verification_log:
            self._verification_log[-1]['result'] = 'PASS' if valid else 'FAIL'
            self._verification_log[-1]['reason'] = reason

    # -- Boot chain verification --

    def verify_boot_chain(self, components: List[BootComponent],
                          timestamp: Optional[float] = None) -> Tuple[bool, List[Dict]]:
        """
        Verify an entire boot chain.

        Returns (all_valid: bool, results: list of per-component results).
        """
        results = []
        all_valid = True

        for component in components:
            valid, reason = self.verify_component(component, timestamp)
            results.append({
                'component': component.name,
                'type': component.component_type.value,
                'valid': valid,
                'reason': reason,
            })
            if not valid:
                all_valid = False
                if self.policy == BootPolicy.FULL or self.policy == BootPolicy.DEPLOYED:
                    break  # Stop on first failure in strict mode

        return all_valid, results

    # -- Status --

    def get_status(self) -> Dict[str, Any]:
        """Get current Secure Boot status."""
        return {
            'setup_mode': self._setup_mode,
            'pk_enrolled': self.pk_enrolled,
            'pk_subject': self._pk.subject if self._pk else None,
            'kek_count': len(self._kek_certs),
            'db_cert_count': len(self.db.get_all_certificates()),
            'dbx_hash_count': len(self.dbx.get_all_hashes()),
            'policy': self.policy.value,
        }

    def get_verification_log(self) -> List[Dict[str, Any]]:
        return list(self._verification_log)

    def clear_log(self):
        self._verification_log.clear()


# ---------------------------------------------------------------------------
# High-level boot simulation
# ---------------------------------------------------------------------------

def create_standard_boot_chain(verifier: SecureBootVerifier,
                                os_vendor_key: PrivateKey,
                                os_vendor_cert: Certificate) -> List[BootComponent]:
    """
    Create a standard UEFI boot chain for testing.

    Components: Shim → GRUB → Kernel
    """
    shim = BootComponent(
        name="shimx64.efi",
        component_type=BootComponentType.SHIM,
        data=b"shim-bootloader-v15.8",
    )
    grub = BootComponent(
        name="grubx64.efi",
        component_type=BootComponentType.GRUB,
        data=b"grub2-2.06-efi",
    )
    kernel = BootComponent(
        name="vmlinuz-5.15.0-generic",
        component_type=BootComponentType.KERNEL,
        data=b"linux-kernel-5.15.0-amd64",
    )

    # Sign all components with OS vendor key
    for comp in [shim, grub, kernel]:
        verifier.sign_component(comp, os_vendor_key, os_vendor_cert)

    return [shim, grub, kernel]

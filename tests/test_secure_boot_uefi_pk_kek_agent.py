"""
Tests for UEFI Secure Boot Verification Simulator.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import time
from simulator import (
    SecureBootVerifier, PrivateKey, Certificate, BootComponent,
    BootComponentType, BootPolicy, SignatureType, Signature,
    SignatureDatabase, create_standard_boot_chain,
)


# ---------------------------------------------------------------------------
# Certificate tests
# ---------------------------------------------------------------------------

class TestCertificate:
    def test_create_certificate(self):
        key = PrivateKey("test-key")
        cert = key.get_certificate("Test Subject", "Test Issuer")
        assert cert.subject == "Test Subject"
        assert cert.issuer == "Test Issuer"
        assert len(cert.cert_id) == 16

    def test_certificate_validity(self):
        now = time.time()
        cert = Certificate(
            subject="Test", issuer="Test",
            serial_number=b'\x01' * 16,
            not_before=now - 3600,
            not_after=now + 3600,
            public_key_hash=b'\x00' * 32,
        )
        assert cert.is_valid_at(now) is True
        assert cert.is_valid_at(now - 7200) is False
        assert cert.is_valid_at(now + 7200) is False

    def test_certificate_to_dict(self):
        key = PrivateKey("test")
        cert = key.get_certificate("Subject")
        d = cert.to_dict()
        assert 'cert_id' in d
        assert 'subject' in d
        assert d['subject'] == "Subject"


# ---------------------------------------------------------------------------
# PrivateKey tests
# ---------------------------------------------------------------------------

class TestPrivateKey:
    def test_sign_verify(self):
        key = PrivateKey("key-001")
        data = b"test-data"
        sig = key.sign(data)
        assert len(sig) == 32  # SHA-256 digest

    def test_deterministic_sign(self):
        key = PrivateKey("key-001", secret=b'\x01' * 32)
        sig1 = key.sign(b"data")
        sig2 = key.sign(b"data")
        assert sig1 == sig2

    def test_different_keys_different_sigs(self):
        k1 = PrivateKey("k1")
        k2 = PrivateKey("k2")
        data = b"same-data"
        assert k1.sign(data) != k2.sign(data)


# ---------------------------------------------------------------------------
# SignatureDatabase tests
# ---------------------------------------------------------------------------

class TestSignatureDatabase:
    def test_add_certificate(self):
        db = SignatureDatabase("test-db")
        key = PrivateKey("k")
        cert = key.get_certificate("Test")
        cert_id = db.add_certificate(cert)
        assert db.contains_certificate(cert_id)
        assert db.size == 1

    def test_remove_certificate(self):
        db = SignatureDatabase()
        key = PrivateKey("k")
        cert = key.get_certificate("Test")
        db.add_certificate(cert)
        assert db.remove_certificate(cert.cert_id) is True
        assert db.contains_certificate(cert.cert_id) is False

    def test_remove_nonexistent(self):
        db = SignatureDatabase()
        assert db.remove_certificate("nonexistent") is False

    def test_add_hash_entry(self):
        db = SignatureDatabase()
        db.add_hash_entry(b'\xaa' * 32, "revoked")
        assert db.contains_hash(b'\xaa' * 32)
        assert db.size == 1

    def test_get_all_certificates(self):
        db = SignatureDatabase()
        k1 = PrivateKey("k1")
        k2 = PrivateKey("k2")
        db.add_certificate(k1.get_certificate("A"))
        db.add_certificate(k2.get_certificate("B"))
        assert len(db.get_all_certificates()) == 2


# ---------------------------------------------------------------------------
# SecureBootVerifier tests
# ---------------------------------------------------------------------------

class TestSecureBootVerifier:
    def test_initial_setup_mode(self):
        v = SecureBootVerifier()
        assert v.is_setup_mode is True
        assert v.pk_enrolled is False

    def test_enroll_pk(self):
        v = SecureBootVerifier()
        pk_key = PrivateKey("PK")
        cert = v.enroll_pk(pk_key, "Platform Owner")
        assert v.pk_enrolled is True
        assert v.is_setup_mode is False
        assert cert.subject == "Platform Owner"

    def test_enroll_kek(self):
        v = SecureBootVerifier()
        pk_key = PrivateKey("PK")
        v.enroll_pk(pk_key)
        kek_key = PrivateKey("KEK")
        cert = v.enroll_kek(kek_key, "OS Vendor")
        assert cert.subject == "OS Vendor"

    def test_setup_mode_allows_all(self):
        v = SecureBootVerifier()
        comp = BootComponent("test.efi", BootComponentType.BOOT_APPLICATION, b"data")
        valid, reason = v.verify_component(comp)
        assert valid is True
        assert "setup mode" in reason.lower()

    def test_unsigned_rejected_in_full_mode(self):
        v = SecureBootVerifier(BootPolicy.FULL)
        pk_key = PrivateKey("PK")
        v.enroll_pk(pk_key)
        comp = BootComponent("test.efi", BootComponentType.BOOT_APPLICATION, b"data")
        valid, reason = v.verify_component(comp)
        assert valid is False
        assert "no signature" in reason.lower()

    def test_unsigned_allowed_in_audit_mode(self):
        v = SecureBootVerifier(BootPolicy.AUDIT)
        pk_key = PrivateKey("PK")
        v.enroll_pk(pk_key)
        comp = BootComponent("test.efi", BootComponentType.BOOT_APPLICATION, b"data")
        valid, reason = v.verify_component(comp)
        assert valid is True
        assert "audit" in reason.lower()

    def test_signed_component_accepted(self):
        v = SecureBootVerifier(BootPolicy.FULL)
        pk_key = PrivateKey("PK")
        v.enroll_pk(pk_key)
        kek_key = PrivateKey("KEK")
        v.enroll_kek(kek_key)
        signer_key = PrivateKey("Signer")
        signer_cert = signer_key.get_certificate("Boot Signer")
        v.enroll_db_cert(signer_cert)

        comp = BootComponent("grub.efi", BootComponentType.GRUB, b"grub-data")
        v.sign_component(comp, signer_key, signer_cert)
        valid, reason = v.verify_component(comp)
        assert valid is True

    def test_dbx_rejection(self):
        v = SecureBootVerifier(BootPolicy.FULL)
        pk_key = PrivateKey("PK")
        v.enroll_pk(pk_key)
        kek_key = PrivateKey("KEK")
        v.enroll_kek(kek_key)
        signer_key = PrivateKey("Signer")
        signer_cert = signer_key.get_certificate("Signer")
        v.enroll_db_cert(signer_cert)

        comp = BootComponent("bad.efi", BootComponentType.BOOT_APPLICATION, b"malware")
        v.sign_component(comp, signer_key, signer_cert)
        # Add hash to dbx
        v.enroll_dbx_hash(comp.hash_value, "Revoked")
        valid, reason = v.verify_component(comp)
        assert valid is False
        assert "dbx" in reason.lower() or "forbidden" in reason.lower()

    def test_verify_boot_chain(self):
        v = SecureBootVerifier(BootPolicy.FULL)
        pk_key = PrivateKey("PK")
        v.enroll_pk(pk_key)
        kek_key = PrivateKey("KEK")
        v.enroll_kek(kek_key)
        os_key = PrivateKey("OS")
        os_cert = os_key.get_certificate("OS Signer")
        v.enroll_db_cert(os_cert)

        components = create_standard_boot_chain(v, os_key, os_cert)
        all_valid, results = v.verify_boot_chain(components)
        assert all_valid is True
        assert len(results) == 3

    def test_boot_chain_with_revoked_component(self):
        v = SecureBootVerifier(BootPolicy.FULL)
        pk_key = PrivateKey("PK")
        v.enroll_pk(pk_key)
        kek_key = PrivateKey("KEK")
        v.enroll_kek(kek_key)
        os_key = PrivateKey("OS")
        os_cert = os_key.get_certificate("OS Signer")
        v.enroll_db_cert(os_cert)

        components = create_standard_boot_chain(v, os_key, os_cert)
        # Revoke the kernel
        v.enroll_dbx_hash(components[2].hash_value, "CVE-2023-XXXX")
        all_valid, results = v.verify_boot_chain(components)
        assert all_valid is False

    def test_get_status(self):
        v = SecureBootVerifier(BootPolicy.DEPLOYED)
        pk_key = PrivateKey("PK")
        v.enroll_pk(pk_key, "Dell Inc.")
        status = v.get_status()
        assert status['pk_enrolled'] is True
        assert status['pk_subject'] == "Dell Inc."
        assert status['policy'] == 'deployed'

    def test_verification_log(self):
        v = SecureBootVerifier(BootPolicy.FULL)
        pk_key = PrivateKey("PK")
        v.enroll_pk(pk_key)
        comp = BootComponent("test.efi", BootComponentType.BOOT_APPLICATION, b"data")
        v.verify_component(comp)
        log = v.get_verification_log()
        assert len(log) == 1
        assert log[0]['component'] == 'test.efi'


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

class TestCLI:
    def test_setup_command(self):
        from cli import main
        ret = main(['setup', '--policy', 'full'])
        assert ret == 0

    def test_verify_command(self):
        from cli import main
        ret = main(['verify', '--name', 'test.efi', '--data', 'test-data'])
        assert ret == 0

    def test_chain_command(self):
        from cli import main
        ret = main(['chain'])
        assert ret == 0

    def test_status_command(self):
        from cli import main
        ret = main(['status'])
        assert ret == 0

    def test_demo_command(self):
        from cli import main
        ret = main(['demo'])
        assert ret == 0

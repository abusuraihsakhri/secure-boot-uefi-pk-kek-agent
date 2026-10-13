"""Regression tests for the deliberately simplified, local-only Secure Boot simulator."""
import hashlib
import time

import pytest

from simulator import (BootComponent, BootComponentType, BootPolicy, PrivateKey,
                       SecureBootVerifier, Signature, SignatureType)
from agents.base import AuditTrail


def configured():
    verifier = SecureBootVerifier(BootPolicy.FULL)
    verifier.enroll_pk(PrivateKey("pk"))
    verifier.enroll_kek(PrivateKey("kek"))
    signer = PrivateKey("trusted")
    cert = signer.get_certificate("Trusted Test Signer")
    verifier.enroll_db_cert(cert, signer)
    component = BootComponent("shim.efi", BootComponentType.SHIM, b"trusted bytes")
    verifier.sign_component(component, signer, cert)
    return verifier, signer, cert, component


def test_forged_nonempty_signature_is_rejected():
    verifier, signer, cert, component = configured()
    component.signature = Signature(SignatureType.HMAC_SHA256, cert.cert_id, b"X" * 32)
    ok, reason = verifier.verify_component(component)
    assert not ok
    assert "signature verification failed" in reason


def test_other_private_key_cannot_impersonate_enrolled_cert():
    verifier, _, cert, component = configured()
    adversary = PrivateKey("attacker")
    verifier.sign_component(component, adversary, cert)
    assert verifier.verify_component(component)[0] is False


def test_modified_bytes_with_stale_cached_hash_are_rejected():
    verifier, _, _, component = configured()
    component.data = b"modified"
    assert verifier.verify_component(component)[0] is False
    assert "hash mismatch" in component.verification_error


def test_recomputed_hash_does_not_authorize_modified_bytes():
    verifier, _, _, component = configured()
    component.data = b"modified"
    component.hash_value = hashlib.sha256(component.data).digest()
    assert verifier.verify_component(component)[0] is False


def test_dbx_revokes_current_component_hash():
    verifier, _, _, component = configured()
    verifier.enroll_dbx_hash(hashlib.sha256(component.data).digest())
    assert verifier.verify_component(component)[0] is False


def test_dbx_revokes_signer_certificate():
    verifier, _, cert, component = configured()
    verifier.dbx.add_certificate(cert)
    ok, reason = verifier.verify_component(component)
    assert not ok
    assert "revoked" in reason


def test_wrong_signing_key_rejected_at_enrollment():
    verifier, _, cert, _ = configured()
    with pytest.raises(ValueError, match="does not match"):
        verifier.enroll_db_cert(cert, PrivateKey("wrong"))


def test_non_hmac_signature_types_never_succeed():
    verifier, _, cert, component = configured()
    component.signature.signature_type = SignatureType.RSA2048_SHA256
    assert verifier.verify_component(component)[0] is False


def test_valid_signature_passes_and_clears_previous_error():
    verifier, signer, cert, component = configured()
    component.signature.value = b"0" * 32
    assert verifier.verify_component(component)[0] is False
    verifier.sign_component(component, signer, cert)
    assert verifier.verify_component(component)[0] is True
    assert component.verification_error == ""


def test_expired_certificate_rejected():
    verifier, _, cert, component = configured()
    cert.not_after = time.time() - 1
    assert verifier.verify_component(component)[0] is False


def test_kek_required_for_trust_simulation():
    verifier = SecureBootVerifier()
    verifier.enroll_pk(PrivateKey("pk"))
    signer = PrivateKey("signer")
    cert = signer.get_certificate("Signer")
    verifier.enroll_db_cert(cert, signer)
    comp = BootComponent("boot.efi", BootComponentType.SHIM, b"img")
    verifier.sign_component(comp, signer, cert)
    assert verifier.verify_component(comp)[0] is False


def test_audit_trail_detects_mutation_and_returns_defensive_copy():
    audit = AuditTrail(secret_key="ephemeral-test-only")
    audit.log("tester", "qa", "event", {"status": "ok"})
    assert audit.verify_integrity()
    exposed = audit.get_trail()
    exposed[0]["actor"] = "attacker"
    assert audit.verify_integrity()
    audit.logs[0]["actor"] = "attacker"
    assert not audit.verify_integrity()


def test_audit_trail_detects_recomputed_chain_pointer_without_valid_mac():
    audit = AuditTrail(secret_key="ephemeral-test-only")
    audit.log("tester", "qa", "event", {"status": "ok"})
    audit.logs[0]["payload_hash"] = "0" * 64
    assert audit.verify_integrity() is False


def test_default_audit_keys_are_not_static():
    assert AuditTrail().secret_key != AuditTrail().secret_key


def test_chain_cli_honors_requested_policy(capsys):
    from cli import main
    assert main(["chain", "--policy", "audit"]) == 0
    assert "audit policy" in capsys.readouterr().out


def test_packaged_entry_points_importable():
    from secure_boot_uefi.cli import main
    assert callable(main)


def test_rejects_nonfinite_metrics_in_legacy_evaluator():
    from secure_boot_uefi.models import FrontierPayload
    with pytest.raises(ValueError):
        FrontierPayload("task", "target", float("nan"), 1.0, "NOMINAL")
    with pytest.raises(ValueError):
        FrontierPayload("task", "target", 1.0, float("inf"), "NOMINAL")


def test_rejects_nonfinite_metrics_in_pydantic_api():
    from pydantic import ValidationError
    from agents.models import SystemTaskPayload
    with pytest.raises(ValidationError):
        SystemTaskPayload(task_id="t", target_identifier="id", primary_metric=float("nan"))


def test_csv_boolean_parser_avoids_truthy_false_strings():
    from secure_boot_uefi.cli import _parse_bool
    assert _parse_bool("False") is False
    assert _parse_bool("TRUE") is True
    assert _parse_bool("0") is False
    with pytest.raises(ValueError):
        _parse_bool("maybe")


def test_kek_expiry_uses_verification_timestamp():
    verifier, _, _, component = configured()
    kek = next(iter(verifier._kek_certs.values()))
    when = time.time()
    kek.not_before = when - 120
    kek.not_after = when - 30
    signer_cert = verifier.db.get_certificate(component.signature.signer_cert_id)
    signer_cert.not_before = when - 120
    assert verifier.verify_component(component, timestamp=when - 60)[0] is True
    assert verifier.verify_component(component, timestamp=when)[0] is False

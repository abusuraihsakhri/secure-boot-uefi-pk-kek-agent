"""Integration checks for the Python code executed inside Pyodide."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "web"))

from browser_bridge import evaluate


def simulate(policy, scenario):
    return json.loads(evaluate(json.dumps({
        "label": "Browser smoke test",
        "policy": policy,
        "scenario": scenario,
    })))


def test_valid_chain_succeeds():
    result = simulate("full", "valid")
    assert result["boot_allowed"] is True
    assert len(result["results"]) == 3
    assert result["platform"]["pk_enrolled"] is True


def test_tampered_component_fails():
    result = simulate("full", "tampered")
    assert result["boot_allowed"] is False
    assert result["executed_checks"] == 2
    assert "hash mismatch" in result["results"][1]["reason"]


def test_forged_signature_fails():
    result = simulate("full", "forged_signature")
    assert result["boot_allowed"] is False


def test_unsigned_component_in_audit_mode_is_allowed():
    result = simulate("audit", "unsigned")
    assert result["boot_allowed"] is True
    assert result["executed_checks"] == 3
    assert result["results"][1]["reason"].startswith("AUDIT:")


def test_revoked_kernel_fails_even_in_audit_mode():
    result = simulate("audit", "revoked_hash")
    assert result["boot_allowed"] is False
    assert result["executed_checks"] == 3


def test_setup_mode_skips_enrollment():
    result = simulate("setup", "valid")
    assert result["platform"]["pk_enrolled"] is False
    assert result["boot_allowed"] is True


def test_unknown_scenario_is_rejected():
    import pytest
    with pytest.raises(ValueError, match="Unsupported"):
        simulate("full", "this-does-not-exist")

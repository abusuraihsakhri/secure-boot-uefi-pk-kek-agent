"""Pyodide bridge for the static, local-only Secure Boot teaching simulator.

This does not inspect actual UEFI variables, certificates or signed PE files.
It exercises the repository's stdlib HMAC demonstration implementation.
"""
import json

from simulator import (BootPolicy, BootComponent, BootComponentType, PrivateKey,
                       SecureBootVerifier, create_standard_boot_chain)


SCENARIOS = {"valid", "unsigned", "tampered", "revoked_hash",
             "forged_signature", "untrusted_signer"}


def evaluate(raw_json):
    options = json.loads(raw_json)
    policy = BootPolicy(options.get("policy", "full"))
    scenario = options.get("scenario", "valid")
    if scenario not in SCENARIOS:
        raise ValueError("Unsupported scenario")
    label = options.get("label", "Example Boot Chain")
    if not isinstance(label, str) or not 1 <= len(label.strip()) <= 80:
        raise ValueError("Label must contain between 1 and 80 characters")

    verifier = SecureBootVerifier(policy)
    if policy != BootPolicy.SETUP:
        verifier.enroll_pk(PrivateKey("example-pk"), "Example Platform Owner")
        verifier.enroll_kek(PrivateKey("example-kek"), "Example KEK")

    signer_key = PrivateKey("example-image-signer")
    signer_cert = signer_key.get_certificate("Example Boot Image Signer")
    verifier.enroll_db_cert(signer_cert, signing_key=signer_key)
    chain = create_standard_boot_chain(verifier, signer_key, signer_cert)

    if scenario == "unsigned":
        chain[1].signature = None
    elif scenario == "tampered":
        # Cache still describes the originally signed bytes.
        chain[1].data = b"modified-grub-data"
    elif scenario == "revoked_hash":
        verifier.enroll_dbx_hash(chain[2].hash_value, "Example revocation")
    elif scenario == "forged_signature":
        attacker = PrivateKey("attacker")
        verifier.sign_component(chain[1], attacker, signer_cert)
    elif scenario == "untrusted_signer":
        attacker = PrivateKey("attacker")
        forged_cert = attacker.get_certificate("Untrusted Signer")
        verifier.sign_component(chain[1], attacker, forged_cert)

    valid, results = verifier.verify_boot_chain(chain)
    return json.dumps({
        "label": label.strip(),
        "policy": policy.value,
        "scenario": scenario,
        "boot_allowed": valid,
        "platform": verifier.get_status(),
        "results": results,
        "executed_checks": len(results),
        "note": ("Educational HMAC model only. Does not parse UEFI signature "
                 "databases or verify real PE/COFF Authenticode signatures."),
    }, indent=2)

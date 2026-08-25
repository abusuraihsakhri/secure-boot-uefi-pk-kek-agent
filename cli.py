"""
CLI for UEFI Secure Boot Verification Simulator.

Commands:
- setup: Set up a Secure Boot environment with PK, KEK, db, dbx
- verify: Verify a boot component
- chain: Verify an entire boot chain
- status: Show Secure Boot status
- enroll-pk: Enroll a Platform Key
- enroll-kek: Enroll a Key Exchange Key
- add-db: Add a certificate to db
- add-dbx: Add a hash to dbx (forbidden)
- demo: Run a full Secure Boot demonstration
"""
import argparse
import json
import sys
import time

from simulator import (
    SecureBootVerifier, PrivateKey, Certificate, BootComponent,
    BootComponentType, BootPolicy, SignatureType,
    create_standard_boot_chain,
)


def cmd_setup(args):
    """Set up a complete Secure Boot environment."""
    policy = BootPolicy(args.policy)
    verifier = SecureBootVerifier(policy=policy)

    # Create and enroll PK
    pk_key = PrivateKey("PK-001")
    pk_cert = verifier.enroll_pk(pk_key, "Platform Owner")
    print(f"PK enrolled: {pk_cert.subject} (ID: {pk_cert.cert_id})")

    # Create and enroll KEK
    kek_key = PrivateKey("KEK-001")
    kek_cert = verifier.enroll_kek(kek_key, "OS Vendor KEK")
    print(f"KEK enrolled: {kek_cert.subject} (ID: {kek_cert.cert_id})")

    # Add OS vendor cert to db
    os_key = PrivateKey("OS-Signer-001")
    os_cert = os_key.get_certificate("OS Boot Signer", is_ca=False)
    verifier.enroll_db_cert(os_cert)
    print(f"db cert added: {os_cert.subject} (ID: {os_cert.cert_id})")

    # Optionally add a revoked hash to dbx
    if args.revoke_hash:
        revoked_hash = bytes.fromhex(args.revoke_hash)
        verifier.enroll_dbx_hash(revoked_hash, "Revoked component")
        print(f"dbx hash added: {args.revoke_hash}")

    status = verifier.get_status()
    print(f"\nSecure Boot Status:")
    for k, v in status.items():
        print(f"  {k}: {v}")
    return 0


def cmd_verify(args):
    """Verify a single boot component."""
    verifier = SecureBootVerifier(BootPolicy.FULL)
    pk_key = PrivateKey("PK")
    verifier.enroll_pk(pk_key)
    kek_key = PrivateKey("KEK")
    kek_cert = verifier.enroll_kek(kek_key)
    signer_key = PrivateKey("Signer")
    signer_cert = signer_key.get_certificate("Boot Signer")
    verifier.enroll_db_cert(signer_cert)

    component = BootComponent(
        name=args.name,
        component_type=BootComponentType.BOOT_APPLICATION,
        data=args.data.encode(),
    )
    if not args.unsigned:
        verifier.sign_component(component, signer_key, signer_cert)

    valid, reason = verifier.verify_component(component)
    print(f"Component: {args.name}")
    print(f"  Valid: {valid}")
    print(f"  Reason: {reason}")
    return 0 if valid else 1


def cmd_chain(args):
    """Verify an entire boot chain."""
    verifier = SecureBootVerifier(BootPolicy.FULL)
    pk_key = PrivateKey("PK")
    verifier.enroll_pk(pk_key)
    kek_key = PrivateKey("KEK")
    verifier.enroll_kek(kek_key)
    os_key = PrivateKey("OS-Signer")
    os_cert = os_key.get_certificate("OS Boot Signer")
    verifier.enroll_db_cert(os_cert)

    components = create_standard_boot_chain(verifier, os_key, os_cert)

    if args.revoke_kernel:
        # Add kernel hash to dbx
        verifier.enroll_dbx_hash(components[2].hash_value, "Revoked kernel")

    all_valid, results = verifier.verify_boot_chain(components)

    print(f"Boot Chain Verification ({args.policy} policy):")
    for r in results:
        status = "PASS" if r['valid'] else "FAIL"
        print(f"  [{status}] {r['component']} ({r['type']}): {r['reason']}")
    print(f"\nOverall: {'PASS' if all_valid else 'FAIL'}")
    return 0 if all_valid else 1


def cmd_status(args):
    """Show Secure Boot status."""
    verifier = SecureBootVerifier(BootPolicy.DEPLOYED)
    pk_key = PrivateKey("PK")
    verifier.enroll_pk(pk_key, "Dell Inc.")
    kek_key = PrivateKey("KEK")
    verifier.enroll_kek(kek_key, "Microsoft Corporation KEK")
    os_key = PrivateKey("DB-001")
    os_cert = os_key.get_certificate("Microsoft Windows Production PCA 2011")
    verifier.enroll_db_cert(os_cert)

    status = verifier.get_status()
    print("UEFI Secure Boot Status:")
    print(f"  Setup Mode:  {'Yes' if status['setup_mode'] else 'No'}")
    print(f"  PK Enrolled: {'Yes' if status['pk_enrolled'] else 'No'}")
    print(f"  PK Subject:  {status['pk_subject']}")
    print(f"  KEK Count:   {status['kek_count']}")
    print(f"  db Certs:    {status['db_cert_count']}")
    print(f"  dbx Hashes:  {status['dbx_hash_count']}")
    print(f"  Policy:      {status['policy']}")
    return 0


def cmd_demo(args):
    """Run a full Secure Boot demonstration."""
    print("=" * 60)
    print("UEFI Secure Boot Demonstration")
    print("=" * 60)

    # 1. Setup
    print("\n[1] Setting up Secure Boot environment...")
    verifier = SecureBootVerifier(BootPolicy.FULL)
    pk_key = PrivateKey("PK-DEMO")
    pk_cert = verifier.enroll_pk(pk_key, "Demo Platform Owner")
    print(f"    PK: {pk_cert.subject}")

    kek_key = PrivateKey("KEK-DEMO")
    kek_cert = verifier.enroll_kek(kek_key, "Demo OS Vendor")
    print(f"    KEK: {kek_cert.subject}")

    os_key = PrivateKey("OS-SIGNER")
    os_cert = os_key.get_certificate("Demo OS Boot Signer")
    verifier.enroll_db_cert(os_cert)
    print(f"    db: {os_cert.subject}")

    # 2. Valid boot chain
    print("\n[2] Verifying valid boot chain...")
    components = create_standard_boot_chain(verifier, os_key, os_cert)
    all_valid, results = verifier.verify_boot_chain(components)
    for r in results:
        s = "PASS" if r['valid'] else "FAIL"
        print(f"    [{s}] {r['component']}")
    print(f"    Result: {'ALL PASS' if all_valid else 'FAILED'}")

    # 3. Tampered component
    print("\n[3] Verifying tampered boot chain...")
    verifier.clear_log()
    tampered = BootComponent(
        name="trojan-grub.efi",
        component_type=BootComponentType.GRUB,
        data=b"malicious-grub-payload",
    )
    # Sign with a different (unauthorized) key
    bad_key = PrivateKey("ATTACKER")
    bad_cert = bad_key.get_certificate("Evil Corp")
    verifier.sign_component(tampered, bad_key, bad_cert)
    valid, reason = verifier.verify_component(tampered)
    print(f"    Tampered component: {'PASS' if valid else 'FAIL'}")
    print(f"    Reason: {reason}")

    # 4. Revoked component
    print("\n[4] Testing dbx revocation...")
    verifier.clear_log()
    revoked_comp = BootComponent(
        name="old-shim.efi",
        component_type=BootComponentType.SHIM,
        data=b"old-vulnerable-shim-v14",
    )
    verifier.sign_component(revoked_comp, os_key, os_cert)
    # Add to dbx
    verifier.enroll_dbx_hash(revoked_comp.hash_value, "CVE-2023-XXXX")
    valid, reason = verifier.verify_component(revoked_comp)
    print(f"    Revoked component: {'PASS' if valid else 'FAIL'}")
    print(f"    Reason: {reason}")

    # 5. Status
    print("\n[5] Final Status:")
    status = verifier.get_status()
    for k, v in status.items():
        print(f"    {k}: {v}")

    print("\n" + "=" * 60)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='secure-boot-uefi',
        description='UEFI Secure Boot Verification Simulator'
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # setup
    p = sub.add_parser('setup', help='Set up Secure Boot environment')
    p.add_argument('--policy', choices=['full', 'audit', 'deployed', 'setup'], default='full')
    p.add_argument('--revoke-hash', type=str, default=None, help='Hash to add to dbx (hex)')
    p.set_defaults(func=cmd_setup)

    # verify
    p = sub.add_parser('verify', help='Verify a boot component')
    p.add_argument('--name', type=str, default='test.efi', help='Component name')
    p.add_argument('--data', type=str, default='test-boot-data', help='Component data')
    p.add_argument('--unsigned', action='store_true', help='Leave component unsigned')
    p.set_defaults(func=cmd_verify)

    # chain
    p = sub.add_parser('chain', help='Verify boot chain')
    p.add_argument('--policy', choices=['full', 'audit', 'deployed'], default='full')
    p.add_argument('--revoke-kernel', action='store_true', help='Add kernel to dbx')
    p.set_defaults(func=cmd_chain)

    # status
    p = sub.add_parser('status', help='Show Secure Boot status')
    p.set_defaults(func=cmd_status)

    # demo
    p = sub.add_parser('demo', help='Run full demonstration')
    p.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())

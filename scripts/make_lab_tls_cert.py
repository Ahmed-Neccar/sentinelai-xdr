"""Create a self-signed certificate for the lab HTTPS proxy (https://localhost:8443).

Lab only. The certificate is not issued by a trusted authority, so browsers
show a warning that must be accepted once. A real deployment needs a
certificate from a trusted authority on a real host name; see DEPLOYMENT.md.

Writes .data/tls-lab/localhost.crt and localhost.key and never replaces
existing files unless --force is given.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def build(days: int) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SentinelAI lab (localhost)")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--directory", type=Path, default=root / ".data" / "tls-lab")
    parser.add_argument("--days", type=int, default=90)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    certificate_path = args.directory / "localhost.crt"
    key_path = args.directory / "localhost.key"
    if (certificate_path.exists() or key_path.exists()) and not args.force:
        print(f"A certificate already exists in {args.directory}; use --force to replace it.")
        return 0
    if not 1 <= args.days <= 397:
        print("Error: --days must be between 1 and 397.", file=sys.stderr)
        return 1
    certificate, key = build(args.days)
    args.directory.mkdir(parents=True, exist_ok=True)
    certificate_path.write_bytes(certificate)
    key_path.write_bytes(key)
    print(f"Wrote {certificate_path} (valid {args.days} days) and its private key.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

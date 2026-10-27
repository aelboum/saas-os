"""ADR-0059 end-to-end fixture: a throw-away CA and two server certificates,
`good` for hooks.e2e.test and `wrong` for another name, written as PEM files
to the directory given. Nothing here is a real credential.

`python make_certs.py <directory>`
"""

from __future__ import annotations

import datetime
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def main(directory: Path) -> None:
    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SaaS OS egress e2e CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for name, hostname in (("good", "hooks.e2e.test"), ("wrong", "someone-else.e2e.test")):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        (directory / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (directory / f"{name}.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )


def hand_over(directory: Path) -> None:
    """This runs as root in a container: give the files to the owner of the
    directory, readable by everyone (throw-away test keys), so the host can
    read and remove them."""
    owner = directory.stat()
    chown = getattr(os, "chown", None)  # POSIX only; this runs in a Linux container
    for path in directory.iterdir():
        path.chmod(0o644)
        if chown is None:
            continue
        try:
            chown(path, owner.st_uid, owner.st_gid)
        except OSError:
            pass  # a bind mount that does not support ownership (Docker Desktop)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
    hand_over(Path(sys.argv[1]))

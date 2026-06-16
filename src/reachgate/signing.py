"""Cryptographic signing for the ReachGate evidence capsule (tamper-evidence).

The capsule already carries an sha256 evidence manifest, so a reviewer can
confirm offline that the artifacts inside are the exact bytes ReachGate
produced. That proves *integrity against accidental change*, and it is fully
standard-library / no-dependency.

This module adds *authenticity + tamper-evidence against deliberate forgery*:
an Ed25519 detached signature over the capsule's exact bytes. A verifier who
holds the publisher's public key can confirm the capsule was signed by the
holder of the matching private key and has not been altered by a single byte.

Design choices (and why):
  * Ed25519, asymmetric. A reviewer verifies with the PUBLIC key alone; they
    never need a shared secret. (An HMAC would be symmetric -- the verifier
    could forge a signature -- which defeats "tamper-evident proof you can
    trust without trusting us".)
  * Detached signature. The capsule bytes are never modified; the signature
    lives in a sidecar ``.sig`` file, so the existing byte-stable capsule and
    its sha256 manifest are untouched.
  * Optional dependency. Signing/verifying needs the ``cryptography`` package,
    installed via the ``[sign]`` extra. The rest of ReachGate -- including the
    sha256 manifest integrity check -- stays standard-library only. If
    ``cryptography`` is absent, these functions fail loudly with a clear
    install hint rather than silently degrading.

The signature is stored base64-encoded text; public/private keys are PEM.
"""

from __future__ import annotations

import base64
from pathlib import Path

_INSTALL_HINT = (
    "ReachGate signing needs the 'cryptography' package. Install the signing "
    "extra:\n    pip install 'reachgate[sign]'\n(the rest of ReachGate, "
    "including the sha256 evidence manifest, works without it)."
)


class SigningError(RuntimeError):
    """A user-facing signing/verification problem (missing dep, bad key, etc.)."""


def _ed25519():
    """Import the Ed25519 primitives, or raise a helpful SigningError."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:  # cryptography not installed
        raise SigningError(_INSTALL_HINT) from exc
    return ed25519, serialization, InvalidSignature


def crypto_available() -> bool:
    """True when the optional ``cryptography`` dependency is importable."""
    try:
        _ed25519()
    except SigningError:
        return False
    return True


def generate_keypair() -> tuple[bytes, bytes]:
    """Return ``(private_pem, public_pem)`` for a fresh Ed25519 key.

    The private key is unencrypted PKCS8 PEM -- it is the publisher's secret and
    must be kept private; the public key is SubjectPublicKeyInfo PEM and is the
    one to publish so others can verify.
    """
    ed25519, serialization, _ = _ed25519()
    private = ed25519.Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def public_from_private(private_pem: bytes) -> bytes:
    """Derive the public-key PEM from a private-key PEM."""
    ed25519, serialization, _ = _ed25519()
    try:
        private = serialization.load_pem_private_key(private_pem, password=None)
    except Exception as exc:  # malformed PEM / wrong type
        raise SigningError(f"invalid private key: {exc}") from exc
    if not isinstance(private, ed25519.Ed25519PrivateKey):
        raise SigningError("private key is not an Ed25519 key")
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def sign_bytes(private_pem: bytes, data: bytes) -> bytes:
    """Sign ``data`` with a private-key PEM; return the raw 64-byte signature."""
    ed25519, serialization, _ = _ed25519()
    try:
        private = serialization.load_pem_private_key(private_pem, password=None)
    except Exception as exc:
        raise SigningError(f"invalid private key: {exc}") from exc
    if not isinstance(private, ed25519.Ed25519PrivateKey):
        raise SigningError("private key is not an Ed25519 key")
    return private.sign(data)


def verify_bytes(public_pem: bytes, data: bytes, signature: bytes) -> bool:
    """Return True iff ``signature`` is a valid Ed25519 signature of ``data``."""
    ed25519, serialization, InvalidSignature = _ed25519()
    try:
        public = serialization.load_pem_public_key(public_pem)
    except Exception as exc:
        raise SigningError(f"invalid public key: {exc}") from exc
    if not isinstance(public, ed25519.Ed25519PublicKey):
        raise SigningError("public key is not an Ed25519 key")
    try:
        public.verify(signature, data)
    except InvalidSignature:
        return False
    return True


# --- file helpers ----------------------------------------------------------

def _b64_with_header(signature: bytes) -> str:
    """Detached-signature file text: a small header + base64 signature.

    The header keeps the file self-describing without a separate format; lines
    starting with ``#`` are ignored on read.
    """
    b64 = base64.b64encode(signature).decode("ascii")
    return (
        "# ReachGate detached signature (Ed25519 over the exact target bytes)\n"
        "# Verify: reachgate capsule verify <target> --sig <this> --pubkey <pub>\n"
        f"{b64}\n"
    )


def _read_sig_text(text: str) -> bytes:
    """Parse a ``.sig`` file: skip ``#`` comment lines, base64-decode the rest."""
    payload = "".join(
        line.strip() for line in text.splitlines() if not line.startswith("#")
    )
    if not payload:
        raise SigningError("signature file has no signature payload")
    try:
        return base64.b64decode(payload, validate=True)
    except Exception as exc:
        raise SigningError(f"signature file is not valid base64: {exc}") from exc


def sign_file(target: Path, private_pem: bytes, sig_path: Path) -> Path:
    """Sign the exact bytes of ``target``; write the detached signature."""
    target = Path(target)
    try:
        data = target.read_bytes()
    except FileNotFoundError as exc:
        raise SigningError(f"nothing to sign: {target} not found") from exc
    signature = sign_bytes(private_pem, data)
    sig_path = Path(sig_path)
    sig_path.parent.mkdir(parents=True, exist_ok=True)
    sig_path.write_text(_b64_with_header(signature), encoding="utf-8")
    return sig_path


def verify_file(target: Path, public_pem: bytes, sig_path: Path) -> bool:
    """Return True iff ``sig_path`` is a valid signature of ``target``'s bytes."""
    target = Path(target)
    try:
        data = target.read_bytes()
    except FileNotFoundError as exc:
        raise SigningError(f"nothing to verify: {target} not found") from exc
    try:
        sig_text = Path(sig_path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SigningError(f"signature not found: {sig_path}") from exc
    signature = _read_sig_text(sig_text)
    return verify_bytes(public_pem, data, signature)

"""Ed25519 tamper-evidence for the evidence capsule.

These tests pin the signing layer:
  * keygen -> sign -> verify round-trips;
  * a single changed byte (in the data or the signature) fails verification;
  * a different key fails verification (asymmetric: the public key alone
    verifies, and only the matching private key can sign);
  * the detached signature file is parseable and robust to comments;
  * the CLI `capsule keygen / sign / verify` flow works end to end and returns
    exit 0 for an authentic capsule, exit 1 for a tampered one.

Signing needs the optional ``cryptography`` dependency (the ``[sign]`` extra);
the whole module is skipped when it is absent, so the default suite stays green
without it. The rest of ReachGate (including the sha256 manifest) does not need
it.
"""

import pytest

pytest.importorskip("cryptography")

from src.reachgate import signing  # noqa: E402
from src.reachgate import cli  # noqa: E402


# --- module-level round-trip and tamper detection --------------------------

def test_crypto_is_available_under_this_suite():
    # The module is only collected when cryptography imports, so this must hold.
    assert signing.crypto_available() is True


def test_sign_verify_roundtrip():
    priv, pub = signing.generate_keypair()
    data = b"reachgate evidence capsule bytes"
    sig = signing.sign_bytes(priv, data)
    assert signing.verify_bytes(pub, data, sig) is True


def test_tampered_data_fails_verification():
    priv, pub = signing.generate_keypair()
    sig = signing.sign_bytes(priv, b"original bytes")
    assert signing.verify_bytes(pub, b"original bytez", sig) is False


def test_tampered_signature_fails_verification():
    priv, pub = signing.generate_keypair()
    data = b"payload"
    sig = bytearray(signing.sign_bytes(priv, data))
    sig[0] ^= 0x01  # flip one bit
    assert signing.verify_bytes(pub, data, bytes(sig)) is False


def test_wrong_key_fails_verification():
    priv1, _ = signing.generate_keypair()
    _, pub2 = signing.generate_keypair()
    data = b"signed by key 1, verified against key 2"
    sig = signing.sign_bytes(priv1, data)
    assert signing.verify_bytes(pub2, data, sig) is False


def test_public_from_private_matches_keygen():
    priv, pub = signing.generate_keypair()
    assert signing.public_from_private(priv) == pub


def test_invalid_private_key_raises():
    with pytest.raises(signing.SigningError):
        signing.sign_bytes(b"not a pem", b"data")


def test_sig_file_roundtrip_and_comments(tmp_path):
    priv, pub = signing.generate_keypair()
    target = tmp_path / "capsule.zip"
    target.write_bytes(b"\x00\x01\x02 capsule payload")
    sig_path = tmp_path / "capsule.zip.sig"

    signing.sign_file(target, priv, sig_path)
    text = sig_path.read_text(encoding="utf-8")
    assert text.startswith("#")  # self-describing header
    assert signing.verify_file(target, pub, sig_path) is True


def test_verify_file_detects_modified_target(tmp_path):
    priv, pub = signing.generate_keypair()
    target = tmp_path / "capsule.zip"
    target.write_bytes(b"authentic")
    sig_path = tmp_path / "capsule.zip.sig"
    signing.sign_file(target, priv, sig_path)

    target.write_bytes(b"tampered!")  # change after signing
    assert signing.verify_file(target, pub, sig_path) is False


def test_empty_sig_file_is_rejected(tmp_path):
    priv, pub = signing.generate_keypair()
    target = tmp_path / "t"
    target.write_bytes(b"x")
    bad_sig = tmp_path / "t.sig"
    bad_sig.write_text("# only a comment, no payload\n", encoding="utf-8")
    with pytest.raises(signing.SigningError):
        signing.verify_file(target, pub, bad_sig)


# --- CLI flow: keygen -> sign -> verify ------------------------------------

def test_cli_keygen_writes_keypair(tmp_path, capsys):
    rc = cli.main(["capsule", "keygen", "--out-dir", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "reachgate-signing.key").exists()
    assert (tmp_path / "reachgate-signing.pub").exists()
    assert "SECRET" in capsys.readouterr().out


def test_cli_sign_then_verify_roundtrip(tmp_path, capsys):
    # keygen
    assert cli.main(["capsule", "keygen", "--out-dir", str(tmp_path)]) == 0
    key = tmp_path / "reachgate-signing.key"
    capsule = tmp_path / "capsule.zip"
    capsule.write_bytes(b"PK\x03\x04 pretend-zip evidence")
    sig = tmp_path / "capsule.zip.sig"

    # sign
    rc = cli.main(["capsule", "sign", str(capsule), "--key", str(key),
                   "--output", str(sig)])
    assert rc == 0
    assert sig.exists()
    pub = capsule.with_name("capsule.zip.pub")
    assert pub.exists()  # public-key sidecar emitted for the verifier

    # verify
    capsys.readouterr()
    rc = cli.main(["capsule", "verify", str(capsule),
                   "--sig", str(sig), "--pubkey", str(pub)])
    assert rc == 0
    assert "valid" in capsys.readouterr().out


def test_cli_verify_fails_on_tampered_capsule(tmp_path, capsys):
    assert cli.main(["capsule", "keygen", "--out-dir", str(tmp_path)]) == 0
    key = tmp_path / "reachgate-signing.key"
    capsule = tmp_path / "capsule.zip"
    capsule.write_bytes(b"authentic capsule")
    sig = tmp_path / "capsule.zip.sig"
    assert cli.main(["capsule", "sign", str(capsule), "--key", str(key),
                     "--output", str(sig)]) == 0
    pub = capsule.with_name("capsule.zip.pub")

    capsule.write_bytes(b"tampered capsule")  # modify after signing
    capsys.readouterr()
    rc = cli.main(["capsule", "verify", str(capsule),
                   "--sig", str(sig), "--pubkey", str(pub)])
    assert rc == 1
    assert "does NOT match" in capsys.readouterr().err


def test_cli_sign_requires_key(tmp_path, capsys):
    capsule = tmp_path / "capsule.zip"
    capsule.write_bytes(b"x")
    rc = cli.main(["capsule", "sign", str(capsule)])
    assert rc == 2
    assert "--key" in capsys.readouterr().err

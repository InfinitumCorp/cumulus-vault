import io
import json

import pytest

from cumulus_vault import crypto
from cumulus_vault.cli import main
from cumulus_vault.ledger import Ledger
from cumulus_vault.storage import LocalBackend
from cumulus_vault.vault import Vault


def make(tmp_path):
    v = Vault(tmp_path / "home", LocalBackend(tmp_path / "home" / "store"))
    v.init()
    return v


def test_roundtrip_multi_chunk():
    key = crypto.generate_key()
    data = b"x" * (crypto.CHUNK * 2 + 123)
    enc = io.BytesIO()
    h1 = crypto.encrypt_stream(key, io.BytesIO(data), enc)
    out = io.BytesIO()
    enc.seek(0)
    assert crypto.decrypt_stream(key, enc, out) == h1
    assert out.getvalue() == data


def test_truncation_and_tamper_detected():
    key = crypto.generate_key()
    enc = io.BytesIO()
    crypto.encrypt_stream(key, io.BytesIO(b"a" * (crypto.CHUNK + 10)), enc)
    raw = enc.getvalue()
    first_chunk_end = 8 + 16 + 8 + 4 + crypto.CHUNK + 16
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_stream(key, io.BytesIO(raw[:first_chunk_end]), io.BytesIO())
    bad = bytearray(raw)
    bad[40] ^= 1
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_stream(key, io.BytesIO(bytes(bad)), io.BytesIO())


def test_backup_restore_verify(tmp_path):
    src = tmp_path / "docs"
    src.mkdir()
    (src / "a.txt").write_text("hello")
    v = make(tmp_path)
    e = v.backup(src)
    v.restore(tmp_path / "out")
    assert (tmp_path / "out" / "docs" / "a.txt").read_text() == "hello"
    res = v.verify()
    assert res["ledger_ok"] and res["restore_ok"] and res["backup_seq"] == e["seq"]


def test_ledger_tamper_detected(tmp_path):
    v = make(tmp_path)
    (tmp_path / "f").write_text("1")
    v.backup(tmp_path / "f")
    v.backup(tmp_path / "f")
    lines = v.ledger.path.read_text().splitlines()
    e = json.loads(lines[0])
    e["label"] = "changed"
    lines[0] = json.dumps(e)
    v.ledger.path.write_text("\n".join(lines) + "\n")
    ok, msg = v.ledger.verify()
    assert not ok and "altered" in msg


def test_wrong_key_fails_verify(tmp_path):
    v = make(tmp_path)
    (tmp_path / "f").write_text("1")
    v.backup(tmp_path / "f")
    v.key_path.write_bytes(crypto.generate_key())
    assert v.verify(record=False)["restore_ok"] is False


def test_cli(tmp_path, capsys):
    home = str(tmp_path / "h")
    (tmp_path / "f.txt").write_text("cli")
    assert main(["--home", home, "init"]) == 0
    assert main(["--home", home, "backup", str(tmp_path / "f.txt")]) == 0
    assert main(["--home", home, "verify"]) == 0
    assert main(["--home", home, "restore", str(tmp_path / "r")]) == 0
    assert (tmp_path / "r" / "f.txt").read_text() == "cli"


def test_anchor_builds_ots(tmp_path, monkeypatch):
    from cumulus_vault import anchor as anc

    v = make(tmp_path)
    (tmp_path / "f").write_text("1")
    v.backup(tmp_path / "f")
    monkeypatch.setattr(anc, "submit", lambda d, c=None: [b"\x00" + b"x" * 8, b"\x00" + b"y" * 8])
    cp, proof = anc.anchor(v.ledger.entries(), tmp_path / "anchors")
    data = proof.read_bytes()
    import hashlib
    assert data.startswith(anc.HEADER + anc.OP_SHA256 + hashlib.sha256(cp.read_bytes()).digest())
    assert anc.OP_FORK in data

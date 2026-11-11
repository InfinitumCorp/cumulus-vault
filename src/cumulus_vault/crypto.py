"""Chunked authenticated encryption (ChaCha20-Poly1305).

Format: MAGIC(8) | salt(16) | base_nonce(8) | chunks...
Each chunk: length(4, big-endian) | ciphertext(len). The 12-byte nonce for chunk i is
base_nonce || i (4 bytes). The final chunk is authenticated with associated data b"final",
so truncating the stream is detected.
"""
from __future__ import annotations

import hashlib
import os
import struct
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CVAULT01"
CHUNK = 1 << 20  # 1 MiB plaintext per chunk


class DecryptionError(Exception):
    pass


def generate_key() -> bytes:
    return ChaCha20Poly1305.generate_key()


def derive_key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())


def _nonce(base: bytes, i: int) -> bytes:
    return base + struct.pack(">I", i)


def encrypt_stream(key: bytes, src: BinaryIO, dst: BinaryIO, salt: bytes | None = None) -> str:
    """Encrypt src into dst. Returns sha256 hex digest of the plaintext."""
    aead = ChaCha20Poly1305(key)
    salt = salt or os.urandom(16)
    base = os.urandom(8)
    dst.write(MAGIC + salt + base)
    h = hashlib.sha256()
    i = 0
    buf = src.read(CHUNK)
    while True:
        nxt = src.read(CHUNK)
        final = not nxt
        h.update(buf)
        ct = aead.encrypt(_nonce(base, i), buf, b"final" if final else b"")
        dst.write(struct.pack(">I", len(ct)) + ct)
        i += 1
        if final:
            break
        buf = nxt
    return h.hexdigest()


def read_salt(src: BinaryIO) -> bytes:
    head = src.read(len(MAGIC) + 16)
    if head[: len(MAGIC)] != MAGIC:
        raise DecryptionError("not a Cumulus Vault archive")
    src.seek(0)
    return head[len(MAGIC):]


def decrypt_stream(key: bytes, src: BinaryIO, dst: BinaryIO) -> str:
    """Decrypt src into dst. Returns sha256 hex digest of the plaintext."""
    aead = ChaCha20Poly1305(key)
    if src.read(len(MAGIC)) != MAGIC:
        raise DecryptionError("not a Cumulus Vault archive")
    src.read(16)
    base = src.read(8)
    h = hashlib.sha256()
    i = 0
    while True:
        hdr = src.read(4)
        if len(hdr) < 4:
            raise DecryptionError("archive truncated")
        (n,) = struct.unpack(">I", hdr)
        ct = src.read(n)
        if len(ct) != n:
            raise DecryptionError("archive truncated")
        final = src.peek(1)[:1] == b"" if hasattr(src, "peek") else _at_eof(src)
        try:
            pt = aead.decrypt(_nonce(base, i), ct, b"final" if final else b"")
        except Exception as e:  # InvalidTag
            raise DecryptionError("authentication failed: wrong key or tampered data") from e
        h.update(pt)
        dst.write(pt)
        i += 1
        if final:
            return h.hexdigest()


def _at_eof(f: BinaryIO) -> bool:
    pos = f.tell()
    b = f.read(1)
    f.seek(pos)
    return b == b""

#!/usr/bin/env python3
"""sealbox: stdlib-only local secrets vault, secure share, TOTP, and scanner.

This file is intentionally self-contained for the Zero Dependency Hackathon's
Single File bonus. The crypto construction follows the event specification:
RFC 3526 Group 14 DH -> RFC 5869 HKDF-SHA256 -> HMAC-SHA256 counter keystream
-> encrypt-then-MAC.

Important: this is a hackathon security utility, not a replacement for a
professionally audited password manager or AEAD library.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Iterator, Sequence

# ---------------------------------------------------------------------------
# Version / protocol constants
# ---------------------------------------------------------------------------

APP_NAME = "sealbox"
APP_VERSION = "1.0.0"
VAULT_MAGIC = b"SBX1"
VAULT_VERSION = 1
HEADER_STRUCT = struct.Struct(">4sH16sIII")
RECORD_PREFIX_STRUCT = struct.Struct(">H16sI")
TAG_SIZE = hashlib.sha256().digest_size
NONCE_SIZE = 16
DH_SIZE = 256
MAX_NAME_BYTES = 1024
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_SHARE_BYTES = 64 * 1024 * 1024
MAX_FRAME_BYTES = MAX_SHARE_BYTES + 4096
SOCKET_TIMEOUT = 15.0

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024

# RFC 3526, section 3, 2048-bit MODP Group 14, generator 2.
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_G = 2

HKDF_INFO_ENC = b"sealbox/v1/enc"
HKDF_INFO_MAC = b"sealbox/v1/mac"
HKDF_INFO_VAULT_ENC = b"sealbox/v1/vault-enc"
HKDF_INFO_VAULT_MAC = b"sealbox/v1/vault-mac"
PASSWORD_VERIFY_NAME = b"__sealbox_verify__"
INTEGRITY_NAME = b"__sealbox_integrity__"
PASSWORD_VERIFY_VALUE = b"sealbox-password-verifier-v1"
SHARE_ENVELOPE_MAGIC = b"SBX-SHARE1"

EXIT_OK = 0
EXIT_IO = 1
EXIT_NOT_FOUND = 2
EXIT_AUTH = 3
EXIT_USAGE = 4


class SealboxError(Exception):
    """Expected user-facing application error."""


class FormatError(SealboxError):
    """The vault or wire format is invalid."""


class AuthenticationError(SealboxError):
    """An authentication tag or password verifier failed."""


class NotFoundError(SealboxError):
    """A requested entry does not exist."""


# ---------------------------------------------------------------------------
# Secure-ish byte helpers
# ---------------------------------------------------------------------------


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor operands must have the same length")
    return bytes(a ^ b for a, b in zip(left, right))


def _validate_password(password: str) -> bytes:
    # UTF-8 is the stable external representation; reject absurd input that
    # would make KDF work needlessly expensive and inconsistent across tools.
    if not 1 <= len(password) <= 1024:
        raise SealboxError("master password must be 1..1024 Unicode characters")
    return password.encode("utf-8", "surrogatepass")


def _set_private_mode(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Windows and restrictive mounts may reject POSIX chmod semantics.
        pass


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# HMAC / HKDF / DH
# ---------------------------------------------------------------------------


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract from RFC 5869 using HMAC-SHA256."""
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand from RFC 5869 using HMAC-SHA256."""
    if length < 0:
        raise ValueError("HKDF length must be non-negative")
    hash_len = hashlib.sha256().digest_size
    if length > 255 * hash_len:
        raise ValueError("HKDF output too long")
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac_sha256(prk, previous + info + bytes([counter]))
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def dh_generate_keypair() -> tuple[int, int]:
    private = secrets.randbits(256)
    if private < 2:
        private = 2
    public = pow(DH_G, private, DH_P)
    return private, public


def dh_validate_public(peer_public: int) -> None:
    if not 2 <= peer_public <= DH_P - 2:
        raise AuthenticationError("invalid DH public value")


def dh_shared_secret(private: int, peer_public: int) -> bytes:
    dh_validate_public(peer_public)
    shared_int = pow(peer_public, private, DH_P)
    if shared_int in (0, 1, DH_P - 1):
        raise AuthenticationError("invalid DH shared secret")
    return shared_int.to_bytes(DH_SIZE, "big")


def derive_share_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    # Fixed empty salt gives the same deterministic derivation both directions;
    # domain-separated info values keep encryption and MAC keys independent.
    prk = hkdf_extract(b"", shared_secret)
    return (
        hkdf_expand(prk, HKDF_INFO_ENC, 32),
        hkdf_expand(prk, HKDF_INFO_MAC, 32),
    )


# ---------------------------------------------------------------------------
# Authenticated keystream composition
# ---------------------------------------------------------------------------


def keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must be exactly 16 bytes")
    if length < 0:
        raise ValueError("length cannot be negative")
    blocks = []
    counter = 0
    remaining = length
    while remaining > 0:
        block = hmac_sha256(key, nonce + struct.pack(">Q", counter))
        blocks.append(block)
        remaining -= len(block)
        counter += 1
    return b"".join(blocks)[:length]


def encrypt_then_mac(enc_key: bytes, mac_key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = secrets.token_bytes(NONCE_SIZE)
    stream = keystream(enc_key, nonce, len(plaintext))
    ciphertext = xor_bytes(plaintext, stream)
    tag = hmac_sha256(mac_key, nonce + ciphertext)
    return nonce, ciphertext, tag


def decrypt_then_verify(enc_key: bytes, mac_key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    if len(nonce) != NONCE_SIZE or len(tag) != TAG_SIZE:
        raise AuthenticationError("invalid authenticated payload framing")
    expected = hmac_sha256(mac_key, nonce + ciphertext)
    if not hmac.compare_digest(expected, tag):
        raise AuthenticationError("authentication tag mismatch")
    stream = keystream(enc_key, nonce, len(ciphertext))
    return xor_bytes(ciphertext, stream)


def password_keys(password: str, salt: bytes, n: int, r: int, p: int) -> tuple[bytes, bytes]:
    if len(salt) < 16:
        raise FormatError("vault KDF salt is too short")
    if n < 2 or n & (n - 1):
        raise FormatError("vault scrypt N must be a power of two >= 2")
    if r <= 0 or p <= 0:
        raise FormatError("vault scrypt parameters are invalid")
    raw = hashlib.scrypt(
        _validate_password(password),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=32,
        maxmem=SCRYPT_MAXMEM,
    )
    prk = hkdf_extract(b"", raw)
    return (
        hkdf_expand(prk, HKDF_INFO_VAULT_ENC, 32),
        hkdf_expand(prk, HKDF_INFO_VAULT_MAC, 32),
    )


# ---------------------------------------------------------------------------
# Vault serialization
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VaultHeader:
    version: int
    salt: bytes
    n: int
    r: int
    p: int


@dataclass(frozen=True)
class VaultRecord:
    name: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def _encode_record(record: VaultRecord) -> bytes:
    name_bytes = record.name.encode("utf-8")
    if not name_bytes or len(name_bytes) > MAX_NAME_BYTES:
        raise SealboxError("entry name must be 1..1024 UTF-8 bytes")
    if len(record.nonce) != NONCE_SIZE:
        raise ValueError("invalid nonce")
    if len(record.ciphertext) > MAX_RECORD_BYTES:
        raise SealboxError("entry is too large")
    if len(record.tag) != TAG_SIZE:
        raise ValueError("invalid tag")
    return (
        RECORD_PREFIX_STRUCT.pack(len(name_bytes), record.nonce, len(record.ciphertext))
        + name_bytes
        + record.ciphertext
        + record.tag
    )


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = stream.read(size - len(chunks))
        if not part:
            raise FormatError("unexpected end of file")
        chunks.extend(part)
    return bytes(chunks)


def _parse_vault(raw: bytes) -> tuple[VaultHeader, list[VaultRecord]]:
    if len(raw) < HEADER_STRUCT.size:
        raise FormatError("vault is truncated")
    magic, version, salt, n, r, p = HEADER_STRUCT.unpack_from(raw, 0)
    if magic != VAULT_MAGIC:
        raise FormatError("not a sealbox vault")
    if version != VAULT_VERSION:
        raise FormatError(f"unsupported vault version: {version}")
    if len(salt) != 16:
        raise FormatError("invalid KDF salt")
    header = VaultHeader(version, salt, n, r, p)
    pos = HEADER_STRUCT.size
    records: list[VaultRecord] = []
    while pos < len(raw):
        if len(raw) - pos < RECORD_PREFIX_STRUCT.size:
            raise FormatError("truncated vault record prefix")
        name_len, nonce, ct_len = RECORD_PREFIX_STRUCT.unpack_from(raw, pos)
        pos += RECORD_PREFIX_STRUCT.size
        if name_len == 0 or name_len > MAX_NAME_BYTES:
            raise FormatError("invalid entry name length")
        if ct_len > MAX_RECORD_BYTES:
            raise FormatError("entry ciphertext exceeds limit")
        total = name_len + ct_len + TAG_SIZE
        if len(raw) - pos < total:
            raise FormatError("truncated vault record")
        try:
            name = raw[pos : pos + name_len].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FormatError("entry name is not valid UTF-8") from exc
        pos += name_len
        ciphertext = raw[pos : pos + ct_len]
        pos += ct_len
        tag = raw[pos : pos + TAG_SIZE]
        pos += TAG_SIZE
        records.append(VaultRecord(name, nonce, ciphertext, tag))
    return header, records


class Vault:
    """A small authenticated single-file local vault."""

    def __init__(self, path: Path, password: str, header: VaultHeader, records: list[VaultRecord]):
        self.path = Path(path)
        self.password = password
        self.header = header
        self.records = records
        self.enc_key, self.mac_key = password_keys(
            password, header.salt, header.n, header.r, header.p
        )
        self._verify_password()

    @classmethod
    def create(cls, path: Path, password: str) -> "Vault":
        if Path(path).exists():
            raise SealboxError(f"vault already exists: {path}")
        _validate_password(password)
        header = VaultHeader(
            VAULT_VERSION,
            secrets.token_bytes(16),
            SCRYPT_N,
            SCRYPT_R,
            SCRYPT_P,
        )
        enc_key, mac_key = password_keys(password, header.salt, header.n, header.r, header.p)
        nonce, ciphertext, tag = encrypt_then_mac(enc_key, mac_key, PASSWORD_VERIFY_VALUE)
        records = [VaultRecord(PASSWORD_VERIFY_NAME.decode(), nonce, ciphertext, tag)]
        vault = cls.__new__(cls)
        vault.path = Path(path)
        vault.password = password
        vault.header = header
        vault.records = records
        vault.enc_key = enc_key
        vault.mac_key = mac_key
        vault._write()
        return vault

    @classmethod
    def open(cls, path: Path, password: str) -> "Vault":
        try:
            raw = Path(path).read_bytes()
        except OSError as exc:
            raise SealboxError(f"cannot read vault: {exc}") from exc
        header, records = _parse_vault(raw)
        return cls(path, password, header, records)

    def _header_bytes(self) -> bytes:
        return HEADER_STRUCT.pack(
            VAULT_MAGIC,
            self.header.version,
            self.header.salt,
            self.header.n,
            self.header.r,
            self.header.p,
        )

    def _integrity_payload(self, records: Sequence[VaultRecord]) -> bytes:
        canonical = bytearray(self._header_bytes())
        for record in records:
            if record.name == INTEGRITY_NAME.decode():
                continue
            canonical.extend(_encode_record(record))
        return hmac_sha256(self.mac_key, bytes(canonical))

    def _verify_password(self) -> None:
        verifier = next((r for r in self.records if r.name == PASSWORD_VERIFY_NAME.decode()), None)
        if verifier is None:
            raise AuthenticationError("vault password verifier is missing")
        plaintext = decrypt_then_verify(
            self.enc_key, self.mac_key, verifier.nonce, verifier.ciphertext, verifier.tag
        )
        if not hmac.compare_digest(plaintext, PASSWORD_VERIFY_VALUE):
            raise AuthenticationError("incorrect master password")

        integrity = next((r for r in self.records if r.name == INTEGRITY_NAME.decode()), None)
        if integrity is None:
            raise AuthenticationError("vault integrity record is missing")
        stored_digest = decrypt_then_verify(
            self.enc_key, self.mac_key, integrity.nonce, integrity.ciphertext, integrity.tag
        )
        expected_digest = self._integrity_payload(self.records)
        if not hmac.compare_digest(stored_digest, expected_digest):
            raise AuthenticationError("vault integrity check failed")

    def _refresh_integrity(self) -> None:
        normal_records = [r for r in self.records if r.name != INTEGRITY_NAME.decode()]
        digest = self._integrity_payload(normal_records)
        nonce, ciphertext, tag = encrypt_then_mac(self.enc_key, self.mac_key, digest)
        self.records = normal_records + [
            VaultRecord(INTEGRITY_NAME.decode(), nonce, ciphertext, tag)
        ]

    def _write(self) -> None:
        self._refresh_integrity()
        payload = bytearray(self._header_bytes())
        for record in self.records:
            payload.extend(_encode_record(record))

        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent)
        tmp_path = Path(tmp_name)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self.path)
            _set_private_mode(self.path)
            _fsync_directory(self.path.parent)
        finally:
            if fd != -1:
                os.close(fd)
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass

    def _make_record(self, name: str, value: bytes) -> VaultRecord:
        nonce, ciphertext, tag = encrypt_then_mac(self.enc_key, self.mac_key, value)
        return VaultRecord(name, nonce, ciphertext, tag)

    def _find_record(self, name: str) -> VaultRecord:
        for record in self.records:
            if record.name == name:
                return record
        raise NotFoundError(name)

    def list_names(self) -> list[str]:
        return sorted(
            r.name
            for r in self.records
            if r.name not in {PASSWORD_VERIFY_NAME.decode(), INTEGRITY_NAME.decode()}
        )

    def get(self, name: str) -> bytes:
        record = self._find_record(name)
        if name in {PASSWORD_VERIFY_NAME.decode(), INTEGRITY_NAME.decode()}:
            raise NotFoundError(name)
        return decrypt_then_verify(
            self.enc_key, self.mac_key, record.nonce, record.ciphertext, record.tag
        )

    def put(self, name: str, value: bytes) -> None:
        if not name or name in {PASSWORD_VERIFY_NAME.decode(), INTEGRITY_NAME.decode()}:
            raise SealboxError("invalid entry name")
        if len(value) > MAX_RECORD_BYTES:
            raise SealboxError("secret exceeds 16 MiB")
        replacement = self._make_record(name, value)
        filtered = [r for r in self.records if r.name != name]
        filtered.append(replacement)
        self.records = filtered
        self._write()

    def remove(self, name: str) -> None:
        if name == PASSWORD_VERIFY_NAME.decode():
            raise NotFoundError(name)
        old = len(self.records)
        self.records = [r for r in self.records if r.name != name]
        if len(self.records) == old:
            raise NotFoundError(name)
        self._write()

    def stats(self) -> dict[str, object]:
        st = self.path.stat()
        return {
            "entries": len(self.list_names()),
            "size": st.st_size,
            "modified": st.st_mtime,
        }


# ---------------------------------------------------------------------------
# TOTP (RFC 6238 / RFC 4226 dynamic truncation)
# ---------------------------------------------------------------------------


def totp_code(secret: bytes, timestamp: int, digits: int = 6, step: int = 30, digest: str = "sha1") -> str:
    if digits not in (6, 8):
        raise ValueError("TOTP digits must be 6 or 8")
    if step <= 0:
        raise ValueError("TOTP step must be positive")
    try:
        digest_fn = getattr(hashlib, digest)
    except AttributeError as exc:
        raise ValueError(f"unsupported digest: {digest}") from exc
    counter = timestamp // step
    msg = struct.pack(">Q", counter)
    mac = hmac.new(secret, msg, digest_fn).digest()
    offset = mac[-1] & 0x0F
    binary = ((mac[offset] & 0x7F) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]
    return f"{binary % (10**digits):0{digits}d}"


def totp_remaining(timestamp: int, step: int = 30) -> int:
    return step - (timestamp % step)


# ---------------------------------------------------------------------------
# Share wire protocol
# ---------------------------------------------------------------------------


def _send_all(sock: socket.socket, data: bytes) -> None:
    view = memoryview(data)
    while view:
        sent = sock.send(view)
        if sent <= 0:
            raise SealboxError("socket closed while sending")
        view = view[sent:]


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    if size < 0 or size > MAX_FRAME_BYTES:
        raise FormatError("invalid frame size")
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise SealboxError("peer closed connection")
        chunks.extend(chunk)
    return bytes(chunks)


def _send_length_prefixed(sock: socket.socket, data: bytes) -> None:
    _send_all(sock, struct.pack(">I", len(data)) + data)


def _recv_length_prefixed(sock: socket.socket, max_len: int) -> bytes:
    length = struct.unpack(">I", _recv_exact(sock, 4))[0]
    if length > max_len:
        raise FormatError("peer sent an oversized frame")
    return _recv_exact(sock, length)


def _dh_handshake(sock: socket.socket) -> tuple[bytes, bytes]:
    private, public = dh_generate_keypair()
    public_bytes = public.to_bytes(DH_SIZE, "big")
    # Symmetric send-then-receive avoids role-dependent framing.
    _send_length_prefixed(sock, public_bytes)
    peer_bytes = _recv_length_prefixed(sock, DH_SIZE)
    if len(peer_bytes) != DH_SIZE:
        raise AuthenticationError("invalid DH public key length")
    peer_public = int.from_bytes(peer_bytes, "big")
    dh_validate_public(peer_public)
    shared = dh_shared_secret(private, peer_public)
    return derive_share_keys(shared)


def _build_share_envelope(kind: str, name: str | None, content: bytes) -> bytes:
    if kind not in {"message", "file"}:
        raise ValueError("unsupported share kind")
    kind_byte = b"M" if kind == "message" else b"F"
    name_bytes = (name or "").encode("utf-8")
    if len(name_bytes) > 4096:
        raise SealboxError("shared filename is too long")
    if len(content) > MAX_SHARE_BYTES:
        raise SealboxError("shared payload exceeds 64 MiB")
    return (
        SHARE_ENVELOPE_MAGIC
        + kind_byte
        + struct.pack(">H", len(name_bytes))
        + name_bytes
        + struct.pack(">I", len(content))
        + content
    )


def _parse_share_envelope(payload: bytes) -> tuple[str, str | None, bytes]:
    if len(payload) < len(SHARE_ENVELOPE_MAGIC) + 1 + 2 + 4:
        raise FormatError("share envelope is truncated")
    pos = 0
    if not payload.startswith(SHARE_ENVELOPE_MAGIC):
        raise FormatError("unknown share envelope")
    pos += len(SHARE_ENVELOPE_MAGIC)
    kind_byte = payload[pos : pos + 1]
    pos += 1
    if kind_byte not in (b"M", b"F"):
        raise FormatError("unknown share payload type")
    name_len = struct.unpack_from(">H", payload, pos)[0]
    pos += 2
    if len(payload) - pos < name_len + 4:
        raise FormatError("truncated share metadata")
    raw_name = payload[pos : pos + name_len]
    pos += name_len
    try:
        name = raw_name.decode("utf-8") if raw_name else None
    except UnicodeDecodeError as exc:
        raise FormatError("invalid shared filename") from exc
    content_len = struct.unpack_from(">I", payload, pos)[0]
    pos += 4
    if content_len > MAX_SHARE_BYTES or len(payload) - pos != content_len:
        raise FormatError("invalid share content length")
    return ("message" if kind_byte == b"M" else "file", name, payload[pos:])


def share_encrypt_frame(enc_key: bytes, mac_key: bytes, plaintext: bytes) -> bytes:
    if len(plaintext) > MAX_SHARE_BYTES + 4096:
        raise SealboxError("share payload too large")
    nonce, ciphertext, tag = encrypt_then_mac(enc_key, mac_key, plaintext)
    return nonce + struct.pack(">I", len(ciphertext)) + ciphertext + tag


def share_decrypt_frame(enc_key: bytes, mac_key: bytes, frame: bytes) -> bytes:
    if len(frame) < NONCE_SIZE + 4 + TAG_SIZE:
        raise FormatError("share frame too short")
    nonce = frame[:NONCE_SIZE]
    ct_len = struct.unpack_from(">I", frame, NONCE_SIZE)[0]
    if ct_len > MAX_SHARE_BYTES + 4096:
        raise FormatError("share ciphertext too large")
    expected_len = NONCE_SIZE + 4 + ct_len + TAG_SIZE
    if len(frame) != expected_len:
        raise FormatError("share frame length mismatch")
    ciphertext = frame[NONCE_SIZE + 4 : NONCE_SIZE + 4 + ct_len]
    tag = frame[-TAG_SIZE:]
    # No plaintext is materialized until tag verification succeeds.
    return decrypt_then_verify(enc_key, mac_key, nonce, ciphertext, tag)


def share_send(host: str, port: int, kind: str, name: str | None, content: bytes) -> None:
    with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as sock:
        sock.settimeout(SOCKET_TIMEOUT)
        enc_key, mac_key = _dh_handshake(sock)
        envelope = _build_share_envelope(kind, name, content)
        frame = share_encrypt_frame(enc_key, mac_key, envelope)
        _send_length_prefixed(sock, frame)


def share_receive(host: str, port: int) -> tuple[str, str | None, bytes]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        listener.settimeout(300.0)
        conn, _addr = listener.accept()
        with conn:
            conn.settimeout(SOCKET_TIMEOUT)
            enc_key, mac_key = _dh_handshake(conn)
            frame = _recv_length_prefixed(conn, MAX_FRAME_BYTES)
            plaintext = share_decrypt_frame(enc_key, mac_key, frame)
            return _parse_share_envelope(plaintext)


# ---------------------------------------------------------------------------
# Secret scanner
# ---------------------------------------------------------------------------

AWS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*[\"']([^\"']{8,})[\"']"
)
HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
B64_RE = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")


@dataclass(frozen=True)
class ScanFinding:
    path: Path
    line: int
    rule: str
    masked: str


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    visible = min(4, len(value) // 4)
    return value[:visible] + "…" + value[-visible:]


def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data:
        return True
    bad = sum(1 for b in data[:8192] if b < 9 or (13 < b < 32))
    return bad > len(data[:8192]) * 0.02


def iter_text_files(root: Path) -> Iterator[Path]:
    root = root.resolve()
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in {".git", ".hg", ".svn", "__pycache__", ".venv", "venv"} for part in path.parts):
            continue
        yield path


def scan_path(root: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for path in iter_text_files(root):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if len(raw) > 8 * 1024 * 1024 or _looks_binary(raw):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            seen: set[tuple[str, str]] = set()
            for label, regex in (("aws-access-key", AWS_RE), ("private-key-header", PEM_RE)):
                for match in regex.finditer(line):
                    token = match.group(0)
                    key = (label, token)
                    if key not in seen:
                        findings.append(ScanFinding(path, line_no, label, mask_secret(token)))
                        seen.add(key)
            for match in ASSIGNMENT_RE.finditer(line):
                token = match.group(1)
                key = ("assignment", token)
                if key not in seen:
                    findings.append(ScanFinding(path, line_no, "secret-assignment", mask_secret(token)))
                    seen.add(key)
            for label, regex in (("high-entropy-hex", HEX_RE), ("high-entropy-base64", B64_RE)):
                for match in regex.finditer(line):
                    token = match.group(0)
                    threshold = 3.5 if label.endswith("hex") else 4.5
                    if len(token) >= 32 and shannon_entropy(token) >= threshold:
                        key = (label, token)
                        if key not in seen:
                            findings.append(ScanFinding(path, line_no, label, mask_secret(token)))
                            seen.add(key)
    return findings


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def password_prompt(confirm: bool = False) -> str:
    password = getpass.getpass("Master password: ")
    if confirm:
        again = getpass.getpass("Confirm password: ")
        if not hmac.compare_digest(password, again):
            raise SealboxError("passwords do not match")
    return password


def resolve_vault_path(path_arg: str | None) -> Path:
    raw = path_arg or os.environ.get("SEALBOX_VAULT") or "sealbox.vault"
    return Path(raw).expanduser()


def cmd_init(args: argparse.Namespace) -> int:
    path = resolve_vault_path(args.vault)
    password = password_prompt(confirm=True)
    Vault.create(path, password)
    print(f"Initialized {path}")
    return EXIT_OK


def open_vault(path: str | None) -> Vault:
    return Vault.open(resolve_vault_path(path), password_prompt())


def cmd_add(args: argparse.Namespace) -> int:
    vault = open_vault(args.vault)
    value = args.value
    if value is None:
        value = getpass.getpass("Secret value: ")
    vault.put(args.name, value.encode("utf-8", "surrogatepass"))
    print(f"Stored {args.name}")
    return EXIT_OK


def cmd_get(args: argparse.Namespace) -> int:
    vault = open_vault(args.vault)
    value = vault.get(args.name)
    sys.stdout.buffer.write(value)
    sys.stdout.buffer.write(b"\n")
    return EXIT_OK


def cmd_rm(args: argparse.Namespace) -> int:
    vault = open_vault(args.vault)
    vault.remove(args.name)
    print(f"Removed {args.name}")
    return EXIT_OK


def cmd_ls(args: argparse.Namespace) -> int:
    vault = open_vault(args.vault)
    for name in vault.list_names():
        print(name)
    return EXIT_OK


def cmd_totp_add(args: argparse.Namespace) -> int:
    secret = args.secret
    # Validate before writing. The vault stores the canonical uppercase value
    # so users do not depend on CLI spacing/casing quirks.
    decoded = _decode_base32_secret(secret)
    if len(decoded) < 10:
        raise SealboxError("TOTP secret is suspiciously short")
    vault = open_vault(args.vault)
    compact = re.sub(r"\s+", "", secret).upper().rstrip("=")
    vault.put(args.name, compact.encode("ascii"))
    print(f"Stored TOTP secret {args.name}")
    return EXIT_OK


def cmd_totp_code(args: argparse.Namespace) -> int:
    value = open_vault(args.vault).get(args.name).decode("ascii")
    secret = _decode_base32_secret(value)
    now = int(time.time())
    code = totp_code(secret, now, digits=args.digits, step=args.step, digest=args.algorithm)
    print(f"{code}  ({totp_remaining(now, args.step)}s)")
    return EXIT_OK


def _decode_base32_secret(secret: str) -> bytes:
    compact = re.sub(r"\s+", "", secret).upper()
    padded = compact + "=" * ((8 - len(compact) % 8) % 8)
    try:
        return base64.b32decode(padded, casefold=True)
    except Exception as exc:
        raise SealboxError("invalid base32 TOTP secret") from exc


def cmd_share_connect(args: argparse.Namespace) -> int:
    source = Path(args.payload)
    if source.is_file():
        content = source.read_bytes()
        share_send(args.host, args.port, "file", source.name, content)
        print(f"Sent {source.name} ({len(content)} bytes)")
    else:
        content = args.payload.encode("utf-8", "surrogatepass")
        share_send(args.host, args.port, "message", None, content)
        print("Sent encrypted message")
    return EXIT_OK


def cmd_share_listen(args: argparse.Namespace) -> int:
    print(f"Listening on {args.host}:{args.port} …", flush=True)
    kind, name, content = share_receive(args.host, args.port)
    if kind == "message":
        sys.stdout.buffer.write(content)
        sys.stdout.buffer.write(b"\n")
        return EXIT_OK
    safe_name = Path(name or "file.bin").name
    if safe_name in {"", ".", ".."} or "\x00" in safe_name:
        raise FormatError("invalid received filename")
    destination = Path(args.output or ("received_" + safe_name)).resolve()
    if destination.exists() and not args.force:
        raise SealboxError(f"refusing to overwrite {destination}; use --force")
    fd, tmp_name = tempfile.mkstemp(prefix=destination.name + ".", suffix=".part", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, destination)
    finally:
        try:
            Path(tmp_name).unlink()
        except FileNotFoundError:
            pass
    print(f"Received {destination} ({len(content)} bytes)")
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    findings = scan_path(Path(args.path))
    for item in findings:
        print(f"{item.path}:{item.line}: {item.rule}: {item.masked}")
    print(f"{len(findings)} finding(s)")
    return EXIT_IO if findings and args.fail_on_findings else EXIT_OK


def cmd_stats(args: argparse.Namespace) -> int:
    vault = open_vault(args.vault)
    stats = vault.stats()
    print(f"entries: {stats['entries']}")
    print(f"size: {stats['size']} bytes")
    print(f"modified: {time.strftime('%Y-%m-%d %H:%M:%S %z', time.localtime(stats['modified']))}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=APP_NAME, description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create a new vault")
    p.add_argument("--vault", help="vault path (default: sealbox.vault)")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("add", help="add or overwrite a secret")
    p.add_argument("name")
    p.add_argument("--value", help="secret value; omit to prompt")
    p.add_argument("--vault")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("get", help="decrypt a secret")
    p.add_argument("name")
    p.add_argument("--vault")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("rm", help="remove a secret")
    p.add_argument("name")
    p.add_argument("--vault")
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("ls", help="list entry names")
    p.add_argument("--vault")
    p.set_defaults(func=cmd_ls)

    totp = sub.add_parser("totp", help="TOTP operations")
    totp_sub = totp.add_subparsers(dest="totp_command", required=True)
    p = totp_sub.add_parser("add", help="store a base32 TOTP secret")
    p.add_argument("name")
    p.add_argument("secret")
    p.add_argument("--vault")
    p.set_defaults(func=cmd_totp_add)
    p = totp_sub.add_parser("code", help="print the current TOTP code")
    p.add_argument("name")
    p.add_argument("--vault")
    p.add_argument("--digits", type=int, default=6)
    p.add_argument("--step", type=int, default=30)
    p.add_argument("--algorithm", choices=("sha1", "sha256", "sha512"), default="sha1")
    p.set_defaults(func=cmd_totp_code)

    share = sub.add_parser("share", help="encrypted one-shot file/message sharing")
    share_sub = share.add_subparsers(dest="share_command", required=True)
    p = share_sub.add_parser("listen", help="receive exactly one share")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--output")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_share_listen)
    p = share_sub.add_parser("connect", help="send a message or file")
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("payload", help="message text or path to an existing file")
    p.set_defaults(func=cmd_share_connect)

    p = sub.add_parser("scan", help="scan a directory or file for likely secrets")
    p.add_argument("path")
    p.add_argument("--fail-on-findings", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("stats", help="show vault metadata")
    p.add_argument("--vault")
    p.set_defaults(func=cmd_stats)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return int(args.func(args))
    except AuthenticationError as exc:
        print(f"sealbox: authentication failure: {exc}", file=sys.stderr)
        return EXIT_AUTH
    except NotFoundError as exc:
        print(f"sealbox: not found: {exc}", file=sys.stderr)
        return EXIT_NOT_FOUND
    except (SealboxError, OSError, ValueError) as exc:
        print(f"sealbox: {exc}", file=sys.stderr)
        return EXIT_IO
    except KeyboardInterrupt:
        print("sealbox: interrupted", file=sys.stderr)
        return EXIT_IO


if __name__ == "__main__":
    raise SystemExit(main())

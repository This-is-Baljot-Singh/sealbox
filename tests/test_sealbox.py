import base64
import hashlib
import hmac
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sealbox


class TestCryptoVectors(unittest.TestCase):
    def test_hmac_sha256_rfc4231_case_2(self):
        key = bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819")
        data = bytes.fromhex("cd" * 50)
        expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        self.assertEqual(sealbox.hmac_sha256(key, data).hex(), expected)

    def test_hkdf_rfc5869_case_1(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        okm = (
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        self.assertEqual(sealbox.hkdf_extract(salt, ikm).hex(), prk)
        self.assertEqual(sealbox.hkdf(salt, ikm, info, 42).hex(), okm)

    def test_totp_rfc6238_sha1(self):
        secret = b"12345678901234567890"
        self.assertEqual(sealbox.totp_code(secret, 59, digits=8, digest="sha1"), "94287082")
        self.assertEqual(sealbox.totp_code(secret, 1111111109, digits=8, digest="sha1"), "07081804")
        self.assertEqual(sealbox.totp_code(secret, 1234567890, digits=8, digest="sha1"), "89005924")

    def test_totp_rfc6238_sha256(self):
        secret = b"12345678901234567890123456789012"
        self.assertEqual(sealbox.totp_code(secret, 59, digits=8, digest="sha256"), "46119246")

    def test_dh_shared_secret_matches(self):
        a_priv, a_pub = sealbox.dh_generate_keypair()
        b_priv, b_pub = sealbox.dh_generate_keypair()
        self.assertEqual(
            sealbox.dh_shared_secret(a_priv, b_pub),
            sealbox.dh_shared_secret(b_priv, a_pub),
        )


class TestAuthenticatedEncryption(unittest.TestCase):
    def setUp(self):
        self.enc = hashlib.sha256(b"enc").digest()
        self.mac = hashlib.sha256(b"mac").digest()

    def test_empty_roundtrip(self):
        nonce, ciphertext, tag = sealbox.encrypt_then_mac(self.enc, self.mac, b"")
        self.assertEqual(ciphertext, b"")
        self.assertEqual(sealbox.decrypt_then_verify(self.enc, self.mac, nonce, ciphertext, tag), b"")

    def test_random_lengths_roundtrip(self):
        for length in (1, 2, 31, 32, 33, 127, 1024):
            plain = os.urandom(length)
            nonce, ciphertext, tag = sealbox.encrypt_then_mac(self.enc, self.mac, plain)
            self.assertEqual(len(nonce), sealbox.NONCE_SIZE)
            self.assertEqual(len(tag), sealbox.TAG_SIZE)
            self.assertEqual(sealbox.decrypt_then_verify(self.enc, self.mac, nonce, ciphertext, tag), plain)

    def test_ciphertext_tamper_fails(self):
        nonce, ciphertext, tag = sealbox.encrypt_then_mac(self.enc, self.mac, b"important")
        tampered = bytearray(ciphertext)
        tampered[0] ^= 1
        with self.assertRaises(sealbox.AuthenticationError):
            sealbox.decrypt_then_verify(self.enc, self.mac, nonce, bytes(tampered), tag)

    def test_tag_tamper_fails(self):
        nonce, ciphertext, tag = sealbox.encrypt_then_mac(self.enc, self.mac, b"important")
        tampered = bytearray(tag)
        tampered[-1] ^= 1
        with self.assertRaises(sealbox.AuthenticationError):
            sealbox.decrypt_then_verify(self.enc, self.mac, nonce, ciphertext, bytes(tampered))


class TestVault(unittest.TestCase):
    def test_restart_and_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sealbox.vault"
            vault = sealbox.Vault.create(path, "correct horse battery staple")
            vault.put("github", b"super-secret")
            vault.put("note", "unicode ✓".encode())
            self.assertEqual(vault.list_names(), ["github", "note"])

            reopened = sealbox.Vault.open(path, "correct horse battery staple")
            self.assertEqual(reopened.get("github"), b"super-secret")
            self.assertEqual(reopened.get("note"), "unicode ✓".encode())

            with self.assertRaises(sealbox.AuthenticationError):
                sealbox.Vault.open(path, "wrong")

            raw = bytearray(path.read_bytes())
            raw[-1] ^= 1
            path.write_bytes(raw)
            with self.assertRaises(sealbox.AuthenticationError):
                sealbox.Vault.open(path, "correct horse battery staple")

    def test_atomic_rewrite_survives_normal_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "vault"
            v = sealbox.Vault.create(path, "pass")
            v.put("a", b"1")
            v.put("b", b"2")
            v.remove("a")
            self.assertEqual(v.list_names(), ["b"])
            self.assertEqual(sealbox.Vault.open(path, "pass").get("b"), b"2")


class TestShare(unittest.TestCase):
    def test_frame_tamper(self):
        enc = hashlib.sha256(b"e").digest()
        mac = hashlib.sha256(b"m").digest()
        frame = sealbox.share_encrypt_frame(enc, mac, sealbox._build_share_envelope("message", None, b"hello"))
        tampered = bytearray(frame)
        tampered[-1] ^= 1
        with self.assertRaises(sealbox.AuthenticationError):
            sealbox.share_decrypt_frame(enc, mac, bytes(tampered))

    def test_local_share_process(self):
        # Use a real ephemeral TCP listener and let share_receive bind a known port.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        received = {}
        def receiver():
            received["value"] = sealbox.share_receive("127.0.0.1", port)

        thread = threading.Thread(target=receiver)
        thread.start()
        time.sleep(0.05)
        sealbox.share_send("127.0.0.1", port, "message", None, b"network secret")
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(received["value"], ("message", None, b"network secret"))


class TestScanner(unittest.TestCase):
    def test_fixture_detection_and_masking(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "sample.txt").write_text(
                "AWS=AKIA1234567890ABCDEF\n"
                "token = \"this-is-a-fake-long-secret\"\n"
                "-----BEGIN PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            findings = sealbox.scan_path(root)
            rules = {item.rule for item in findings}
            self.assertIn("aws-access-key", rules)
            self.assertIn("secret-assignment", rules)
            self.assertIn("private-key-header", rules)
            self.assertTrue(all("1234567890ABCDEF" not in item.masked for item in findings))

    def test_entropy(self):
        self.assertGreater(sealbox.shannon_entropy("a8B4c9D0e1F2g3H4i5J6k7L8m9N0pQ"), 3.0)
        self.assertEqual(sealbox.shannon_entropy(""), 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

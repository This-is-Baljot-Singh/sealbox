import hashlib
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

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

    def test_hkdf_rejects_oversized_output(self):
        with self.assertRaises(ValueError):
            sealbox.hkdf_expand(b"x" * 32, b"info", 255 * 32 + 1)

    def test_totp_rfc6238_sha1(self):
        secret = b"12345678901234567890"
        self.assertEqual(sealbox.totp_code(secret, 59, digits=8, digest="sha1"), "94287082")
        self.assertEqual(sealbox.totp_code(secret, 1111111109, digits=8, digest="sha1"), "07081804")
        self.assertEqual(sealbox.totp_code(secret, 1234567890, digits=8, digest="sha1"), "89005924")

    def test_totp_rfc6238_sha256(self):
        secret = b"12345678901234567890123456789012"
        self.assertEqual(sealbox.totp_code(secret, 59, digits=8, digest="sha256"), "46119246")

    def test_totp_remaining(self):
        self.assertEqual(sealbox.totp_remaining(59, 30), 1)
        self.assertEqual(sealbox.totp_remaining(60, 30), 30)

    def test_dh_shared_secret_matches(self):
        a_priv, a_pub = sealbox.dh_generate_keypair()
        b_priv, b_pub = sealbox.dh_generate_keypair()
        self.assertEqual(
            sealbox.dh_shared_secret(a_priv, b_pub),
            sealbox.dh_shared_secret(b_priv, a_pub),
        )

    def test_dh_rejects_degenerate_public_values(self):
        private, _public = sealbox.dh_generate_keypair()
        for bad in (0, 1, sealbox.DH_P - 1, sealbox.DH_P, sealbox.DH_P + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(sealbox.AuthenticationError):
                    sealbox.dh_shared_secret(private, bad)

    def test_scrypt_parameters_are_bounded_before_derivation(self):
        with self.assertRaises(sealbox.FormatError):
            sealbox.password_keys("password", b"0" * 16, 2**31, 8, 1)

    def test_share_key_derivation_binds_public_transcript(self):
        left_priv, left_pub = sealbox.dh_generate_keypair()
        right_priv, right_pub = sealbox.dh_generate_keypair()
        shared = sealbox.dh_shared_secret(left_priv, right_pub)
        enc1, mac1 = sealbox.derive_share_keys(
            shared, left_pub.to_bytes(sealbox.DH_SIZE, "big"), right_pub.to_bytes(sealbox.DH_SIZE, "big")
        )
        altered = bytearray(right_pub.to_bytes(sealbox.DH_SIZE, "big"))
        altered[-1] ^= 1
        enc2, mac2 = sealbox.derive_share_keys(
            shared, left_pub.to_bytes(sealbox.DH_SIZE, "big"), bytes(altered)
        )
        self.assertNotEqual(enc1, enc2)
        self.assertNotEqual(mac1, mac2)


<<<<<<< HEAD
    def test_totp_rejects_negative_timestamp(self):
        with self.assertRaises(ValueError):
            sealbox.totp_code(b"secret", -1)
        with self.assertRaises(ValueError):
            sealbox.totp_remaining(-1, 30)

=======
>>>>>>> origin/main
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

    def test_invalid_nonce_and_tag_lengths_fail_closed(self):
        with self.assertRaises(sealbox.AuthenticationError):
            sealbox.decrypt_then_verify(self.enc, self.mac, b"short", b"", b"x" * 32)
        with self.assertRaises(sealbox.AuthenticationError):
            sealbox.decrypt_then_verify(self.enc, self.mac, b"x" * 16, b"", b"short")


class TestVault(unittest.TestCase):
    PASSWORD = "correct horse battery staple"

    def test_restart_and_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sealbox.vault"
            vault = sealbox.Vault.create(path, self.PASSWORD)
            vault.put("github", b"super-secret")
            vault.put("note", "unicode ✓".encode())
            self.assertEqual(vault.list_names(), ["github", "note"])

            reopened = sealbox.Vault.open(path, self.PASSWORD)
            self.assertEqual(reopened.get("github"), b"super-secret")
            self.assertEqual(reopened.get("note"), "unicode ✓".encode())

            with self.assertRaises(sealbox.AuthenticationError):
                sealbox.Vault.open(path, "wrong")

            raw = bytearray(path.read_bytes())
            raw[-1] ^= 1
            path.write_bytes(raw)
            with self.assertRaises(sealbox.AuthenticationError):
                sealbox.Vault.open(path, self.PASSWORD)

    def test_verify_method(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "vault"
            sealbox.Vault.create(path, self.PASSWORD)
            vault = sealbox.Vault.open(path, self.PASSWORD)
            vault.verify()

    def test_reserved_and_control_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "vault"
            vault = sealbox.Vault.create(path, "pass")
            for bad in ("bad\nname", "bad\tname", "bad\x1bname"):
                with self.subTest(bad=bad):
                    with self.assertRaises(sealbox.SealboxError):
                        vault.put(bad, b"x")
            with self.assertRaises(sealbox.SealboxError):
                vault.put("__sealbox_verify__", b"x")
            with self.assertRaises(sealbox.NotFoundError):
                vault.remove("__sealbox_integrity__")

    def test_duplicate_internal_record_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "vault"
            vault = sealbox.Vault.create(path, self.PASSWORD)
            verifier = next(r for r in vault.records if r.name == "__sealbox_verify__")
            integrity = next(r for r in vault.records if r.name == "__sealbox_integrity__")
            raw = bytearray(vault._header_bytes())
            raw.extend(sealbox._encode_record(verifier))
            raw.extend(sealbox._encode_record(verifier))
            raw.extend(sealbox._encode_record(integrity))
            path.write_bytes(raw)
            with self.assertRaises(sealbox.AuthenticationError):
                sealbox.Vault.open(path, self.PASSWORD)

    def test_missing_internal_record_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "vault"
            vault = sealbox.Vault.create(path, self.PASSWORD)
            for missing in ("__sealbox_verify__", "__sealbox_integrity__"):
                with self.subTest(missing=missing):
                    records = [r for r in vault.records if r.name != missing]
                    raw = bytearray(vault._header_bytes())
                    for record in records:
                        raw.extend(sealbox._encode_record(record))
                    path.write_bytes(raw)
                    with self.assertRaises(sealbox.AuthenticationError):
                        sealbox.Vault.open(path, self.PASSWORD)

    def test_duplicate_user_record_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "vault"
            vault = sealbox.Vault.create(path, self.PASSWORD)
            vault.put("a", b"1")
            records = list(vault.records)
            user = next(r for r in records if r.name == "a")
            raw = bytearray(vault._header_bytes())
            for record in records:
                raw.extend(sealbox._encode_record(record))
            raw.extend(sealbox._encode_record(user))
            path.write_bytes(raw)
            with self.assertRaises(sealbox.AuthenticationError):
                sealbox.Vault.open(path, self.PASSWORD)

    def test_atomic_rewrite_survives_normal_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "vault"
            v = sealbox.Vault.create(path, self.PASSWORD)
            v.put("a", b"1")
            v.put("b", b"2")
            v.remove("a")
            self.assertEqual(v.list_names(), ["b"])
            self.assertEqual(sealbox.Vault.open(path, self.PASSWORD).get("b"), b"2")

    def test_vault_file_permissions_are_owner_only_on_posix(self):
        if os.name == "nt":
            self.skipTest("POSIX mode bits are not portable to Windows")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "vault"
            sealbox.Vault.create(path, self.PASSWORD)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_symlink_vault_is_rejected(self):
        if os.name == "nt":
            self.skipTest("symlink behavior varies with Windows privileges")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real = root / "real.vault"
            sealbox.Vault.create(real, self.PASSWORD)
            link = root / "link.vault"
            link.symlink_to(real)
            with self.assertRaises(sealbox.SealboxError):
                sealbox.Vault.open(link, self.PASSWORD)


class TestShare(unittest.TestCase):
<<<<<<< HEAD
    def test_share_file_reader_enforces_bound(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "payload.bin"
            path.write_bytes(b"x" * 32)
            self.assertEqual(sealbox._read_bounded_file(path, 32), b"x" * 32)
            with self.assertRaises(sealbox.SealboxError):
                sealbox._read_bounded_file(path, 31)

=======
>>>>>>> origin/main
    def test_frame_tamper(self):
        enc = hashlib.sha256(b"e").digest()
        mac = hashlib.sha256(b"m").digest()
        frame = sealbox.share_encrypt_frame(enc, mac, sealbox._build_share_envelope("message", None, b"hello"))
        tampered = bytearray(frame)
        tampered[-1] ^= 1
        with self.assertRaises(sealbox.AuthenticationError):
            sealbox.share_decrypt_frame(enc, mac, bytes(tampered))

    def test_dh_fingerprint_matches(self):
        left, right = socket.socketpair()
        results = {}

        def run_side(key):
            results[key] = sealbox._dh_handshake(left if key == "a" else right)

        ta = threading.Thread(target=run_side, args=("a",))
        tb = threading.Thread(target=run_side, args=("b",))
        ta.start()
        tb.start()
        ta.join(5)
        tb.join(5)
        left.close()
        right.close()
        self.assertFalse(ta.is_alive() or tb.is_alive())
        self.assertEqual(results["a"][2], results["b"][2])
        self.assertEqual(len(results["a"][2]), sealbox.FINGERPRINT_SIZE * 2)

    def test_fingerprint_normalization_and_mismatch(self):
        fingerprint = "c0799f5607ca27ccb1f4e539414389ab"
        self.assertEqual(sealbox._normalize_fingerprint("c079 9f56 07CA 27cc b1f4 e539 4143 89ab"), fingerprint)

    def test_fingerprint_confirmation_accepts_peer_value(self):
        import unittest.mock as mock

        fingerprint = "c0799f5607ca27ccb1f4e539414389ab"
        with mock.patch("builtins.input", return_value="c079 9f56 07ca 27cc b1f4 e539 4143 89ab"):
            sealbox._confirm_fingerprint(fingerprint)
        sealbox._verify_fingerprint(fingerprint, "C079-9F56-07CA-27CC-B1F4-E539-4143-89AB")
        with self.assertRaises(sealbox.AuthenticationError):
            sealbox._verify_fingerprint(fingerprint, "0000 0000 0000 0000 0000 0000 0000 0000")
        with self.assertRaises(sealbox.SealboxError):
            sealbox._normalize_fingerprint("short")
        with self.assertRaises(sealbox.SealboxError):
            sealbox._normalize_fingerprint("c0799f5607ca27ccb1f4e539414389ab!")

    def test_local_share_process(self):
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
<<<<<<< HEAD
    def test_scanner_fixture_is_shipped(self):
        fixture = Path(__file__).resolve().parents[1] / "testdata" / "fake_secrets.txt"
        self.assertTrue(fixture.is_file())
        findings = sealbox.scan_path(fixture)
        self.assertEqual({finding.rule for finding in findings}, {
            "aws-access-key", "secret-assignment", "private-key-header"
        })

=======
>>>>>>> origin/main
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

    def test_public_dh_constant_is_not_reported_as_secret(self):
        findings = sealbox.scan_path(Path(sealbox.__file__))
        self.assertNotIn("high-entropy-hex", {item.rule for item in findings})

    def test_ignore_patterns_skip_directories_and_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "skip").mkdir()
            (root / "skip" / "x.txt").write_text("token = \"hidden-secret-value\"\n", encoding="utf-8")
            (root / "keep.txt").write_text("token = \"visible-secret-value\"\n", encoding="utf-8")
            findings = sealbox.scan_path(root, excludes=["skip", "keep.txt"])
            self.assertEqual(findings, [])

    def test_repository_scanner_respects_sealboxignore(self):
        root = Path(sealbox.__file__).resolve().parent
        findings = sealbox.scan_path(root)
        self.assertEqual(findings, [])


class TestCLI(unittest.TestCase):
    def test_parser_exposes_verification_and_fingerprint_controls(self):
        parser = sealbox.build_parser()
        args = parser.parse_args(["verify", "--vault", "vault.bin"])
        self.assertEqual(args.command, "verify")
        args = parser.parse_args([
            "share", "connect", "127.0.0.1", "47821", "hello",
            "--show-fingerprint",
            "--expect-fingerprint", "c079 9f56 07ca 27cc b1f4 e539 4143 89ab",
        ])
        self.assertTrue(args.show_fingerprint)
        self.assertEqual(args.expect_fingerprint.replace(" ", ""), "c0799f5607ca27ccb1f4e539414389ab")

    def test_verify_command_with_vault(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "vault"
            sealbox.Vault.create(path, "pass")
            with patch.object(sealbox, "password_prompt", return_value="pass"):
                self.assertEqual(
                    sealbox.main(["verify", "--vault", str(path)]),
                    sealbox.EXIT_OK,
                )



if __name__ == "__main__":
    unittest.main(verbosity=2)

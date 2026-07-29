import unittest

from tests._bootstrap import ensure_runtime_path

ensure_runtime_path()

from parallax_omega.memory import MemoryProtocolError, MemorySteward
from parallax_omega.sensitivity import (
    detect_credentials,
    is_prohibited_label,
    normalize_label,
)

BENIGN = "user prefers concise status reports"

# These fixtures must match the credential shapes the detector looks for, which means a
# literal in this file would be flagged by scripts/secret_scan.py -- correctly, since that
# scanner cannot tell a fixture from a leak. Assembling them at import time keeps the
# scanner strict instead of carving out an exemption for tests/, and the detector still
# sees a fully-formed value.
FAKE_OPENAI_KEY = "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz0123"
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_PRIVATE_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----"
FAKE_JWT = ".".join(
    ["eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0", "dBjftJeZ4CVPmB92K27uhbUJU1p1r"]
)


class LabelNormalizationTests(unittest.TestCase):
    """Audit finding A-10, layer 1: the prohibited-label check was a bare str.lower()
    membership test, so padded, case-varied, zero-width and homoglyph spellings passed."""

    def test_plain_label_is_prohibited(self):
        self.assertTrue(is_prohibited_label("secret"))

    def test_padding_and_case_do_not_bypass(self):
        for value in (" secret", "secret ", "SECRET ", "  SeCrEt  ", "\tsecret\n"):
            with self.subTest(value=value):
                self.assertTrue(is_prohibited_label(value))

    def test_zero_width_and_compatibility_space_do_not_bypass(self):
        # U+200B is category Cf and survives both NFKC and str.strip; U+00A0 is folded
        # to a plain space by NFKC and then stripped.
        for value in ("secret​", "​secret", " secret ", "secret﻿"):
            with self.subTest(value=repr(value)):
                self.assertTrue(is_prohibited_label(value))

    def test_normalization_is_idempotent(self):
        once = normalize_label(" SeCrEt​ ")
        self.assertEqual(once, "secret")
        self.assertEqual(normalize_label(once), once)

    def test_benign_labels_are_not_prohibited(self):
        for value in ("normal", "internal", "routine"):
            with self.subTest(value=value):
                self.assertFalse(is_prohibited_label(value))


class CredentialDetectionTests(unittest.TestCase):
    """Audit finding A-10, layer 2: the label is caller-declared, so a model under
    injection simply declares 'normal'. Content must be inspected regardless."""

    def test_credential_shapes_are_detected(self):
        cases = {
            "openai_key": f"my key is {FAKE_OPENAI_KEY}",
            "aws_key": f"{FAKE_AWS_KEY} is the id",
            "private_key": FAKE_PRIVATE_KEY,
            "jwt": FAKE_JWT,
        }
        for expected, content in cases.items():
            with self.subTest(shape=expected):
                self.assertIn(expected, detect_credentials(content))

    def test_benign_content_is_clean(self):
        self.assertEqual(detect_credentials(BENIGN), ())


class StewardEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.steward = MemorySteward()

    def propose(self, *, content=BENIGN, sensitivity="normal"):
        return self.steward.propose(
            content=content,
            purpose="formatting preference",
            sensitivity=sensitivity,
            retention_days=30,
            target="journal",
            deletion_path="settings/delete",
        )

    def test_benign_candidate_is_still_accepted(self):
        candidate = self.propose()
        self.assertEqual(candidate.sensitivity, "normal")

    def test_every_audit_label_bypass_is_refused(self):
        for value in (" secret", "SECRET ", "secret​", " secret "):
            with self.subTest(value=repr(value)):
                with self.assertRaises(MemoryProtocolError) as ctx:
                    self.propose(sensitivity=value)
                self.assertEqual(str(ctx.exception), "sensitive_memory_prohibited")

    def test_homoglyph_label_is_refused_as_non_ascii(self):
        # NFKC does not fold Cyrillic U+0455 to Latin 's', so it is refused outright
        # rather than compared and silently accepted.
        with self.assertRaises(MemoryProtocolError) as ctx:
            self.propose(sensitivity="ѕecret")
        self.assertEqual(str(ctx.exception), "sensitivity_label_not_ascii")

    def test_empty_label_is_refused(self):
        with self.assertRaises(MemoryProtocolError) as ctx:
            self.propose(sensitivity="  ​ ")
        self.assertEqual(str(ctx.exception), "sensitivity_label_required")

    def test_credential_content_refused_under_benign_label(self):
        with self.assertRaises(MemoryProtocolError) as ctx:
            self.propose(content=f"token {FAKE_OPENAI_KEY}", sensitivity="normal")
        self.assertEqual(str(ctx.exception), "credential_content_prohibited")

    def test_steward_label_set_has_one_definition(self):
        from parallax_omega.sensitivity import PROHIBITED_SENSITIVITY

        self.assertIs(MemorySteward.PROHIBITED_SENSITIVITY, PROHIBITED_SENSITIVITY)


if __name__ == "__main__":
    unittest.main()

"""Sensitivity classification for memory candidates.

Audit finding A-10 recorded two separate weaknesses in the original check:

1. the prohibited-label comparison was a bare ``str.lower()`` membership test, so
   ``" secret"``, ``"SECRET "``, ``"secret​"`` and the Cyrillic-homoglyph
   ``"ѕecret"`` all passed; and
2. the label is supplied by the caller, so a model under injection simply declares
   ``"normal"`` and no label check of any kind can see the payload.

Normalization alone therefore only closes the first weakness. The second needs the
content itself to be inspected, which is what :func:`detect_credentials` does, using the
same credential shapes the repository already scans release artifacts for.

Content detection here is limited to credential shapes, which are precise and carry a low
false-positive rate. It is deliberately *not* a general personal-data classifier; that
remains a deployment responsibility and is recorded as such rather than implied.
"""
from __future__ import annotations

import re
import unicodedata

PROHIBITED_SENSITIVITY = frozenset(
    {
        "secret",
        "credential",
        "medical",
        "intimate",
        "payment",
        "biometric",
        "private-third-party",
    }
)

# Same shapes as scripts/secret_scan.py, which screens release artifacts. Keeping the two
# in agreement means a value refused at the memory boundary is also refused at packaging.
CREDENTIAL_PATTERNS: dict[str, re.Pattern[str]] = {
    "openai_key": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "private_key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
}

_STRIPPED_CATEGORIES = {"Cc", "Cf"}


def normalize_label(value: str) -> str:
    """Fold a caller-supplied sensitivity label to a canonical comparable form.

    NFKC collapses compatibility forms such as NBSP into plain ASCII space. Format and
    control characters survive both NFKC and ``str.strip`` (U+200B is category ``Cf``),
    so they are removed explicitly before stripping and case folding.
    """
    normalized = unicodedata.normalize("NFKC", value)
    without_invisibles = "".join(
        ch for ch in normalized if unicodedata.category(ch) not in _STRIPPED_CATEGORIES
    )
    return without_invisibles.strip().casefold()


def is_prohibited_label(value: str) -> bool:
    return normalize_label(value) in PROHIBITED_SENSITIVITY


def detect_credentials(content: str) -> tuple[str, ...]:
    """Return the names of credential shapes present in ``content``.

    The declared label is never consulted: this runs regardless of what the caller claims
    the sensitivity to be, which is the point of the check.
    """
    return tuple(sorted(name for name, pattern in CREDENTIAL_PATTERNS.items() if pattern.search(content)))

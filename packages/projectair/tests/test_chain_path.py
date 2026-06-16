"""Path-traversal containment for the ceremony server's ``chain`` field.

Guards CodeQL ``py/path-injection`` alert #18: the untrusted ``chain`` value on
``POST /authorize/verify`` must never steer the evidence chain outside its root.

The helper under test is import-light by design, so these tests exercise the
containment logic directly without pulling in the optional WebAuthn/FastAPI deps
the ceremony server (``server.app``) needs.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# server/ is not on the default pytest pythonpath (["src"]); add the package dir
# (parent of server/) so the import-light helper is importable on its own.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.chain_path import CHAIN_LOG_ROOT, safe_chain_path

ROOT = CHAIN_LOG_ROOT.resolve()

# Inputs an attacker would use to escape the chain root. Each must EITHER be
# confined to a bare filename under ROOT or rejected — never resolve outside.
MALICIOUS = [
    "../../etc/passwd",
    "../../../../../../etc/passwd",
    "/etc/passwd",
    "/etc/cron.d/payload",
    "..",
    ".",
    "",
    "/",
    "foo/../../bar",
    "subdir/evil.jsonl",
    "a b.jsonl",          # space — outside the allowlist
    "name;rm -rf.jsonl",  # shell metacharacters
    "evil\n.jsonl",       # control character
    "..%2f..%2fpasswd",   # literal, un-decoded percent-encoding
]


@pytest.mark.parametrize("name", ["chain.jsonl", "delegation-A01.jsonl", "x.log"])
def test_valid_names_resolve_under_root(name: str) -> None:
    result = safe_chain_path(name)
    assert result.is_relative_to(ROOT)
    assert result.name == name
    assert result == (ROOT / name)


@pytest.mark.parametrize("evil", MALICIOUS)
def test_malicious_names_never_escape_root(evil: str) -> None:
    """The security invariant: confined under ROOT, or a hard rejection."""
    try:
        result = safe_chain_path(evil)
    except ValueError:
        return  # rejected outright — safe
    # If not rejected, it MUST be contained under the root.
    assert result.is_relative_to(ROOT), f"{evil!r} escaped to {result}"


def test_traversal_does_not_reach_real_target() -> None:
    """`../` and absolute inputs collapse to a basename inside ROOT, not /etc."""
    assert safe_chain_path("../../etc/passwd") == ROOT / "passwd"
    assert safe_chain_path("/etc/passwd") == ROOT / "passwd"


def test_empty_and_dot_names_rejected() -> None:
    for bad in ("", ".", "..", "/"):
        with pytest.raises(ValueError, match="invalid chain name"):
            safe_chain_path(bad)


def test_custom_root_is_honored(tmp_path: Path) -> None:
    result = safe_chain_path("chain.jsonl", root=tmp_path)
    assert result == (tmp_path.resolve() / "chain.jsonl")
    with pytest.raises(ValueError, match="invalid chain name"):
        safe_chain_path("bad name", root=tmp_path)

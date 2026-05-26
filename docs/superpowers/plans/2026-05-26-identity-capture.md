# Identity Capture (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build consent-based identity capture surfaces (air login, first-run email prompt, opt-in update checker, air config) so Vindicara knows who installs and uses Project AIR on launch day.

**Architecture:** CLI surfaces in the OSS `projectair` package reuse existing Auth0 device flow code. Config stored at `~/.config/projectair/` (same directory as anchoring keys). Backend routes added to existing Vindicara FastAPI app with DynamoDB storage. All surfaces are opt-in; the CLI works fully offline if the user skips everything.

**Tech Stack:** Python 3.12+, Typer CLI, Auth0 device flow (existing), httpx, tomllib (stdlib), FastAPI, DynamoDB, CDK

**Spec:** `docs/superpowers/specs/2026-05-25-identity-capture-design.md`

---

### Task 1: Config module (read/write ~/.config/projectair/config.toml)

**Files:**
- Create: `packages/projectair/src/projectair/config.py`
- Create: `packages/projectair/tests/test_config.py`

- [ ] **Step 1: Write failing tests**

Create `packages/projectair/tests/test_config.py`:

```python
"""Tests for CLI config module."""
from __future__ import annotations

from pathlib import Path

import pytest


def test_config_dir_returns_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.config import config_dir
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    d = config_dir()
    assert d == tmp_path / "projectair"


def test_get_returns_none_for_missing_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.config import get_config
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert get_config("telemetry", "update_check") is None


def test_set_and_get_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.config import get_config, set_config
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    set_config("telemetry", "update_check", "true")
    assert get_config("telemetry", "update_check") == "true"


def test_set_creates_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.config import config_dir, set_config
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    set_config("identity", "email", "test@example.com")
    assert (config_dir() / "config.toml").exists()


def test_list_config_returns_all(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.config import list_config, set_config
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    set_config("identity", "email", "test@example.com")
    set_config("telemetry", "update_check", "true")
    result = list_config()
    assert "identity" in result
    assert "telemetry" in result


def test_session_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.config import session_path
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert session_path().name == "session.json"


def test_prompted_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.config import config_dir, has_been_prompted, mark_prompted
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert not has_been_prompted()
    mark_prompted()
    assert has_been_prompted()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest packages/projectair/tests/test_config.py -v`
Expected: FAIL (module not found)

- [ ] **Step 3: Implement config module**

Create `packages/projectair/src/projectair/config.py`:

```python
"""CLI config: ~/.config/projectair/ session, preferences, markers."""
from __future__ import annotations

import json
import os
import sys
import tomllib
from pathlib import Path
from typing import Any


def config_dir() -> Path:
    """Platform-appropriate config directory for Project AIR."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "projectair"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "projectair"
    return Path.home() / ".config" / "projectair"


def _config_path() -> Path:
    return config_dir() / "config.toml"


def session_path() -> Path:
    return config_dir() / "session.json"


def _prompted_path() -> Path:
    return config_dir() / "prompted"


def _ensure_dir() -> None:
    config_dir().mkdir(parents=True, exist_ok=True)


def get_config(section: str, key: str) -> str | None:
    path = _config_path()
    if not path.exists():
        return None
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return data.get(section, {}).get(key)


def set_config(section: str, key: str, value: str) -> None:
    _ensure_dir()
    path = _config_path()
    data: dict[str, dict[str, str]] = {}
    if path.exists():
        with open(path, "rb") as f:
            data = tomllib.load(f)
    if section not in data:
        data[section] = {}
    data[section][key] = value
    lines: list[str] = []
    for sec, kvs in data.items():
        lines.append(f"[{sec}]")
        for k, v in kvs.items():
            lines.append(f'{k} = "{v}"')
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def list_config() -> dict[str, dict[str, str]]:
    path = _config_path()
    if not path.exists():
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def has_been_prompted() -> bool:
    return _prompted_path().exists()


def mark_prompted() -> None:
    _ensure_dir()
    _prompted_path().touch()


def load_session() -> dict[str, Any] | None:
    path = session_path()
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_session(data: dict[str, Any]) -> None:
    _ensure_dir()
    path = session_path()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.chmod(path, 0o600)


def delete_session() -> bool:
    path = session_path()
    if path.exists():
        path.unlink()
        return True
    return False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest packages/projectair/tests/test_config.py -v`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add packages/projectair/src/projectair/config.py packages/projectair/tests/test_config.py
git commit -m "feat: add CLI config module for ~/.config/projectair/"
```

---

### Task 2: air login / logout / whoami commands

**Files:**
- Modify: `packages/projectair/src/projectair/cli.py`
- Create: `packages/projectair/tests/test_login.py`

- [ ] **Step 1: Write failing tests**

Create `packages/projectair/tests/test_login.py`:

```python
"""Tests for air login / logout / whoami CLI commands."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from projectair.cli import app

runner = CliRunner()


def test_whoami_not_logged_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    result = runner.invoke(app, ["whoami"])
    assert "Not logged in" in result.stdout


def test_whoami_shows_email(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    session_dir = tmp_path / "projectair"
    session_dir.mkdir(parents=True)
    (session_dir / "session.json").write_text(json.dumps({
        "email": "kevin@example.com",
        "sub": "auth0|123",
        "expires_at": "2099-01-01T00:00:00Z",
        "logged_in_at": "2026-05-26T12:00:00Z",
    }))
    result = runner.invoke(app, ["whoami"])
    assert "kevin@example.com" in result.stdout


def test_whoami_expired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    session_dir = tmp_path / "projectair"
    session_dir.mkdir(parents=True)
    (session_dir / "session.json").write_text(json.dumps({
        "email": "kevin@example.com",
        "sub": "auth0|123",
        "expires_at": "2020-01-01T00:00:00Z",
        "logged_in_at": "2020-01-01T00:00:00Z",
    }))
    result = runner.invoke(app, ["whoami"])
    assert "expired" in result.stdout.lower()


def test_logout_deletes_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    session_dir = tmp_path / "projectair"
    session_dir.mkdir(parents=True)
    (session_dir / "session.json").write_text('{"email": "test@example.com"}')
    result = runner.invoke(app, ["logout"])
    assert "Logged out" in result.stdout
    assert not (session_dir / "session.json").exists()


def test_logout_when_not_logged_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    result = runner.invoke(app, ["logout"])
    assert "Not logged in" in result.stdout
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest packages/projectair/tests/test_login.py -v`
Expected: FAIL (commands not found)

- [ ] **Step 3: Add login/logout/whoami to cli.py**

In `packages/projectair/src/projectair/cli.py`, add the `auth_login`, `logout`, and `whoami` commands. The existing `login` command handles Pro license installation; rename it to avoid collision:

Find the existing `login` command (around line 741) and rename to `install_license`:

```python
@app.command(name="install-license")
def install_license(
    license_token: str = typer.Option(...),
    ...
```

Then add the new identity commands:

```python
_AUTH0_CLI_CLIENT_ID = "YOUR_CLIENT_ID_HERE"  # Set after creating Auth0 app
_AUTH0_DOMAIN = "dev-kilt2vkudvbu75ny.us.auth0.com"
_AUTH0_AUDIENCE = "https://api.vindicara.io"


@app.command()
def login() -> None:
    """Authenticate with Vindicara via Auth0."""
    from airsdk.containment.auth0_flows import (
        Auth0Tenant,
        start_device_flow,
        poll_device_token,
    )
    from projectair.config import save_session

    tenant = Auth0Tenant(
        domain=_AUTH0_DOMAIN,
        audience=_AUTH0_AUDIENCE,
        client_id=_AUTH0_CLI_CLIENT_ID,
        scope="openid email profile offline_access",
    )
    typer.echo("\n  Authenticating with Vindicara...\n")
    try:
        device = start_device_flow(tenant)
    except Exception as exc:
        typer.secho(f"  Failed to start device flow: {exc}", fg=typer.colors.RED)
        raise typer.Exit(1) from exc

    typer.echo(f"  On any device, open:")
    typer.echo(f"    {device.verification_uri}\n")
    typer.echo(f"  And enter user code:")
    typer.echo(f"    {device.user_code}\n")
    typer.echo("  Waiting for authentication...")

    try:
        token = poll_device_token(tenant, device.device_code, interval=device.interval)
    except Exception as exc:
        typer.secho(f"\n  Authentication failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(1) from exc

    import jwt
    claims = jwt.decode(token, options={"verify_signature": False})
    email = claims.get("email", claims.get("sub", "unknown"))
    from datetime import datetime, timezone
    save_session({
        "access_token": token,
        "email": email,
        "sub": claims.get("sub", ""),
        "expires_at": datetime.fromtimestamp(claims.get("exp", 0), tz=timezone.utc).isoformat(),
        "logged_in_at": datetime.now(tz=timezone.utc).isoformat(),
    })
    typer.secho(f"\n  Logged in as {email}", fg=typer.colors.GREEN)
    typer.echo(f"  Session saved to {config.session_path()}")


@app.command()
def logout() -> None:
    """Remove saved Vindicara session."""
    from projectair.config import delete_session
    if delete_session():
        typer.echo("  Logged out.")
    else:
        typer.echo("  Not logged in.")


@app.command()
def whoami() -> None:
    """Show current login status."""
    from projectair.config import load_session
    session = load_session()
    if session is None:
        typer.echo("  Not logged in. Run `air login`.")
        return
    from datetime import datetime, timezone
    expires = session.get("expires_at", "")
    try:
        exp_dt = datetime.fromisoformat(expires)
        if exp_dt < datetime.now(tz=timezone.utc):
            typer.echo("  Session expired. Run `air login` to re-authenticate.")
            return
    except (ValueError, TypeError):
        pass
    typer.echo(f"  Logged in as {session.get('email', 'unknown')}")
    typer.echo(f"  Since: {session.get('logged_in_at', 'unknown')}")
```

**Note:** The existing `login` command at line 741 handles Pro license installation. Rename it to `install-license` (add `name="install-license"` to the decorator) to free the `login` name for the identity auth flow. Update the `upgrade` command if it references `air login` to say `air install-license` instead.

- [ ] **Step 4: Run tests**

Run: `pytest packages/projectair/tests/test_login.py -v`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add packages/projectair/src/projectair/cli.py packages/projectair/tests/test_login.py
git commit -m "feat(cli): add air login/logout/whoami for Auth0 identity"
```

---

### Task 3: First-run email prompt

**Files:**
- Create: `packages/projectair/src/projectair/first_run.py`
- Create: `packages/projectair/tests/test_first_run.py`
- Modify: `packages/projectair/src/projectair/cli.py` (call first_run in demo/trace)

- [ ] **Step 1: Write failing tests**

Create `packages/projectair/tests/test_first_run.py`:

```python
"""Tests for first-run email prompt."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


def test_prompt_collects_email(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.first_run import maybe_prompt_first_run
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    with patch("builtins.input", side_effect=["test@example.com", "Y"]):
        with patch("projectair.first_run._post_registration") as mock_post:
            maybe_prompt_first_run()
    mock_post.assert_called_once()
    from projectair.config import get_config
    assert get_config("identity", "email") == "test@example.com"


def test_prompt_skip_creates_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.first_run import maybe_prompt_first_run
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    with patch("builtins.input", side_effect=["", "n"]):
        maybe_prompt_first_run()
    from projectair.config import has_been_prompted
    assert has_been_prompted()


def test_prompt_not_shown_twice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.first_run import maybe_prompt_first_run
    from projectair.config import mark_prompted
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    (tmp_path / "projectair").mkdir(parents=True, exist_ok=True)
    mark_prompted()
    maybe_prompt_first_run()
    # Should return immediately without prompting


def test_prompt_skipped_in_non_tty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.first_run import maybe_prompt_first_run
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    with patch("sys.stdin") as mock_stdin:
        mock_stdin.isatty.return_value = False
        maybe_prompt_first_run()
    from projectair.config import has_been_prompted
    assert has_been_prompted()


def test_prompt_skipped_when_logged_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import json
    from projectair.first_run import maybe_prompt_first_run
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    session_dir = tmp_path / "projectair"
    session_dir.mkdir(parents=True)
    (session_dir / "session.json").write_text(json.dumps({"email": "x@y.com"}))
    maybe_prompt_first_run()
    # No prompt shown, session exists


def test_update_check_opt_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.first_run import maybe_prompt_first_run
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    with patch("builtins.input", side_effect=["test@example.com", "Y"]):
        with patch("projectair.first_run._post_registration"):
            maybe_prompt_first_run()
    from projectair.config import get_config
    assert get_config("telemetry", "update_check") == "true"


def test_update_check_opt_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from projectair.first_run import maybe_prompt_first_run
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    with patch("builtins.input", side_effect=["test@example.com", "n"]):
        with patch("projectair.first_run._post_registration"):
            maybe_prompt_first_run()
    from projectair.config import get_config
    assert get_config("telemetry", "update_check") == "false"
```

- [ ] **Step 2: Implement first_run module**

Create `packages/projectair/src/projectair/first_run.py`:

```python
"""First-run email prompt and update check opt-in."""
from __future__ import annotations

import platform
import sys

import httpx

from airsdk import __version__
from projectair.config import (
    get_config,
    has_been_prompted,
    load_session,
    mark_prompted,
    set_config,
)

_REGISTER_URL = "https://api.vindicara.io/api/v1/identity/register"


def maybe_prompt_first_run() -> None:
    if has_been_prompted():
        return
    if load_session() is not None:
        return
    if not sys.stdin.isatty():
        mark_prompted()
        return
    _do_prompt()


def _do_prompt() -> None:
    try:
        print()
        email = input("  Want security advisories and release notes for Project AIR?\n  Email (or press Enter to skip): ").strip()
    except (EOFError, KeyboardInterrupt):
        mark_prompted()
        return

    if email and "@" in email and "." in email.split("@")[-1]:
        set_config("identity", "email", email)
        _post_registration(email)
        print("\n  Thanks! You'll get security advisories only. No spam.")
    elif email:
        print("\n  That doesn't look like a valid email. Skipping.")

    try:
        update_choice = input("\n  Check for AIR updates automatically? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        update_choice = "n"

    if update_choice in ("", "y", "yes"):
        set_config("telemetry", "update_check", "true")
        print("  Update checks enabled. Disable anytime: air config set telemetry.update_check false")
    else:
        set_config("telemetry", "update_check", "false")

    mark_prompted()


def _post_registration(email: str) -> None:
    try:
        httpx.post(
            _REGISTER_URL,
            json={
                "email": email,
                "source": "first_run",
                "version": __version__,
                "platform": platform.system().lower(),
            },
            timeout=5.0,
        )
    except Exception:
        pass
```

- [ ] **Step 3: Wire into demo/trace commands**

In `packages/projectair/src/projectair/cli.py`, add at the top of the `demo()` and `trace()` functions:

```python
from projectair.first_run import maybe_prompt_first_run
maybe_prompt_first_run()
```

- [ ] **Step 4: Run tests**

Run: `pytest packages/projectair/tests/test_first_run.py -v`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add packages/projectair/src/projectair/first_run.py packages/projectair/tests/test_first_run.py packages/projectair/src/projectair/cli.py
git commit -m "feat(cli): add first-run email prompt with update check opt-in"
```

---

### Task 4: Update checker

**Files:**
- Create: `packages/projectair/src/projectair/update_check.py`
- Create: `packages/projectair/tests/test_update_check.py`
- Modify: `packages/projectair/src/projectair/cli.py` (call on startup)

- [ ] **Step 1: Write failing tests**

Create `packages/projectair/tests/test_update_check.py`:

```python
"""Tests for opt-in update checker."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


def test_check_skipped_when_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from projectair.update_check import maybe_check_update
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    maybe_check_update()
    assert "newer version" not in capsys.readouterr().out


def test_check_prints_update_available(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from projectair.config import set_config
    from projectair.update_check import maybe_check_update
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    set_config("telemetry", "update_check", "true")
    mock_resp = type("R", (), {"json": lambda self: {"latest": "99.0.0", "update_available": True}, "status_code": 200})()
    with patch("httpx.get", return_value=mock_resp):
        maybe_check_update()
    assert "99.0.0" in capsys.readouterr().out


def test_check_silent_on_current_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from projectair.config import set_config
    from projectair.update_check import maybe_check_update
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    set_config("telemetry", "update_check", "true")
    mock_resp = type("R", (), {"json": lambda self: {"latest": "1.0.1", "update_available": False}, "status_code": 200})()
    with patch("httpx.get", return_value=mock_resp):
        maybe_check_update()
    assert "newer version" not in capsys.readouterr().out


def test_check_silent_on_network_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    import httpx as _httpx
    from projectair.config import set_config
    from projectair.update_check import maybe_check_update
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    set_config("telemetry", "update_check", "true")
    with patch("httpx.get", side_effect=_httpx.ConnectError("nope")):
        maybe_check_update()
    assert capsys.readouterr().out == ""


def test_check_respects_24h_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import datetime, timezone
    from projectair.config import set_config
    from projectair.update_check import maybe_check_update
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    set_config("telemetry", "update_check", "true")
    set_config("telemetry", "last_check", datetime.now(tz=timezone.utc).isoformat())
    with patch("httpx.get") as mock_get:
        maybe_check_update()
    mock_get.assert_not_called()
```

- [ ] **Step 2: Implement update checker**

Create `packages/projectair/src/projectair/update_check.py`:

```python
"""Opt-in update checker. Runs at most once per 24 hours."""
from __future__ import annotations

import platform
from datetime import datetime, timezone

import blake3
import httpx

from airsdk import __version__
from projectair.config import get_config, set_config

_VERSION_CHECK_URL = "https://api.vindicara.io/api/v1/telemetry/version-check"
_CHECK_INTERVAL_HOURS = 24


def maybe_check_update() -> None:
    if get_config("telemetry", "update_check") != "true":
        return
    last = get_config("telemetry", "last_check")
    if last:
        try:
            last_dt = datetime.fromisoformat(last)
            hours_since = (datetime.now(tz=timezone.utc) - last_dt).total_seconds() / 3600
            if hours_since < _CHECK_INTERVAL_HOURS:
                return
        except (ValueError, TypeError):
            pass
    try:
        session_id = blake3.blake3(platform.node().encode()).hexdigest()[:16]
        resp = httpx.get(
            _VERSION_CHECK_URL,
            params={
                "version": __version__,
                "python": platform.python_version(),
                "platform": platform.system().lower(),
                "session_id": session_id,
            },
            timeout=2.0,
        )
        data = resp.json()
        set_config("telemetry", "last_check", datetime.now(tz=timezone.utc).isoformat())
        if data.get("update_available"):
            print(f"  A newer version of AIR is available ({data['latest']}). Run: pip install --upgrade projectair")
    except Exception:
        pass
```

- [ ] **Step 3: Wire into CLI app callback**

In `packages/projectair/src/projectair/cli.py`, add an app callback that runs the update check before every command:

```python
@app.callback(invoke_without_command=True)
def _app_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is not None:
        from projectair.update_check import maybe_check_update
        maybe_check_update()
```

If a callback already exists, add the `maybe_check_update()` call to it.

- [ ] **Step 4: Run tests**

Run: `pytest packages/projectair/tests/test_update_check.py -v`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add packages/projectair/src/projectair/update_check.py packages/projectair/tests/test_update_check.py packages/projectair/src/projectair/cli.py
git commit -m "feat(cli): add opt-in update checker with 24h cache"
```

---

### Task 5: air config set/get/list commands

**Files:**
- Modify: `packages/projectair/src/projectair/cli.py`

- [ ] **Step 1: Write failing test**

Add to `packages/projectair/tests/test_config.py`:

```python
def test_cli_config_set_and_get(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner
    from projectair.cli import app
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["config", "set", "telemetry.update_check", "false"])
    assert result.exit_code == 0
    result = runner.invoke(app, ["config", "get", "telemetry.update_check"])
    assert "false" in result.stdout


def test_cli_config_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner
    from projectair.cli import app
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(app, ["config", "set", "identity.email", "test@example.com"])
    result = runner.invoke(app, ["config", "list"])
    assert "identity" in result.stdout
    assert "test@example.com" in result.stdout
```

- [ ] **Step 2: Add config subcommands to cli.py**

```python
config_app = typer.Typer(help="Manage AIR CLI configuration.")
app.add_typer(config_app, name="config")


@config_app.command("set")
def config_set(key_value: str = typer.Argument(..., help="section.key format"), value: str = typer.Argument(...)) -> None:
    """Set a config value (e.g., air config set telemetry.update_check false)."""
    from projectair.config import set_config
    parts = key_value.split(".", 1)
    if len(parts) != 2:
        typer.secho("Key must be in section.key format (e.g., telemetry.update_check)", fg=typer.colors.RED)
        raise typer.Exit(1)
    set_config(parts[0], parts[1], value)
    typer.echo(f"  {key_value} = {value}")


@config_app.command("get")
def config_get(key: str = typer.Argument(..., help="section.key format")) -> None:
    """Get a config value."""
    from projectair.config import get_config
    parts = key.split(".", 1)
    if len(parts) != 2:
        typer.secho("Key must be in section.key format", fg=typer.colors.RED)
        raise typer.Exit(1)
    val = get_config(parts[0], parts[1])
    if val is None:
        typer.echo(f"  {key}: (not set)")
    else:
        typer.echo(f"  {key} = {val}")


@config_app.command("list")
def config_list() -> None:
    """Show all config values."""
    from projectair.config import list_config
    data = list_config()
    if not data:
        typer.echo("  No config set.")
        return
    for section, kvs in data.items():
        typer.echo(f"  [{section}]")
        for k, v in kvs.items():
            typer.echo(f"    {k} = {v}")
```

- [ ] **Step 3: Run tests**

Run: `pytest packages/projectair/tests/test_config.py -v`
Expected: all pass

- [ ] **Step 4: Commit**

```bash
git add packages/projectair/src/projectair/cli.py packages/projectair/tests/test_config.py
git commit -m "feat(cli): add air config set/get/list commands"
```

---

### Task 6: Backend API routes (identity + telemetry)

**Files:**
- Create: `src/vindicara/api/routes/identity.py`
- Create: `src/vindicara/api/routes/telemetry.py`
- Modify: `src/vindicara/api/app.py` (register routes)
- Create: `tests/unit/api/test_identity_routes.py`
- Create: `tests/unit/api/test_telemetry_routes.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/api/test_identity_routes.py`:

```python
"""Tests for identity registration endpoint."""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from vindicara.api.app import create_app


@pytest.fixture
def app():
    return create_app(dev_api_keys=["vnd_test"])


@pytest.mark.asyncio
async def test_register_valid_email(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/v1/identity/register", json={
            "email": "test@example.com",
            "source": "first_run",
            "version": "1.0.1",
            "platform": "darwin",
        })
    assert resp.status_code in (200, 201)
    assert resp.json()["status"] in ("registered", "already_registered")


@pytest.mark.asyncio
async def test_register_rejects_empty_email(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/v1/identity/register", json={
            "email": "",
            "source": "first_run",
        })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_rejects_invalid_email(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/v1/identity/register", json={
            "email": "notanemail",
            "source": "first_run",
        })
    assert resp.status_code == 422
```

Create `tests/unit/api/test_telemetry_routes.py`:

```python
"""Tests for telemetry version-check endpoint."""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from vindicara.api.app import create_app


@pytest.fixture
def app():
    return create_app(dev_api_keys=["vnd_test"])


@pytest.mark.asyncio
async def test_version_check_returns_latest(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/v1/telemetry/version-check", params={"version": "1.0.0"})
    assert resp.status_code == 200
    data = resp.json()
    assert "latest" in data
    assert "update_available" in data


@pytest.mark.asyncio
async def test_version_check_handles_missing_optional_params(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/v1/telemetry/version-check", params={"version": "1.0.0"})
    assert resp.status_code == 200
```

- [ ] **Step 2: Implement identity route**

Create `src/vindicara/api/routes/identity.py`:

```python
"""Identity registration endpoint."""
from __future__ import annotations

from pydantic import BaseModel, field_validator
from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/identity", tags=["identity"])

_registered_emails: set[str] = set()


class RegisterRequest(BaseModel):
    email: str
    source: str = "unknown"
    version: str = ""
    platform: str = ""

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        v = v.strip()
        if not v or "@" not in v:
            raise ValueError("email must contain @")
        if "." not in v.split("@")[-1]:
            raise ValueError("email domain must contain .")
        return v


@router.post("/register", status_code=201)
async def register(body: RegisterRequest) -> dict[str, str]:
    if body.email in _registered_emails:
        return {"status": "already_registered"}
    _registered_emails.add(body.email)
    return {"status": "registered"}
```

- [ ] **Step 3: Implement telemetry route**

Create `src/vindicara/api/routes/telemetry.py`:

```python
"""Telemetry version-check endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Query
from packaging.version import Version

router = APIRouter(prefix="/api/v1/telemetry", tags=["telemetry"])

LATEST_VERSION = "1.0.1"


@router.get("/version-check")
async def version_check(
    version: str = Query(...),
    python: str = Query(default=""),
    platform: str = Query(default=""),
    session_id: str = Query(default=""),
) -> dict[str, object]:
    try:
        update_available = Version(version) < Version(LATEST_VERSION)
    except Exception:
        update_available = False
    return {
        "latest": LATEST_VERSION,
        "update_available": update_available,
    }
```

- [ ] **Step 4: Register routes in app.py**

In `src/vindicara/api/app.py`, add imports and include_router calls:

```python
from vindicara.api.routes import identity, telemetry
# ...
app.include_router(identity.router)
app.include_router(telemetry.router)
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/unit/api/test_identity_routes.py tests/unit/api/test_telemetry_routes.py -v`
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add src/vindicara/api/routes/identity.py src/vindicara/api/routes/telemetry.py src/vindicara/api/app.py tests/unit/api/test_identity_routes.py tests/unit/api/test_telemetry_routes.py
git commit -m "feat(api): add identity/register and telemetry/version-check endpoints"
```

---

### Task 7: CDK DynamoDB tables

**Files:**
- Modify: `src/vindicara/infra/stacks/data_stack.py`

- [ ] **Step 1: Add tables to DataStack**

In `src/vindicara/infra/stacks/data_stack.py`, add after the existing tables:

```python
self.identity_registrations_table = dynamodb.Table(
    self,
    "IdentityRegistrationsTable",
    table_name="vindicara-identity-registrations",
    partition_key=dynamodb.Attribute(name="email", type=dynamodb.AttributeType.STRING),
    sort_key=dynamodb.Attribute(name="registered_at", type=dynamodb.AttributeType.STRING),
    billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
    removal_policy=RemovalPolicy.RETAIN,
)

self.telemetry_pings_table = dynamodb.Table(
    self,
    "TelemetryPingsTable",
    table_name="vindicara-telemetry-pings",
    partition_key=dynamodb.Attribute(name="session_id", type=dynamodb.AttributeType.STRING),
    sort_key=dynamodb.Attribute(name="timestamp", type=dynamodb.AttributeType.STRING),
    billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
    removal_policy=RemovalPolicy.DESTROY,
    time_to_live_attribute="ttl",
)
```

- [ ] **Step 2: Commit**

```bash
git add src/vindicara/infra/stacks/data_stack.py
git commit -m "infra: add identity_registrations and telemetry_pings DDB tables"
```

---

### Task 8: Full test suite verification

- [ ] **Step 1: Run OSS test suite**

```bash
pytest packages/projectair/tests/ -x -q
```

Expected: 510+ passed, 0 failures

- [ ] **Step 2: Run engine test suite**

```bash
cd /Users/KMiI/Desktop/vindicara && pytest tests/unit/ tests/integration/api/ tests/integration/dashboard/ -x -q
```

Expected: 340+ passed, 0 failures

- [ ] **Step 3: Run svelte-check**

```bash
cd site && npm run check
```

Expected: 0 errors

- [ ] **Step 4: Final commit if fixes needed**

```bash
git add -A && git commit -m "fix: address test issues from identity capture integration"
```

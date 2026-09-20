"""Storage for API keys and webhook URLs, using the OS credential store.

**The threat model, stated plainly, because "encrypted" is a word people use
loosely and it matters here.**

What this protects against: a secret ending up in the git repo, in a config
file someone pastes into an issue, in a screenshot of the dashboard, in a log
file, or in the SQLite database that this project deliberately treats as
sensitive already. Those are the ways a home-lab API key actually leaks. Not
sophisticated ones -- boring ones.

What this does *not* protect against: malware running as you, on your machine,
right now. Every mechanism below unseals for your user account, which means
code running as your user account can unseal it too. Anyone claiming otherwise
about a desktop credential store is selling something. If the host is owned,
the key is owned; rotate it and move on.

**How each platform stores it**

Windows
    DPAPI (``CryptProtectData``), scoped to the current user. The key material
    is derived from your logon credential and held by the OS -- there is no key
    for PNMA to store, which is the entire point. Reached through ``ctypes``,
    so this needs no third-party package.

macOS
    Keychain, via the ``security`` CLI. Same deal: the OS holds the key.

Linux
    Secret Service via ``secret-tool`` when a keyring daemon is present.

Anywhere else, or when the above is unavailable
    An environment variable, and **this is not encrypted**. The module says so
    out loud rather than letting the word "secrets" imply protection it is not
    providing. It is supported because a key in an env var on a machine you
    control still beats a key committed to GitHub, but it is a fallback and is
    reported as one.

Nothing here ever writes a secret to ``config/pnma.toml``, to the database, or
to a log line. :func:`redact` exists so that stays true even when something
else formats an error message containing one.
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess
import sys

log = logging.getLogger(__name__)

SERVICE = "pnma"

# Secrets PNMA knows about. Declaring them means `pnma secrets status` can
# report what is set without anything having to guess at names, and means a
# typo in a key name fails loudly instead of silently returning None.
KNOWN_SECRETS = {
    "virustotal_api_key": "VirusTotal API key (enrichment)",
    "abuseipdb_api_key": "AbuseIPDB API key (enrichment)",
    "otx_api_key": "AlienVault OTX API key (enrichment)",
    "webhook_url": "Alert webhook URL",
    "ntfy_topic_url": "ntfy topic URL for push-to-phone alerts",
    "hibp_api_key": "Have I Been Pwned API key (identity breach lookups)",
    "dashboard_token": "Bearer token the dashboard requires when bound off loopback",
}

ENV_PREFIX = "PNMA_"

# Populated as secrets are read, so redact() can scrub them from any string
# without the caller needing to know which secrets exist. Values only, never
# written anywhere.
_SEEN_VALUES: set[str] = set()


class SecretsUnavailable(RuntimeError):
    """No credential store is usable on this platform."""


def _env_name(name: str) -> str:
    return f"{ENV_PREFIX}{name.upper()}"


# ----------------------------------------------------------------- Windows --


def _dpapi_available() -> bool:
    return sys.platform == "win32"


def _dpapi(encrypt: bool, data: bytes) -> bytes | None:
    """CryptProtectData / CryptUnprotectData through ctypes.

    Scoped to the current user (no CRYPTPROTECT_LOCAL_MACHINE), so another
    account on the same box cannot unseal it.
    """
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def to_blob(b: bytes) -> DATA_BLOB:
        buf = ctypes.create_string_buffer(b, len(b))
        return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

    def from_blob(blob: DATA_BLOB) -> bytes:
        return ctypes.string_at(blob.pbData, blob.cbData)

    fn = (
        ctypes.windll.crypt32.CryptProtectData
        if encrypt
        else ctypes.windll.crypt32.CryptUnprotectData
    )
    blob_in = to_blob(data)
    blob_out = DATA_BLOB()
    desc = ctypes.c_wchar_p("pnma")

    ok = fn(
        ctypes.byref(blob_in),
        desc if encrypt else None,
        None,
        None,
        None,
        0,
        ctypes.byref(blob_out),
    )
    if not ok:
        return None
    try:
        return from_blob(blob_out)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _win_path() -> "os.PathLike[str]":
    from pathlib import Path

    base = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "pnma"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _win_set(name: str, value: str) -> bool:
    blob = _dpapi(True, value.encode("utf-8"))
    if blob is None:
        return False
    from pathlib import Path

    p = Path(_win_path()) / f"{name}.dpapi"
    p.write_bytes(blob)
    # Not world-readable in any meaningful sense on Windows, but the DPAPI
    # blob is useless to another user account regardless.
    return True


def _win_get(name: str) -> str | None:
    from pathlib import Path

    p = Path(_win_path()) / f"{name}.dpapi"
    if not p.exists():
        return None
    out = _dpapi(False, p.read_bytes())
    return out.decode("utf-8") if out else None


def _win_delete(name: str) -> bool:
    from pathlib import Path

    p = Path(_win_path()) / f"{name}.dpapi"
    if p.exists():
        p.unlink()
        return True
    return False


# ------------------------------------------------------------------ macOS --


def _mac_run(args: list[str], stdin: str | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["security", *args],
            capture_output=True,
            text=True,
            input=stdin,
            timeout=20,
            check=False,
        )
        return proc.returncode, (proc.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""


def _mac_set(name: str, value: str) -> bool:
    # -U updates in place if it already exists, rather than erroring.
    # -w takes the value; passing it as an argument is visible in `ps`, which
    # is exactly the kind of leak this module exists to avoid -- but the
    # `security` CLI offers no stdin form for add-generic-password, so this is
    # the documented trade-off. The window is milliseconds and local-only.
    rc, _ = _mac_run(
        ["add-generic-password", "-U", "-s", SERVICE, "-a", name, "-w", value]
    )
    return rc == 0


def _mac_get(name: str) -> str | None:
    rc, out = _mac_run(["find-generic-password", "-s", SERVICE, "-a", name, "-w"])
    return out if rc == 0 and out else None


def _mac_delete(name: str) -> bool:
    rc, _ = _mac_run(["delete-generic-password", "-s", SERVICE, "-a", name])
    return rc == 0


# ------------------------------------------------------------------ Linux --


def _linux_available() -> bool:
    from shutil import which

    return which("secret-tool") is not None


def _linux_set(name: str, value: str) -> bool:
    try:
        proc = subprocess.run(
            ["secret-tool", "store", "--label", f"pnma {name}", "service", SERVICE, "account", name],
            input=value,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _linux_get(name: str) -> str | None:
    try:
        proc = subprocess.run(
            ["secret-tool", "lookup", "service", SERVICE, "account", name],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        return (proc.stdout or "").strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _linux_delete(name: str) -> bool:
    try:
        proc = subprocess.run(
            ["secret-tool", "clear", "service", SERVICE, "account", name],
            capture_output=True,
            timeout=20,
            check=False,
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


# --------------------------------------------------------------- frontend --


def backend() -> tuple[str, bool]:
    """Return ``(backend_name, is_encrypted)`` for this platform."""
    if _dpapi_available():
        return "Windows DPAPI (per-user)", True
    if sys.platform == "darwin":
        return "macOS Keychain", True
    if _linux_available():
        return "Secret Service (secret-tool)", True
    return "environment variable", False


def get_secret(name: str, *, required: bool = False) -> str | None:
    """Read a secret. Credential store first, environment second.

    The environment fallback is intentional and intentionally second: it makes
    CI and container use possible without ever making it the default path on a
    workstation.
    """
    if name not in KNOWN_SECRETS:
        raise KeyError(f"unknown secret {name!r}; add it to KNOWN_SECRETS first")

    value: str | None = None
    if _dpapi_available():
        value = _win_get(name)
    elif sys.platform == "darwin":
        value = _mac_get(name)
    elif _linux_available():
        value = _linux_get(name)

    if value is None:
        value = os.environ.get(_env_name(name)) or None
        if value:
            log.debug("secret %s read from environment (not encrypted at rest)", name)

    if value:
        _SEEN_VALUES.add(value)
    elif required:
        store, _ = backend()
        raise SecretsUnavailable(
            f"secret {name!r} is not set. Store it with:  pnma secrets set {name}\n"
            f"(this machine would use: {store})"
        )
    return value


def set_secret(name: str, value: str) -> tuple[bool, str]:
    """Write a secret to the OS credential store.

    Returns ``(stored_encrypted, message)``. When no credential store is
    available this refuses to write anything rather than silently dropping a
    plaintext file somewhere -- the caller is told to use an environment
    variable and told that it is not encrypted.
    """
    if name not in KNOWN_SECRETS:
        raise KeyError(f"unknown secret {name!r}; add it to KNOWN_SECRETS first")
    if not value or not value.strip():
        raise ValueError("refusing to store an empty secret")

    value = value.strip()
    _SEEN_VALUES.add(value)

    if _dpapi_available():
        if _win_set(name, value):
            return True, "stored via Windows DPAPI, scoped to your user account"
        return False, "DPAPI call failed"

    if sys.platform == "darwin":
        if _mac_set(name, value):
            return True, "stored in the macOS Keychain"
        return False, "the `security` command failed"

    if _linux_available():
        if _linux_set(name, value):
            return True, "stored via Secret Service"
        return False, "`secret-tool` failed"

    return False, (
        f"No OS credential store found on {platform.system()}. PNMA will not "
        f"write a plaintext secret to disk. Set {_env_name(name)} in your "
        "environment instead -- note that this is NOT encrypted at rest."
    )


def delete_secret(name: str) -> bool:
    if _dpapi_available():
        return _win_delete(name)
    if sys.platform == "darwin":
        return _mac_delete(name)
    if _linux_available():
        return _linux_delete(name)
    return False


def status() -> list[dict]:
    """Which secrets are set, and where from. Never returns values."""
    store, encrypted = backend()
    out = []
    for name, desc in KNOWN_SECRETS.items():
        in_store = False
        if _dpapi_available():
            in_store = _win_get(name) is not None
        elif sys.platform == "darwin":
            in_store = _mac_get(name) is not None
        elif _linux_available():
            in_store = _linux_get(name) is not None

        in_env = _env_name(name) in os.environ

        out.append(
            {
                "name": name,
                "description": desc,
                "set": in_store or in_env,
                "source": "credential store" if in_store else ("environment" if in_env else None),
                "encrypted_at_rest": bool(in_store and encrypted),
                "backend": store,
            }
        )
    return out


def redact(text: str, placeholder: str = "[REDACTED]") -> str:
    """Scrub any secret this process has read out of a string.

    Belt and braces for log lines and error messages. A third-party library
    that echoes a request URL containing an API key does not know it is doing
    something wrong; this is what catches it.
    """
    if not text:
        return text
    for value in _SEEN_VALUES:
        # Short values would cause absurd false-positive replacement.
        if value and len(value) >= 8:
            text = text.replace(value, placeholder)
    return text


class RedactingFilter(logging.Filter):
    """Logging filter that runs :func:`redact` over every record.

    Attach once at the root logger and secrets stop reaching handlers, however
    they got into the message.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = redact(record.msg)
            if record.args:
                record.args = tuple(
                    redact(a) if isinstance(a, str) else a for a in record.args
                )
        except Exception:  # noqa: BLE001 - logging must never raise
            pass
        return True

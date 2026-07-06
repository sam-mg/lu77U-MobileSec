"""Secure credential storage for lu77U-MobileSec."""

import json
import os
import stat
from pathlib import Path
from typing import Optional

import keyring
from keyring.errors import KeyringError

from .paths import get_config_dir
from ..ui.colors import Colors

SERVICE_NAME = "lu77U-MobileSec"

_FALLBACK_WARNED = False  # so the headless warning prints only once per run
_USE_FALLBACK: Optional[bool] = None  # cached backend decision

def _key_name(provider: str) -> str:
    """keyring 'username' under which a provider's API key is stored."""
    return f"{provider}_api_key"

def _fernet_key_path() -> Path:
    return get_config_dir() / ".fernet_key"

def _secrets_path() -> Path:
    return get_config_dir() / ".secrets.enc"

def _warn_fallback_once() -> None:
    global _FALLBACK_WARNED
    if not _FALLBACK_WARNED:
        print(
            f"{Colors.WARNING}[!] No OS keychain is available; API keys will be "
            f"stored in a Fernet-encrypted file under {get_config_dir()} instead. "
            f"This is not hardware-backed — protect that directory.{Colors.RESET}"
        )
        _FALLBACK_WARNED = True

def _load_fernet():
    """Return a Fernet instance, creating the local key file (0600) if needed."""
    from cryptography.fernet import Fernet

    key_path = _fernet_key_path()
    if key_path.exists():
        key = key_path.read_bytes()
    else:
        key = Fernet.generate_key()
        key_path.write_bytes(key)
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return Fernet(key)

def _fallback_read() -> dict:
    path = _secrets_path()
    if not path.exists():
        return {}
    try:
        fernet = _load_fernet()
        return json.loads(fernet.decrypt(path.read_bytes()).decode("utf-8"))
    except Exception:
        return {}

def _fallback_write(data: dict) -> None:
    fernet = _load_fernet()
    token = fernet.encrypt(json.dumps(data).encode("utf-8"))
    path = _secrets_path()
    path.write_bytes(token)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

def _fallback_set(provider: str, value: str) -> None:
    data = _fallback_read()
    data[_key_name(provider)] = value
    _fallback_write(data)

def _fallback_get(provider: str) -> Optional[str]:
    return _fallback_read().get(_key_name(provider))

def _fallback_delete(provider: str) -> None:
    data = _fallback_read()
    data.pop(_key_name(provider), None)
    _fallback_write(data)

def keyring_available() -> bool:
    """True when the OS keychain backend is usable (not the 'fail' backend)."""
    global _USE_FALLBACK
    if _USE_FALLBACK is not None:
        return not _USE_FALLBACK
    try:
        backend = keyring.get_keyring()
        # keyring.backends.fail.Keyring raises on use; treat it as unavailable.
        if backend.__class__.__module__.endswith("fail"):
            _USE_FALLBACK = True
        else:
            _USE_FALLBACK = False
    except Exception:
        _USE_FALLBACK = True
    return not _USE_FALLBACK

def set_api_key(provider: str, value: str) -> None:
    """Persist a provider's API key in the most secure store available."""
    if keyring_available():
        try:
            keyring.set_password(SERVICE_NAME, _key_name(provider), value)
            return
        except KeyringError:
            pass  # fall through to encrypted-file fallback
    _warn_fallback_once()
    _fallback_set(provider, value)

def get_api_key(provider: str) -> Optional[str]:
    """Return a provider's stored API key, or None if not set."""
    if keyring_available():
        try:
            value = keyring.get_password(SERVICE_NAME, _key_name(provider))
            if value is not None:
                return value
        except KeyringError:
            pass
    return _fallback_get(provider)

def delete_api_key(provider: str) -> None:
    """Remove a provider's stored API key from both stores."""
    if keyring_available():
        try:
            keyring.delete_password(SERVICE_NAME, _key_name(provider))
        except Exception:
            pass
    _fallback_delete(provider)

def has_api_key(provider: str) -> bool:
    value = get_api_key(provider)
    return bool(value and value.strip())
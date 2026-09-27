#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.config.credentials

Purpose:
    Store and retrieve AI provider API keys, preferring the operating system keychain and falling back to an encrypted file where no keychain exists.

Responsibilities:
    Detect keychain availability, read and write keys through it, maintain the encrypted fallback store, support multiple keys per provider, and mask keys for display.

Dependencies:
    keyring for the OS keychain, cryptography (Fernet) for the fallback, .paths for the config directory, ..ui.colors for the warning.

Implementation notes:
    Multiple keys per provider are supported so that a user can rotate across keys when one hits a rate limit. The storage format is a JSON list under a single keychain entry; a plain string is still accepted on read, so entries written by earlier versions keep working.

Security considerations:
    The OS keychain is the intended store. The Fernet fallback exists for headless Linux and containers where no keychain daemon is running, and it is genuinely weaker: the encryption key sits in the same directory as the ciphertext, so anyone who can read one can read the other. It protects against casual disclosure -- a backup, a shared screen, a misdirected file copy -- not against a local attacker. The user is warned once, explicitly, when this path is taken. Key files are chmodded to owner-only. Keys are never logged, and mask_key exists so that no display path has a reason to print one in full.
"""

import json
import os
import stat
from pathlib import Path
from typing import List, Optional

import keyring
from keyring.errors import KeyringError

from .paths import APP_NAME, get_config_dir
from ..ui.colors import Colors

SERVICE_NAME = APP_NAME

_FALLBACK_WARNED = False
_USE_FALLBACK: Optional[bool] = None

def _key_name(provider: str) -> str:
    """
    Purpose:
        Build the per-provider entry name used in both the keychain and the fallback store.

    Parameters:
        provider: Provider identifier.

    Returns:
        The entry name.

    Implementation notes:
        Shared by both backends so that a user who gains a keychain after using the fallback, or loses one, finds their keys under the same name.
    """
    return f"{provider}_api_key"

def _fernet_key_path() -> Path:
    """
    Purpose:
        Locate the Fernet key file used by the fallback store.

    Returns:
        The key path.

    Side effects:
        Creates the config directory as a consequence of resolving it.

    Security considerations:
        This file is the encryption key for the fallback secrets file and sits in the same directory as it. Read access to this file is equivalent to read access to every stored API key.
    """
    return get_config_dir() / ".fernet_key"

def _secrets_path() -> Path:
    """
    Purpose:
        Locate the encrypted fallback secrets file.

    Returns:
        The ciphertext path.

    Side effects:
        Creates the config directory as a consequence of resolving it.
    """
    return get_config_dir() / ".secrets.enc"

def _warn_fallback_once() -> None:
    """
    Purpose:
        Tell the user, exactly once per process, that their keys are being stored in a file rather than a keychain.

    Side effects:
        Prints a warning and sets a module-global flag.

    Thread-safety:
        The flag is set without a lock, so concurrent first calls can print the warning twice. Harmless, and not worth a lock on a path that runs once.

    Security considerations:
        This warning is the user's only signal that their keys are protected by a file rather than the OS keychain, and that the protecting key sits beside them. It names the directory so the user can restrict it. It must not be silenced.
    """
    global _FALLBACK_WARNED
    if not _FALLBACK_WARNED:
        print(
            f"{Colors.WARNING}[!] No OS keychain is available; API keys will be "
            f"stored in a Fernet-encrypted file under {get_config_dir()} instead. "
            f"This is not hardware-backed - protect that directory.{Colors.RESET}"
        )
        _FALLBACK_WARNED = True

def _load_fernet():
    """
    Purpose:
        Load the fallback encryption key, generating one on first use.

    Returns:
        A Fernet instance.

    Raises:
        ImportError: When cryptography is not installed.
        OSError: When the key file cannot be read or written.

    Side effects:
        Creates and chmods the key file on first call.

    Security considerations:
        The new key is written and then chmodded, so it exists briefly with the process umask applied. On a multi-user host with a permissive umask another local user can read it during that window. Creating the file with restrictive permissions from the start would close this. cryptography is imported lazily so that installations using the OS keychain never load it, and its absence only affects the fallback path.
    """
    from cryptography.fernet import Fernet

    key_path = _fernet_key_path()
    if key_path.exists():
        key = key_path.read_bytes()
    else:
        key = Fernet.generate_key()
        key_path.write_bytes(key)
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    return Fernet(key)

def _fallback_read() -> dict:
    """
    Purpose:
        Read and decrypt the fallback secrets file.

    Returns:
        The stored mapping, or an empty dict when the file is missing, undecryptable, or malformed.

    Implementation notes:
        Every failure returns an empty dict rather than raising. A corrupted or key-mismatched store is indistinguishable here from an empty one, and treating it as empty lets the user re-enter their keys instead of facing an unrecoverable error on every run.

    Known limitations:
        That same behaviour means a store that fails to decrypt is silently ignored, and the next write overwrites it.

    Security considerations:
        The decrypted mapping contains live API keys in memory and must never be logged or serialised anywhere but back into the encrypted file.
    """
    path = _secrets_path()
    if not path.exists():
        return {}
    try:
        fernet = _load_fernet()
        return json.loads(fernet.decrypt(path.read_bytes()).decode("utf-8"))
    except Exception:
        return {}

def _fallback_write(data: dict) -> None:
    """
    Purpose:
        Encrypt and write the fallback secrets file.

    Parameters:
        data: Mapping of entry name to key.

    Raises:
        OSError: When the file cannot be written.

    Side effects:
        Replaces the secrets file and sets owner-only permissions.

    Security considerations:
        The write is not atomic -- the file is replaced in place rather than written to a temporary file and renamed -- so an interruption mid-write can leave a truncated, undecryptable store. Combined with the read path treating that as empty, an ill-timed crash silently loses the stored keys. As with the key file, permissions are applied after creation rather than at creation.
    """
    fernet = _load_fernet()
    token = fernet.encrypt(json.dumps(data).encode("utf-8"))
    path = _secrets_path()
    path.write_bytes(token)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

def _fallback_set(provider: str, value: str) -> None:
    """
    Purpose:
        Store one provider entry in the fallback store.

    Parameters:
        provider: Provider identifier.
        value: Serialised key material.

    Side effects:
        Rewrites the whole secrets file.
    """
    data = _fallback_read()
    data[_key_name(provider)] = value
    _fallback_write(data)

def _fallback_get(provider: str) -> Optional[str]:
    """
    Purpose:
        Read one provider entry from the fallback store.

    Parameters:
        provider: Provider identifier.

    Returns:
        The stored value, or None when absent.
    """
    return _fallback_read().get(_key_name(provider))

def _fallback_delete(provider: str) -> None:
    """
    Purpose:
        Remove one provider entry from the fallback store.

    Parameters:
        provider: Provider identifier.

    Side effects:
        Rewrites the whole secrets file. Deleting an absent entry is a no-op.
    """
    data = _fallback_read()
    data.pop(_key_name(provider), None)
    _fallback_write(data)

def keyring_available() -> bool:
    """
    Purpose:
        Decide, once per process, whether a usable OS keychain backend exists.

    Returns:
        True when the keychain should be used.

    Side effects:
        Caches the verdict in a module-global on first call.

    Implementation notes:
        The probe checks whether the resolved backend class comes from keyring's "fail" module, which is what keyring installs when it finds no working backend. Inspecting the module name is indirect, but keyring's fail backend raises only on use, so the alternative would be attempting a real write during a capability check. The result is cached because this is consulted on every credential operation and backend resolution is not free. The cache also keeps behaviour stable within a run: a keychain that becomes unavailable mid-process does not silently start splitting keys across two stores.

    Thread-safety:
        The cached verdict is written without a lock. Concurrent first calls may both probe, but they compute the same answer.
    """
    global _USE_FALLBACK
    if _USE_FALLBACK is not None:
        return not _USE_FALLBACK
    try:
        backend = keyring.get_keyring()
        if backend.__class__.__module__.endswith("fail"):
            _USE_FALLBACK = True
        else:
            _USE_FALLBACK = False
    except Exception:
        _USE_FALLBACK = True
    return not _USE_FALLBACK

def _set_raw(provider: str, value: str) -> None:
    """
    Purpose:
        Write a provider entry to the keychain, falling back to the encrypted file when that fails.

    Parameters:
        provider: Provider identifier.
        value: Serialised key material.

    Side effects:
        Writes to the keychain or the fallback store, and may print the one-time fallback warning.

    Implementation notes:
        A KeyringError at write time falls through to the file store rather than failing, because a keychain can be present but locked or unwritable -- a locked login keyring over SSH is the common case -- and losing the user's key entry over that would be worse than storing it less strongly, provided they are told.

    Security considerations:
        The fallback is only taken after the warning is emitted, so the downgrade is never silent.
    """
    if keyring_available():
        try:
            keyring.set_password(SERVICE_NAME, _key_name(provider), value)
            return
        except KeyringError:
            pass
    _warn_fallback_once()
    _fallback_set(provider, value)

def _get_raw(provider: str) -> Optional[str]:
    """
    Purpose:
        Read a provider entry, trying the keychain first and the fallback store second.

    Parameters:
        provider: Provider identifier.

    Returns:
        The stored value, or None when neither store has it.

    Implementation notes:
        The fallback is consulted whenever the keychain yields nothing, not only when it errors. That covers the case where keys were written before a keychain became available, so gaining one does not appear to erase the user's keys.
    """
    if keyring_available():
        try:
            value = keyring.get_password(SERVICE_NAME, _key_name(provider))
            if value is not None:
                return value
        except KeyringError:
            pass
    return _fallback_get(provider)


def get_api_keys(provider: str) -> List[str]:
    """
    Purpose:
        Return every stored key for a provider, in rotation order.

    Parameters:
        provider: Provider identifier.

    Returns:
        A list of keys, empty when none are stored. Never None.

    Implementation notes:
        Handles both storage formats. A JSON list is the current format; any value that is not a JSON list of strings is treated as one literal key, which covers entries written before multi-key support and also the case where a key itself happens to be valid JSON. Empty and whitespace-only entries are filtered out so that a stray blank cannot become a key the provider then tries to authenticate with.

    Security considerations:
        Returns live credentials. The result must not be logged; use mask_key for anything user-visible.
    """
    raw = _get_raw(provider)
    if raw is None or not str(raw).strip():
        return []
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return [raw]
    if isinstance(parsed, list) and all(isinstance(k, str) for k in parsed):
        return [k for k in parsed if k and k.strip()]
    return [raw]

def set_api_keys(provider: str, keys: List[str]) -> None:
    """
    Purpose:
        Replace the stored key list for a provider.

    Parameters:
        provider: Provider identifier.
        keys: Keys to store. None and empty are accepted.

    Postconditions:
        Keys are stripped, blanks removed and duplicates dropped while preserving order. An empty result deletes the entry entirely rather than storing an empty list, so "no keys" has one representation.

    Side effects:
        Writes to the keychain or the fallback store.

    Security considerations:
        Deduplication compares full key values in memory only; nothing is logged.
    """
    cleaned: List[str] = []
    for key in keys or []:
        key = (key or "").strip()
        if key and key not in cleaned:
            cleaned.append(key)
    if not cleaned:
        delete_api_key(provider)
        return
    _set_raw(provider, json.dumps(cleaned))

def add_api_key(provider: str, value: str) -> None:
    """
    Purpose:
        Append one key to a provider's rotation list.

    Parameters:
        provider: Provider identifier.
        value: Key to add. Blank values are ignored.

    Side effects:
        Rewrites the provider entry.

    Postconditions:
        A key already present is not duplicated, by virtue of the deduplication in set_api_keys.
    """
    value = (value or "").strip()
    if not value:
        return
    set_api_keys(provider, get_api_keys(provider) + [value])

def remove_api_key(provider: str, index: int) -> None:
    """
    Purpose:
        Remove one key from a provider's rotation list by position.

    Parameters:
        provider: Provider identifier.
        index: Zero-based position, as displayed in the settings UI.

    Side effects:
        Rewrites the provider entry when the index is valid.

    Implementation notes:
        An out-of-range index is ignored rather than raising. The index comes from a UI list that may be stale if another window changed the keys, and silently ignoring a stale index is better than an error dialog -- though it does mean the caller cannot tell a removal from a no-op.

    Security considerations:
        Removal is by position rather than by value, so the UI never has to send a full key back to be deleted.
    """
    keys = get_api_keys(provider)
    if 0 <= index < len(keys):
        del keys[index]
        set_api_keys(provider, keys)

def set_api_key(provider: str, value: str) -> None:
    """
    Purpose:
        Replace a provider's keys with a single key.

    Parameters:
        provider: Provider identifier.
        value: The key to store.

    Side effects:
        Discards any other keys stored for that provider.
    """
    set_api_keys(provider, [value])

def get_api_key(provider: str) -> Optional[str]:
    """
    Purpose:
        Return the primary key for a provider, for callers that do not rotate.

    Parameters:
        provider: Provider identifier.

    Returns:
        The first stored key, or None when none are stored.

    Security considerations:
        Returns a live credential; never log the result.
    """
    keys = get_api_keys(provider)
    return keys[0] if keys else None

def delete_api_key(provider: str) -> None:
    """
    Purpose:
        Remove a provider's keys from both stores.

    Parameters:
        provider: Provider identifier.

    Side effects:
        Deletes from the keychain and from the fallback store.

    Implementation notes:
        Both stores are cleared unconditionally, and keychain errors are swallowed. Deletion must be thorough: leaving a copy in the store that was not checked would mean a key the user believes they revoked is still on disk and still usable.
    """
    if keyring_available():
        try:
            keyring.delete_password(SERVICE_NAME, _key_name(provider))
        except Exception:
            pass
    _fallback_delete(provider)

def has_api_key(provider: str) -> bool:
    """
    Purpose:
        Report whether a provider has any key configured, for readiness checks and UI state.

    Parameters:
        provider: Provider identifier.

    Returns:
        True when at least one key is stored.

    Security considerations:
        Returns only a boolean, so a readiness check never has to handle key material.
    """
    return bool(get_api_keys(provider))

def mask_key(value: str) -> str:
    """
    Purpose:
        Render a key safely for display in the UI and in logs.

    Parameters:
        value: The key. None and blank are accepted.

    Returns:
        First four and last four characters around an ellipsis; for a short value, bullets only, revealing nothing but the length.

    Security considerations:
        This is the only sanctioned way to put key material on screen. Revealing the first and last four characters lets a user tell two keys apart without exposing enough to use one. Keys under twelve characters are hidden entirely, because four plus four of an eleven-character value would expose most of it.
    """
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) < 12:
        return "•" * len(value)
    return f"{value[:4]}…{value[-4:]}"

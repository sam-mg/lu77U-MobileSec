#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.config.credentials

Purpose:
    Store and retrieve AI provider API keys, preferring the operating system keychain and falling back to an encrypted file where no keychain exists.

Responsibilities:
    Detect keychain availability, read and write keys through it, maintain the encrypted fallback store, support multiple keys per provider each with an optional label, and mask keys for display.

Dependencies:
    keyring for the OS keychain, cryptography (Fernet) for the fallback, .paths for the config directory, ..ui.colors for the warning.

Implementation notes:
    Multiple keys per provider are supported so that a user can rotate across keys when one hits a rate limit. The storage format is a JSON list under a single keychain entry; a plain string is still accepted on read, so entries written by earlier versions keep working. A key with a label is stored as {"key": ..., "label": ...} in that list and a key without one as the bare string, so a pool nobody has labelled is stored exactly as before and an older version of the tool still reads it.

Security considerations:
    The OS keychain is the intended store. The Fernet fallback exists for headless Linux and containers where no keychain daemon is running, and it is genuinely weaker: the encryption key sits in the same directory as the ciphertext, so anyone who can read one can read the other. It protects against casual disclosure -- a backup, a shared screen, a misdirected file copy -- not against a local attacker. The user is warned once, explicitly, when this path is taken. Key files are chmodded to owner-only. Keys are never logged, and mask_key exists so that no display path has a reason to print one in full.
"""

import contextlib
import functools
import json
import os
import stat
import unicodedata
from pathlib import Path
from typing import Dict, List, Optional, Union

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

from .paths import APP_NAME, get_config_dir
from ..ui.colors import Colors

SERVICE_NAME = APP_NAME

LABEL_MAX_CHARS = 80

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

@functools.cache
def _warn_fallback_once() -> None:
    """
    Purpose:
        Tell the user, exactly once per process, that their keys are being stored in a file rather than a keychain.

    Side effects:
        Prints a warning on the first call only; functools.cache remembers that call, so every later call returns without printing.

    Thread-safety:
        functools.cache does not lock around the first call, so concurrent first calls can print the warning twice. Harmless, and not worth a lock on a path that runs once.

    Implementation notes:
        The once-per-process guarantee comes from the cache rather than a module-global flag, so there is no mutable global to forget to set. Tests reset it with _warn_fallback_once.cache_clear().

    Security considerations:
        This warning is the user's only signal that their keys are protected by a file rather than the OS keychain, and that the protecting key sits beside them. It names the directory so the user can restrict it. It must not be silenced.
    """
    print(
        f"{Colors.WARNING}[!] No OS keychain is available; API keys will be stored in a Fernet-encrypted file under {get_config_dir()} instead. This is not hardware-backed - protect that directory.{Colors.RESET}"
    )

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
        The fallback is consulted whenever the keychain yields nothing, not only when it errors. That covers the case where keys were written before a keychain became available, so gaining one does not appear to erase the user's keys. A KeyringError on read is suppressed for the same reason: a locked or broken keychain is treated as holding nothing, and the fallback store gets its turn.
    """
    if keyring_available():
        with contextlib.suppress(KeyringError):
            value = keyring.get_password(SERVICE_NAME, _key_name(provider))
            if value is not None:
                return value
    return _fallback_get(provider)


def clean_label(label: Optional[str]) -> str:
    """
    Purpose:
        Normalise a key's label and reject one that cannot be shown safely on one line.

    Parameters:
        label: The label as the user typed it. None and blank mean no label.

    Returns:
        The label with its whitespace collapsed to single spaces; empty when there is none.

    Raises:
        ValueError: When it runs past LABEL_MAX_CHARS or carries a control or invisible formatting character.

    Security considerations:
        A label is free text a user types, such as the account the key belongs to, and it is shown beside the masked key. Invisible formatting characters, bidirectional overrides among them, are refused because they can make a label read as something other than what it holds.
    """
    text = " ".join((label or "").split())
    if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in text):
        raise ValueError("A key label cannot contain control or invisible formatting characters.")
    if len(text) > LABEL_MAX_CHARS:
        raise ValueError(f"A key label is at most {LABEL_MAX_CHARS} characters.")
    return text


def _parse_entries(raw: Optional[str]) -> List[Dict[str, str]]:
    """
    Purpose:
        Read a stored value into its keys and their labels.

    Parameters:
        raw: The stored value, or None.

    Returns:
        One {"key", "label"} entry per key, in rotation order, with blank keys left out.

    Implementation notes:
        A JSON list whose items are strings or {"key", "label"} objects is the current format. Any other value is treated as one literal key, which covers entries written before multi-key support and also a key that itself happens to be valid JSON.
    """
    if raw is None or not str(raw).strip():
        return []
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return [{"key": raw, "label": ""}]
    if not isinstance(parsed, list):
        return [{"key": raw, "label": ""}]
    entries: List[Dict[str, str]] = []
    for item in parsed:
        if isinstance(item, str):
            key, label = item, ""
        elif isinstance(item, dict) and isinstance(item.get("key"), str):
            key = item["key"]
            label = item["label"] if isinstance(item.get("label"), str) else ""
        else:
            return [{"key": raw, "label": ""}]
        if key and key.strip():
            entries.append({"key": key, "label": label})
    return entries


def get_api_key_entries(provider: str) -> List[Dict[str, str]]:
    """
    Purpose:
        Return every stored key for a provider with its label, in rotation order.

    Parameters:
        provider: Provider identifier.

    Returns:
        A list of {"key", "label"} entries; the label is empty for a key without one. Never None.

    Security considerations:
        Returns live credentials. Only the settings surface reads labels, and it masks the keys; scan output never carries a label, since a label is often an email address and a scan's folder can end up shared.
    """
    return _parse_entries(_get_raw(provider))


def get_api_keys(provider: str) -> List[str]:
    """
    Purpose:
        Return every stored key for a provider, in rotation order.

    Parameters:
        provider: Provider identifier.

    Returns:
        A list of keys, empty when none are stored. Never None.

    Implementation notes:
        Labels are dropped here, so providers, which only need the keys, are unaffected by them. Empty and whitespace-only entries are filtered out so that a stray blank cannot become a key the provider then tries to authenticate with.

    Security considerations:
        Returns live credentials. The result must not be logged; use mask_key for anything user-visible.
    """
    return [entry["key"] for entry in get_api_key_entries(provider)]

def set_api_keys(provider: str, keys: List[Union[str, Dict[str, str]]]) -> None:
    """
    Purpose:
        Replace the stored key list for a provider.

    Parameters:
        provider: Provider identifier.
        keys: Keys to store, each a bare key or a {"key", "label"} entry. None and empty are accepted.

    Raises:
        ValueError: When a label is rejected by clean_label.

    Postconditions:
        Keys are stripped, blanks removed and duplicates dropped while preserving order; the first occurrence of a key keeps its label. An empty result deletes the entry entirely rather than storing an empty list, so "no keys" has one representation.

    Side effects:
        Writes to the keychain or the fallback store.

    Security considerations:
        Deduplication compares full key values in memory only; nothing is logged.
    """
    cleaned: List[Dict[str, str]] = []
    seen = set()
    for item in keys or []:
        if isinstance(item, dict):
            key, label = item.get("key") or "", item.get("label") or ""
        else:
            key, label = item or "", ""
        key = key.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        cleaned.append({"key": key, "label": clean_label(label)})
    if not cleaned:
        delete_api_key(provider)
        return
    _set_raw(provider, json.dumps([entry if entry["label"] else entry["key"] for entry in cleaned]))

def add_api_key(provider: str, value: str, label: str = "") -> None:
    """
    Purpose:
        Append one key to a provider's rotation list, optionally with a label.

    Parameters:
        provider: Provider identifier.
        value: Key to add. Blank values are ignored.
        label: What the key is for, such as the account it belongs to. Empty for none.

    Raises:
        ValueError: When the label is rejected by clean_label.

    Side effects:
        Rewrites the provider entry.

    Postconditions:
        A key already present is not duplicated. Adding it again with a label gives the stored key that label, so a key can be labelled by pasting it a second time.
    """
    value = (value or "").strip()
    if not value:
        return
    label = clean_label(label)
    entries = get_api_key_entries(provider)
    positions = {entry["key"].strip(): i for i, entry in enumerate(entries)}
    if value in positions:
        if label:
            entries[positions[value]]["label"] = label
        set_api_keys(provider, entries)
        return
    set_api_keys(provider, entries + [{"key": value, "label": label}])

def set_api_key_label(provider: str, index: int, label: str) -> bool:
    """
    Purpose:
        Give one stored key a label, change it, or clear it, by position.

    Parameters:
        provider: Provider identifier.
        index: Zero-based position, as displayed in the settings UI.
        label: The new label; empty clears it.

    Returns:
        True when the key existed and was relabelled, False for an out-of-range position.

    Raises:
        ValueError: When the label is rejected by clean_label.

    Side effects:
        Rewrites the provider entry when the position is valid.

    Security considerations:
        Addressed by position, like removal, so the settings page never has to send a key back to label it.
    """
    entries = get_api_key_entries(provider)
    if not 0 <= index < len(entries):
        return False
    entries[index]["label"] = clean_label(label)
    set_api_keys(provider, entries)
    return True

def remove_api_key(provider: str, index: int) -> None:
    """
    Purpose:
        Remove one key from a provider's rotation list by position.

    Parameters:
        provider: Provider identifier.
        index: Zero-based position, as displayed in the settings UI.

    Side effects:
        Rewrites the provider entry when the index is valid; every other key keeps its label.

    Implementation notes:
        An out-of-range index is ignored rather than raising. The index comes from a UI list that may be stale if another window changed the keys, and silently ignoring a stale index is better than an error dialog -- though it does mean the caller cannot tell a removal from a no-op.

    Security considerations:
        Removal is by position rather than by value, so the UI never has to send a full key back to be deleted.
    """
    entries = get_api_key_entries(provider)
    if 0 <= index < len(entries):
        del entries[index]
        set_api_keys(provider, entries)

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
        Deletes from the keychain and from the fallback store, and prints a warning when the keychain entry could not be removed.

    Implementation notes:
        Both stores are cleared unconditionally: a keychain failure never stops the fallback store being cleared. Deletion must be thorough: leaving a copy in the store that was not checked would mean a key the user believes they revoked is still on disk and still usable. PasswordDeleteError is the keychain saying there was nothing to delete, which is the normal case for a provider whose key lives only in the fallback store, so it stays silent. Any other failure -- a locked keychain, a denied access prompt, a broken backend -- means the key may still be stored, so the user is warned rather than left believing it is gone.

    Security considerations:
        The warning names the provider but never the key itself.
    """
    if keyring_available():
        try:
            keyring.delete_password(SERVICE_NAME, _key_name(provider))
        except Exception as exc:
            if not isinstance(exc, PasswordDeleteError):
                print(
                    f"{Colors.WARNING}[!] Could not remove the {provider} key from the OS keychain ({type(exc).__name__}); it may still be stored in the fallback store.{Colors.RESET}"
                )
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

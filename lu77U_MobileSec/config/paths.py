#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.config.paths

Purpose:
    Resolve the two filesystem locations the tool owns -- the per-user configuration directory and the base directory scans write into -- so that platform conventions are applied in one place.

Responsibilities:
    Locate and create the config directory, name the settings file, and resolve the output base from user settings with a documented default.

Dependencies:
    platformdirs for the per-platform config location, .._metadata for the application name.

Implementation notes:
    Configuration follows the platform convention via platformdirs, while output defaults to Documents rather than a hidden directory. That split is deliberate: settings are machine state the user should rarely see, whereas reports are documents the user needs to find and share.

Security considerations:
    The config directory holds the encrypted credential fallback. Its permissions come from the platform default rather than being tightened here; the credential module sets restrictive modes on the files themselves.
"""

from pathlib import Path

import platformdirs

from .._metadata import NAME as APP_NAME

def get_config_dir() -> Path:
    """
    Purpose:
        Resolve the per-user configuration directory, creating it if needed.

    Returns:
        The directory as a Path, guaranteed to exist on return.

    Raises:
        OSError: When the directory cannot be created.

    Side effects:
        Creates the directory tree.

    Implementation notes:
        Creation happens here rather than at first write so that every caller -- settings, credentials, the fallback key store -- can assume the directory exists. The cost is that merely asking where config lives creates it.

    Security considerations:
        The directory is created with the process umask. Anything sensitive written inside must set its own mode; see the credential module.
    """
    path = Path(platformdirs.user_config_dir(APP_NAME))
    path.mkdir(parents=True, exist_ok=True)
    return path

def get_settings_path() -> Path:
    """
    Purpose:
        Name the JSON file holding user settings.

    Returns:
        The settings file path. The file itself may not exist yet.

    Side effects:
        Creates the config directory as a consequence of resolving it.
    """
    return get_config_dir() / "settings.json"

def default_output_base() -> Path:
    """
    Purpose:
        State the default location for scan output when the user has not chosen one.

    Returns:
        A path under the user's Documents directory, named after the application. Not created.

    Implementation notes:
        Documents is chosen over a platformdirs data directory because reports are meant to be found, opened and shared. A hidden application data directory would technically be more correct and practically useless.

    Known limitations:
        The Documents path is assembled literally rather than through platformdirs, so it is wrong on a system where the user directory has been relocated or localised.
    """
    return Path.home() / "Documents" / APP_NAME

def get_output_base() -> Path:
    """
    Purpose:
        Resolve the base directory scans write into, honouring the user setting when one is configured.

    Returns:
        The directory as a Path, guaranteed to exist on return.

    Raises:
        OSError: When the directory cannot be created -- typically a configured path that is unwritable or on a disconnected volume.

    Side effects:
        Reads user settings and creates the directory tree.

    Implementation notes:
        user_settings is imported inside the function to break an import cycle: user_settings needs get_settings_path from this module. The configured value is expanded with expanduser so that a setting written as a tilde path behaves as the user expects. An empty or whitespace-only setting falls back to the default, so clearing the field in the UI restores default behaviour rather than resolving to the current working directory.

    Security considerations:
        The configured path is operator-supplied and is used as given. It is not constrained to any root, which is intended -- the operator chooses where their own reports go -- but it means a mistyped value can create a directory anywhere the user can write.
    """
    from . import user_settings
    configured = (user_settings.get_output_dir() or "").strip()
    base = Path(configured).expanduser() if configured else default_output_base()
    base.mkdir(parents=True, exist_ok=True)
    return base

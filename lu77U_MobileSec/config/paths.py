"""Per-user application data paths for lu77U-MobileSec."""

from pathlib import Path

import platformdirs

APP_NAME = "lu77U-MobileSec"

def get_config_dir() -> Path:
    """Return the per-user config directory, creating it if needed."""
    path = Path(platformdirs.user_config_dir(APP_NAME))
    path.mkdir(parents=True, exist_ok=True)
    return path

def get_settings_path() -> Path:
    """Path to the JSON settings file (non-secret fields only)."""
    return get_config_dir() / "settings.json"

def default_output_base() -> Path:
    """The default location for scan output when the user hasn't set one:
    ``~/Documents/lu77U-MobileSec``. Deliberately a visible, user-owned folder
    (not App Support) so a user can find and delete scan artifacts easily."""
    return Path.home() / "Documents" / APP_NAME

def get_output_base() -> Path:
    """Return the base directory scan folders are written under, creating it if
    needed. Uses the user's configured ``output_dir`` (Settings) when set, else
    :func:`default_output_base`. Settings/credentials still live in the config
    dir — only per-scan output moves here."""
    # Imported lazily to avoid a config import cycle (user_settings imports paths).
    from . import user_settings
    configured = (user_settings.get_output_dir() or "").strip()
    base = Path(configured).expanduser() if configured else default_output_base()
    base.mkdir(parents=True, exist_ok=True)
    return base
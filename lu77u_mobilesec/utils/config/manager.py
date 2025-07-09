#!/usr/bin/env python3
"""
Configuration manager for lu77U-MobileSec
"""

import json
from pathlib import Path
from typing import Any, Optional


def get_config_value(key: str, default: Any = None) -> Any:
    """
    Get a configuration value from the MobileSec config file.
    
    Args:
        key: Configuration key to retrieve
        default: Default value if key not found
        
    Returns:
        The configuration value or default
    """
    try:
        config_file = Path.home() / ".mobilesec" / "config.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                config = json.loads(f.read())
                return config.get(key, default)
    except Exception:
        pass
    
    return default


def set_config_value(key: str, value: Any) -> bool:
    """
    Set a configuration value in the MobileSec config file.
    
    Args:
        key: Configuration key to set
        value: Value to set
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        config_dir = Path.home() / ".mobilesec"
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / "config.json"
        
        # Load existing config or create new
        config = {}
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    config = json.loads(f.read())
            except Exception:
                config = {}
        
        # Update value
        config[key] = value
        
        # Save config
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        return True
        
    except Exception:
        return False

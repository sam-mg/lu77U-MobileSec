#!/usr/bin/env python3
"""
API key management for lu77U-MobileSec
"""

import os
import json
from pathlib import Path
from typing import Optional


def load_groq_api_key() -> Optional[str]:
    """
    Load GROQ API key from multiple sources in order of preference:
    1. Environment variable GROQ_API_KEY
    2. MobileSec config file (~/.mobilesec/config.json)
    3. Shell profile files (.zshrc, .bashrc, etc.)
    
    Returns:
        str: The API key if found, None otherwise
    """
    
    # 1. Check environment variable first
    api_key = os.environ.get('GROQ_API_KEY')
    if api_key:
        return api_key
    
    # 2. Check our config file
    try:
        config_file = Path.home() / ".mobilesec" / "config.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                config = json.loads(f.read())
                api_key = config.get('GROQ_API_KEY')
                if api_key:
                    # Set in environment for current session
                    os.environ['GROQ_API_KEY'] = api_key
                    return api_key
    except Exception:
        pass
    
    # 3. Check shell profile as backup
    try:
        api_key = load_api_key_from_profile('GROQ_API_KEY')
        if api_key:
            os.environ['GROQ_API_KEY'] = api_key
            return api_key
    except Exception:
        pass
    
    return None


def ensure_groq_api_key() -> str:
    """
    Ensure GROQ API key is available, prompt user if not found.
    
    Returns:
        str: The API key
        
    Raises:
        ValueError: If no API key is provided or found
    """
    api_key = load_groq_api_key()
    
    if not api_key:
        print("🔑 GROQ API key not found!")
        print("Please run 'lu77u-mobilesec doctor' to configure it,")
        print("or set it manually:")
        print("  export GROQ_API_KEY='your_key_here'")
        
        # Prompt for manual entry as fallback
        api_key = input("\nEnter GROQ API key (or press Enter to abort): ").strip()
        
        if not api_key:
            raise ValueError("GROQ API key is required for AI-powered analysis")
        
        # Save for future use
        save_api_key_to_config('GROQ_API_KEY', api_key)
    
    return api_key


def load_api_key_from_config() -> Optional[str]:
    """Load API key from MobileSec config file"""
    try:
        config_file = Path.home() / ".mobilesec" / "config.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                config = json.loads(f.read())
                return config.get('GROQ_API_KEY')
    except Exception:
        pass
    return None


def load_api_key_from_profile(key_name: str = 'GROQ_API_KEY') -> Optional[str]:
    """Load API key from shell profile files"""
    try:
        home = Path.home()
        shell_profiles = [
            home / ".zshrc",
            home / ".bashrc", 
            home / ".bash_profile",
            home / ".profile",
        ]
        
        for profile in shell_profiles:
            if profile.exists():
                content = profile.read_text()
                for line in content.split('\n'):
                    if f'export {key_name}=' in line:
                        # Extract the API key from the line
                        parts = line.split('=', 1)
                        if len(parts) == 2:
                            api_key = parts[1].strip().strip('"\'')
                            if api_key:
                                return api_key
    except Exception:
        pass
    return None


def save_api_key_to_config(key_name: str, api_key: str) -> bool:
    """Save API key to MobileSec config file"""
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
        
        # Update with new API key
        config[key_name] = api_key
        
        # Save back to file
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ {key_name} saved to {config_file}")
        return True
    except Exception as e:
        print(f"❌ Failed to save {key_name}: {e}")
        return False


def save_api_key_to_profile(api_key: str, shell_profile: str, key_name: str = 'GROQ_API_KEY') -> bool:
    """Save API key to shell profile"""
    try:
        profile_path = Path.home() / shell_profile
        
        # Read existing content
        content = ""
        if profile_path.exists():
            content = profile_path.read_text()
        
        # Check if API key already exists
        lines = content.split('\n')
        found = False
        for i, line in enumerate(lines):
            if f'export {key_name}=' in line:
                lines[i] = f'export {key_name}="{api_key}"'
                found = True
                break
        
        # If not found, add to end
        if not found:
            if content and not content.endswith('\n'):
                content += '\n'
            content += f'export {key_name}="{api_key}"\n'
        else:
            content = '\n'.join(lines)
        
        # Write back to file
        profile_path.write_text(content)
        print(f"✅ {key_name} saved to {profile_path}")
        return True
    except Exception as e:
        print(f"❌ Failed to save {key_name} to profile: {e}")
        return False


def check_groq_api_key() -> bool:
    """Check if GROQ API key is available"""
    return load_groq_api_key() is not None

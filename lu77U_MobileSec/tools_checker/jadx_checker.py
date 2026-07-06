"""JADX configuration checker for lu77U-MobileSec"""

import os
from ..config import user_settings
from ..ui.colors import Colors
from ..utils.verbose import verbose_print

def check_jadx_configured(verbose: bool = False) -> bool:
    jadx_path = user_settings.get_jadx_path()
    if not jadx_path or jadx_path == "path_goes_here":
        return False

    if not os.path.exists(jadx_path):
        return False

    verbose_print(f"JADX is configured at: {jadx_path}", verbose)

    return True

def get_jadx_setup_message(verbose: bool = False) -> str:
    message = f"""\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  JADX Configuration Required
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

To use APK Analysis features, you need to configure JADX.

Steps to configure:
  1. Install JADX on your system
     • macOS: brew install jadx
     • Linux: Download from https://github.com/skylot/jadx
     • Windows: Download from https://github.com/skylot/jadx
     
  2. Use option 4. Edit Settings from the main menu
  
  3. Set JADX_PATH to your JADX executable location
     • Example (macOS): /opt/homebrew/bin/jadx
     • Example (Linux): /usr/local/bin/jadx
     • Example (Windows): C:\\Program Files\\jadx\\bin\\jadx.bat

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
    
    verbose_print(message, verbose)
    return message
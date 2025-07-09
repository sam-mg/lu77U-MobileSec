#!/usr/bin/env python3
"""
CLI commands for lu77U-MobileSec
"""

import os
from pathlib import Path


def list_sample_apks():
    """List available sample APKs in the workspace"""
    print("\n📱 Available Sample APKs:")
    print("=" * 30)
    
    # Get project root by going up from the current file
    current_file = Path(__file__)
    project_root = current_file.parent.parent.parent
    apk_outputs_dir = project_root / "APK Outputs"
    
    if not apk_outputs_dir.exists():
        print("❌ No APK Outputs directory found")
        return
    
    apk_files = []
    for apk_type in ['Java', 'React Native', 'Flutter']:
        type_dir = apk_outputs_dir / apk_type
        if type_dir.exists():
            for apk_file in type_dir.glob('*.apk'):
                apk_files.append((apk_type, apk_file))
    
    if not apk_files:
        print("❌ No sample APK files found")
        return
    
    for i, (apk_type, apk_file) in enumerate(apk_files, 1):
        print(f"  {i}. [{apk_type}] {apk_file.name}")
    
    print(f"\nFound {len(apk_files)} sample APKs")
    return apk_files

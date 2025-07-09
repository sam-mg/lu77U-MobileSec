#!/usr/bin/env python3
"""
Path checker utilities for lu77U-MobileSec tools
"""

import shutil
import subprocess
from typing import Optional
from pathlib import Path


class PathChecker:
    """Class for checking tool paths"""
    
    @staticmethod
    def find_tool_path(tool_name: str) -> Optional[str]:
        """Find the path to a tool executable"""
        return shutil.which(tool_name)
    
    @staticmethod
    def get_jadx_path() -> Optional[str]:
        """Get JADX path"""
        return PathChecker.find_tool_path('jadx')
    
    @staticmethod
    def get_apktool_path() -> Optional[str]:
        """Get APKTool path"""
        return PathChecker.find_tool_path('apktool')
    
    @staticmethod
    def get_aapt_path() -> Optional[str]:
        """Get AAPT path"""
        return PathChecker.find_tool_path('aapt')
    
    @staticmethod
    def get_nodejs_path() -> Optional[str]:
        """Get Node.js path"""
        return PathChecker.find_tool_path('node')
    
    @staticmethod
    def get_npm_path() -> Optional[str]:
        """Get NPM path"""
        return PathChecker.find_tool_path('npm')
    
    @staticmethod
    def get_ollama_path() -> Optional[str]:
        """Get Ollama path"""
        return PathChecker.find_tool_path('ollama')
    
    @staticmethod
    def get_git_path() -> Optional[str]:
        """Get Git path"""
        return PathChecker.find_tool_path('git')
    
    @staticmethod
    def get_blutter_path() -> Optional[str]:
        """Get Blutter path"""
        # Check common locations for blutter.py
        possible_paths = [
            Path.home() / '.mobilesec-tools' / 'blutter' / 'blutter.py',
        ]
        
        # Check if any of these paths exist
        for path in possible_paths:
            if path.exists():
                return str(path)
        
        # Also check if blutter command is available in PATH (but not if it's a shell function)
        try:
            result = subprocess.run(['which', 'blutter'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                output = result.stdout.strip()
                if not ('function' in output or '{' in output):
                    return output
        except Exception:
            pass
        
        return None
    
    @staticmethod
    def get_react_native_decompiler_path() -> Optional[str]:
        """Get React Native decompiler path"""
        try:
            result = subprocess.run(['which', 'react-native-decompiler'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    @staticmethod
    def get_python_package_path(package_name: str) -> Optional[str]:
        """Get path of a Python package"""
        try:
            module = __import__(package_name)
            return getattr(module, '__file__', None)
        except ImportError:
            return None

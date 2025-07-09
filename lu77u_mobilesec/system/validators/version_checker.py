#!/usr/bin/env python3
"""
Version checker utilities for lu77U-MobileSec tools
"""

import subprocess
from typing import Optional
from pathlib import Path


class VersionChecker:
    """Class for checking tool versions"""
    
    @staticmethod
    def get_tool_version(tool_name: str, version_arg: str = '--version') -> Optional[str]:
        """Get version information for a tool"""
        try:
            result = subprocess.run([tool_name, version_arg], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
            return None
        except Exception:
            return None
    
    @staticmethod
    def get_jadx_version() -> Optional[str]:
        """Get JADX version"""
        return VersionChecker.get_tool_version('jadx', '-v')
    
    @staticmethod
    def get_apktool_version() -> Optional[str]:
        """Get APKTool version"""
        return VersionChecker.get_tool_version('apktool', '-version')
    
    @staticmethod
    def get_aapt_version() -> Optional[str]:
        """Get AAPT version"""
        return VersionChecker.get_tool_version('aapt', 'version')
    
    @staticmethod
    def get_nodejs_version() -> Optional[str]:
        """Get Node.js version"""
        return VersionChecker.get_tool_version('node', '--version')
    
    @staticmethod
    def get_npm_version() -> Optional[str]:
        """Get NPM version"""
        return VersionChecker.get_tool_version('npm', '--version')
    
    @staticmethod
    def get_git_version() -> Optional[str]:
        """Get Git version"""
        return VersionChecker.get_tool_version('git', '--version')
    
    @staticmethod
    def get_ollama_version() -> Optional[str]:
        """Get Ollama version"""
        return VersionChecker.get_tool_version('ollama', '--version')
    
    @staticmethod
    def get_ollama_models() -> list:
        """Get list of available Ollama models"""
        models = []
        try:
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        model_name = line.split()[0]
                        models.append(model_name)
        except Exception:
            pass
        return models
    
    @staticmethod
    def get_react_native_decompiler_version() -> Optional[str]:
        """Get React Native decompiler version"""
        try:
            # Get the version from npm
            result = subprocess.run(['npm', 'list', '-g', 'react-native-decompiler', '--depth=0'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse the output to get version
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'react-native-decompiler@' in line:
                        return line.split('@')[1].strip()
        except Exception:
            pass
        return None
    
    @staticmethod
    def get_python_package_version(package_name: str) -> Optional[str]:
        """Get version of a Python package"""
        try:
            module = __import__(package_name)
            return getattr(module, '__version__', None)
        except ImportError:
            return None

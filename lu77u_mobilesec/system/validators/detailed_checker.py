#!/usr/bin/env python3
"""
Detailed tool information checker for lu77U-MobileSec
"""

from typing import Dict, Any, Optional
from .path_checker import PathChecker
from .version_checker import VersionChecker
from .tool_checker import check_nodejs, check_npm


class DetailedToolChecker:
    """Class for getting detailed tool information including paths and versions"""
    
    @staticmethod
    def get_detailed_tool_info(tool_name: str, get_path_func, get_version_func) -> Dict[str, Any]:
        """Get detailed information about a tool including path and version"""
        path = get_path_func()
        version = None
        
        if path:
            version = get_version_func()
        
        return {
            'available': path is not None,
            'path': path,
            'version': version
        }
    
    @staticmethod
    def get_jadx_detailed() -> Dict[str, Any]:
        """Get detailed JADX information"""
        return DetailedToolChecker.get_detailed_tool_info(
            'jadx',
            PathChecker.get_jadx_path,
            VersionChecker.get_jadx_version
        )
    
    @staticmethod
    def get_apktool_detailed() -> Dict[str, Any]:
        """Get detailed APKTool information"""
        return DetailedToolChecker.get_detailed_tool_info(
            'apktool',
            PathChecker.get_apktool_path,
            VersionChecker.get_apktool_version
        )
    
    @staticmethod
    def get_aapt_detailed() -> Dict[str, Any]:
        """Get detailed AAPT information"""
        return DetailedToolChecker.get_detailed_tool_info(
            'aapt',
            PathChecker.get_aapt_path,
            VersionChecker.get_aapt_version
        )
    
    @staticmethod
    def get_nodejs_detailed() -> Dict[str, Any]:
        """Get detailed Node.js information"""
        return DetailedToolChecker.get_detailed_tool_info(
            'node',
            PathChecker.get_nodejs_path,
            VersionChecker.get_nodejs_version
        )
    
    @staticmethod
    def get_npm_detailed() -> Dict[str, Any]:
        """Get detailed NPM information"""
        return DetailedToolChecker.get_detailed_tool_info(
            'npm',
            PathChecker.get_npm_path,
            VersionChecker.get_npm_version
        )
    
    @staticmethod
    def get_ollama_detailed() -> Dict[str, Any]:
        """Get detailed Ollama information"""
        info = DetailedToolChecker.get_detailed_tool_info(
            'ollama',
            PathChecker.get_ollama_path,
            VersionChecker.get_ollama_version
        )
        
        # Also check for available models
        if info['available']:
            info['models'] = VersionChecker.get_ollama_models()
        else:
            info['models'] = []
        
        return info
    
    @staticmethod
    def get_blutter_detailed() -> Dict[str, Any]:
        """Get detailed Blutter information"""
        path = PathChecker.get_blutter_path()
        
        return {
            'available': path is not None,
            'path': path,
            'version': None
        }
    
    @staticmethod
    def get_react_native_decompiler_detailed() -> Dict[str, Any]:
        """Get detailed React Native decompiler information"""
        if not check_nodejs() or not check_npm():
            return {
                'available': False, 
                'path': None, 
                'version': None, 
                'error': 'Node.js or NPM not available'
            }
        
        path = PathChecker.get_react_native_decompiler_path()
        version = VersionChecker.get_react_native_decompiler_version()
        
        return {
            'available': version is not None,
            'path': path,
            'version': version
        }
    
    @staticmethod
    def get_python_package_detailed(package_name: str) -> Dict[str, Any]:
        """Get detailed Python package information"""
        path = PathChecker.get_python_package_path(package_name)
        version = VersionChecker.get_python_package_version(package_name)
        
        return {
            'available': path is not None,
            'path': path,
            'version': version
        }
    
    @staticmethod
    def get_git_detailed() -> Dict[str, Any]:
        """Get detailed Git information"""
        return DetailedToolChecker.get_detailed_tool_info(
            'git',
            PathChecker.get_git_path,
            VersionChecker.get_git_version
        )

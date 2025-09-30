"""System utilities for lu77U-MobileSec"""

import sys
import platform
from .verbose import verbose_print

def get_python_version(verbose: bool = False):
    """Get current Python version string"""
    verbose_print("Starting Python version detection", verbose)
    
    major = sys.version_info.major
    minor = sys.version_info.minor
    micro = sys.version_info.micro
    
    verbose_print(f"Python version components - Major: {major}, Minor: {minor}, Micro: {micro}", verbose)
    
    version = f"{major}.{minor}.{micro}"
    verbose_print(f"Formatted Python version: {version}", verbose)
    
    # Additional version info
    full_version = sys.version
    verbose_print(f"Full Python version string: {full_version.splitlines()[0]}", verbose)
    
    return version

def check_python_compatibility(verbose: bool = False):
    """Check if current Python version is compatible"""
    verbose_print("Starting Python compatibility check", verbose)
    
    required_major = 3
    required_minor = 12
    verbose_print(f"Required Python version: {required_major}.{required_minor}+", verbose)
    
    current_major = sys.version_info.major
    current_minor = sys.version_info.minor
    current_micro = sys.version_info.micro
    
    verbose_print(f"Current Python version: {current_major}.{current_minor}.{current_micro}", verbose)
    
    is_compatible = sys.version_info >= (required_major, required_minor)
    compatibility_status = "Compatible" if is_compatible else "Incompatible"
    
    verbose_print(f"Compatibility check result: {compatibility_status}", verbose)
    
    if not is_compatible:
        verbose_print(f"Version gap: Current {current_major}.{current_minor} < Required {required_major}.{required_minor}", verbose)
    else:
        verbose_print("Python version meets minimum requirements", verbose)
    
    return is_compatible

def get_platform_info(verbose: bool = False):
    """Get current platform information"""
    verbose_print("Gathering platform information", verbose)
    
    system = platform.system()
    verbose_print(f"System: {system}", verbose)
    
    platform_str = platform.platform()
    verbose_print(f"Platform: {platform_str}", verbose)
    
    architecture = platform.architecture()
    verbose_print(f"Architecture: {architecture}", verbose)
    
    machine = platform.machine()
    verbose_print(f"Machine: {machine}", verbose)
    
    try:
        processor = platform.processor()
        verbose_print(f"Processor: {processor}", verbose)
    except Exception as e:
        verbose_print(f"Could not get processor info: {e}", verbose)
        processor = "Unknown"
    
    # Additional platform details
    try:
        release = platform.release()
        verbose_print(f"Release: {release}", verbose)
    except Exception as e:
        verbose_print(f"Could not get release info: {e}", verbose)
        release = "Unknown"
    
    platform_info = {
        'system': system,
        'platform': platform_str,
        'architecture': architecture,
        'machine': machine,
        'processor': processor,
        'release': release
    }
    
    verbose_print(f"Complete platform info gathered: {len(platform_info)} fields", verbose)
    return platform_info

def get_system_info(verbose: bool = False):
    """Get comprehensive system information"""
    verbose_print("Starting comprehensive system information gathering", verbose)
    
    verbose_print("Getting Python version information", verbose)
    python_version = get_python_version(verbose)
    
    verbose_print("Checking Python compatibility", verbose)
    python_compatible = check_python_compatibility(verbose)
    
    verbose_print("Collecting platform information", verbose)
    platform_info = get_platform_info(verbose)
    
    system_info = {
        'python_version': python_version,
        'python_compatible': python_compatible,
        'platform': platform_info
    }
    
    verbose_print(f"System information collection complete", verbose)
    verbose_print(f"Python version: {python_version}", verbose)
    verbose_print(f"Python compatible: {python_compatible}", verbose)
    verbose_print(f"Platform system: {platform_info['system']}", verbose)
    verbose_print(f"Platform architecture: {platform_info['architecture'][0] if platform_info['architecture'] else 'Unknown'}", verbose)
    
    return system_info

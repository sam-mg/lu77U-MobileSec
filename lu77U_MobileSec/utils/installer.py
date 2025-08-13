"""
Dependency installer for lu77U-MobileSec
Reads requirements.txt and installs missing packages
"""

import sys
import os
import subprocess
from pathlib import Path


def get_requirements_file():
    """Get the path to requirements.txt file"""
    current_file = Path(__file__)
    project_root = current_file.parent.parent.parent
    requirements_path = project_root / "requirements.txt"
    
    if not requirements_path.exists():
        print(f"[!] requirements.txt not found at: {requirements_path}")
        return None
    
    return requirements_path


def parse_requirements(requirements_file):
    """Parse requirements.txt and return list of packages"""
    packages = []
    
    try:
        with open(requirements_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                if ';' in line:
                    package, condition = line.split(';', 1)
                    package = package.strip()
                    condition = condition.strip()
                    
                    if 'sys_platform=="win32"' in condition:
                        import platform
                        if platform.system() == "Windows":
                            packages.append(package)
                    else:
                        packages.append(package)
                else:
                    packages.append(line)
    
    except Exception as e:
        print(f"[!] Error reading requirements.txt: {e}")
        return []
    
    return packages


def is_package_installed(package_name):
    """Check if a package is already installed"""
    if '>=' in package_name:
        package_name = package_name.split('>=')[0]
    elif '==' in package_name:
        package_name = package_name.split('==')[0]
    elif '>' in package_name:
        package_name = package_name.split('>')[0]
    elif '<' in package_name:
        package_name = package_name.split('<')[0]
    
    try:
        __import__(package_name)
        return True
    except ImportError:
        return False


def install_package(package):
    """Install a single package using pip"""
    try:
        print(f"[!] Installing missing module: {package}")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", package
        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        print(f"[✓] Successfully installed: {package}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[✗] Failed to install {package}: {e}")
        return False


def install_missing_dependencies():
    """Main function to install missing dependencies from requirements.txt"""
    print("[*] Checking dependencies...")
    
    requirements_file = get_requirements_file()
    if not requirements_file:
        return False
    
    packages = parse_requirements(requirements_file)
    if not packages:
        print("[!] No packages found in requirements.txt")
        return False
    
    missing_packages = []
    for package in packages:
        if not is_package_installed(package):
            missing_packages.append(package)
    
    if not missing_packages:
        print("[✓] All dependencies are already installed")
        return True
    
    print(f"[*] Found {len(missing_packages)} missing packages")
    
    success_count = 0
    for package in missing_packages:
        if install_package(package):
            success_count += 1
    
    if success_count == len(missing_packages):
        print(f"[✓] Successfully installed all {success_count} missing packages")
        return True
    else:
        print(f"[!] Installed {success_count}/{len(missing_packages)} packages")
        return False


if __name__ != "__main__":
    install_missing_dependencies()


if __name__ == "__main__":
    install_missing_dependencies()

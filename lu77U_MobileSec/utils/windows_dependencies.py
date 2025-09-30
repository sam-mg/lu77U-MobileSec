"""Windows Dependencies Installer for lu77U-MobileSec"""

import os
import sys
import platform
import subprocess
import urllib.request
import tempfile
import ssl
import time

from .verbose import verbose_print
from pathlib import Path

class WindowsDependencyInstaller:
    """Handles automatic installation of Windows dependencies for WeasyPrint"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.msys2_base_url = "https://github.com/msys2/msys2-installer/releases/download/2024-01-13/msys2-base-x86_64-20240113.sfx.exe"
        self.msys2_install_path = Path("C:/msys64")
        self.msys2_bin_path = self.msys2_install_path / "mingw64" / "bin"
        
    def is_windows(self) -> bool:
        """Check if running on Windows"""
        return platform.system().lower() == "windows"
    
    def is_admin(self) -> bool:
        """Check if running with administrator privileges"""
        try:
            return os.getuid() == 0
        except AttributeError:
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
    
    def is_msys2_installed(self) -> bool:
        """Check if MSYS2 is already installed"""
        verbose_print(f"Checking if MSYS2 is installed at: {self.msys2_install_path}", self.verbose)
        path_exists = self.msys2_install_path.exists()
        verbose_print(f"MSYS2 install path exists: {path_exists}", self.verbose)
        bash_path = self.msys2_install_path / "usr" / "bin" / "bash.exe"
        bash_exists = bash_path.exists()
        verbose_print(f"MSYS2 bash exists at {bash_path}: {bash_exists}", self.verbose)
        result = path_exists and bash_exists
        verbose_print(f"MSYS2 installation check result: {result}", self.verbose)
        return result
    
    def is_pango_installed(self) -> bool:
        """Check if Pango is installed in MSYS2"""
        verbose_print(f"Checking if Pango is installed in: {self.msys2_bin_path}", self.verbose)
        pango_dll = self.msys2_bin_path / "libpango-1.0-0.dll"
        gobject_dll = self.msys2_bin_path / "libgobject-2.0-0.dll"
        pango_exists = pango_dll.exists()
        gobject_exists = gobject_dll.exists()
        verbose_print(f"Pango DLL exists at {pango_dll}: {pango_exists}", self.verbose)
        verbose_print(f"GObject DLL exists at {gobject_dll}: {gobject_exists}", self.verbose)
        result = pango_exists and gobject_exists
        verbose_print(f"Pango installation check result: {result}", self.verbose)
        return result
    
    def download_file(self, url: str, dest_path: Path, chunk_size: int = 8192) -> bool:
        """Download a file with progress indication and SSL handling"""
        try:
            verbose_print(f"Starting download from: {url}", self.verbose)
            verbose_print(f"Destination: {dest_path}", self.verbose)
            verbose_print(f"Downloading {url}...", self.verbose)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            verbose_print("Created SSL context with certificate verification disabled", self.verbose)
            try:
                verbose_print("Attempting download with custom SSL context...", self.verbose)
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, context=ssl_context) as response:
                    total_size = int(response.headers.get('Content-Length', 0))
                    verbose_print(f"Response received, content length: {total_size} bytes", self.verbose)
                    downloaded = 0
                    with open(dest_path, 'wb') as f:
                        verbose_print("Starting file write...", self.verbose)
                        while True:
                            chunk = response.read(chunk_size)
                            if not chunk:
                                break
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0:
                                progress = (downloaded / total_size) * 100
                                verbose_print(f"Progress: {progress:.1f}%", self.verbose)
                    verbose_print(f"\nDownload completed, total bytes written: {downloaded}", self.verbose)
                    verbose_print("Download completed!", self.verbose)
                    return True
            except Exception as ssl_error:
                verbose_print(f"SSL download failed with error: {ssl_error}", self.verbose)
                verbose_print(f"SSL download failed: {ssl_error}", self.verbose)
                verbose_print("Trying alternative download method...", self.verbose)
                verbose_print("Attempting fallback download without SSL context...", self.verbose)
                with urllib.request.urlopen(url) as response:
                    total_size = int(response.headers.get('Content-Length', 0))
                    verbose_print(f"Fallback response received, content length: {total_size} bytes", self.verbose)
                    downloaded = 0
                    with open(dest_path, 'wb') as f:
                        verbose_print("Starting fallback file write...", self.verbose)
                        while True:
                            chunk = response.read(chunk_size)
                            if not chunk:
                                break
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0:
                                progress = (downloaded / total_size) * 100
                                verbose_print(f"Progress: {progress:.1f}%", self.verbose)
                    verbose_print(f"Fallback download completed, total bytes written: {downloaded}", self.verbose)
                    verbose_print("Download completed!", self.verbose)
                    return True
        except Exception as e:
            verbose_print(f"Download failed with exception: {e}", self.verbose)
            verbose_print(f"Exception type: {type(e).__name__}", self.verbose)
            verbose_print(f"Error downloading file: {e}", self.verbose)
            return False
    
    def try_winget_install_msys2(self) -> bool:
        """Try to install MSYS2 using Windows Package Manager (winget)"""
        try:
            verbose_print("Attempting to install MSYS2 using winget...", self.verbose)
            winget_check = subprocess.run(["winget", "--version"], capture_output=True, text=True, timeout=10)
            if winget_check.returncode != 0:
                verbose_print("winget not available or not working", self.verbose)
                return False
            verbose_print(f"winget is available, version: {winget_check.stdout.strip()}", self.verbose)
            cmd = ["winget", "install", "--id", "MSYS2.MSYS2", "--silent", "--accept-package-agreements", "--accept-source-agreements"]
            verbose_print(f"Running winget command: {' '.join(cmd)}", self.verbose)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            verbose_print(f"winget return code: {result.returncode}", self.verbose)
            verbose_print(f"winget stdout: {result.stdout}", self.verbose)
            verbose_print(f"winget stderr: {result.stderr}", self.verbose)
            if result.returncode == 0:
                verbose_print("winget installation completed successfully", self.verbose)
                if self.is_msys2_installed():
                    verbose_print("MSYS2 installation verified successfully via winget", self.verbose)
                    return True
                else:
                    verbose_print("MSYS2 installation verification failed after winget", self.verbose)
                    return False
            else:
                verbose_print(f"winget installation failed with return code {result.returncode}", self.verbose)
                return False
        except FileNotFoundError:
            verbose_print("winget command not found", self.verbose)
            return False
        except subprocess.TimeoutExpired:
            verbose_print("winget installation timed out", self.verbose)
            return False
        except Exception as e:
            verbose_print(f"winget installation failed with exception: {e}", self.verbose)
            return False

    def install_msys2(self) -> bool:
        """Install MSYS2 automatically"""
        verbose_print("Starting MSYS2 installation check...", self.verbose)
        if self.is_msys2_installed():
            verbose_print("MSYS2 already installed, skipping installation", self.verbose)
            verbose_print("MSYS2 is already installed.", self.verbose)
            return True
        verbose_print("MSYS2 not found, proceeding with installation", self.verbose)
        verbose_print("Installing MSYS2...", self.verbose)
        verbose_print("Trying winget installation first...", self.verbose)
        if self.try_winget_install_msys2():
            verbose_print("winget installation successful", self.verbose)
            return True
        verbose_print("winget failed, trying manual SFX extraction...", self.verbose)
        with tempfile.TemporaryDirectory() as temp_dir:
            verbose_print(f"Created temporary directory: {temp_dir}", self.verbose)
            installer_path = Path(temp_dir) / "msys2-installer.exe"
            verbose_print(f"Installer will be saved to: {installer_path}", self.verbose)
            verbose_print(f"Attempting to download from: {self.msys2_base_url}", self.verbose)
            if not self.download_file(self.msys2_base_url, installer_path):
                verbose_print("Download failed, returning False", self.verbose)
                return False
            verbose_print(f"Download completed, file size: {installer_path.stat().st_size} bytes", self.verbose)
            try:
                verbose_print("Preparing to run MSYS2 installer...", self.verbose)
                verbose_print("MSYS2 installer is a 7-Zip SFX archive, extracting directly...", self.verbose)
                cmd = [str(installer_path), "-o" + str(self.msys2_install_path.parent), "-y"]
                verbose_print(f"Running 7-Zip SFX command: {' '.join(cmd)}", self.verbose)
                verbose_print("Running MSYS2 installer...", self.verbose)
                self.msys2_install_path.parent.mkdir(parents=True, exist_ok=True)
                verbose_print(f"Created parent directory: {self.msys2_install_path.parent}", self.verbose)
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                verbose_print(f"Installer return code: {result.returncode}", self.verbose)
                verbose_print(f"Installer stdout: {result.stdout}", self.verbose)
                verbose_print(f"Installer stderr: {result.stderr}", self.verbose)
                if result.returncode == 0:
                    verbose_print("SFX extraction completed successfully", self.verbose)
                    verbose_print("MSYS2 installed successfully!", self.verbose)
                    if self.is_msys2_installed():
                        verbose_print("MSYS2 installation verified successfully", self.verbose)
                        return True
                    else:
                        verbose_print("MSYS2 installation verification failed", self.verbose)
                        verbose_print("MSYS2 installation verification failed", self.verbose)
                        return False
                else:
                    verbose_print("7-Zip SFX extraction failed, trying manual extraction...", self.verbose)
                    verbose_print("Trying to run SFX without parameters for interactive extraction...", self.verbose)
                    original_cwd = os.getcwd()
                    target_dir = self.msys2_install_path.parent
                    target_dir.mkdir(parents=True, exist_ok=True)
                    try:
                        os.chdir(str(target_dir))
                        verbose_print(f"Changed working directory to: {target_dir}", self.verbose)
                        cmd2 = [str(installer_path)]
                        verbose_print(f"Running SFX in target directory: {' '.join(cmd2)}", self.verbose)
                        process = subprocess.Popen(cmd2, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        stdout, stderr = process.communicate(input="y\ny\ny\n", timeout=300)
                        verbose_print(f"SFX process return code: {process.returncode}", self.verbose)
                        verbose_print(f"SFX stdout: {stdout}", self.verbose)
                        verbose_print(f"SFX stderr: {stderr}", self.verbose)
                        os.chdir(original_cwd)
                        if process.returncode == 0:
                            verbose_print("SFX extraction completed successfully", self.verbose)
                            verbose_print("MSYS2 installed successfully!", self.verbose)
                            if self.is_msys2_installed():
                                verbose_print("MSYS2 installation verified successfully", self.verbose)
                                return True
                            else:
                                verbose_print("MSYS2 installation verification failed, checking for msys64 folder...", self.verbose)
                                possible_paths = [
                                    target_dir / "msys64",
                                    Path.cwd() / "msys64",
                                    Path("C:/") / "msys64"
                                ]
                                for path in possible_paths:
                                    verbose_print(f"Checking for MSYS2 at: {path}", self.verbose)
                                    if path.exists() and (path / "usr" / "bin" / "bash.exe").exists():
                                        verbose_print(f"Found MSYS2 installation at: {path}", self.verbose)
                                        self.msys2_install_path = path
                                        self.msys2_bin_path = path / "mingw64" / "bin"
                                        verbose_print("Updated MSYS2 paths", self.verbose)
                                        return True
                                verbose_print("MSYS2 installation not found in expected locations", self.verbose)
                                return False
                        else:
                            verbose_print(f"SFX extraction failed with return code {process.returncode}", self.verbose)
                            return False
                    finally:
                        os.chdir(original_cwd)
            except subprocess.TimeoutExpired:
                verbose_print("MSYS2 installation timed out after 300 seconds", self.verbose)
                verbose_print("MSYS2 installation timed out", self.verbose)
                return False
            except Exception as e:
                verbose_print(f"Exception during MSYS2 installation: {e}", self.verbose)
                verbose_print(f"Exception type: {type(e).__name__}", self.verbose)
                verbose_print(f"Error installing MSYS2: {e}", self.verbose)
                return False
    
    def install_pango_dependencies(self) -> bool:
        """Install Pango and GTK dependencies through MSYS2."""
        verbose_print("Starting Pango installation check...", self.verbose)
        if not self.is_msys2_installed():
            verbose_print("MSYS2 not found, proceeding with installation", self.verbose)
            if not self.install_msys2():
                return False
        if self.is_pango_installed():
            verbose_print("Pango is already installed", self.verbose)
            return True
        verbose_print("Pango not found, proceeding with installation", self.verbose)
        try:
            bash_path = os.path.join(self.msys2_install_path, "usr", "bin", "bash.exe")
            verbose_print(f"Looking for bash at: {bash_path}", self.verbose)
            if not os.path.exists(bash_path):
                verbose_print(f"Bash not found at {bash_path}", self.verbose)
                return False
            verbose_print(f"Bash found at {bash_path}", self.verbose)
            mirrors = [
                "https://mirrors.tuna.tsinghua.edu.cn/msys2/",
                "https://mirror.yandex.ru/mirrors/msys2/",
                "https://mirrors.dotsrc.org/msys2/",
                "https://ftp.osuosl.org/pub/msys2/"
            ]
            verbose_print("Trying to update package database with multiple strategies...", self.verbose)
            verbose_print("Updating MSYS2 package database...", self.verbose)
            update_success = False
            verbose_print("Strategy 1: Simple update with extended timeout", self.verbose)
            try:
                update_cmd = [bash_path, "-lc", "pacman -Sy --noconfirm"]
                verbose_print(f"Running command: {' '.join(update_cmd)}", self.verbose)
                result = subprocess.run(update_cmd, capture_output=True, text=True, timeout=300, creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode == 0:
                    verbose_print("Package database update completed successfully", self.verbose)
                    update_success = True
                else:
                    verbose_print(f"Update failed with return code {result.returncode}", self.verbose)
                    verbose_print(f"Update stderr: {result.stderr}", self.verbose)
            except subprocess.TimeoutExpired:
                verbose_print("Strategy 1 timed out, trying alternative approach", self.verbose)
            except Exception as e:
                verbose_print(f"Strategy 1 failed: {e}", self.verbose)
            if not update_success:
                verbose_print("Strategy 2: Trying with alternative mirror configuration", self.verbose)
                try:
                    mirrorlist_cmd = [bash_path, "-lc", 
                        "echo 'Server = https://mirrors.tuna.tsinghua.edu.cn/msys2/\\$repo/' > /etc/pacman.d/mirrorlist.msys && "
                        "echo 'Server = https://mirror.yandex.ru/mirrors/msys2/\\$repo/' >> /etc/pacman.d/mirrorlist.msys && "
                        "echo 'Server = https://ftp.osuosl.org/pub/msys2/\\$repo/' >> /etc/pacman.d/mirrorlist.msys"
                    ]
                    verbose_print(f"Setting up alternative mirrors...", self.verbose)
                    subprocess.run(mirrorlist_cmd, capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
                    update_cmd = [bash_path, "-lc", "pacman -Sy --noconfirm"]
                    verbose_print(f"Running update with alternative mirrors: {' '.join(update_cmd)}", self.verbose)
                    result = subprocess.run(update_cmd, capture_output=True, text=True, timeout=300, creationflags=subprocess.CREATE_NO_WINDOW)
                    if result.returncode == 0:
                        verbose_print("Package database update completed with alternative mirrors", self.verbose)
                        update_success = True
                    else:
                        verbose_print(f"Alternative mirror update failed: {result.stderr}", self.verbose)
                except Exception as e:
                    verbose_print(f"Strategy 2 failed: {e}", self.verbose)
            if not update_success:
                verbose_print("Strategy 3: Attempting installation without database update", self.verbose)
                verbose_print("This may work if packages are cached or mirrors recover", self.verbose)
            packages = [
                "mingw-w64-x86_64-pango",
                "mingw-w64-x86_64-gtk3", 
                "mingw-w64-x86_64-glib2",
                "mingw-w64-x86_64-cairo",
                "mingw-w64-x86_64-gobject-introspection"
            ]
            verbose_print("Installing Pango and GTK dependencies...", self.verbose)
            verbose_print("Installing Pango and GTK dependencies...", self.verbose)
            installed_packages = 0
            for package in packages:
                verbose_print(f"Installing package: {package}", self.verbose)
                verbose_print(f"Installing {package}...", self.verbose)
                package_success = False
                for attempt in range(3):
                    verbose_print(f"Installation attempt {attempt + 1} for {package}", self.verbose)
                    try:
                        install_cmd = [bash_path, "-lc", f"pacman -S --noconfirm {package}"]
                        verbose_print(f"Running command: {' '.join(install_cmd)}", self.verbose)
                        result = subprocess.run(install_cmd, capture_output=True, text=True, timeout=300, creationflags=subprocess.CREATE_NO_WINDOW)
                        verbose_print(f"Package {package} installation return code: {result.returncode}", self.verbose)
                        if result.stdout:
                            verbose_print(f"Package {package} stdout: {result.stdout[:500]}...", self.verbose)
                        if result.stderr:
                            verbose_print(f"Package {package} stderr: {result.stderr[:500]}...", self.verbose)
                        if result.returncode == 0:
                            verbose_print(f"{package} installed successfully", self.verbose)
                            package_success = True
                            installed_packages += 1
                            break
                        elif "target not found" in result.stderr.lower():
                            verbose_print(f"Package {package} not found in repositories", self.verbose)
                            break
                        else:
                            verbose_print(f"Attempt {attempt + 1} failed for {package}: {result.stderr[:200]}...", self.verbose)
                            if attempt < 2:
                                verbose_print(f"Waiting 10 seconds before retry...", self.verbose)
                                time.sleep(10)
                    except subprocess.TimeoutExpired:
                        verbose_print(f"Timeout during {package} installation attempt {attempt + 1}", self.verbose)
                        if attempt < 2:
                            verbose_print(f"Waiting 15 seconds before retry...", self.verbose)
                            time.sleep(15)
                    except Exception as e:
                        verbose_print(f"Error installing {package} attempt {attempt + 1}: {e}", self.verbose)
                        if attempt < 2:
                            time.sleep(5)
                if not package_success:
                    verbose_print(f"Failed to install {package} after 3 attempts", self.verbose)
            verbose_print(f"Installation completed. Successfully installed {installed_packages}/{len(packages)} packages", self.verbose)
            if installed_packages == 0:
                verbose_print("No packages installed via pacman, trying alternative approach...", self.verbose)
                return self.try_alternative_pango_installation()
            if self.is_pango_installed():
                verbose_print("Pango installation verified successfully", self.verbose)
                return True
            elif installed_packages >= 2:
                verbose_print(f"Partial installation ({installed_packages} packages), checking if functional...", self.verbose)
                time.sleep(5)
                if self.is_pango_installed():
                    verbose_print("Delayed verification successful", self.verbose)
                    return True
                else:
                    verbose_print("Partial installation not sufficient", self.verbose)
                    return False
            else:
                verbose_print("Pango installation verification failed - too few packages installed", self.verbose)
                return False
        except Exception as e:
            verbose_print(f"Error during Pango installation: {e}", self.verbose)
            verbose_print(f"Exception type: {type(e).__name__}", self.verbose)
            return False
    
    def try_alternative_pango_installation(self) -> bool:
        """Try alternative method for installing Pango when pacman fails."""
        verbose_print("Attempting alternative Pango installation method...", self.verbose)
        verbose_print("Trying alternative installation method...", self.verbose)
        try:
            bash_path = os.path.join(self.msys2_install_path, "usr", "bin", "bash.exe")
            verbose_print("Forcing database refresh...", self.verbose)
            refresh_cmd = [bash_path, "-lc", "pacman -Syy --noconfirm"]
            try:
                result = subprocess.run(refresh_cmd, capture_output=True, text=True, timeout=120, creationflags=subprocess.CREATE_NO_WINDOW)
                verbose_print(f"Database refresh result: {result.returncode}", self.verbose)
            except Exception as e:
                verbose_print(f"Database refresh failed: {e}", self.verbose)
            essential_packages = ["mingw-w64-x86_64-pango", "mingw-w64-x86_64-glib2"]
            for package in essential_packages:
                verbose_print(f"Trying essential package: {package}", self.verbose)
                try:
                    install_cmd = [bash_path, "-lc", f"pacman -S --noconfirm --needed {package}"]
                    result = subprocess.run(install_cmd, capture_output=True, text=True, timeout=180, creationflags=subprocess.CREATE_NO_WINDOW)
                    if result.returncode == 0:
                        verbose_print(f"Essential package {package} installed successfully", self.verbose)
                    else:
                        verbose_print(f"Essential package {package} failed: {result.stderr[:200]}...", self.verbose)
                except subprocess.TimeoutExpired:
                    verbose_print(f"Essential package {package} installation timed out", self.verbose)
                except Exception as e:
                    verbose_print(f"Essential package {package} error: {e}", self.verbose)
            if self.is_pango_installed():
                verbose_print("Alternative installation successful!", self.verbose)
                return True
            verbose_print("Trying cached package installation...", self.verbose)
            cache_cmd = [bash_path, "-lc", "pacman -U /var/cache/pacman/pkg/mingw-w64-x86_64-pango*.pkg.tar.* --noconfirm"]
            try:
                result = subprocess.run(cache_cmd, capture_output=True, text=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode == 0:
                    verbose_print("Cached package installation successful", self.verbose)
                    if self.is_pango_installed():
                        return True
            except Exception as e:
                verbose_print(f"Cached package installation failed: {e}", self.verbose)
            verbose_print("All alternative installation methods failed", self.verbose)
            return False
        except Exception as e:
            verbose_print(f"Alternative installation method error: {e}", self.verbose)
            return False
    
    def set_dll_path(self) -> bool:
        """Set the DLL path environment variable"""
        verbose_print("Setting DLL path environment variable", self.verbose)
        if not self.msys2_bin_path.exists():
            verbose_print("MSYS2 bin path not found!", self.verbose)
            return False
        dll_path = str(self.msys2_bin_path)
        os.environ["WEASYPRINT_DLL_DIRECTORIES"] = dll_path
        verbose_print(f"Set WEASYPRINT_DLL_DIRECTORIES to: {dll_path}", self.verbose)
        
        if self.is_admin():
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "WEASYPRINT_DLL_DIRECTORIES", 0, winreg.REG_SZ, dll_path)
                winreg.CloseKey(key)
                verbose_print("Environment variable set permanently!", self.verbose)
                import ctypes
                ctypes.windll.kernel32.SetEnvironmentVariableW("WEASYPRINT_DLL_DIRECTORIES", dll_path)
                return True
            except Exception as e:
                verbose_print(f"Could not set permanent environment variable: {e}", self.verbose)
                verbose_print("Setting for current session only...", self.verbose)
                return True
        else:
            verbose_print("Setting environment variable for current session...", self.verbose)
            verbose_print("(Run as administrator to set permanently)", self.verbose)
            return True
    
    def try_simple_weasyprint_install(self) -> bool:
        """Try to install WeasyPrint with newer Windows wheel that includes dependencies"""
        try:
            verbose_print("Starting simple WeasyPrint installation method...", self.verbose)
            verbose_print("Attempting to install WeasyPrint with bundled Windows dependencies...", self.verbose)
            cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "weasyprint>=60.0"]
            verbose_print(f"Running command: {' '.join(cmd)}", self.verbose)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            verbose_print(f"pip install return code: {result.returncode}", self.verbose)
            if result.stdout:
                verbose_print(f"pip install stdout: {result.stdout}", self.verbose)
            if result.stderr:
                verbose_print(f"pip install stderr: {result.stderr}", self.verbose)
            if result.returncode == 0:
                verbose_print("WeasyPrint installed/upgraded successfully!", self.verbose)
                verbose_print("Testing WeasyPrint functionality...", self.verbose)
                try:
                    verbose_print("Attempting to import weasyprint...", self.verbose)
                    import weasyprint
                    verbose_print("WeasyPrint imported successfully", self.verbose)
                    verbose_print("Testing HTML to PDF conversion...", self.verbose)
                    html_doc = weasyprint.HTML(string="<html><body><h1>Test</h1></body></html>")
                    verbose_print("HTML document created, attempting PDF generation...", self.verbose)
                    html_doc.write_pdf()
                    verbose_print("WeasyPrint is working correctly!", self.verbose)
                    return True
                except Exception as test_error:
                    verbose_print(f"WeasyPrint test failed with error: {test_error}", self.verbose)
                    verbose_print(f"Error type: {type(test_error).__name__}", self.verbose)
                    verbose_print(f"WeasyPrint still has issues: {test_error}", self.verbose)
                    return False
            else:
                verbose_print(f"pip install failed with return code {result.returncode}", self.verbose)
                verbose_print(f"Failed to install WeasyPrint: {result.stderr}", self.verbose)
                return False
        except subprocess.TimeoutExpired:
            verbose_print("WeasyPrint installation timed out after 120 seconds", self.verbose)
            verbose_print("WeasyPrint installation timed out", self.verbose)
            return False
        except Exception as e:
            verbose_print(f"Exception in try_simple_weasyprint_install: {e}", self.verbose)
            verbose_print(f"Exception type: {type(e).__name__}", self.verbose)
            verbose_print(f"Error trying simple WeasyPrint install: {e}", self.verbose)
            return False

    def install_all_dependencies(self) -> bool:
        """Install all required dependencies for WeasyPrint on Windows"""
        if not self.is_windows():
            verbose_print("This installer is only for Windows systems.", self.verbose)
            return False
        print("Starting Windows dependency installation for lu77U-MobileSec...")
        print("This may take several minutes...")
        print("\n" + "="*50)
        print("Trying simple installation method...")
        print("="*50)
        if self.try_simple_weasyprint_install():
            print("\n" + "="*50)
            print("Simple installation successful!")
            print("WeasyPrint should now work properly")
            print("You can now use lu77U-MobileSec PDF features")
            print("="*50)
            return True
        print("\n" + "="*50)
        print("Simple method failed, trying advanced installation...")
        print("="*50)
        if not self.install_msys2():
            verbose_print("Failed to install MSYS2", self.verbose)
            return False
        if not self.install_pango_dependencies():
            verbose_print("Failed to install Pango", self.verbose)
            return False
        if not self.set_dll_path():
            verbose_print("Failed to set DLL path", self.verbose)
            return False
        print("\n" + "="*50)
        print("All dependencies installed successfully!")
        print("WeasyPrint should now work properly")
        print("You can now use lu77U-MobileSec PDF features")
        print("="*50)
        return True
    
    def check_dependencies(self) -> bool:
        """Check if all dependencies are installed and working"""
        if not self.is_windows():
            return True
        try:
            import weasyprint
            verbose_print("WeasyPrint is working correctly", self.verbose)
            return True
        except ImportError as e:
            if "libgobject" in str(e) or "libpango" in str(e):
                verbose_print("WeasyPrint dependencies are missing", self.verbose)
                return False
            else:
                verbose_print(f"WeasyPrint import error: {e}", self.verbose)
                return False
        except Exception as e:
            verbose_print(f"Unexpected error checking dependencies: {e}", self.verbose)
            return False

def auto_install_windows_dependencies(verbose: bool = False):
    """Main function to automatically install Windows dependencies"""
    verbose_print("Starting auto_install_windows_dependencies function", verbose)
    installer = WindowsDependencyInstaller(verbose=verbose)
    if not installer.is_windows():
        verbose_print("Not running on Windows, returning True", verbose)
        return True
    verbose_print("Running on Windows, checking dependencies", verbose)
    print("Checking Windows dependencies for PDF generation...")
    try:
        verbose_print("Attempting to import weasyprint for initial test...", verbose)
        import weasyprint
        verbose_print("WeasyPrint imported successfully, testing functionality...", verbose)
        verbose_print("Creating test HTML document...", verbose)
        html_doc = weasyprint.HTML(string="<html><body><h1>Test</h1></body></html>")
        verbose_print("Attempting to generate PDF from test HTML...", verbose)
        html_doc.write_pdf()
        verbose_print("PDF generation test successful", verbose)
        verbose_print("WeasyPrint is working correctly", verbose)
        return True
    except ImportError as ie:
        verbose_print(f"WeasyPrint import failed: {ie}", verbose)
        verbose_print("WeasyPrint is not installed", verbose)
    except Exception as e:
        verbose_print(f"WeasyPrint functionality test failed: {e}", verbose)
        verbose_print(f"Error type: {type(e).__name__}", verbose)
        if "libgobject" in str(e) or "libpango" in str(e) or "cairo" in str(e):
            verbose_print("System dependencies missing, attempting auto-install", verbose)
        else:
            verbose_print(f"WeasyPrint error: {e}", verbose)
    verbose_print("WeasyPrint not working, proceeding with installation", verbose)
    print("\nWindows dependencies for PDF generation are missing.")
    print("lu77U-MobileSec can automatically install them for you.")
    while True:
        response = input("\nWould you like to install dependencies automatically? (y/n): ").lower().strip()
        verbose_print(f"User response: '{response}'", verbose)
        if response in ['y', 'yes']:
            verbose_print("User chose to install dependencies", verbose)
            break
        elif response in ['n', 'no']:
            verbose_print("User chose not to install dependencies", verbose)
            print("\nSkipping dependency installation.")
            print("Note: PDF report generation may not work without these dependencies.")
            return False
        else:
            verbose_print("Invalid user response, asking again", verbose)
            print("Please enter 'y' for yes or 'n' for no.")
    verbose_print("Starting dependency installation process", verbose)
    success = installer.install_all_dependencies()
    verbose_print(f"Installation process completed with success: {success}", verbose)
    if not success:
        verbose_print("Installation failed, showing manual instructions", verbose)
        verbose_print("Automatic installation failed", verbose)
        verbose_print("Manual installation instructions:", verbose)
        verbose_print("1. Install Python 3.11+ with pip")
        verbose_print("2. Run: pip install --upgrade weasyprint")
        verbose_print("3. If issues persist, visit: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows")
        verbose_print("="*50)
    verbose_print(f"Returning from auto_install_windows_dependencies with: {success}", verbose)
    return success

def check_and_install_windows_dependencies(verbose=False):
    """Check and install Windows dependencies if needed"""
    if platform.system().lower() != "windows":
        return True
    
    verbose_print("Checking Windows dependencies for PDF generation...", verbose)
    try:
        installer = WindowsDependencyInstaller(verbose=verbose)
        if installer.is_pango_installed() and installer.is_msys2_installed():
            verbose_print("System dependencies appear to be installed", verbose)
            return True
        else:
            verbose_print("System dependencies missing, attempting auto-install", verbose)
            try:
                return auto_install_windows_dependencies(verbose=verbose)
            except Exception as install_error:
                verbose_print(f"Failed to auto-install dependencies: {install_error}", verbose)
                verbose_print("\n" + "="*60)
                print("Windows Dependencies Required")
                verbose_print("="*60)
                verbose_print("PDF report generation requires additional Windows libraries.")
                print("The automatic installer failed.")
                verbose_print("\nPlease visit: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation")
                verbose_print("Or open an issue at: https://github.com/sam-mg/lu77U-MobileSec/issues")
                verbose_print("="*60)
                return False               
    except Exception as e:
        verbose_print(f"Error checking dependencies: {e}", verbose)
        verbose_print("\n" + "="*60)
        print("Unable to Check Dependencies")
        verbose_print("="*60)
        verbose_print("There was an error checking Windows dependencies.")
        print("PDF report generation may not work.")
        verbose_print("\nFor manual installation:")
        verbose_print("https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation")
        verbose_print("="*60)
        return False

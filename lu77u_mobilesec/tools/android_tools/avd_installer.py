#!/usr/bin/env python3
"""
Android Virtual Device (AVD) installer for lu77U-MobileSec

Automatically downloads Android SDK command-line tools and sets up
a dedicated AVD for mobile app security testing.
"""

import os
import platform
import subprocess
import sys
import shutil
import zipfile
import urllib.request
from pathlib import Path

# === CONFIG ===
AVD_NAME = "lu77U-MobileSec"
API_LEVEL = "31"
DEVICE = "pixel"

# Global debug flag
DEBUG_MODE = False

# === UTILITY FUNCTIONS ===

def debug_print(message):
    """Print debug message only if debug mode is enabled"""
    if DEBUG_MODE:
        print(f"🐛 DEBUG: {message}")

def info_print(message):
    """Print info message always"""
    print(message)

# Detect architecture for appropriate system image
def get_system_image():
    """Get the appropriate system image based on architecture across all platforms"""
    try:
        # Get machine architecture
        machine = platform.machine().lower()
        system = platform.system()
        
        # Check for ARM architecture on all platforms
        if any(arch in machine for arch in ['arm64', 'aarch64', 'arm']):
            debug_print(f"Detected ARM architecture: {machine} on {system}")
            return f"system-images;android-{API_LEVEL};google_apis;arm64-v8a"
        
        # Check for x86_64/AMD64 architecture
        elif any(arch in machine for arch in ['x86_64', 'amd64', 'x64']):
            debug_print(f"Detected x86_64 architecture: {machine} on {system}")
            return f"system-images;android-{API_LEVEL};google_apis;x86_64"
        
        # Fallback: try uname -m for Unix-like systems
        elif system in ['Darwin', 'Linux']:
            result = subprocess.run(['uname', '-m'], capture_output=True, text=True)
            if result.returncode == 0:
                uname_machine = result.stdout.strip().lower()
                if any(arch in uname_machine for arch in ['arm64', 'aarch64', 'arm']):
                    debug_print(f"Detected ARM via uname: {uname_machine} on {system}")
                    return f"system-images;android-{API_LEVEL};google_apis;arm64-v8a"
        
        # Default fallback to x86_64
        debug_print(f"Using default x86_64 for machine: {machine} on {system}")
        return f"system-images;android-{API_LEVEL};google_apis;x86_64"
        
    except Exception as e:
        debug_print(f"Architecture detection failed: {e}, using x86_64 default")
        return f"system-images;android-{API_LEVEL};google_apis;x86_64"

# Use ~/.mobilesec/android for consistency with other tools
BASE_DIR = Path.home() / ".mobilesec"
SDK_DIR = BASE_DIR / "android"
CMDLINE_TOOLS_DIR = SDK_DIR / "cmdline-tools" / "latest"

CMDLINE_TOOLS_URLS = {
    "Linux": "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip",
    "Darwin": "https://dl.google.com/android/repository/commandlinetools-mac-11076708_latest.zip", 
    "Windows": "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip"
}

def run_cmd(cmd, env=None, check=True, capture_output=False, silent=False):
    """Run a command with better error handling"""
    if not silent or DEBUG_MODE:
        print(f"> {cmd}")
    
    debug_print(f"Command environment: {env is not None}")
    debug_print(f"Capture output: {capture_output}")
    debug_print(f"Check return code: {check}")
    
    try:
        if capture_output:
            result = subprocess.run(cmd, shell=True, env=env or os.environ, 
                                  capture_output=True, text=True)
        else:
            result = subprocess.run(cmd, shell=True, env=env or os.environ)
        
        if check and result.returncode != 0:
            if capture_output:
                debug_print(f"Command failed with return code {result.returncode}")
                if result.stderr:
                    debug_print(f"Error output: {result.stderr}")
                if not silent:
                    print(f"Command failed with return code {result.returncode}")
                    if result.stderr:
                        print(f"Error: {result.stderr}")
            return False
        
        debug_print(f"Command completed successfully (return code: {result.returncode})")
        return result if capture_output else True
    except Exception as e:
        debug_print(f"Exception running command: {e}")
        if not silent:
            print(f"Error running command: {e}")
        return False

def download_and_extract_sdk():
    """Download and extract Android SDK command-line tools"""
    system = platform.system()
    debug_print(f"Detected OS: {system}")
    
    url = CMDLINE_TOOLS_URLS.get(system)
    if not url:
        print(f"❌ Unsupported OS: {system}")
        return False

    debug_print(f"Creating SDK directory: {SDK_DIR}")
    if DEBUG_MODE:
        info_print(f"📁 Creating SDK directory: {SDK_DIR}")
    SDK_DIR.mkdir(parents=True, exist_ok=True)
    CMDLINE_TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    zip_path = SDK_DIR / "cmdline-tools.zip"
    debug_print(f"Download destination: {zip_path}")
    
    try:
        if DEBUG_MODE:
            info_print(f"📥 Downloading command-line tools from: {url}")
        else:
            info_print("📥 Downloading Android SDK...")
        debug_print("Starting download...")
        urllib.request.urlretrieve(url, zip_path)
        debug_print(f"Download completed. File size: {zip_path.stat().st_size} bytes")

        if DEBUG_MODE:
            info_print("📦 Extracting...")
        else:
            info_print("📦 Installing SDK...")
        temp_dir = SDK_DIR / "cmdline-tools" / "temp"
        debug_print(f"Temporary extraction directory: {temp_dir}")
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            debug_print(f"ZIP contents: {zip_ref.namelist()[:5]}...")  # Show first 5 files
            zip_ref.extractall(temp_dir)

        extracted_dir = temp_dir / "cmdline-tools"
        debug_print(f"Extracted directory: {extracted_dir}")
        debug_print(f"Extracted directory exists: {extracted_dir.is_dir()}")
        
        if extracted_dir.is_dir():
            debug_print("Moving extracted files to latest directory")
            # Move contents to latest directory
            for item in extracted_dir.iterdir():
                debug_print(f"Moving: {item} -> {CMDLINE_TOOLS_DIR}")
                shutil.move(str(item), str(CMDLINE_TOOLS_DIR))

        # Make executables executable
        bin_dir = CMDLINE_TOOLS_DIR / "bin"
        debug_print(f"Setting executable permissions for: {bin_dir}")
        if bin_dir.exists():
            for exe_file in bin_dir.iterdir():
                if exe_file.is_file():
                    debug_print(f"Setting executable: {exe_file}")
                    exe_file.chmod(0o755)

        # Clean up
        debug_print("Cleaning up temporary files")
        shutil.rmtree(temp_dir)
        zip_path.unlink()
        
        info_print("✅ Android SDK installed successfully")
        return True
        
    except Exception as e:
        debug_print(f"Exception during download/extract: {e}")
        print(f"❌ Failed to download/extract SDK: {e}")
        return False

def check_java():
    """Check if Java is installed"""
    try:
        result = subprocess.run(['java', '-version'], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def install_java_macos():
    """Install Java on macOS using Homebrew"""
    try:
        print("📦 Installing Java via Homebrew...")
        result = subprocess.run(['brew', 'install', 'openjdk@11'], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Java: Successfully installed")
            # Add Java to PATH
            print("🔗 Linking Java...")
            subprocess.run(['brew', 'link', 'openjdk@11', '--force'], capture_output=True)
            return True
        else:
            print(f"❌ Java installation failed: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Java installation error: {e}")
        return False

def setup_env():
    """Setup environment variables for Android SDK"""
    tools_bin = CMDLINE_TOOLS_DIR / "bin"
    emulator_dir = SDK_DIR / "emulator"
    platform_tools_dir = SDK_DIR / "platform-tools"

    debug_print(f"Setting up environment variables:")
    debug_print(f"  ANDROID_HOME: {SDK_DIR}")
    debug_print(f"  Tools bin: {tools_bin}")
    debug_print(f"  Emulator dir: {emulator_dir}")
    debug_print(f"  Platform tools: {platform_tools_dir}")

    env = os.environ.copy()
    env["ANDROID_HOME"] = str(SDK_DIR)
    env["ANDROID_SDK_ROOT"] = str(SDK_DIR)
    
    # Add to PATH
    current_path = env.get('PATH', '')
    new_path_components = [
        str(tools_bin),
        str(emulator_dir), 
        str(platform_tools_dir)
    ]
    env["PATH"] = os.pathsep.join(new_path_components + [current_path])
    
    debug_print(f"Updated PATH: {env['PATH'][:200]}...")  # Show first 200 chars
    
    return env

def install_packages(env):
    """Install required Android SDK packages"""
    debug_print("Starting SDK package installation")
    
    if DEBUG_MODE:
        info_print("📄 Accepting SDK licenses...")
    debug_print("Running license acceptance command")
    if not run_cmd("yes | sdkmanager --licenses", env, check=False, silent=True):
        debug_print("License acceptance may have failed, but continuing...")
        if DEBUG_MODE:
            print("⚠️  License acceptance may have failed, continuing...")

    if DEBUG_MODE:
        info_print("📦 Installing required SDK packages...")
    else:
        info_print("📦 Installing SDK packages...")
    
    system_image = get_system_image()
    packages = [
        "platform-tools",
        "emulator", 
        f"platforms;android-{API_LEVEL}",
        system_image
    ]
    
    debug_print(f"Packages to install: {packages}")
    
    for package in packages:
        if DEBUG_MODE:
            info_print(f"   Installing {package}...")
        debug_print(f"Installing package: {package}")
        if not run_cmd(f'sdkmanager "{package}"', env, silent=True):
            debug_print(f"Failed to install package: {package}")
            print(f"❌ Failed to install {package}")
            return False
        debug_print(f"Successfully installed: {package}")
    
    info_print("✅ SDK packages installed successfully")
    debug_print("Package installation completed")
    return True

def create_avd(env):
    """Create Android Virtual Device"""
    debug_print("Starting AVD creation process")
    if DEBUG_MODE:
        info_print(f"📱 Creating AVD: {AVD_NAME}")
    else:
        info_print("📱 Creating Android Virtual Device...")
    
    # Check if AVD already exists
    avd_home = Path.home() / ".android" / "avd"
    avd_path = avd_home / f"{AVD_NAME}.avd"
    
    debug_print(f"Checking for existing AVD at: {avd_path}")
    
    if avd_path.exists():
        info_print(f"✅ AVD already exists")
        debug_print("AVD already exists, skipping creation")
        return True

    # Create AVD with specific configuration for security testing
    system_image = get_system_image()
    cmd = f'echo no | avdmanager create avd -n {AVD_NAME} -k "{system_image}" -d {DEVICE}'
    debug_print(f"Creating AVD with command: {cmd}")
    
    if run_cmd(cmd, env, silent=True):
        info_print(f"✅ AVD created successfully")
        debug_print("AVD creation successful")
        
        # Configure AVD for security testing (if config.ini exists)
        config_file = avd_path / "config.ini"
        debug_print(f"Looking for config file: {config_file}")
        
        if config_file.exists():
            debug_print("Configuring AVD for security testing")
            try:
                # Add security testing friendly settings
                config_additions = [
                    "\n# lu77U-MobileSec security testing configuration\n",
                    "hw.keyboard=yes\n",
                    "hw.dPad=yes\n", 
                    "hw.gsmModem=yes\n",
                    "hw.gps=yes\n",
                    "hw.camera.back=webcam0\n",
                    "hw.camera.front=webcam0\n",
                    "hw.ramSize=2048\n",
                    "disk.dataPartition.size=4096M\n"
                ]
                
                with open(config_file, 'a') as f:
                    f.writelines(config_additions)
                
                if DEBUG_MODE:
                    info_print("🔧 AVD configured for security testing")
                debug_print("Security testing configuration applied")
            except Exception as e:
                debug_print(f"Could not configure AVD settings: {e}")
                if DEBUG_MODE:
                    print(f"⚠️  Could not configure AVD settings: {e}")
        else:
            debug_print("Config file not found, skipping configuration")
        
        return True
    else:
        debug_print("AVD creation failed")
        print(f"❌ Failed to create AVD")
        return False

def check_avd_exists():
    """Check if AVD exists and is properly configured"""
    avd_home = Path.home() / ".android" / "avd"
    avd_path = avd_home / f"{AVD_NAME}.avd"
    return avd_path.exists()

def check_sdk_installed():
    """Check if Android SDK is properly installed"""
    sdkmanager_path = CMDLINE_TOOLS_DIR / "bin" / "sdkmanager"
    if platform.system() == "Windows":
        sdkmanager_path = sdkmanager_path.with_suffix(".bat")
    
    return sdkmanager_path.exists()

def get_avd_info(verbose=False):
    """Get detailed information about the AVD setup"""
    # Get architecture info
    machine = platform.machine().lower()
    system = platform.system()
    system_image = get_system_image()
    
    info = {
        'sdk_installed': check_sdk_installed(),
        'avd_exists': check_avd_exists(),
        'sdk_path': str(SDK_DIR) if SDK_DIR.exists() else None,
        'avd_name': AVD_NAME,
        'api_level': API_LEVEL,
        'system_image': system_image,
        'architecture': machine,
        'platform': system,
        'available': False
    }
    
    # Check emulator compatibility
    is_compatible, compat_msg = verify_emulator_compatibility()
    info['emulator_compatible'] = is_compatible
    info['compatibility_message'] = compat_msg
    
    if info['sdk_installed'] and info['avd_exists']:
        info['available'] = True
        
        # Try to get more details
        try:
            env = setup_env()
            result = run_cmd("avdmanager list avd", env, capture_output=True, silent=not verbose)
            if result and AVD_NAME in result.stdout:
                info['configured'] = True
            
            # Check if emulator binary exists
            emulator_path = SDK_DIR / "emulator" / "emulator"
            if platform.system() == "Windows":
                emulator_path = emulator_path.with_suffix(".exe")
            info['emulator_available'] = emulator_path.exists()
            
            # Test emulator startup capability
            if info['emulator_available']:
                test_success, test_message = test_emulator_startup()
                info['emulator_tested'] = test_success
                info['emulator_test_message'] = test_message
                
                # Add usage instructions
                usage_info = get_emulator_usage_instructions()
                info['usage_instructions'] = usage_info
            
        except Exception as e:
            info['error'] = str(e)
    
    return info

def start_emulator(env, headless=False):
    """Start the AVD emulator with architecture-specific optimizations"""
    if not check_avd_exists():
        print(f"❌ AVD '{AVD_NAME}' does not exist")
        return False
    
    print(f"🚀 Starting emulator: {AVD_NAME}")
    
    # Get architecture-specific arguments
    emulator_args = get_emulator_args()
    
    # Build command with optimizations
    cmd = ['emulator', '-avd', AVD_NAME] + emulator_args
    
    if headless:
        cmd.extend(["-no-window", "-no-audio", "-no-boot-anim"])
    
    # Add verbose output in debug mode
    if DEBUG_MODE:
        cmd.append("-verbose")
        debug_print(f"Emulator command: {' '.join(cmd)}")
    
    # Start emulator in background
    try:
        debug_print("Starting emulator process...")
        process = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL if not DEBUG_MODE else None)
        print(f"✅ Emulator '{AVD_NAME}' started with PID: {process.pid}")
        
        # Give some time for the emulator to initialize
        if not headless:
            print("⏳ Emulator is starting up (this may take a few minutes)...")
        
        return True
    except Exception as e:
        print(f"❌ Failed to start emulator: {e}")
        debug_print(f"Emulator start error: {str(e)}")
        return False

def get_emulator_args():
    """Get architecture-specific emulator arguments for optimal performance"""
    machine = platform.machine().lower()
    system = platform.system()
    args = []
    
    # Check if this is an ARM system
    if any(arch in machine for arch in ['arm64', 'aarch64', 'arm']):
        debug_print(f"Configuring emulator for ARM architecture: {machine}")
        
        if system == "Darwin":  # macOS Apple Silicon
            # Use Hypervisor.framework for better performance on Apple Silicon
            args.extend(["-accel", "hvf"])
            # Optimize for Apple Silicon
            args.extend(["-gpu", "swiftshader_indirect"])
        else:  # ARM Linux/Windows
            # Use KVM on Linux ARM or WHPX on Windows ARM if available
            if system == "Linux":
                args.extend(["-accel", "kvm"])
            args.extend(["-gpu", "swiftshader_indirect"])
        
        # ARM-specific optimizations
        args.extend(["-cpu-delay", "0"])
        
    else:  # x86_64 systems
        debug_print(f"Configuring emulator for x86_64 architecture: {machine}")
        
        if system == "Darwin":  # Intel Mac
            args.extend(["-accel", "hvf"])
        elif system == "Linux":
            args.extend(["-accel", "kvm"])
        elif system == "Windows":
            args.extend(["-accel", "whpx"])
        
        # x86_64 optimizations
        args.extend(["-gpu", "host"])
    
    # Common optimizations for all architectures
    args.extend([
        "-skin", "1080x1920",
        "-memory", "2048",
        "-partition-size", "2048"
    ])
    
    debug_print(f"Emulator args: {' '.join(args)}")
    return args

def verify_emulator_compatibility():
    """Verify that the emulator can run on the current architecture"""
    machine = platform.machine().lower()
    system = platform.system()
    
    debug_print(f"Verifying emulator compatibility for {machine} on {system}")
    
    # Check for known compatibility issues
    if system == "Darwin" and any(arch in machine for arch in ['arm64', 'aarch64']):
        # Apple Silicon - check for Rosetta 2 or native support
        try:
            # Check if we can run emulator
            result = subprocess.run(['which', 'emulator'], capture_output=True, text=True)
            if result.returncode != 0:
                debug_print("Emulator binary not found in PATH")
                return False, "Emulator binary not found"
            
            # Try a quick emulator version check
            emulator_path = result.stdout.strip()
            version_result = subprocess.run([emulator_path, '-version'], 
                                          capture_output=True, text=True, timeout=10)
            
            if version_result.returncode == 0:
                debug_print("Emulator compatibility verified")
                return True, "Compatible"
            else:
                debug_print(f"Emulator version check failed: {version_result.stderr}")
                return False, "Emulator version check failed"
                
        except subprocess.TimeoutExpired:
            debug_print("Emulator version check timed out")
            return False, "Emulator check timeout"
        except Exception as e:
            debug_print(f"Emulator compatibility check failed: {e}")
            return False, f"Compatibility check error: {e}"
    
    # For other architectures, assume compatibility
    debug_print("Assuming emulator compatibility for this platform")
    return True, "Compatible"

def install_avd(debug=False):
    """Main installation function"""
    global DEBUG_MODE
    DEBUG_MODE = debug
    
    debug_print("Starting AVD installation")
    
    info_print("📱 Installing Android Virtual Device...")
    
    # Check Java first
    debug_print("Checking Java installation")
    if not check_java():
        info_print("☕ Installing Java...")
        debug_print("Java not found, attempting installation")
        if platform.system() == "Darwin":  # macOS
            if not install_java_macos():
                print("❌ Java installation failed. Please install Java manually:")
                print("   brew install openjdk@11")
                return False
        else:
            print("❌ Java not found. Please install Java manually:")
            print("   Linux: sudo apt install openjdk-11-jdk")
            print("   Windows: Download from https://adoptium.net/")
            return False
    else:
        debug_print("Java check passed")
    
    # Create base directory
    debug_print(f"Creating base directory: {BASE_DIR}")
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    
    # Download and install SDK if not present
    debug_print("Checking if SDK is already installed")
    if not check_sdk_installed():
        debug_print("SDK not found, downloading and installing")
        if not download_and_extract_sdk():
            debug_print("SDK installation failed")
            return False
    else:
        info_print("✅ Android SDK already installed")
        debug_print("SDK already installed, skipping download")
    
    # Setup environment
    debug_print("Setting up environment variables")
    env = setup_env()
    
    # Install required packages
    debug_print("Installing required SDK packages")
    if not install_packages(env):
        debug_print("Package installation failed")
        return False
    
    # Create AVD
    debug_print("Creating AVD")
    if not create_avd(env):
        debug_print("AVD creation failed")
        return False
    debug_print("AVD installation process completed successfully")
    
    info_print("✅ Android Virtual Device installed successfully")
    
    debug_print("Installation function returning success")
    return True

def test_emulator_startup(timeout=30):
    """Test if the emulator can start and run properly"""
    if not check_avd_exists():
        return False, "AVD does not exist"
    
    if not check_sdk_installed():
        return False, "Android SDK not installed"
    
    debug_print("Testing emulator startup...")
    
    try:
        env = setup_env()
        emulator_path = SDK_DIR / "emulator" / "emulator"
        
        if platform.system() == "Windows":
            emulator_path = emulator_path.with_suffix(".exe")
        
        if not emulator_path.exists():
            return False, "Emulator binary not found"
        
        # Test 1: Check if emulator can list AVDs
        list_cmd = [str(emulator_path), "-list-avds"]
        debug_print(f"Testing AVD list: {' '.join(list_cmd)}")
        
        result = subprocess.run(list_cmd, env=env, capture_output=True, text=True, timeout=10)
        if result.returncode != 0 or AVD_NAME not in result.stdout:
            return False, f"AVD '{AVD_NAME}' not found in emulator list"
        
        # Test 2: Check system image exists
        system_image_path = SDK_DIR / "system-images" / f"android-{API_LEVEL}" / "google_apis" / get_system_image().split(';')[-1]
        debug_print(f"Checking system image path: {system_image_path}")
        
        if not system_image_path.exists():
            return False, f"System image not found at {system_image_path}"
        
        # Test 3: Test emulator help (basic functionality)
        help_cmd = [str(emulator_path), "-help"]
        result = subprocess.run(help_cmd, env=env, capture_output=True, text=True, timeout=5)
        
        if result.returncode != 0:
            return False, "Emulator binary is not functional"
        
        # Test 4: Test the exact command users should use
        exact_cmd = [str(emulator_path), "-avd", AVD_NAME, "-no-window", "-no-boot-anim", "-no-audio", "-gpu", "off"]
        debug_print(f"Testing exact user command: {' '.join(exact_cmd)}")
        
        try:
            # Start the process but kill it quickly - we just want to see if it starts without panicking
            process = subprocess.Popen(exact_cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Wait a short time to see if it panics immediately
            try:
                stdout, stderr = process.communicate(timeout=3)
                # If it completes quickly, check for panic
                if "PANIC" in stderr:
                    return False, f"Emulator panic: {stderr.split('PANIC:')[1].split('\\n')[0].strip()}"
                elif "Cannot find AVD system path" in stderr:
                    return False, "Cannot find AVD system path - environment issue"
                elif "ANDROID_SDK_ROOT" in stderr and ("not" in stderr.lower() or "cannot" in stderr.lower()):
                    return False, "ANDROID_SDK_ROOT environment variable issue"
            except subprocess.TimeoutExpired:
                # This is good - emulator started and didn't panic immediately
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        except Exception as e:
            return False, f"Emulator test failed: {str(e)}"
        
        # If we get here without panics, the emulator should be able to start
        debug_print("Emulator validation completed without critical errors")
        return True, f"Emulator works correctly with: {emulator_path} -avd {AVD_NAME}"
            
    except subprocess.TimeoutExpired:
        return False, f"Emulator test timed out after {timeout} seconds"
    except Exception as e:
        debug_print(f"Emulator test error: {e}")
        return False, f"Emulator test failed: {str(e)}"

def get_emulator_usage_instructions():
    """Get instructions for properly using the emulator"""
    env = setup_env()
    emulator_path = SDK_DIR / "emulator" / "emulator"
    
    instructions = {
        'direct_command': f"{emulator_path} -avd {AVD_NAME}",
        'env_setup': [
            f"export ANDROID_SDK_ROOT={SDK_DIR}",
            f"export ANDROID_HOME={SDK_DIR}",
            f"export PATH={SDK_DIR}/emulator:{SDK_DIR}/platform-tools:$PATH"
        ],
        'recommended_usage': f"Use the lu77U-MobileSec tools which automatically set the correct environment"
    }
    
    return instructions

def start_avd_properly():
    """Start the AVD with the correct environment - user-friendly function"""
    if not check_avd_exists():
        print(f"❌ AVD '{AVD_NAME}' does not exist. Run 'lu77u-mobilesec doctor' first.")
        return False
    
    if not check_sdk_installed():
        print(f"❌ Android SDK not installed. Run 'lu77u-mobilesec doctor' first.")
        return False
    
    print(f"🚀 Starting lu77U-MobileSec Android Virtual Device...")
    print(f"📱 AVD Name: {AVD_NAME}")
    print(f"🏗️  Architecture: {platform.machine()}")
    
    try:
        env = setup_env()
        return start_emulator(env, headless=False)
    except Exception as e:
        print(f"❌ Failed to start emulator: {e}")
        return False

# === MAIN INSTALLATION FUNCTION ===
def install_mobilesec(debug=False):
    """Main installation function for lu77U-MobileSec"""
    global DEBUG_MODE
    DEBUG_MODE = debug
    
    debug_print("Starting lu77U-MobileSec installation")
    
    info_print("🔧 Installing lu77U-MobileSec...")
    
    # Check Java first
    debug_print("Checking Java installation")
    if not check_java():
        info_print("☕ Installing Java...")
        debug_print("Java not found, attempting installation")
        if platform.system() == "Darwin":  # macOS
            if not install_java_macos():
                print("❌ Java installation failed. Please install Java manually:")
                print("   brew install openjdk@11")
                return False
        else:
            print("❌ Java not found. Please install Java manually:")
            print("   Linux: sudo apt install openjdk-11-jdk")
            print("   Windows: Download from https://adoptium.net/")
            return False
    else:
        debug_print("Java check passed")
    
    # Create base directory
    debug_print(f"Creating base directory: {BASE_DIR}")
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    
    # Download and install SDK if not present
    debug_print("Checking if SDK is already installed")
    if not check_sdk_installed():
        debug_print("SDK not found, downloading and installing")
        if not download_and_extract_sdk():
            debug_print("SDK installation failed")
            return False
    else:
        info_print("✅ Android SDK already installed")
        debug_print("SDK already installed, skipping download")
    
    # Setup environment
    debug_print("Setting up environment variables")
    env = setup_env()
    
    # Install required packages
    debug_print("Installing required SDK packages")
    if not install_packages(env):
        debug_print("Package installation failed")
        return False
    
    # Create AVD
    debug_print("Creating AVD")
    if not create_avd(env):
        debug_print("AVD creation failed")
        return False
    
    info_print("✅ lu77U-MobileSec installed successfully")
    debug_print("lu77U-MobileSec installation process completed")
    
    # Provide usage instructions
    instructions = get_emulator_usage_instructions()
    info_print("\n📚 Emulator Usage Instructions:")
    info_print(f"  Direct command: {instructions['direct_command']}")
    info_print("  Environment setup:")
    for setup_command in instructions['env_setup']:
        info_print(f"    {setup_command}")
    info_print(f"  Recommended usage: {instructions['recommended_usage']}")
    
    return True

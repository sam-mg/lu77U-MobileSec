#!/usr/bin/env python3
"""
System doctor for lu77U-MobileSec

Checks system dependencies and configuration. Also installs missing components.
"""

import subprocess
import time
import shutil
import os
from ..validators.tool_checker import (
    check_jadx, check_apktool, check_aapt, check_nodejs, 
    check_npm, check_ollama, check_react_native_decompiler,
    install_react_native_decompiler, check_blutter, install_blutter,
    get_jadx_detailed, get_apktool_detailed, get_aapt_detailed,
    get_nodejs_detailed, get_npm_detailed, get_ollama_detailed,
    get_blutter_detailed, get_react_native_decompiler_detailed,
    check_mobsf, install_mobsf, start_mobsf, get_mobsf_detailed,
    check_avd, get_avd_detailed, install_avd, start_avd,
    check_adb, get_adb_detailed, check_java, get_java_detailed,
    check_frida, get_frida_detailed
)
from ..validators.detailed_checker import DetailedToolChecker
from ...utils.config.api_keys import check_groq_api_key, ensure_groq_api_key


class MobileSecDoctor:
    """System doctor for checking dependencies and configuration"""
    
    def __init__(self, detailed: bool = False):
        self.checks_passed = 0
        self.checks_total = 0
        self.detailed = detailed
    
    def print_header(self):
        """Print doctor header"""
        banner = """
╔════════════════════════════════════════════════════════════════════════════════╗
║                                                                                ║
║                            🤖 lu77U-MobileSec v1.0 🔐                          ║
║                                                                                ║
║        Advanced APK Security Analysis & Vulnerability Detection Platform       ║
║                                                                                ║
║          📱 Multi-Framework: Java/Kotlin • React Native • Flutter              ║
║        🔍 Static Analysis: JADX • APKTool • Blutter • Pattern Scanning         ║
║     🚀 Dynamic Analysis: MobSF • Frida • Android Virtual Device Integration    ║
║    🤖 AI-Powered: Groq • Ollama • Smart Vulnerability Detection & Fixes        ║
║    📁 Structured Output: Organized Analysis Results • Detailed Reports         ║
║      🛠️  Auto-Installation: Missing Dependencies Installed Automatically        ║
║      🔧 System Doctor: Comprehensive Environment Setup & Validation            ║
║                                                                                ║
╚════════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
        if self.detailed:
            print("🔧 Detailed diagnostic mode enabled")
        print("\n🔍 Checking system dependencies and configuration...\n")
    
    def run_doctor(self):
        """Run comprehensive system check and installation"""
        self.print_header()
        
        print("\n🐍 Checking Python environment...")
        # Check Python dependencies
        self.check_python_requirements()
        
        print("\n🔧 Checking Android analysis tools...")
        # Check Java first (required for Android tools)
        self._check_tool("Java JDK", check_java, get_java_detailed)
        
        # Check external tools
        self._check_tool("JADX", check_jadx, get_jadx_detailed)
        self._check_tool("APKTool", check_apktool, get_apktool_detailed) 
        self._check_tool("AAPT", check_aapt, get_aapt_detailed)
        self._check_tool("ADB", check_adb, get_adb_detailed)
        self._check_tool("Node.js", check_nodejs, get_nodejs_detailed)
        self._check_tool("NPM", check_npm, get_npm_detailed)
        
        print("\n🔧 Checking Development tools...")
        # Check development environment
        self._check_tool_detailed("Git", DetailedToolChecker.get_git_detailed)
        
        print("\n⚛️  Checking React Native tools...")
        # Check React Native specific tools
        self.check_react_native_decompiler()
        
        print("\n🦋 Checking Flutter tools...")
        # Check Flutter specific tools  
        self.check_blutter()
        
        print("\n🔒 Checking Security Analysis tools...")
        # Check MobSF
        self.check_mobsf()
        
        # Check Frida for dynamic analysis
        self._check_tool("Frida", check_frida, get_frida_detailed)
        
        print("\n📱 Checking Android Virtual Device...")
        # Check AVD setup
        self.check_avd()
        
        # Set up Android environment variables if AVD is available
        if check_avd():
            if self.detailed:
                print("\n🔧 Setting up Android environment...")
            self.setup_android_environment()
        
        # Check and setup Ollama with model
        self.setup_ollama_with_model()
        
        # Check and setup API keys
        self.setup_groq_api_key()
        
        # Check and setup MobSF
        self.setup_mobsf()
        
        self.print_summary()
    
    def setup_ollama_with_model(self):
        """Setup Ollama service and ensure DeepSeek model is installed"""
        print("\n🤖 Setting up Ollama and DeepSeek model...")
        
        # Check if Ollama is installed
        if self.detailed:
            info = get_ollama_detailed()
            if not info['available']:
                print("❌ Ollama: Not installed")
                print("📥 Installing Ollama automatically...")
                if not self._install_ollama():
                    print("❌ Failed to install Ollama. Please install manually from: https://ollama.com/download")
                    self.checks_total += 1
                    return
            else:
                print("✅ Ollama                   Installed")
                if info['path']:
                    print(f"   📁 Path: {info['path']}")
                if info['version']:
                    print(f"   🏷️  Version: {info['version']}")
                print()  # Add spacing
                self.checks_passed += 1
                self.checks_total += 1
        else:
            if not check_ollama():
                print("❌ Ollama: Not installed")
                print("📥 Installing Ollama automatically...")
                if not self._install_ollama():
                    print("❌ Failed to install Ollama. Please install manually from: https://ollama.com/download")
                    self.checks_total += 1
                    return
            else:
                print("✅ Ollama                   Installed")
                print()  # Add spacing
                self.checks_passed += 1
                self.checks_total += 1
        
        # Start Ollama service
        print("🚀 Starting Ollama service...")
        try:
            # Start ollama serve in background
            process = subprocess.Popen(
                ['ollama', 'serve'], 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            
            # Wait for service to start - no timeout, wait until ready
            if self.detailed:
                print("⏳ Waiting for Ollama service to start...")
            max_retries = 30  # 30 attempts, 2 seconds each = 60 seconds max
            retry_count = 0
            
            while retry_count < max_retries:
                time.sleep(2)
                try:
                    # Check if service is running and get model list
                    result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        print("✅ Ollama service           Running")
                        print()  # Add spacing
                        self.checks_passed += 1
                        
                        # Check for DeepSeek model
                        if 'deepseek-coder:6.7b' in result.stdout:
                            print("✅ DeepSeek Coder 6.7B      Available")
                            print()  # Add spacing
                            self.checks_passed += 1
                        else:
                            print("📥 DeepSeek Coder 6.7B: Not found, installing...")
                            self._install_deepseek_model()
                        
                        self.checks_total += 2
                        print("✅ Stopped ollama service process")
                        print()  # Add spacing
                        return
                        
                except Exception:
                    pass
                
                retry_count += 1
                print(f"⏳ Waiting... (attempt {retry_count}/{max_retries})")
            
            print("❌ Ollama service: Failed to start after waiting")
            print("💡 Try manually running: ollama serve")
                
        except Exception as e:
            print(f"❌ Ollama setup error: {e}")
        
        self.checks_total += 2
    
    def _install_deepseek_model(self):
        """Install DeepSeek Coder model - NO TIMEOUT"""
        try:
            print("📦 Installing DeepSeek Coder 6.7B model...")
            print("⏳ This may take several minutes, please wait...")
            
            # No timeout - let it complete
            result = subprocess.run(
                ['ollama', 'pull', 'deepseek-coder:6.7b'], 
                capture_output=True, 
                text=True
            )
            
            if result.returncode == 0:
                print("✅ DeepSeek Coder 6.7B      Successfully installed")
                print()  # Add spacing
                self.checks_passed += 1
            else:
                print(f"❌ DeepSeek model installation failed: {result.stderr}")
                print()  # Add spacing
                
        except Exception as e:
            print(f"❌ DeepSeek model installation error: {e}")

    def _install_ollama(self):
        """Install Ollama using brew on macOS"""
        try:
            print("📦 Installing Ollama via Homebrew...")
            result = subprocess.run(['brew', 'install', 'ollama'], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Ollama: Successfully installed")
                return True
            else:
                print(f"❌ Ollama installation failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Ollama installation error: {e}")
            return False
    
    def check_react_native_decompiler(self):
        """Check and install React Native decompiler if needed"""
        self.checks_total += 1
        
        # First check if Node.js and NPM are available
        if not check_nodejs() or not check_npm():
            print("❌ React Native Decompiler: Requires Node.js and NPM")
            return
        
        if self.detailed:
            info = get_react_native_decompiler_detailed()
            if info['available']:
                print("✅ React Native Decompiler  Available")
                if info['version']:
                    print(f"   🏷️  Version: {info['version']}")
                if info['path']:
                    print(f"   📁 Path: {info['path']}")
                if 'error' in info:
                    print(f"   ⚠️  {info['error']}")
                print()  # Add spacing
                self.checks_passed += 1
            else:
                print("❌ React Native Decompiler  Not found")
                if 'error' in info:
                    print(f"   ⚠️  {info['error']}")
                print("📥 Installing react-native-decompiler automatically...")
                
                if install_react_native_decompiler():
                    print("✅ React Native Decompiler: Successfully installed")
                    self.checks_passed += 1
                else:
                    print("❌ React Native Decompiler: Installation failed")
                    print("💡 Manual install: npm install -g react-native-decompiler")
                print()  # Add spacing
        else:
            # Check if react-native-decompiler is available
            if check_react_native_decompiler():
                print("✅ React Native Decompiler  Available")
                self.checks_passed += 1
            else:
                print("❌ React Native Decompiler  Not found")
                print("📥 Installing react-native-decompiler automatically...")
                
                if install_react_native_decompiler():
                    print("✅ React Native Decompiler: Successfully installed")
                    self.checks_passed += 1
                else:
                    print("❌ React Native Decompiler: Installation failed")
                    print("💡 Manual install: npm install -g react-native-decompiler")

    def check_blutter(self):
        """Check and install Blutter if needed"""
        self.checks_total += 1
        
        if self.detailed:
            info = get_blutter_detailed()
            if info['available']:
                print("✅ Blutter (Flutter)        Available")
                if info['path']:
                    print(f"   📁 Path: {info['path']}")
                if info['version']:
                    print(f"   🏷️  Version: {info['version']}")
                print()  # Add spacing
                self.checks_passed += 1
            else:
                print("❌ Blutter (Flutter)        Not found")
                print("📥 Installing Blutter automatically...")
                
                if install_blutter():
                    print("✅ Blutter (Flutter): Successfully installed")
                    print("💡 Note: Add ~/.local/bin to PATH if not already done")
                    self.checks_passed += 1
                else:
                    print("❌ Blutter (Flutter): Installation failed")
                    print("💡 Manual install: git clone https://github.com/worawit/blutter.git")
                print()  # Add spacing
        else:
            # Check if Blutter is available
            if check_blutter():
                print("✅ Blutter (Flutter)        Available")
                self.checks_passed += 1
            else:
                print("❌ Blutter (Flutter)        Not found")
                print("📥 Installing Blutter automatically...")
                
                if install_blutter():
                    print("✅ Blutter (Flutter): Successfully installed")
                    print("💡 Note: Add ~/.local/bin to PATH if not already done")
                    self.checks_passed += 1
                else:
                    print("❌ Blutter (Flutter): Installation failed")
                    print("💡 Manual install: git clone https://github.com/worawit/blutter.git")

    def check_avd(self):
        """Check and install Android Virtual Device if needed"""
        self.checks_total += 1
        
        if self.detailed:
            info = get_avd_detailed(verbose=True)
            if info['available']:
                print("✅ Android Virtual Device   Available")
                if info.get('avd_name'):
                    print(f"   📱 AVD Name: {info['avd_name']}")
                if info.get('api_level'):
                    print(f"   🤖 API Level: {info['api_level']}")
                if info.get('system_image'):
                    print(f"   🏗️  System Image: {info['system_image']}")
                if info.get('architecture'):
                    print(f"   💻 Architecture: {info['architecture']}")
                if info.get('sdk_path'):
                    print(f"   📁 SDK Path: {info['sdk_path']}")
                if info.get('emulator_available'):
                    print("   🚀 Emulator: Available")
                    # Show emulator test results if available
                    if info.get('emulator_tested') is not None:
                        if info['emulator_tested']:
                            print("   ✅ Emulator Test: Passed")
                        else:
                            print("   ⚠️  Emulator Test: Failed")
                        if info.get('emulator_test_message'):
                            print(f"      {info['emulator_test_message']}")
                    
                    # Show usage instructions
                    if info.get('usage_instructions'):
                        usage = info['usage_instructions']
                        print("   📋 Usage Instructions:")
                        print(f"      Direct: {usage['direct_command']}")
                        print("      Environment setup:")
                        for env_cmd in usage['env_setup']:
                            print(f"        {env_cmd}")
                else:
                    print("   ⚠️  Emulator: Not found")
                print()  # Add spacing
                self.checks_passed += 1
            else:
                print("❌ Android Virtual Device   Not found")
                if 'error' in info:
                    print(f"   ⚠️  {info['error']}")
                print("📥 Installing Android Virtual Device automatically...")
                
                if install_avd():
                    print("✅ Android Virtual Device: Successfully installed")
                    self.checks_passed += 1
                else:
                    print("❌ Android Virtual Device: Installation failed")
                print()  # Add spacing
        else:
            # Check if AVD is available
            if check_avd():
                print("✅ Android Virtual Device   Available")
                self.checks_passed += 1
            else:
                print("❌ Android Virtual Device   Not found")
                print("📥 Installing Android Virtual Device automatically...")
                
                if install_avd():
                    print("✅ Android Virtual Device: Successfully installed")
                    self.checks_passed += 1
                else:
                    print("❌ Android Virtual Device: Installation failed")

    def check_mobsf(self):
        """Check and install MobSF if needed"""
        self.checks_total += 1
        
        if self.detailed:
            info = get_mobsf_detailed()
            if info['available']:
                print("✅ MobSF (Mobile Security)  Available")
                if info['path']:
                    print(f"   📁 Path: {info['path']}")
                if info['version']:
                    print(f"   🏷️  Version: {info['version']}")
                
                if info['running']:
                    print("   🟢 Status: Running on http://127.0.0.1:8000")
                    
                    # Show authentication status
                    if info.get('authenticated', False):
                        print("   ✅ Authentication: Working (mobsf/mobsf)")
                    else:
                        print("   ⚠️  Authentication: Failed (mobsf/mobsf)")
                        
                    if info.get('api_key'):
                        print(f"   🔑 API Key: {info['api_key'][:20]}...")
                    
                    # Setup browser access automatically
                    self.setup_mobsf_browser_access()
                    
                    self.checks_passed += 1
                else:
                    print("   🟡 Status: Installed but not running")
                    print("🚀 Starting MobSF server...")
                    if start_mobsf():
                        print("✅ MobSF server: Started successfully")
                        print("   🌐 Access at: http://127.0.0.1:8000")
                        print("   🔐 Authentication: Automated (mobsf/mobsf)")
                        
                        # Setup browser access
                        self.setup_mobsf_browser_access()
                        
                        self.checks_passed += 1
                    else:
                        print("❌ MobSF server: Failed to start")
                        print("💡 Manual start: cd ~/.mobilesec/tools/Mobile-Security-Framework-MobSF && ./run.sh")
                    print()  # Add spacing
            else:
                print("❌ MobSF (Mobile Security)  Not found")
                if 'error' in info:
                    print(f"   ⚠️  {info['error']}")
                print("📥 Installing MobSF automatically...")
                
                if install_mobsf():
                    print("✅ MobSF: Successfully installed")
                    print("🚀 Starting MobSF server...")
                    if start_mobsf():
                        print("✅ MobSF server: Started successfully")
                        print("   🌐 Access at: http://127.0.0.1:8000")
                        print("   � Authentication: Automated (mobsf/mobsf)")
                        self.checks_passed += 1
                    else:
                        print("❌ MobSF server: Failed to start")
                        print("💡 Please check the installation and try starting manually:")
                        print("   cd ~/.mobilesec/tools/Mobile-Security-Framework-MobSF && ./run.sh")
                        print("   🌐 Then access: http://127.0.0.1:8000")
                        print("   🔑 Default credentials: mobsf/mobsf")
                else:
                    print("❌ MobSF: Installation failed")
                    print("💡 Manual install:")
                    print("   mkdir -p ~/.mobilesec/tools")
                    print("   cd ~/.mobilesec/tools")
                    print("   git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git")
                    print("   cd Mobile-Security-Framework-MobSF")
                    print("   ./setup.sh  # or setup.bat on Windows")
                print()  # Add spacing
        else:
            # Check if MobSF is available and running
            if check_mobsf():
                print("✅ MobSF (Mobile Security)  Running")
                if self.detailed:
                    print("   🌐 Access at: http://127.0.0.1:8000")
                    print("   🔐 Authentication: Automated (mobsf/mobsf)")
                
                # Setup browser access
                self.setup_mobsf_browser_access()
                
                self.checks_passed += 1
            else:
                # Check if installed but not running
                info = get_mobsf_detailed()
                if info['available']:
                    print("🟡 MobSF (Mobile Security)  Installed, starting...")
                    if start_mobsf():
                        print("✅ MobSF server: Started successfully")
                        print("   🌐 Access at: http://127.0.0.1:8000")
                        print("   � Authentication: Automated (mobsf/mobsf)")
                        self.checks_passed += 1
                    else:
                        print("❌ MobSF server: Failed to start")
                        print("💡 Manual start: cd ~/.mobilesec/tools/Mobile-Security-Framework-MobSF && ./run.sh")
                        print("   🌐 Access: http://127.0.0.1:8000")
                        print("   � Authentication: Automated (mobsf/mobsf)")
                else:
                    print("❌ MobSF (Mobile Security)  Not found")
                    print("📥 Installing MobSF automatically...")
                    
                    if install_mobsf():
                        print("✅ MobSF: Successfully installed")
                        print("🚀 Starting MobSF server...")
                        if start_mobsf():
                            print("✅ MobSF server: Started successfully")
                            print("   🌐 Access at: http://127.0.0.1:8000")
                            print("   🔑 Default credentials: mobsf/mobsf")
                            self.checks_passed += 1
                        else:
                            print("❌ MobSF server: Failed to start")
                            print("💡 Please check the installation and try starting manually:")
                            print("   cd ~/.mobilesec/tools/Mobile-Security-Framework-MobSF && ./run.sh")
                            print("   🌐 Then access: http://127.0.0.1:8000")
                            print("   🔑 Default credentials: mobsf/mobsf")
                    else:
                        print("❌ MobSF: Installation failed")
                        print("💡 Manual install:")
                        print("   mkdir -p ~/.mobilesec/tools")
                        print("   cd ~/.mobilesec/tools")
                        print("   git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git")
                        print("   cd Mobile-Security-Framework-MobSF")
                        print("   ./setup.sh  # or setup.bat on Windows")
                        print("   🌐 Access: http://127.0.0.1:8000")
                        print("   🔑 Default credentials: mobsf/mobsf")

    def setup_groq_api_key(self):
        """Setup GROQ API key"""
        print("\n🔑 Checking GROQ API configuration...")
        
        if check_groq_api_key():
            print("✅ GROQ API Key             Available")
            
            if self.detailed:
                # Try to get more info about the API key (without revealing it)
                try:
                    import os
                    from pathlib import Path
                    
                    # Check where the key is stored
                    if 'GROQ_API_KEY' in os.environ:
                        print("   📁 Source: Environment variable (GROQ_API_KEY)")
                    
                    # Check if there's a config file
                    config_dir = Path.home() / '.mobilesec-p4tch3r'
                    config_file = config_dir / 'config.json'
                    if config_file.exists():
                        print(f"   📁 Config file: {config_file}")
                    
                except Exception:
                    pass
                print()  # Add spacing
            
            self.checks_passed += 1
        else:
            print("❌ GROQ API Key             Not found")
            try:
                api_key = ensure_groq_api_key()
                if api_key:
                    print("✅ GROQ API Key: Configured")
                    if self.detailed:
                        print("   📁 Source: Newly configured in ~/.mobilesec-p4tch3r/config.json")
                        print()  # Add spacing
                    self.checks_passed += 1
            except ValueError:
                print("⚠️  GROQ API Key: Skipped")
                if self.detailed:
                    print()  # Add spacing
        
        self.checks_total += 1
    
    def setup_mobsf(self):
        """Setup MobSF environment (configuration check only)"""
        if self.detailed:
            print("\n🔧 Verifying MobSF final configuration...")
        
        # Simple check without triggering browser setup again
        try:
            import requests
            response = requests.get('http://127.0.0.1:8000', timeout=5)
            if response.status_code in [200, 302]:
                if self.detailed:
                    print("✅ MobSF                   Ready for dynamic analysis")
                    print("   🌐 Server: http://127.0.0.1:8000")
                    print("   🔐 Credentials: mobsf/mobsf")
                    print("   📱 Ready for APK uploads and testing")
                    print("   🎉 Browser access already configured")
                self.checks_passed += 1
            else:
                if self.detailed:
                    print("❌ MobSF                   Not responding")
                    print("💡 Check MobSF server status")
        except:
            if self.detailed:
                print("❌ MobSF                   Not accessible")
                print("💡 MobSF server may not be running")
        
        self.checks_total += 1
    
    def setup_mobsf_browser_access(self):
        """Setup MobSF browser authentication automatically"""
        if self.detailed:
            print("🔧 Setting up MobSF browser access...")
        
        server = "http://127.0.0.1:8000"
        
        try:
            import requests
            import re
            
            session = requests.Session()
            
            # Get login page
            if self.detailed:
                print("   1️⃣ Accessing login page...")
            login_page = session.get(f"{server}/login/", timeout=10)
            
            if login_page.status_code != 200:
                if self.detailed:
                    print(f"   ❌ Cannot access login page: {login_page.status_code}")
                return False
            
            # Extract CSRF token
            if self.detailed:
                print("   2️⃣ Extracting CSRF token...")
            csrf_token = None
            patterns = [
                r'<input[^>]*name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
                r'name="csrfmiddlewaretoken"\s+value="([^"]+)"',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, login_page.text)
                if match:
                    csrf_token = match.group(1)
                    break
            
            if not csrf_token:
                if self.detailed:
                    print("   ❌ Could not extract CSRF token")
                return False
            
            if self.detailed:
                print(f"   ✅ CSRF token: {csrf_token[:20]}...")
            
            # Submit login
            if self.detailed:
                print("   3️⃣ Submitting login credentials...")
            login_data = {
                'username': 'mobsf',
                'password': 'mobsf',
                'csrfmiddlewaretoken': csrf_token,
            }
            
            headers = {
                'Referer': f"{server}/login/",
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            
            login_response = session.post(
                f"{server}/login/",
                data=login_data,
                headers=headers,
                timeout=10,
                allow_redirects=True
            )
            
            # Check login success
            if login_response.status_code == 200 and 'login' not in login_response.url:
                if self.detailed:
                    print("   ✅ Login successful!")
                
                # Test dashboard access
                dashboard = session.get(f"{server}/", timeout=10)
                if dashboard.status_code == 200 and 'login' not in dashboard.url:
                    if self.detailed:
                        print("   ✅ Dashboard access confirmed")
                        
                        # Save session info
                        cookies = session.cookies.get_dict()
                        print(f"\n   📋 Session Cookies:")
                        for name, value in cookies.items():
                            print(f"      {name}: {value[:20]}...")
                        
                        print(f"\n   🌐 MobSF is now accessible at: {server}")
                        print("   📝 Browser login credentials: mobsf/mobsf")
                        print()  # Add spacing
                    
                    return True
                else:
                    if self.detailed:
                        print(f"   ❌ Dashboard access failed: {dashboard.status_code}")
                    return False
            else:
                if self.detailed:
                    print(f"   ❌ Login failed: {login_response.status_code}")
                    print(f"      URL: {login_response.url}")
                return False
                
        except Exception as e:
            if self.detailed:
                print(f"   ❌ Browser setup failed: {e}")
            return False

    def setup_android_environment(self):
        """Set up Android environment variables for the current session"""
        try:
            from pathlib import Path
            
            # Get SDK directory path
            sdk_base_dir = Path.home() / ".mobilesec" / "android"
            
            # Set up Android environment variables
            android_sdk_path = str(sdk_base_dir)
            emulator_path = str(sdk_base_dir / "emulator")
            platform_tools_path = str(sdk_base_dir / "platform-tools")
            cmdline_tools_path = str(sdk_base_dir / "cmdline-tools" / "latest" / "bin")
            
            # Set environment variables
            os.environ["ANDROID_SDK_ROOT"] = android_sdk_path
            os.environ["ANDROID_HOME"] = android_sdk_path
            
            # Update PATH to include Android tools
            current_path = os.environ.get("PATH", "")
            android_paths = [emulator_path, platform_tools_path, cmdline_tools_path]
            
            # Add Android paths to the beginning of PATH if not already present
            path_components = current_path.split(os.pathsep)
            for android_path in reversed(android_paths):  # reversed to maintain order
                if android_path not in path_components:
                    path_components.insert(0, android_path)
            
            os.environ["PATH"] = os.pathsep.join(path_components)
            
            if self.detailed:
                print("🔧 Android environment variables set:")
                print(f"   ANDROID_SDK_ROOT: {android_sdk_path}")
                print(f"   ANDROID_HOME: {android_sdk_path}")
                print(f"   Added to PATH: {', '.join(android_paths)}")
                print()
            # In regular mode, set up environment silently
            
            return True
            
        except Exception as e:
            if self.detailed:
                print(f"⚠️  Failed to set Android environment: {e}")
            return False

    def _check_tool_detailed(self, name: str, detailed_func):
        """Helper to check a tool using DetailedToolChecker and print result"""
        self.checks_total += 1
        try:
            info = detailed_func()
            if info['available']:
                print(f"✅ {name:<25} Available")
                if self.detailed:
                    if info['version']:
                        print(f"   🏷️  Version: {info['version']}")
                    if info['path']:
                        print(f"   📁 Path: {info['path']}")
                    if 'models' in info and info['models']:
                        print(f"   🤖 Models: {', '.join(info['models'])}")
                    if 'error' in info:
                        print(f"   ⚠️  Note: {info['error']}")
                    print()  # Add spacing between tools
                self.checks_passed += 1
            else:
                print(f"❌ {name:<25} Not found")
                if self.detailed and 'error' in info:
                    print(f"   ⚠️  {info['error']}")
                    print()  # Add spacing between tools
        except Exception as e:
            print(f"❌ {name:<25} Error checking - {e}")
            if self.detailed:
                print()  # Add spacing between tools
    
    def _check_tool(self, name: str, check_func, detailed_func=None):
        """Helper to check a tool and print result"""
        self.checks_total += 1
        try:
            if self.detailed and detailed_func:
                info = detailed_func()
                if info['available']:
                    print(f"✅ {name:<25} Available")
                    if info['version']:
                        print(f"   🏷️  Version: {info['version']}")
                    if info['path']:
                        print(f"   📁 Path: {info['path']}")
                    if 'models' in info and info['models']:
                        print(f"   🤖 Models: {', '.join(info['models'])}")
                    if 'error' in info:
                        print(f"   ⚠️  Note: {info['error']}")
                    print()  # Add spacing between tools
                    self.checks_passed += 1
                else:
                    print(f"❌ {name:<25} Not found")
                    if 'error' in info:
                        print(f"   ⚠️  {info['error']}")
                    print()  # Add spacing between tools
            else:
                if check_func():
                    print(f"✅ {name:<25} Available")
                    self.checks_passed += 1
                else:
                    print(f"❌ {name:<25} Not found")
        except Exception as e:
            print(f"❌ {name:<25} Error checking - {e}")
            if self.detailed:
                print()  # Add spacing between tools
    
    def _check_and_install_tool(self, name: str, check_func, detailed_func=None, install_func=None):
        """Helper to check a tool and install if missing"""
        self.checks_total += 1
        
        try:
            # First check if tool is available
            if self.detailed and detailed_func:
                info = detailed_func()
                tool_available = info['available']
                if tool_available:
                    print(f"✅ {name:<25} Available")
                    if info['version']:
                        print(f"   🏷️  Version: {info['version']}")
                    if info['path']:
                        print(f"   📁 Path: {info['path']}")
                    if 'models' in info and info['models']:
                        print(f"   🤖 Models: {', '.join(info['models'])}")
                    if 'error' in info:
                        print(f"   ⚠️  Note: {info['error']}")
                    print()  # Add spacing between tools
                    self.checks_passed += 1
                    return True
                else:
                    print(f"❌ {name:<25} Not found")
                    if 'error' in info:
                        print(f"   ⚠️  {info['error']}")
            else:
                tool_available = check_func()
                if tool_available:
                    print(f"✅ {name:<25} Available")
                    self.checks_passed += 1
                    return True
                else:
                    print(f"❌ {name:<25} Not found")
            
            # Tool is missing - attempt installation if function provided
            if install_func:
                print(f"🔧 Installing {name}...")
                try:
                    if install_func():
                        print(f"✅ {name:<25} Successfully installed")
                        self.checks_passed += 1
                        return True
                    else:
                        print(f"❌ {name:<25} Installation failed")
                        print(f"   💡 Please install {name} manually")
                        return False
                except Exception as e:
                    print(f"❌ {name:<25} Installation error: {e}")
                    print(f"   💡 Please install {name} manually")
                    return False
            else:
                print(f"   💡 Please install {name} manually")
                return False
                
        except Exception as e:
            print(f"❌ {name:<25} Error checking - {e}")
            return False
        
        finally:
            print()  # Add spacing between tools
    
    def check_python_requirements(self):
        """Check Python package requirements"""
        print("🐍 Checking Python requirements...")
        
        required_packages = [
            'groq', 'requests', 'aiohttp', 'httpx', 
            'zipfile36', 'jsonschema', 'psutil'
        ]
        
        for package in required_packages:
            try:
                module = __import__(package)
                print(f"✅ {package:<25} Available")
                
                if self.detailed:
                    # Try to get version info
                    version = getattr(module, '__version__', None)
                    if version:
                        print(f"   🏷️  Version: {version}")
                    
                    # Try to get file path
                    try:
                        file_path = getattr(module, '__file__', None)
                        if file_path:
                            print(f"   📁 Path: {file_path}")
                    except:
                        pass
                    print()  # Add spacing between packages
                
                self.checks_passed += 1
            except ImportError:
                print(f"❌ {package:<25} Not installed")
                if self.detailed:
                    print()  # Add spacing between packages
            self.checks_total += 1
    
    def print_summary(self):
        """Print summary of checks"""
        print("\n" + "="*60)
        print("📊 System Check Summary")
        print("="*60)
        print(f"Checks passed: {self.checks_passed}/{self.checks_total}")
        
        if self.checks_passed == self.checks_total:
            print("🎉 All checks passed! Your system is ready.")
            print("\n🚀 Your lu77U-MobileSec environment includes:")
            print("   • Android analysis tools (JADX, APKTool, AAPT)")
            print("   • React Native decompiler")
            print("   • Flutter analysis (Blutter)")
            print("   • Mobile Security Framework (MobSF)")
            print("   • Android Virtual Device for dynamic testing")
            print("   • AI-powered vulnerability analysis (Ollama/GROQ)")
        else:
            missing_count = self.checks_total - self.checks_passed
            print(f"⚠️  {missing_count} items need attention.")
            print("\n💡 Missing components have been automatically installed where possible.")
            print("   For manual installations, refer to the messages above.")
        
        print("="*60)
#!/usr/bin/env python3
"""
Tool checker and system validators for lu77U-MobileSec
"""

import os
import shutil
import subprocess
import time
from typing import Optional


def ensure_ollama_running(use_local_llm: bool) -> bool:
    """Check and start Ollama service if using local LLM"""
    if not use_local_llm:
        return True  # Not using Ollama, so no need to check
    
    print("🔧 Checking Ollama service for AI analysis...")
    
    try:
        # Check if ollama is available
        if not shutil.which('ollama'):
            print("❌ Ollama not found. Please install Ollama from https://ollama.com/download")
            print("💡 Alternatively, use GROQ API with: --llm groq")
            return False
        
        # Check if service is running
        result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Ollama service is running")
            
            # Check if deepseek-coder model is available
            if 'deepseek-coder' in result.stdout:
                print("✅ Deepseek Coder model available")
                return True
            else:
                print("📥 Deepseek Coder model not found. Installing...")
                pull_result = subprocess.run(['ollama', 'pull', 'deepseek-coder:6.7b'], 
                                           capture_output=True, text=True)
                if pull_result.returncode == 0:
                    print("✅ Deepseek Coder model installed")
                    return True
                else:
                    print(f"❌ Failed to install model: {pull_result.stderr}")
                    return False
        else:
            # Service not running, try to start it
            print("🚀 Starting Ollama service...")
            
            # Start ollama serve in background
            subprocess.Popen(['ollama', 'serve'], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL)
            
            # Wait for service to start
            time.sleep(5)
            
            # Check if it's running now
            check_result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
            if check_result.returncode == 0:
                print("✅ Ollama service started successfully")
                return True
            else:
                print("❌ Failed to start Ollama service")
                print("💡 Try manually running: ollama serve")
                print("💡 Or use GROQ API with: --llm groq")
                return False
                
    except subprocess.TimeoutExpired:
        print("❌ Ollama service check timed out")
        return False
    except Exception as e:
        print(f"❌ Error checking Ollama: {e}")
        return False


def find_tool_path(tool_name: str) -> Optional[str]:
    """Find the path to a tool executable"""
    return shutil.which(tool_name)


def check_dependencies() -> dict:
    """Check for required dependencies and tools"""
    tools = {
        'jadx': find_tool_path('jadx'),
        'apktool': find_tool_path('apktool'),
        'aapt': find_tool_path('aapt'),
        'node': find_tool_path('node'),
        'npm': find_tool_path('npm'),
        'ollama': find_tool_path('ollama')
    }
    
    return tools


def check_jadx() -> bool:
    """Check if JADX is available"""
    return find_tool_path('jadx') is not None


def check_apktool() -> bool:
    """Check if APKTool is available"""
    return find_tool_path('apktool') is not None


def check_aapt() -> bool:
    """Check if AAPT is available"""
    return find_tool_path('aapt') is not None


def check_nodejs() -> bool:
    """Check if Node.js is available"""
    return find_tool_path('node') is not None


def check_npm() -> bool:
    """Check if NPM is available"""
    return find_tool_path('npm') is not None


def check_blutter() -> bool:
    """Check if Blutter is available"""
    from pathlib import Path
    
    # Check common locations for blutter.py
    possible_paths = [
        # Standard installation path
        Path.home() / '.mobilesec-tools' / 'blutter' / 'blutter.py',
    ]
    
    # Check if any of these paths exist
    for path in possible_paths:
        if path.exists():
            return True
    
    # Also check if blutter command is available in PATH (but not if it's a shell function)
    try:
        result = subprocess.run(['which', 'blutter'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            # Make sure it's not a shell function (your custom function)
            output = result.stdout.strip()
            return not ('function' in output or '{' in output)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    return False


def install_blutter() -> bool:
    """Install Blutter by cloning from GitHub"""
    import os
    from pathlib import Path
    
    # Check if git is available
    if not find_tool_path('git'):
        return False
    
    try:
        # Create tools directory in user's home
        tools_dir = Path.home() / '.mobilesec-tools'
        tools_dir.mkdir(exist_ok=True)
        
        blutter_path = tools_dir / 'blutter'
        
        # Remove if already exists
        if blutter_path.exists():
            import shutil
            shutil.rmtree(blutter_path)
        
        # Clone Blutter
        result = subprocess.run([
            'git', 'clone', 'https://github.com/worawit/blutter.git', str(blutter_path)
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            # Make executable if on Unix-like system
            blutter_executable = blutter_path / 'blutter'
            if blutter_executable.exists() and os.name != 'nt':
                os.chmod(blutter_executable, 0o755)
            
            # Add to PATH by creating a symlink in a common bin directory
            local_bin = Path.home() / '.local' / 'bin'
            local_bin.mkdir(parents=True, exist_ok=True)
            
            symlink_path = local_bin / 'blutter'
            if symlink_path.exists():
                symlink_path.unlink()
            
            try:
                symlink_path.symlink_to(blutter_executable)
            except (OSError, NotImplementedError):
                # Symlinks might not be supported, just note the path
                pass
            
            return True
        
        return False
        
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False


def check_react_native_decompiler() -> bool:
    """Check if React Native decompiler is available via NPX"""
    if not check_nodejs() or not check_npm():
        return False
    
    try:
        # react-native-decompiler shows help when run without arguments and exits with code 0
        result = subprocess.run(['npx', 'react-native-decompiler'], 
                              capture_output=True, text=True, timeout=30)
        # Check if the output contains expected help text
        return result.returncode == 0 and 'react-native-decompiler' in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False


def install_react_native_decompiler() -> bool:
    """Install react-native-decompiler globally via npm"""
    if not check_nodejs() or not check_npm():
        return False
    
    try:
        result = subprocess.run(['npm', 'install', '-g', 'react-native-decompiler'], 
                              capture_output=True, text=True, timeout=300)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False


def check_ollama() -> bool:
    """Check if Ollama is available"""
    return find_tool_path('ollama') is not None


def check_deepseek_model() -> bool:
    """Check if DeepSeek model is available in Ollama"""
    if not check_ollama():
        return False
    
    try:
        result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return 'deepseek-coder' in result.stdout
        return False
    except Exception:
        return False


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


def get_detailed_tool_info(tool_name: str, version_arg: str = '--version') -> dict:
    """Get detailed information about a tool including path and version"""
    path = find_tool_path(tool_name)
    version = None
    
    if path:
        version = get_tool_version(tool_name, version_arg)
    
    return {
        'available': path is not None,
        'path': path,
        'version': version
    }


def get_jadx_detailed() -> dict:
    """Get detailed JADX information"""
    info = get_detailed_tool_info('jadx', '-v')
    return info


def get_apktool_detailed() -> dict:
    """Get detailed APKTool information"""
    info = get_detailed_tool_info('apktool', '-version')
    return info


def get_aapt_detailed() -> dict:
    """Get detailed AAPT information"""
    info = get_detailed_tool_info('aapt', 'version')
    return info


def get_nodejs_detailed() -> dict:
    """Get detailed Node.js information"""
    info = get_detailed_tool_info('node', '--version')
    return info


def get_npm_detailed() -> dict:
    """Get detailed NPM information"""
    info = get_detailed_tool_info('npm', '--version')
    return info


def get_ollama_detailed() -> dict:
    """Get detailed Ollama information"""
    info = get_detailed_tool_info('ollama', '--version')
    
    # Also check for available models
    models = []
    if info['available']:
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
    
    info['models'] = models
    return info


def get_blutter_detailed() -> dict:
    """Get detailed Blutter information"""
    from pathlib import Path
    
    # Check common locations for blutter.py
    possible_paths = [
        Path.home() / '.mobilesec-tools' / 'blutter' / 'blutter.py',
    ]
    
    path = None
    for p in possible_paths:
        if p.exists():
            path = str(p)
            break
    
    if not path:
        # Check if blutter command is available in PATH
        try:
            result = subprocess.run(['which', 'blutter'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                output = result.stdout.strip()
                if not ('function' in output or '{' in output):
                    path = output
        except Exception:
            pass
    
    # Try to get version info
    version = None
    # Blutter doesn't have a meaningful version, so we skip version checking
    
    return {
        'available': path is not None,
        'path': path,
        'version': version
    }


def get_react_native_decompiler_detailed() -> dict:
    """Get detailed React Native decompiler information"""
    if not check_nodejs() or not check_npm():
        return {'available': False, 'path': None, 'version': None, 'error': 'Node.js or NPM not available'}
    
    try:
        # Get the path to react-native-decompiler
        result = subprocess.run(['npm', 'list', '-g', 'react-native-decompiler', '--depth=0'], 
                              capture_output=True, text=True, timeout=30)
        
        path = None
        version = None
        
        if result.returncode == 0:
            # Parse the output to get version
            lines = result.stdout.split('\n')
            for line in lines:
                if 'react-native-decompiler@' in line:
                    version = line.split('@')[1].strip()
                    break
            
            # Get the actual executable path
            try:
                which_result = subprocess.run(['which', 'react-native-decompiler'], 
                                            capture_output=True, text=True, timeout=5)
                if which_result.returncode == 0:
                    path = which_result.stdout.strip()
            except Exception:
                pass
        
        return {
            'available': version is not None,
            'path': path,
            'version': version
        }
    except Exception as e:
        return {'available': False, 'path': None, 'version': None, 'error': str(e)}


def check_mobsf() -> bool:
    """Check if MobSF is available and running"""
    from pathlib import Path
    
    # Check if MobSF is installed in the expected directory
    mobsf_dir = Path.home() / '.mobilesec' / 'tools' / 'Mobile-Security-Framework-MobSF'
    mobsf_script = mobsf_dir / 'run.sh'
    
    if not mobsf_dir.exists() or not mobsf_script.exists():
        return False
    
    # Check if MobSF is running and test authentication
    try:
        import requests
        import re
        
        session = requests.Session()
        
        # Try to access the main page
        response = session.get('http://127.0.0.1:8000/', timeout=10)
        
        # If redirected to login or login page detected, authenticate
        if response.status_code == 302 or 'login' in response.url.lower():
            # Get login page to extract CSRF token
            login_page = session.get('http://127.0.0.1:8000/login/', timeout=10)
            
            if login_page.status_code != 200:
                return False
            
            # Extract CSRF token with multiple patterns
            csrf_token = None
            patterns = [
                r'<input[^>]*name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
                r'name="csrfmiddlewaretoken"\s+value="([^"]+)"',
                r'csrfmiddlewaretoken["\'\s]*[=:]["\'\s]*([^"\'>\s]+)',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, login_page.text)
                if match:
                    csrf_token = match.group(1)
                    break
            
            if not csrf_token:
                return False
            
            # Submit login with credentials
            login_data = {
                'username': 'mobsf',
                'password': 'mobsf',
                'csrfmiddlewaretoken': csrf_token,
            }
            
            headers = {
                'Referer': 'http://127.0.0.1:8000/login/',
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (compatible; lu77U-MobileSec)'
            }
            
            login_response = session.post(
                'http://127.0.0.1:8000/login/',
                data=login_data,
                headers=headers,
                timeout=10,
                allow_redirects=True
            )
            
            # Check if login was successful
            if login_response.status_code == 200 and 'login' not in login_response.url:
                return True
            else:
                return False
                
        elif response.status_code == 200:
            # Check if it's actually MobSF
            if 'MobSF' in response.text or 'Mobile Security Framework' in response.text:
                return True
        
        return False
        
    except (ImportError, Exception):
        return False


def install_mobsf() -> bool:
    """Install MobSF by cloning from GitHub and running setup"""
    import os
    from pathlib import Path
    
    # Check if git is available
    if not find_tool_path('git'):
        print("❌ Git is required to install MobSF")
        return False
    
    try:
        # Create tools directory in user's home
        tools_dir = Path.home() / '.mobilesec' / 'tools'
        tools_dir.mkdir(parents=True, exist_ok=True)
        
        mobsf_path = tools_dir / 'Mobile-Security-Framework-MobSF'
        
        # Remove if already exists
        if mobsf_path.exists():
            import shutil
            print("🗑️ Removing existing MobSF installation...")
            shutil.rmtree(mobsf_path)
        
        # Clone MobSF
        print("📦 Cloning MobSF from GitHub...")
        result = subprocess.run([
            'git', 'clone', 'https://github.com/MobSF/Mobile-Security-Framework-MobSF.git', 
            str(mobsf_path)
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            print(f"❌ Failed to clone MobSF: {result.stderr}")
            return False
        
        # Run setup script based on platform
        setup_script = 'setup.sh' if os.name != 'nt' else 'setup.bat'
        setup_path = mobsf_path / setup_script
        
        if not setup_path.exists():
            print(f"❌ Setup script {setup_script} not found")
            return False
        
        print(f"🔧 Running MobSF setup ({setup_script})...")
        
        # Make setup script executable on Unix-like systems
        if os.name != 'nt':
            os.chmod(setup_path, 0o755)
            
            # Run setup script
            result = subprocess.run([
                'bash', str(setup_path)
            ], cwd=str(mobsf_path), capture_output=True, text=True, timeout=600)
        else:
            # Windows
            result = subprocess.run([
                str(setup_path)
            ], cwd=str(mobsf_path), capture_output=True, text=True, timeout=600)
        
        if result.returncode == 0:
            print("✅ MobSF setup completed successfully")
            
            # Additional step: Install Poetry dependencies if not done
            print("🔧 Installing Poetry dependencies...")
            try:
                poetry_result = subprocess.run([
                    'poetry', 'install'
                ], cwd=str(mobsf_path), capture_output=True, text=True, timeout=300)
                
                if poetry_result.returncode == 0:
                    print("✅ Poetry dependencies installed successfully")
                else:
                    print(f"⚠️ Poetry dependency installation warning: {poetry_result.stderr}")
            except Exception as e:
                print(f"⚠️ Poetry dependency installation error: {e}")
            
            return True
        else:
            print(f"❌ MobSF setup failed: {result.stderr}")
            return False
        
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        print(f"❌ MobSF installation error: {e}")
        return False


def start_mobsf() -> bool:
    """Start MobSF server"""
    from pathlib import Path
    import os
    
    mobsf_dir = Path.home() / '.mobilesec' / 'tools' / 'Mobile-Security-Framework-MobSF'
    
    if not mobsf_dir.exists():
        return False
    
    try:
        print("🔧 Checking MobSF dependencies...")
        
        # First, ensure Poetry dependencies are installed
        try:
            poetry_check = subprocess.run([
                'poetry', 'check'
            ], cwd=str(mobsf_dir), capture_output=True, text=True, timeout=30)
            
            if poetry_check.returncode != 0:
                print("🔧 Installing Poetry dependencies...")
                poetry_install = subprocess.run([
                    'poetry', 'install'
                ], cwd=str(mobsf_dir), capture_output=True, text=True, timeout=300)
                
                if poetry_install.returncode != 0:
                    print(f"❌ Failed to install Poetry dependencies: {poetry_install.stderr}")
                    return False
        except Exception as e:
            print(f"❌ Poetry setup error: {e}")
            return False
        
        # Start MobSF server in background
        print(f"🚀 Starting MobSF server from: {mobsf_dir}")
        if os.name != 'nt':
            # Unix-like systems
            run_script = mobsf_dir / 'run.sh'
            if run_script.exists():
                process = subprocess.Popen([
                    'bash', str(run_script)
                ], cwd=str(mobsf_dir), 
                  stdout=subprocess.PIPE, 
                  stderr=subprocess.PIPE,
                  preexec_fn=os.setsid if hasattr(os, 'setsid') else None)
        else:
            # Windows
            run_script = mobsf_dir / 'run.bat'
            if run_script.exists():
                process = subprocess.Popen([
                    str(run_script)
                ], cwd=str(mobsf_dir), 
                  stdout=subprocess.PIPE, 
                  stderr=subprocess.PIPE)
        
        # Wait for server to start with better error checking
        print("⏳ Waiting for MobSF server to start...")
        max_retries = 20  # Reduced from 30
        retry_count = 0
        
        while retry_count < max_retries:
            time.sleep(3)  # Increased from 2 seconds
            try:
                import requests
                response = requests.get('http://127.0.0.1:8000', timeout=5)
                if response.status_code == 200 and ('MobSF' in response.text or 'Mobile Security Framework' in response.text):
                    print("✅ MobSF server started successfully!")
                    return True
            except requests.exceptions.RequestException:
                pass
            except Exception:
                pass
            
            # Check if process is still running
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                print(f"❌ MobSF process exited with code {process.returncode}")
                if stderr:
                    print(f"Error output: {stderr.decode()[:500]}...")
                return False
            
            retry_count += 1
            if retry_count % 3 == 0:  # Print progress every 9 seconds
                print(f"⏳ Still waiting for MobSF server... (attempt {retry_count}/{max_retries})")
        
        print("❌ MobSF server failed to start after waiting")
        print("💡 Try checking the logs:")
        print(f"   cd {mobsf_dir}")
        print("   bash run.sh")
        
        # Kill the process if it's still running
        try:
            if process.poll() is None:
                process.terminate()
                time.sleep(2)
                if process.poll() is None:
                    process.kill()
        except:
            pass
        
        return False
        
    except Exception as e:
        print(f"❌ Failed to start MobSF: {e}")
        return False


def get_mobsf_detailed() -> dict:
    """Get detailed information about MobSF installation"""
    from pathlib import Path
    
    info = {
        'available': False,
        'path': None,
        'running': False,
        'authenticated': False,
        'version': None,
        'api_key': None,
        'error': None
    }
    
    try:
        # Check installation path
        mobsf_dir = Path.home() / '.mobilesec' / 'tools' / 'Mobile-Security-Framework-MobSF'
        
        if mobsf_dir.exists():
            info['path'] = str(mobsf_dir)
            info['available'] = True
            
            # Try to get version
            try:
                version_file = mobsf_dir / 'mobsf' / '__init__.py'
                if version_file.exists():
                    with open(version_file, 'r') as f:
                        content = f.read()
                        for line in content.split('\n'):
                            if '__version__' in line and '=' in line:
                                version = line.split('=')[1].strip().strip('"\'')
                                info['version'] = version
                                break
            except:
                pass
            
            # Check if running and test authentication
            try:
                import requests
                import re
                
                session = requests.Session()
                response = session.get('http://127.0.0.1:8000/', timeout=10)
                
                if response.status_code == 200 or response.status_code == 302:
                    # Check if it's MobSF
                    if response.status_code == 302:
                        # Follow redirect to check content
                        final_response = session.get('http://127.0.0.1:8000/', timeout=10, allow_redirects=True)
                        response = final_response
                    
                    if 'MobSF' in response.text or 'Mobile Security Framework' in response.text:
                        info['running'] = True
                        
                        # Test authentication if login page is detected
                        if 'login' in response.url.lower() or ('login' in response.text.lower() and 'username' in response.text.lower()):
                            try:
                                # Get login page for CSRF token
                                login_page = session.get('http://127.0.0.1:8000/login/', timeout=10)
                                
                                if login_page.status_code == 200:
                                    # Extract CSRF token
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
                                    
                                    if csrf_token:
                                        # Test authentication
                                        login_data = {
                                            'username': 'mobsf',
                                            'password': 'mobsf',
                                            'csrfmiddlewaretoken': csrf_token,
                                        }
                                        
                                        headers = {
                                            'Referer': 'http://127.0.0.1:8000/login/',
                                            'Content-Type': 'application/x-www-form-urlencoded',
                                        }
                                        
                                        login_response = session.post(
                                            'http://127.0.0.1:8000/login/',
                                            data=login_data,
                                            headers=headers,
                                            timeout=10,
                                            allow_redirects=True
                                        )
                                        
                                        # If login successful, add authentication status
                                        if login_response.status_code == 200 and 'login' not in login_response.url:
                                            info['authenticated'] = True
                                        else:
                                            info['authenticated'] = False
                                    else:
                                        info['authenticated'] = False
                                else:
                                    info['authenticated'] = False
                            except:
                                info['authenticated'] = False
                        else:
                            # No login required
                            info['authenticated'] = True
                    else:
                        info['running'] = False
                else:
                    info['running'] = False
                
                # Try to get API key from server startup log if available
                try:
                    log_dir = Path.home() / '.MobSF' / 'logs'
                    if log_dir.exists():
                        # Look for recent log files
                        for log_file in sorted(log_dir.glob('*.log'), key=lambda x: x.stat().st_mtime, reverse=True):
                            try:
                                with open(log_file, 'r') as f:
                                    content = f.read()
                                    if 'REST API Key:' in content:
                                        for line in content.split('\n'):
                                            if 'REST API Key:' in line:
                                                api_key = line.split('REST API Key:')[1].strip()
                                                if api_key and len(api_key) > 10:  # Basic validation
                                                    info['api_key'] = api_key
                                                    break
                                        if info['api_key']:
                                            break
                            except:
                                continue
                except:
                    pass
                    
            except (ImportError, Exception):
                info['running'] = False
        else:
            info['error'] = "MobSF not found in ~/.mobilesec/tools/"
    
    except Exception as e:
        info['error'] = str(e)
    
    return info


# === AVD (Android Virtual Device) Functions ===

def check_avd():
    """Check if Android Virtual Device is available"""
    try:
        import sys
        from pathlib import Path
        
        # Add the tools directory to path
        tools_dir = Path(__file__).parent.parent.parent / "tools" / "android_tools"
        sys.path.insert(0, str(tools_dir))
        
        from avd_installer import check_avd_exists, check_sdk_installed
        return check_sdk_installed() and check_avd_exists()
    except Exception:
        return False


def get_avd_detailed(verbose=False):
    """Get detailed information about AVD setup"""
    try:
        import sys
        from pathlib import Path
        
        # Add the tools directory to path
        tools_dir = Path(__file__).parent.parent.parent / "tools" / "android_tools"
        sys.path.insert(0, str(tools_dir))
        
        from avd_installer import get_avd_info
        return get_avd_info(verbose=verbose)
    except Exception as e:
        return {
            'available': False,
            'error': f"Failed to get AVD info: {e}"
        }


def install_avd():
    """Install Android Virtual Device"""
    try:
        import sys
        from pathlib import Path
        
        # Add the tools directory to path
        tools_dir = Path(__file__).parent.parent.parent / "tools" / "android_tools"
        sys.path.insert(0, str(tools_dir))
        
        from avd_installer import install_avd as avd_install
        # Use debug=False for system doctor integration to keep output clean
        return avd_install(debug=False)
    except Exception as e:
        print(f"❌ AVD installation failed: {e}")
        return False


def start_avd():
    """Start the Android Virtual Device emulator"""
    try:
        import sys
        from pathlib import Path
        
        # Add the tools directory to path
        tools_dir = Path(__file__).parent.parent.parent / "tools" / "android_tools"
        sys.path.insert(0, str(tools_dir))
        
        from avd_installer import start_emulator, setup_env
        env = setup_env()
        return start_emulator(env, headless=False)
    except Exception as e:
        print(f"❌ Failed to start AVD: {e}")
        return False


def check_adb() -> bool:
    """Check if ADB (Android Debug Bridge) is available"""
    return find_tool_path('adb') is not None


def get_adb_detailed() -> dict:
    """Get detailed ADB information"""
    adb_path = find_tool_path('adb')
    
    if not adb_path:
        return {
            'available': False,
            'path': None,
            'version': None,
            'android_sdk': None
        }
    
    try:
        # Get ADB version
        result = subprocess.run([adb_path, 'version'], 
                              capture_output=True, text=True, timeout=10)
        version = None
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Android Debug Bridge' in line:
                    version = line.strip()
                    break
        
        # Try to determine Android SDK path
        android_sdk = None
        if 'ANDROID_SDK_ROOT' in os.environ:
            android_sdk = os.environ['ANDROID_SDK_ROOT']
        elif 'ANDROID_HOME' in os.environ:
            android_sdk = os.environ['ANDROID_HOME']
        
        return {
            'available': True,
            'path': adb_path,
            'version': version,
            'android_sdk': android_sdk
        }
        
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return {
            'available': True,
            'path': adb_path,
            'version': 'Unable to get version',
            'android_sdk': None
        }


def check_java() -> bool:
    """Check if Java is available"""
    return find_tool_path('java') is not None


def get_java_detailed() -> dict:
    """Get detailed Java information"""
    java_path = find_tool_path('java')
    
    if not java_path:
        return {
            'available': False,
            'path': None,
            'version': None,
            'java_home': None
        }
    
    try:
        # Get Java version
        result = subprocess.run([java_path, '-version'], 
                              capture_output=True, text=True, timeout=10)
        version = None
        if result.returncode == 0:
            # Java prints version to stderr
            version_output = result.stderr if result.stderr else result.stdout
            for line in version_output.split('\n'):
                if 'version' in line.lower():
                    version = line.strip()
                    break
        
        # Get JAVA_HOME
        java_home = os.environ.get('JAVA_HOME')
        
        return {
            'available': True,
            'path': java_path,
            'version': version,
            'java_home': java_home
        }
        
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return {
            'available': True,
            'path': java_path,
            'version': 'Unable to get version',
            'java_home': os.environ.get('JAVA_HOME')
        }


def check_python() -> bool:
    """Check if Python 3 is available"""
    import sys
    return sys.version_info >= (3, 8)


def get_python_detailed() -> dict:
    """Get detailed Python information"""
    import sys
    import platform
    
    return {
        'available': True,
        'version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'full_version': sys.version,
        'executable': sys.executable,
        'platform': platform.platform(),
        'architecture': platform.architecture()[0]
    }


def check_frida() -> bool:
    """Check if Frida is available"""
    return find_tool_path('frida') is not None


def get_frida_detailed() -> dict:
    """Get detailed Frida information"""
    frida_path = find_tool_path('frida')
    
    if not frida_path:
        return {
            'available': False,
            'path': None,
            'version': None,
            'python_module': False
        }
    
    try:
        # Get Frida version
        result = subprocess.run([frida_path, '--version'], 
                              capture_output=True, text=True, timeout=10)
        version = None
        if result.returncode == 0:
            version = result.stdout.strip()
        
        # Check if frida Python module is available
        python_module = False
        try:
            import frida
            python_module = True
        except ImportError:
            pass
        
        return {
            'available': True,
            'path': frida_path,
            'version': version,
            'python_module': python_module
        }
        
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return {
            'available': True,
            'path': frida_path,
            'version': 'Unable to get version',
            'python_module': False
        }

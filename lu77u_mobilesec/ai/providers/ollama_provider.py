#!/usr/bin/env python3
"""
Ollama provider for lu77U-MobileSec
"""

import subprocess
import time
import shutil
import json
from typing import Optional, Dict, Any

# Import ollama at runtime to avoid import errors
ollama = None

from .base_provider import BaseAIProvider


# Ollama configuration
OLLAMA_MODEL = "deepseek-coder:6.7b"


class OllamaProvider(BaseAIProvider):
    """Ollama local LLM provider"""
    
    def __init__(self, debug: bool = False):
        super().__init__(debug)
        self._load_ollama()
    
    def _load_ollama(self):
        """Load ollama module at runtime"""
        global ollama
        if ollama is None:
            try:
                import ollama
                self.debug_print("Ollama module loaded successfully")
            except ImportError:
                self.debug_print("Ollama module not available")
    
    def is_available(self) -> bool:
        """Check if Ollama is available and running"""
        return self.is_ollama_running()
    
    async def analyze_code(self, prompt: str, code: str, context: Optional[str] = None) -> str:
        """Analyze code using local Ollama"""
        result = await self.analyze_with_local_llm(prompt)
        if "error" in result:
            return result["error"]
        return result.get("response", "No response received")
    
    def is_ollama_running(self) -> bool:
        """Check if Ollama service is running"""
        try:
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def check_ollama_setup(self) -> bool:
        """Check if Ollama is properly set up"""
        if not shutil.which('ollama'):
            return False
        return self.is_ollama_running()
    
    def start_ollama_service(self) -> bool:
        """Start Ollama service"""
        try:
            # Start ollama serve in background
            subprocess.Popen(['ollama', 'serve'], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL)
            
            # Wait for service to start
            time.sleep(5)
            
            # Check if it's running now
            return self.is_ollama_running()
        except Exception as e:
            self.debug_print(f"Failed to start Ollama service: {e}")
            return False
    
    def start_ollama_if_needed(self) -> bool:
        """Start Ollama service if not running"""
        if self.is_ollama_running():
            return True
        
        self.debug_print("Starting Ollama service...")
        return self.start_ollama_service()
    
    def check_deepseek_model(self) -> bool:
        """Check if DeepSeek model is available"""
        try:
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
            if result.returncode == 0:
                return 'deepseek-coder' in result.stdout
            return False
        except Exception:
            return False
    
    def ensure_ollama_ready(self) -> bool:
        """Ensure Ollama service is running and model is available"""
        if not self.check_ollama_setup():
            self.debug_print("Ollama not available")
            return False
        
        if not self.start_ollama_if_needed():
            self.debug_print("Failed to start Ollama")
            return False
        
        if not self.check_deepseek_model():
            self.debug_print("DeepSeek model not found, installing...")
            try:
                subprocess.run(['ollama', 'pull', OLLAMA_MODEL], 
                              capture_output=True, text=True, timeout=300)
                return self.check_deepseek_model()
            except Exception as e:
                self.debug_print(f"Failed to install model: {e}")
                return False
        
        return True
    
    async def get_completion(self, prompt: str, system_message: str = "You are a security expert specialized in Android and mobile app vulnerabilities.") -> str:
        """
        Get completion from Ollama for fix generation
        
        Args:
            prompt: The prompt to send to the model
            system_message: System message for context
            
        Returns:
            str: The response content from the model
        """
        result = await self.analyze_with_local_llm(prompt, system_message)
        
        if isinstance(result, dict):
            if "error" in result:
                self.debug_print(f"Ollama completion error: {result['error']}")
                return f"Error: {result['error']}"
            return result.get("response", "No response received")
        elif isinstance(result, list):
            return "\n".join(str(item) for item in result)
        else:
            return str(result)

    async def analyze_with_local_llm(self, prompt: str, system_message: str = "You are a security expert specialized in Android and mobile app vulnerabilities.") -> Dict:
        """Analyze content using local Ollama and always return a list of vulnerabilities."""
        
        if ollama is None:
            self._load_ollama()
            if ollama is None:
                return {"error": "Ollama module not available"}
        
        # Ensure Ollama is running before making requests
        if not self.ensure_ollama_ready():
            return {"error": "Ollama service not available or not ready"}
        
        max_retries = 5  # Increased retries
        retry_delay = 3  # Longer initial delay
        
        for attempt in range(max_retries):
            try:
                self.debug_print(f"🤖 Ollama attempt {attempt + 1}/{max_retries}")
                
                # Add connection check before each attempt
                if not self.is_ollama_running():
                    self.debug_print("🔄 Ollama not running, restarting...")
                    self.start_ollama_service()
                    time.sleep(5)  # Longer wait after restart
                
                response = ollama.chat(
                    model=OLLAMA_MODEL, 
                    messages=[
                        {'role': 'system', 'content': system_message},
                        {'role': 'user', 'content': prompt}
                    ],
                    options={
                        'temperature': 0.2,  # Slightly higher for more varied responses
                        'top_p': 0.3,        # More diverse sampling
                        'repeat_penalty': 1.1, 
                        'num_predict': 2048,  # Limited response length to avoid disconnects
                        'num_ctx': 4096,     # Reduced context window for stability
                        'timeout': 60        # Add timeout
                    }
                )
                
                content = response['message']['content']
                self.debug_print(f"✅ Ollama response received ({len(content)} chars)")
                
                if "=== FIXED CODE ===" in prompt:
                    return {"response": content}
                
                try:
                    # Try to parse as JSON first
                    parsed = json.loads(content)
                    if isinstance(parsed, list):
                        return {"response": parsed}
                    elif isinstance(parsed, dict) and 'vulnerabilities' in parsed:
                        return {"response": parsed['vulnerabilities']}
                    else:
                        return {"response": [parsed]}
                except json.JSONDecodeError:
                    # Return raw content for text parsing
                    return {"response": content}
                    
            except Exception as e:
                error_msg = str(e)
                self.debug_print(f"❌ Ollama attempt {attempt + 1} failed: {error_msg}")
                
                if attempt < max_retries - 1:
                    self.debug_print(f"⏳ Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 1.5, 10)  # Slower exponential backoff, max 10s
                    
                    # Always try to restart Ollama on failures
                    self.debug_print("🔄 Restarting Ollama service...")
                    subprocess.run(['pkill', '-f', 'ollama serve'], capture_output=True)
                    time.sleep(2)
                    self.start_ollama_service()
                    time.sleep(5)
                else:
                    return {"error": f"Ollama failed after {max_retries} attempts: {error_msg}"}

def cleanup_ollama():
    """Stop ollama serve process before script exit"""
    stopped = False
    
    # Try pkill first (more specific)
    try:
        result = subprocess.run(
            ["pkill", "-f", "ollama serve"], 
            capture_output=True, 
            text=True
        )
        if result.returncode == 0:
            stopped = True
    except FileNotFoundError:
        pass
    
    # Try killall only if pkill failed
    if not stopped:
        try:
            result = subprocess.run(
                ["killall", "ollama"], 
                capture_output=True, 
                text=True
            )
            if result.returncode == 0:
                stopped = True
        except Exception:
            pass
    
    # If still not stopped, ollama wasn't running (which is fine)
    return stopped

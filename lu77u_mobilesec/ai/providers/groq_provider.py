#!/usr/bin/env python3
"""
GROQ AI provider for lu77U-MobileSec
"""

import os
from typing import Optional, Dict, Any

# Optional imports
try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import httpx
except ImportError:
    httpx = None

from .base_provider import BaseAIProvider


# GROQ API configuration
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "deepseek-r1-distill-llama-70b"


class GroqProvider(BaseAIProvider):
    """GROQ API provider for AI analysis"""
    
    def __init__(self, api_key: Optional[str] = None, debug: bool = False):
        super().__init__(debug)
        self.api_key = api_key or os.environ.get('GROQ_API_KEY')
        if not self.api_key:
            self.debug_print("No GROQ API key found")
    
    def is_available(self) -> bool:
        """Check if GROQ API is available"""
        if not self.api_key:
            return False
        
        if not (httpx or aiohttp):
            self.debug_print("Neither httpx nor aiohttp is available")
            return False
        
        return True
    
    async def analyze_code(self, prompt: str, code: str, context: Optional[str] = None) -> str:
        """Analyze code using GROQ API"""
        return await self.analyze_with_groq(prompt)
    
    async def analyze_with_groq(self, prompt: str, system_message: str = "You are a security expert specialized in Android and mobile app vulnerabilities.") -> dict:
        """Analyze content using GROQ API"""
        if not self.is_available():
            return {"error": "GROQ API not available"}
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        payload = {
            "model": GROQ_MODEL,
            "messages": [
            {"role": "system", "content": system_message},
            {"role": "user", "content": prompt}
            ]
        }

        try:
            if httpx is not None:
                # Use httpx as primary choice
                async with httpx.AsyncClient() as client:
                    response = await client.post(GROQ_API_URL, headers=headers, json=payload)
                    response.raise_for_status()
                    result = response.json()
                    return {"response": result['choices'][0]['message']['content']}
            else:
                # Fallback to aiohttp
                async with aiohttp.ClientSession() as session:
                    async with session.post(GROQ_API_URL, headers=headers, json=payload) as response:
                        if response.status == 200:
                            result = await response.json()
                            return {"response": result['choices'][0]['message']['content']}
                        else:
                            error_text = await response.text()
                            return {"error": f"GROQ API error {response.status}: {error_text}"}
        except Exception as e:
            return {"error": f"GROQ API request failed: {e}"}

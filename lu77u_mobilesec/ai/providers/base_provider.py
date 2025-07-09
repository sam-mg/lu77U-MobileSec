#!/usr/bin/env python3
"""
Base AI provider for lu77U-MobileSec
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any


class BaseAIProvider(ABC):
    """Base class for AI providers"""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
    
    def debug_print(self, message: str) -> None:
        """Print debug messages if debug mode is enabled"""
        if self.debug:
            print(f"🤖 AI DEBUG: {message}")
    
    @abstractmethod
    async def analyze_code(self, prompt: str, code: str, context: Optional[str] = None) -> str:
        """Analyze code with AI and return results"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the AI provider is available"""
        pass


def choose_llm_option(llm_preference: Optional[str] = None, debug: bool = False) -> str:
    """
    Determine LLM option from configuration
    
    Args:
        llm_preference: LLM preference from command line args ('ollama' or 'groq')
        debug: Enable debug output
        
    Returns:
        str: Selected LLM option ('ollama' or 'groq')
    """
    if debug:
        print(f"🤖 LLM DEBUG: LLM preference from args: {llm_preference}")
    
    # Use provided preference or default to ollama
    selected = llm_preference or 'ollama'
    
    if debug:
        llm_name = "Ollama (DeepSeek Coder-6.7B)" if selected == 'ollama' else "GROQ API"
        print(f"🤖 LLM DEBUG: Selected LLM: {llm_name}")
    
    return selected

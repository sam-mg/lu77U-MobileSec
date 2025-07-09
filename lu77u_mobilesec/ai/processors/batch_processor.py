#!/usr/bin/env python3
"""
Batch Processing Utilities for AI-Based Fix Generation

This module provides intelligent batching capabilities for processing large codebases
with AI models that have token/context limitations. It includes strategies for:
- Module relevance detection for targeted analysis
- Batch size optimization for different AI providers
- Context-aware processing for related vulnerabilities
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path


class BatchProcessor:
    """
    Intelligent batch processing for AI-based vulnerability fix generation.
    
    Handles the challenge of processing large codebases that exceed AI model
    token limits by intelligently batching related modules and vulnerabilities.
    """
    
    def __init__(self, debug: bool = False):
        """Initialize the batch processor."""
        self.debug = debug
        self.default_batch_size = 5  # Conservative default for most AI models
        
    def find_relevant_modules(
        self, 
        target_file: str, 
        available_modules: Dict[str, str],
        max_modules: int = 10
    ) -> Dict[str, str]:
        """
        Find modules that are relevant to a specific vulnerability target file.
        
        This function implements a multi-pass relevance detection algorithm:
        1. Direct name matching (exact/partial filename matches)
        2. Content-based relevance (file references in module content)
        3. Fallback strategy for unknown files
        
        Args:
            target_file: The file name where vulnerability was detected
            available_modules: Dictionary of module_name -> module_content
            max_modules: Maximum number of modules to return (default: 10)
            
        Returns:
            Dictionary of relevant module_name -> module_content
            
        Example:
            >>> processor = BatchProcessor()
            >>> modules = {"auth.js": "...", "login.js": "..."}
            >>> relevant = processor.find_relevant_modules("auth.js", modules)
            >>> print(relevant.keys())  # ['auth.js', 'login.js'] (if related)
        """
        if not target_file or target_file == 'unknown':
            # For unknown files, return a reasonable subset
            return dict(list(available_modules.items())[:max_modules])
        
        relevant_modules = {}
        target_base = self._normalize_filename(target_file)
        
        if self.debug:
            print(f"🔍 Finding modules relevant to: {target_file} (base: {target_base})")
        
        # Pass 1: Direct name similarity matching
        for module_name, module_content in available_modules.items():
            module_base = self._normalize_filename(module_name)
            
            if self._are_files_related(target_base, module_base, target_file, module_name):
                relevant_modules[module_name] = module_content
                if self.debug:
                    print(f"  ✓ Name match: {module_name}")
        
        # Pass 2: Content-based relevance (if we need more modules)
        if len(relevant_modules) < max_modules:
            for module_name, module_content in available_modules.items():
                if module_name not in relevant_modules:
                    if self._is_content_related(target_file, target_base, module_content):
                        relevant_modules[module_name] = module_content
                        if self.debug:
                            print(f"  ✓ Content match: {module_name}")
                        
                        if len(relevant_modules) >= max_modules:
                            break
        
        # Pass 3: Fallback - ensure we have some modules to work with
        if not relevant_modules:
            fallback_count = min(max_modules, len(available_modules))
            items = list(available_modules.items())[:fallback_count]
            relevant_modules = dict(items)
            if self.debug:
                print(f"  ⚠️  No matches found, using fallback: {fallback_count} modules")
        
        if self.debug:
            print(f"  📦 Selected {len(relevant_modules)} relevant modules")
        
        return relevant_modules
    
    def calculate_optimal_batch_size(
        self, 
        total_modules: int,
        ai_provider: str = "ollama",
        complexity_factor: float = 1.0
    ) -> int:
        """
        Calculate optimal batch size based on AI provider and content complexity.
        
        Args:
            total_modules: Total number of modules to process
            ai_provider: AI provider type ("ollama", "groq", "openai", etc.)
            complexity_factor: Multiplier for complexity (0.5-2.0, default 1.0)
            
        Returns:
            Optimal batch size for the given context
        """
        # Base batch sizes per provider (conservative estimates)
        provider_limits = {
            "ollama": 5,      # Local models typically have smaller context windows
            "groq": 8,        # Good performance with medium batches
            "openai": 10,     # Larger context windows available
            "claude": 12,     # Very large context windows
            "gemini": 8,      # Good balance
        }
        
        base_size = provider_limits.get(ai_provider.lower(), self.default_batch_size)
        
        # Adjust for complexity
        adjusted_size = int(base_size * complexity_factor)
        
        # Ensure reasonable bounds
        adjusted_size = max(1, min(adjusted_size, total_modules))
        
        if self.debug:
            print(f"📊 Batch size calculation: {base_size} * {complexity_factor} = {adjusted_size}")
        
        return adjusted_size
    
    def group_vulnerabilities_by_file(
        self, 
        vulnerabilities: List[Dict], 
        selected_indices: List[int]
    ) -> Dict[str, List[Dict]]:
        """
        Group selected vulnerabilities by their source file for efficient batching.
        
        Args:
            vulnerabilities: List of all detected vulnerabilities
            selected_indices: 1-based indices of vulnerabilities to process
            
        Returns:
            Dictionary mapping file_name -> list of vulnerabilities
        """
        file_groups = {}
        selected_vulns = [
            vulnerabilities[i-1] for i in selected_indices 
            if 1 <= i <= len(vulnerabilities)
        ]
        
        for vuln in selected_vulns:
            file_name = vuln.get('file', 'unknown')
            if file_name not in file_groups:
                file_groups[file_name] = []
            file_groups[file_name].append(vuln)
        
        if self.debug:
            print(f"📁 Grouped vulnerabilities by file:")
            for file_name, vulns in file_groups.items():
                print(f"  {file_name}: {len(vulns)} vulnerabilities")
        
        return file_groups
    
    def create_processing_batches(
        self,
        relevant_modules: Dict[str, str],
        batch_size: int
    ) -> List[Tuple[int, int, Dict[str, str]]]:
        """
        Create processing batches from relevant modules.
        
        Args:
            relevant_modules: Dictionary of module_name -> module_content
            batch_size: Maximum modules per batch
            
        Returns:
            List of (batch_num, total_batches, batch_modules) tuples
        """
        module_items = list(relevant_modules.items())
        total_modules = len(module_items)
        total_batches = (total_modules + batch_size - 1) // batch_size
        
        batches = []
        for batch_start in range(0, total_modules, batch_size):
            batch_end = min(batch_start + batch_size, total_modules)
            batch_modules = dict(module_items[batch_start:batch_end])
            batch_num = (batch_start // batch_size) + 1
            
            batches.append((batch_num, total_batches, batch_modules))
        
        return batches
    
    def _normalize_filename(self, filename: str) -> str:
        """Normalize a filename by removing extensions and common suffixes."""
        if not filename:
            return ""
        
        # Remove common extensions
        extensions = ['.js', '.jsx', '.ts', '.tsx', '.java', '.kt', '.dart']
        normalized = filename
        for ext in extensions:
            if normalized.endswith(ext):
                normalized = normalized[:-len(ext)]
                break
        
        return normalized.lower()
    
    def _are_files_related(
        self, 
        target_base: str, 
        module_base: str, 
        target_file: str, 
        module_name: str
    ) -> bool:
        """Check if two files are related based on naming patterns."""
        # Exact base name match
        if target_base == module_base:
            return True
        
        # Partial containment
        if target_base in module_base or module_base in target_base:
            return True
        
        # Full filename containment
        if target_file in module_name or module_name in target_file:
            return True
        
        # Common patterns (e.g., auth/auth-utils, login/login-service)
        target_parts = target_base.split('-')
        module_parts = module_base.split('-')
        
        if target_parts[0] in module_parts or module_parts[0] in target_parts:
            return True
        
        return False
    
    def _is_content_related(self, target_file: str, target_base: str, content: str) -> bool:
        """Check if module content is related to the target file."""
        if not content:
            return False
        
        # Look for direct file references
        if target_file in content or target_base in content:
            return True
        
        # Look for import/require statements
        import_patterns = [
            rf"import.*['\"].*{re.escape(target_base)}.*['\"]",
            rf"require\(['\"].*{re.escape(target_base)}.*['\"]\)",
            rf"from\s+['\"].*{re.escape(target_base)}.*['\"]"
        ]
        
        for pattern in import_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False


# Convenience functions for backward compatibility
def find_relevant_modules(target_file: str, available_modules: Dict[str, str]) -> Dict[str, str]:
    """
    Convenience function for finding relevant modules.
    
    This is a backward-compatible wrapper around BatchProcessor.find_relevant_modules()
    for use in existing code that expects the old function signature.
    """
    processor = BatchProcessor()
    return processor.find_relevant_modules(target_file, available_modules)

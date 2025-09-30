"""Path processor module for lu77U-MobileSec"""

import os
import shlex
from ..utils import verbose_print

class PathProcessor:
    """Class for processing and cleaning file paths"""
    
    def __init__(self, verbose=False):
        """Initialize the path processor"""
        self.verbose = verbose
        verbose_print("PathProcessor initialized", self.verbose)
    
    def process_target_path(self, raw_path: str) -> str:
        """Process and clean the target path"""
        verbose_print(f"Starting path processing for: '{raw_path}'", self.verbose)
        verbose_print(f"Raw path length: {len(raw_path)} characters", self.verbose)
        
        # Remove surrounding quotes
        verbose_print("Checking for surrounding quotes", self.verbose)
        if (raw_path.startswith('"') and raw_path.endswith('"')) or \
           (raw_path.startswith("'") and raw_path.endswith("'")):
            quote_type = raw_path[0]
            raw_path = raw_path[1:-1]
            verbose_print(f"Removed {quote_type} quotes: '{raw_path}'", self.verbose)
        else:
            verbose_print("No surrounding quotes found", self.verbose)
        
        processed_path = raw_path
        verbose_print(f"Initial processed path: '{processed_path}'", self.verbose)
        
        # Handle escaped spaces
        verbose_print("Checking for escaped spaces", self.verbose)
        if '\\ ' in processed_path:
            original_path = processed_path
            processed_path = processed_path.replace('\\ ', ' ')
            verbose_print(f"Unescaped spaces: '{original_path}' -> '{processed_path}'", self.verbose)
        else:
            verbose_print("No escaped spaces found", self.verbose)
            # Try shell parsing if no spaces present
            try:
                verbose_print("Attempting shell parsing", self.verbose)
                if ' ' not in processed_path:
                    parsed_paths = shlex.split(processed_path)
                    if parsed_paths:
                        original_path = processed_path
                        processed_path = parsed_paths[0]
                        verbose_print(f"Shell-parsed path: '{original_path}' -> '{processed_path}'", self.verbose)
                    else:
                        verbose_print("Shell parsing returned empty result", self.verbose)
                else:
                    verbose_print("Skipping shell parsing due to spaces in path", self.verbose)
            except ValueError as e:
                verbose_print(f"Shlex parsing failed with error: {e}", self.verbose)
                verbose_print(f"Using path as-is: '{processed_path}'", self.verbose)
        
        # Convert to absolute path if needed
        verbose_print(f"Checking if path is absolute: {os.path.isabs(processed_path)}", self.verbose)
        if not os.path.isabs(processed_path):
            original_path = processed_path
            absolute_path = os.path.abspath(processed_path)
            verbose_print(f"Converted to absolute path: '{original_path}' -> '{absolute_path}'", self.verbose)
            verbose_print(f"Current working directory: {os.getcwd()}", self.verbose)
            return absolute_path
        else:
            verbose_print("Path is already absolute", self.verbose)
        
        verbose_print(f"Path processing complete: '{processed_path}'", self.verbose)
        return processed_path
    
    def validate_path_exists(self, path: str) -> bool:
        """Validate that the given path exists"""
        verbose_print(f"Validating path existence: '{path}'", self.verbose)
        
        # Check if path exists
        exists = os.path.exists(path)
        verbose_print(f"Path exists check result: {exists}", self.verbose)
        
        if exists:
            # Check if it's a file or directory
            is_file = os.path.isfile(path)
            is_dir = os.path.isdir(path)
            verbose_print(f"Path type - File: {is_file}, Directory: {is_dir}", self.verbose)
            
            # Check permissions
            readable = os.access(path, os.R_OK)
            verbose_print(f"Path is readable: {readable}", self.verbose)
            
            if is_file:
                file_size = os.path.getsize(path)
                verbose_print(f"File size: {file_size} bytes", self.verbose)
            elif is_dir:
                try:
                    contents = os.listdir(path)
                    verbose_print(f"Directory contains {len(contents)} items", self.verbose)
                except PermissionError:
                    verbose_print("Cannot list directory contents (permission denied)", self.verbose)
        else:
            verbose_print(f"Path does not exist: '{path}'", self.verbose)
            # Check parent directory
            parent_dir = os.path.dirname(path)
            if parent_dir and parent_dir != path:
                parent_exists = os.path.exists(parent_dir)
                verbose_print(f"Parent directory '{parent_dir}' exists: {parent_exists}", self.verbose)
        
        return exists

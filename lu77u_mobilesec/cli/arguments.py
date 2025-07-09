#!/usr/bin/env python3
"""
CLI argument parser for lu77U-MobileSec
"""

import argparse
import sys
from .interface import display_banner


class CustomHelpAction(argparse._HelpAction):
    """Custom help action that shows banner before help"""
    def __call__(self, parser, namespace, values, option_string=None):
        display_banner()
        print()  # Add blank line after banner
        
        # Get the help text and add spacing between options
        import io
        help_string = io.StringIO()
        parser.print_help(help_string)
        help_text = help_string.getvalue()
        
        # Split into lines and add spacing between options
        lines = help_text.split('\n')
        formatted_lines = []
        in_options_section = False
        
        for i, line in enumerate(lines):
            formatted_lines.append(line)
            
            # Check if we're entering the options section
            if line.startswith('options:'):
                in_options_section = True
                formatted_lines.append('')  # Add space after "options:" header
            
            # Add spacing between individual options (lines that start with spaces and contain --)
            elif in_options_section and line.strip().startswith('-'):
                # Look ahead to see if the next non-empty line is another option
                next_option_found = False
                for j in range(i + 1, len(lines)):
                    if lines[j].strip():  # Found next non-empty line
                        if lines[j].strip().startswith('-'):  # It's another option
                            next_option_found = True
                        break
                
                if next_option_found:
                    formatted_lines.append('')  # Add blank line after this option
            
            # Stop adding spacing after options section
            elif in_options_section and line.strip() and not line.startswith(' '):
                in_options_section = False
        
        print('\n'.join(formatted_lines))
        parser.exit()


def create_argument_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="lu77U-MobileSec - Mobile Security Analysis & Vulnerability Patching Tool\n\nUsage:\n  lu77u-mobilesec <APK_FILE>    Analyze an APK file\n  lu77u-mobilesec doctor        Check system dependencies",
        add_help=False,  # Disable default help to use our custom one
        prog='lu77u-mobilesec',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Add custom help argument
    parser.add_argument(
        '-h', '--help',
        action=CustomHelpAction,
        help='Show this help message and exit'
    )
    
    parser.add_argument(
        'command',
        nargs='?',
        help='APK file path to analyze OR "doctor" to check system dependencies',
        metavar='APK_FILE|doctor'
    )
    
    parser.add_argument(
        '--type',
        choices=['java', 'kotlin', 'react-native', 'flutter'],
        help='Force specific analysis type'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='store_true',
        help='Show program version and exit'
    )
    
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug mode with verbose output. When used with doctor command, shows detailed information including paths and versions'
    )
    
    parser.add_argument(
        '--llm',
        choices=['groq', 'ollama'],
        default='ollama',
        help='Choose AI model: groq (GROQ API) or ollama (local Deepseek Coder-6.7B) [default: ollama]'
    )

    parser.add_argument(
        '--fix',
        action='store_true',
        help='Enable vulnerability auto-fix prompt after analysis. If set, you will be prompted to select vulnerabilities to patch and receive AI-generated code fixes.'
    )

    parser.add_argument(
        '--dynamic',
        action='store_true',
        help='Enable dynamic analysis testing using MobSF API. Requires MobSF server to be running. You will be prompted to enter the API key.'
    )

    return parser

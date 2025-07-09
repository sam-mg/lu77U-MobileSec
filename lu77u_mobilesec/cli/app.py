#!/usr/bin/env python3
"""
Main CLI application for lu77U-MobileSec
"""

import sys
import asyncio
import atexit

from .arguments import create_argument_parser
from .interface import display_banner
from ..core.orchestrator import MobileSecAnalyzer
from ..system.doctor.main_doctor import MobileSecDoctor
from ..ai.providers.ollama_provider import cleanup_ollama


# Global flag to track if ollama cleanup should be performed
_should_cleanup_ollama = False


async def main():
    """Main entry point"""
    global _should_cleanup_ollama
    
    # Parse command line arguments first to get debug flag
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Handle special case where "doctor" is passed as command
    if args.command and args.command.lower() == "doctor":
        # Don't register ollama cleanup for doctor command
        # Check if -d flag is used for detailed doctor output
        detailed = getattr(args, 'debug', False)  # Reuse -d flag for detailed doctor mode
        doctor = MobileSecDoctor(detailed=detailed)
        doctor.run_doctor()
        return

    # Create main analyzer instance with debug flag, LLM preference
    analyzer = MobileSecAnalyzer(debug=args.debug, llm_preference=args.llm)
    
    # Handle version flag
    if args.version:
        display_banner()
        return
    
    # Display banner for other operations
    display_banner()
    
    # Handle different modes
    if args.command:
        # Enable ollama cleanup for analysis operations
        _should_cleanup_ollama = True
        atexit.register(cleanup_ollama)
        success = await analyzer.detect_and_analyze(
            args.command, 
            args.type, 
            fix_vulnerabilities=args.fix,
            run_dynamic_analysis=args.dynamic
        )
        sys.exit(0 if success else 1)
    
    # No command provided - show help
    display_banner()
    parser.print_help()


def run():
    """Entry point for console script"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 Analysis interrupted by user")
        cleanup_ollama()
        sys.exit(130)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        cleanup_ollama()
        sys.exit(1)
    finally:
        cleanup_ollama()

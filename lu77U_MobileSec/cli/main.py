"""
Main CLI entry point for lu77U-MobileSec
"""

import sys
from .parser import parse_args
from ..core.app import MobileSecApp
from ..utils import debug_print

def main(args=None):
    """Main entry point for the CLI application"""
    try:
        parsed_args = parse_args(args)
        debug_print("Starting lu77U-MobileSec CLI application", parsed_args.verbose)
        debug_print(f"Verbose mode: {parsed_args.verbose}", parsed_args.verbose)
        app = MobileSecApp(verbose=parsed_args.verbose)
        debug_print("MobileSecApp instance created", parsed_args.verbose)
        app.run()
        
    except KeyboardInterrupt:
        debug_print("Received keyboard interrupt, exiting gracefully", parsed_args.verbose if 'parsed_args' in locals() else False)
        print("\n\nExiting lu77U-MobileSec...")
        sys.exit(0)

    except Exception as e:
        verbose = parsed_args.verbose if 'parsed_args' in locals() else False
        debug_print(f"Unexpected error: {e}", verbose)
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
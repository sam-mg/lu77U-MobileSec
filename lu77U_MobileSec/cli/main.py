"""Main CLI entry point for lu77U-MobileSec"""

import sys
import platform

if platform.system() == "Windows":
    try:
        import colorama
        colorama.init(autoreset=True, convert=True, strip=False, wrap=True)
    except ImportError:
        pass

from .parser import parse_args
from ..utils import verbose_print

def main(args=None):
    """Main entry point for the CLI application"""    
    try:
        parsed_args = parse_args(args)
        verbose_print("Starting lu77U-MobileSec CLI application", parsed_args.verbose)
        verbose_print(f"Python version: {sys.version}", parsed_args.verbose)
        verbose_print(f"Platform: {platform.platform()}", parsed_args.verbose)
        verbose_print(f"Verbose mode: {parsed_args.verbose}", parsed_args.verbose)
        
        if platform.system() == "Windows":
            verbose_print("Detected Windows platform", parsed_args.verbose)
            verbose_print("Colorama initialization was attempted during import", parsed_args.verbose)
        else:
            verbose_print(f"Detected {platform.system()} platform", parsed_args.verbose)
        verbose_print("Starting lu77U-MobileSec CLI application", parsed_args.verbose)
        verbose_print(f"Verbose mode: {parsed_args.verbose}", parsed_args.verbose)
        
        verbose_print("Checking Windows dependencies", parsed_args.verbose)
        from ..utils.windows_dependencies import check_and_install_windows_dependencies
        dependency_check_result = check_and_install_windows_dependencies(parsed_args.verbose)
        
        if not dependency_check_result:
            verbose_print("Windows dependencies check failed", parsed_args.verbose)
            print("\nContinuing without PDF generation capabilities...")
            input("Press Enter to continue or Ctrl+C to exit...")
        else:
            verbose_print("Windows dependencies check passed", parsed_args.verbose)
            
        verbose_print("Importing MobileSecApp", parsed_args.verbose)
        from ..core.app import MobileSecApp
        verbose_print("Creating MobileSecApp instance", parsed_args.verbose)
        app = MobileSecApp(verbose=parsed_args.verbose)
        verbose_print("MobileSecApp instance created successfully", parsed_args.verbose)
        
        verbose_print("Starting application", parsed_args.verbose)
        app.run()
        verbose_print("Application completed successfully", parsed_args.verbose)
        
    except KeyboardInterrupt:
        verbose_value = parsed_args.verbose if 'parsed_args' in locals() else False
        verbose_print("Received keyboard interrupt, exiting gracefully", verbose_value)
        print("\n\nExiting lu77U-MobileSec...")
        verbose_print("Clean exit via keyboard interrupt", verbose_value)
        sys.exit(0)
    except Exception as e:
        verbose_value = parsed_args.verbose if 'parsed_args' in locals() else False
        verbose_print(f"Unexpected error occurred: {type(e).__name__}", verbose_value)
        verbose_print(f"Error details: {str(e)}", verbose_value)
        
        if verbose_value:
            verbose_print("Printing full traceback for debugging", verbose_value)
            import traceback
            traceback.print_exc()
            
        print(f"An error occurred: {e}")
        verbose_print("Exiting with error code 1", verbose_value)
        sys.exit(1)

if __name__ == "__main__":
    main()
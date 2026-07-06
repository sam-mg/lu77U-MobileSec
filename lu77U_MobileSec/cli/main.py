"""Main CLI entry point for lu77U-MobileSec."""

import sys
import platform

if platform.system() == "Windows":
    try:
        import colorama
        colorama.init(autoreset=True, convert=True, strip=False, wrap=True)
    except ImportError:
        pass

from .parser import parse_args
from ..utils.verbose import verbose_print

def main(args=None):
    """Main entry point for the CLI application"""
    parsed_args = None
    try:
        parsed_args = parse_args(args)
        verbose_print("Starting lu77U-MobileSec", parsed_args.verbose)
        verbose_print(f"Python version: {sys.version}", parsed_args.verbose)
        verbose_print(f"Platform: {platform.platform()}", parsed_args.verbose)

        from ..web.server import serve
        serve(
            verbose=parsed_args.verbose,
            port=parsed_args.port,
            open_browser=not parsed_args.no_browser,
        )

    except KeyboardInterrupt:
        print("\n\nExiting lu77U-MobileSec...")
        sys.exit(0)
    except Exception as e:
        verbose_value = parsed_args.verbose if parsed_args is not None else False
        if verbose_value:
            import traceback
            traceback.print_exc()
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
"""Command line argument parser for lu77U-MobileSec."""

import argparse

from lu77U_MobileSec import __version__

def create_parser():
    """Create and configure the argument parser"""
    parser = argparse.ArgumentParser(
        prog='lu77U-MobileSec',
        description=(
            'The Only Mobile Security Tool Which You Need.\n\n'
            'Running "lu77U-MobileSec" starts the local web dashboard and opens\n'
            'it in your default browser. Use -V to also stream logs to the\n'
            'terminal.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'lu77U-MobileSec {__version__}',
    )

    parser.add_argument(
        '-V', '--verbose',
        action='store_true',
        help='Stream verbose analysis logs to the terminal (also shown in the web UI)',
    )

    # Developer/advanced options (hidden from normal help output).
    parser.add_argument('--port', type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument('--no-browser', action='store_true', help=argparse.SUPPRESS)

    return parser

def parse_args(args=None):
    """Parse command line arguments"""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    return parsed_args
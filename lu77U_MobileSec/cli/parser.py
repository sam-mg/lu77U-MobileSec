"""
Command line argument parser for lu77U-MobileSec
"""

import argparse
from lu77U_MobileSec import __version__
from lu77U_MobileSec.utils import verbose_print

def create_parser():
    """Create and configure the argument parser"""
    verbose_print("Creating argument parser", False)
    
    parser = argparse.ArgumentParser(
        prog='lu77U-MobileSec',
        description='The Only Mobile Security Tool Which You Need',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'lu77U-MobileSec {__version__}'
    )
    
    parser.add_argument(
        '-V', '--verbose',
        action='store_true',
        help='Enable debug/verbose mode with yellow debug output'
    )
    
    verbose_print("Argument parser created successfully", False)
    return parser

def parse_args(args=None):
    """Parse command line arguments"""
    parser = create_parser()
    parsed_args = parser.parse_args(args)
    
    verbose_print(f"Arguments parsed: {vars(parsed_args)}", parsed_args.verbose)
    
    return parsed_args

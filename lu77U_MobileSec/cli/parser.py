#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.cli.parser

Purpose:
    Define the command-line surface. Kept separate from .main so that the flag set can be built and inspected -- by tests, by shell-completion generators, by documentation tooling -- without starting a server.

Responsibilities:
    Construct the ArgumentParser and expose a one-call parse.

Dependencies:
    argparse, .._metadata for the program name, version and description.

Implementation notes:
    The surface is intentionally tiny. Running the tool with no arguments is the supported workflow: everything else is chosen in the web UI, so options that would duplicate a UI control are deliberately absent rather than provided twice with two chances to disagree.
"""

import argparse

from lu77U_MobileSec._metadata import DESCRIPTION, NAME, VERSION

def create_parser():
    """
    Purpose:
        Build the argument parser for the console script.

    Returns:
        A configured argparse.ArgumentParser. Returned rather than parsed here so callers can extend it or render its help without side effects.

    Postconditions:
        The returned parser defines -v/--version, -V/--verbose, --port and --no-browser, and nothing else.

    Implementation notes:
        -v is version and -V is verbose, which inverts the more common Unix convention; this is deliberate and load-bearing, because the flag set is already published and swapping them would silently change the meaning of existing command lines. RawDescriptionHelpFormatter is required for the newlines in the description to survive; the default formatter reflows them into one paragraph. --port and --no-browser use argparse.SUPPRESS so they stay out of --help. They exist for tests and for embedding, not for the documented workflow, and advertising them would invite users to pin a port that the dashboard is free to change.
    """
    parser = argparse.ArgumentParser(
        prog=NAME,
        description=(
            f'{DESCRIPTION}.\n\n'
            f'Running "{NAME}" starts the local web dashboard and opens\n'
            'it in your default browser. Use -V to also stream logs to the\n'
            'terminal.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'{NAME} {VERSION}',
    )

    parser.add_argument(
        '-V', '--verbose',
        action='store_true',
        help='Stream verbose analysis logs to the terminal (also shown in the web UI)',
    )

    parser.add_argument('--port', type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument('--no-browser', action='store_true', help=argparse.SUPPRESS)

    return parser

def parse_args(args=None):
    """
    Purpose:
        Parse an argument vector against the CLI surface.

    Parameters:
        args: Argument vector to parse. None means read sys.argv, which is the normal path; tests pass an explicit list.

    Returns:
        An argparse.Namespace carrying verbose, port and no_browser.

    Raises:
        SystemExit: Raised by argparse itself -- 0 after --help or --version, 2 on an unrecognised or malformed argument. Callers must expect this; it is not an error path this function can intercept.

    Side effects:
        Writes help or version text to stdout, or an error to stderr, before the exit in those cases.
    """
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    return parsed_args

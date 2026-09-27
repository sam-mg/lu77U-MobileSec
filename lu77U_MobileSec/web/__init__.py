#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web

Purpose:
    Namespace for the local dashboard: the HTTP server, its routes, its background job registry and the services those routes call.

Responsibilities:
    None beyond marking the directory as a package. .server is imported lazily by the CLI so that --help and --version do not pay for the HTTP stack.

Dependencies:
    None at import time.

Security considerations:
    No route is registered as a side effect of importing this package; the server binds only when serve() is called explicitly.
"""

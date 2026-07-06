"""Application shim — the terminal menu UI was replaced by a web dashboard."""

class MobileSecApp:
    """Compatibility wrapper that launches the web dashboard."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def run(self, port=None, open_browser: bool = True):
        from ..web.server import serve
        serve(verbose=self.verbose, port=port, open_browser=open_browser)
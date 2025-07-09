#!/usr/bin/env python3
"""
Basic tests for lu77U-MobileSec package
"""

import pytest
import sys
import os

def test_package_import():
    """Test that the package can be imported successfully"""
    try:
        import lu77u_mobilesec
        assert lu77u_mobilesec.__version__ == "1.0.0"
        assert lu77u_mobilesec.__author__ == "Sam MG Harish (lu77_u)"
    except ImportError as e:
        pytest.fail(f"Failed to import lu77u_mobilesec: {e}")

def test_main_components_import():
    """Test that main components can be imported"""
    try:
        from lu77u_mobilesec.core.orchestrator import MobileSecAnalyzer
        from lu77u_mobilesec.cli.app import main, run
        from lu77u_mobilesec.core.detectors.framework_detector import FrameworkDetector
        
        # Basic instantiation test
        detector = FrameworkDetector()
        assert detector is not None
        
    except ImportError as e:
        pytest.fail(f"Failed to import main components: {e}")

def test_cli_entry_point():
    """Test that CLI entry point is accessible"""
    try:
        from lu77u_mobilesec.cli.app import run
        assert callable(run)
    except ImportError as e:
        pytest.fail(f"Failed to import CLI entry point: {e}")

if __name__ == "__main__":
    pytest.main([__file__])

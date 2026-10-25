#!/usr/bin/env python3
"""
Module: test_dynamic_session

Purpose:
    What the on-device session reports about the app, as opposed to what it reports about the device.

Responsibilities:
    Pin that a working HTTPS interception check is an environment result and adds no finding to the app.

Dependencies:
    pytest and the dynamic analyzer, with fakes for the device bridge, Frida, the proxy, the visual check and UI automation.

Implementation notes:
    The interception check proves the proxy and CA by opening a probe URL in the device's browser, then stops the proxy before the app runs. It was turned into "Interceptable HTTPS Traffic (No Certificate Pinning)" on every app, including Ghera apps that open no connection at all.
"""

import types

from lu77U_MobileSec.dynamic_analysis import dynamic_analyzer as dyn_mod


class _Bridge:
    """
    Purpose:
        A rooted device that records nothing and launches anything.
    """

    def list_devices(self):
        """
        Purpose:
            Report one emulator.

        Returns:
            The device list.
        """
        return [{"serial": "emulator-5554", "model": "x", "android_version": "11", "is_emulator": True}]

    def check_root(self, unused_device):
        """
        Purpose:
            Report root.

        Parameters:
            unused_device: The serial, unused.

        Returns:
            True.
        """
        return True

    def launch_app(self, *unused_args):
        """
        Purpose:
            Pretend to launch the app.

        Parameters:
            unused_args: Serial and package, unused.

        Returns:
            True.
        """
        return True


def test_working_interception_is_not_a_finding_about_the_app(monkeypatch):
    """
    Purpose:
        A passing interception check is recorded as a check and the session reports no runtime finding.

    Parameters:
        monkeypatch: Replaces the visual check and UI automation.
    """
    monkeypatch.setattr(dyn_mod, "run_google_visual_check", lambda *_: (False, "no vision"))
    monkeypatch.setattr(dyn_mod, "UIAutomator", lambda *_, **__: types.SimpleNamespace(connect=lambda: False))
    frida = types.SimpleNamespace(stop_server=lambda *_: None)
    analyzer = dyn_mod.DynamicAnalyzer(adb=_Bridge(), frida=frida)
    analyzer.mitmproxy = types.SimpleNamespace(
        run_https_check=lambda *_: (True, "HTTPS traffic decrypted and captured (www.google.com)."))

    result = analyzer.run("emulator-5554", "com.example.app", skip_app_info=True,
                          frida_env={"ok": True, "message": "Frida running"})

    assert result["env_checks"]["https_intercept"]["ok"] is True
    assert result["runtime_findings"] == []


def test_the_ui_explorer_stops_its_server_when_done():
    """
    Purpose:
        Pin that closing the UI explorer stops the uiautomator2 server it started, and that closing twice or without a connection is harmless.

    Implementation notes:
        Left running, the server held the device's UI automation and the next scan's verifier could not dump the screen.
    """
    from lu77U_MobileSec.dynamic_analysis.ui_automator import UIAutomator

    class Device:
        """
        Purpose:
            A uiautomator2 device that records being stopped.

        Attributes:
            stopped: How many times the server was stopped.
        """
        def __init__(self):
            """
            Purpose:
                Start with nothing stopped.
            """
            self.stopped = 0

        def stop_uiautomator(self):
            """
            Purpose:
                Record a stop.
            """
            self.stopped += 1

    ui = UIAutomator(adb_manager=None, device="emulator-5554")
    ui.close()
    device = Device()
    ui._u2_device = device
    ui.close()
    ui.close()
    assert device.stopped == 1 and ui._u2_device is None

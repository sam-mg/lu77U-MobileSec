#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent

Purpose:
    Facade for the AI static-analysis agent. Exposes run_agent_analysis as the single supported entry point so that callers never drive the agent loop, its tool registry or its code graph directly.

Responsibilities:
    Re-export run_agent_analysis and nothing else.

Dependencies:
    .agent_loop.

Security considerations:
    The agent hands model-selected tool calls to the tool layer, which is where sandboxing and path validation live. Narrowing the public surface to one function keeps those checks impossible to bypass by accident.
"""

from .agent_loop import run_agent_analysis

__all__ = ["run_agent_analysis"]

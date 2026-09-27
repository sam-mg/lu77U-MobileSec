#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.skills_loader

Purpose:
    Load the analysis skills the agent is given: the built-in ones that ship with the tool and the user's own, with the user's taking precedence.

Responsibilities:
    Locate skill files, list them, and assemble the text handed to the agent.

Dependencies:
    The configuration directory.

Implementation notes:
    Skills are prompt fragments describing how to look for a class of issue. Keeping them as files rather than in code lets a user add or replace one without touching the tool, which is the point of the user directory.

Security considerations:
    A skill becomes part of the agent's instructions, so an uploaded one influences what the scan looks for. Upload validation lives in the settings service; this module only reads what is already there.
"""

from pathlib import Path
from typing import Iterable, List, Optional

from ...config.paths import get_config_dir
from ...utils.verbose import verbose_print

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"

CORE_SKILL = "java_kotlin_security"

CORE_SKILLS = {
    "java_kotlin": "java_kotlin_security",
    "flutter": "flutter_dart_security",
    "react_native": "react_native_security",
    "cordova": "cordova_hybrid_security",
    "xamarin": "xamarin_dotnet_security",
}

def user_skills_dir() -> Path:
    """
    Purpose:
        Return the directory holding the user's own skills, creating it if needed.

    Returns:
        The directory.

    Side effects:
        Creates the directory.
    """
    path = get_config_dir() / "skills"
    path.mkdir(parents=True, exist_ok=True)
    return path

def skill_path(name: str) -> Optional[Path]:
    """
    Purpose:
        Locate a skill by name.

    Parameters:
        name: The skill's name.

    Returns:
        The path, or None when no such skill exists.

    Implementation notes:
        The user directory is searched before the built-in one, so a user skill sharing a name shadows the shipped version. That is the intended way to replace a built-in rather than edit it in place, where an upgrade would overwrite it.
    """
    if not name:
        return None
    for base in (user_skills_dir(), SKILLS_DIR):
        candidate = base / f"{name}.md"
        if candidate.is_file():
            return candidate
    return None

def available_skills() -> List[str]:
    """
    Purpose:
        List every skill available, from both sources.

    Returns:
        The skill names, sorted and deduplicated.

    Implementation notes:
        Deduplicated by name, since a shadowing user skill and the built-in it replaces are one skill from the agent's point of view.
    """
    names = {p.stem for p in SKILLS_DIR.glob("*.md")}
    names |= {p.stem for p in user_skills_dir().glob("*.md")}
    return sorted(names)

def load_skill(name: str, verbose: bool = False) -> str:
    """
    Purpose:
        Read one skill's text.

    Parameters:
        name: The skill's name.
        verbose: Traces a missing skill.

    Returns:
        The skill text, or an empty string when it does not exist.

    Implementation notes:
        A missing skill returns empty rather than raising, so a stale reference degrades the guidance rather than failing the analysis.
    """
    path = skill_path(name)
    if path is None:
        verbose_print(f"Skill not found: {name}", verbose)
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")

def load_skills(names: Iterable[str], verbose: bool = False, core: str = CORE_SKILL) -> str:
    """
    Purpose:
        Assemble the skill text handed to the agent for one region.

    Parameters:
        names: The skills relevant to this region.
        verbose: Traces missing skills.
        core: The skill always included first.

    Returns:
        The combined text.

    Implementation notes:
        The core skill is prepended unconditionally, because it carries the output contract and the scoring instructions that every agent needs regardless of what it is looking at. Order is preserved and duplicates removed, so a region whose families overlap does not receive the same guidance twice -- which wastes context and, in practice, makes a model weight the repeated instruction more heavily than intended.
    """
    ordered, seen = [], set()
    for name in [core, *names]:
        if name and name not in seen and skill_path(name) is not None:
            seen.add(name)
            ordered.append(name)
    parts = [load_skill(n, verbose) for n in ordered]
    return "\n\n---\n\n".join(p for p in parts if p)

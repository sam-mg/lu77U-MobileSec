"""Contextual loader for the file-based skills in ``lu77U_MobileSec/skills/``."""

from pathlib import Path
from typing import Iterable

from ...utils.verbose import verbose_print

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"

#: Always loaded — the core review guidance.
CORE_SKILL = "java_kotlin_security"

def available_skills() -> list:
    return sorted(p.stem for p in SKILLS_DIR.glob("*.md"))

def load_skill(name: str, verbose: bool = False) -> str:
    path = SKILLS_DIR / f"{name}.md"
    if not path.exists():
        verbose_print(f"Skill not found: {name}", verbose)
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")

def load_skills(names: Iterable[str], verbose: bool = False) -> str:
    """Concatenate the named skills (deduped, core first) into one block."""
    ordered, seen = [], set()
    for name in [CORE_SKILL, *names]:
        if name and name not in seen and (SKILLS_DIR / f"{name}.md").exists():
            seen.add(name)
            ordered.append(name)
    parts = [load_skill(n, verbose) for n in ordered]
    return "\n\n---\n\n".join(p for p in parts if p)
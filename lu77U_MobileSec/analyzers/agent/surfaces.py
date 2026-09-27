#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.surfaces

Purpose:
    Define the attack surfaces the agent fans out across -- the coherent areas of an app worth examining as a unit -- and map sink families onto them.

Responsibilities:
    Declare the surface type, the Android surfaces, and the family mapping.

Dependencies:
    dataclasses only.

Implementation notes:
    Fanning out by attack surface rather than by directory is what makes the agent phase both faster and more thorough. Each agent gets a coherent objective and the code relevant to it, instead of a slice of a tree it has to orient itself in. Each surface carries an objective written as an instruction, because it becomes part of that agent's prompt.
"""

from dataclasses import dataclass, field
from typing import FrozenSet, Tuple

SURFACE_SHARD_THRESHOLD = 120


@dataclass(frozen=True)
class AttackSurface:
    """
    Purpose:
        One area of an app the agent examines as a unit.

    Attributes:
        key: Surface identifier.
        label: Human-readable name, used in progress and reports.
        objective: What the agent examining this surface is asked to establish.
        sink_families: Sink families that place code on this surface.
        secondary_families: Families that are relevant but not defining.

    Invariants:
        Frozen and shared across agents.

    Thread-safety:
        Immutable and safe to share.
    """
    key: str
    label: str
    objective: str
    sink_families: FrozenSet[str] = field(default_factory=frozenset)
    secondary_families: FrozenSet[str] = field(default_factory=frozenset)
    roles: FrozenSet[str] = field(default_factory=frozenset)
    skills: Tuple[str, ...] = ()
    wants_intent_actions: bool = False
    wants_secrets: bool = False
    wants_native_libs: bool = False


ANDROID_SURFACES: Tuple[AttackSurface, ...] = (
    AttackSurface(
        key="component_exposure",
        label="Exported components & IPC",
        objective=(
            "Audit this app's externally reachable components. For every exported "
            "Activity, Service, Receiver and Provider in your map: determine what an "
            "unprivileged third-party app can invoke, what data it can read or write, "
            "and whether any permission check actually guards it. Prioritise exported "
            "ContentProviders (read/write access to app data) and exported components "
            "that perform privileged actions on behalf of the caller. Do not audit "
            "WebView configuration or credential storage - other agents own those."
        ),
        sink_families=frozenset({"ipc"}),
        roles=frozenset({"exported-activity", "exported-service",
                         "exported-receiver", "exported-provider"}),
        skills=("manifest_review", "android_analysis", "reading_obfuscated_code"),
    ),
    AttackSurface(
        key="deeplinks_intents",
        label="Deep links & intent handling",
        objective=(
            "Trace untrusted input from Intents and deep links into the app. Start at "
            "every component with an intent-filter or that reads getIntent()/getData()/"
            "getStringExtra(), then follow that value: does it reach a WebView load, a "
            "file path, a SQL string, a redirect, or another startActivity()? Report "
            "intent redirection, unvalidated deep-link parameters and any deep link "
            "that reaches an authenticated context. Focus on the data flow, not on "
            "whether the component is exported - another agent covers exposure."
        ),
        sink_families=frozenset({"ipc", "uri"}),
        roles=frozenset({"exported-activity", "exported-receiver"}),
        skills=("vulnerability_classes", "chain_building", "reading_obfuscated_code"),
        wants_intent_actions=True,
    ),
    AttackSurface(
        key="storage",
        label="Data storage & databases",
        objective=(
            "Audit how this app stores data at rest. Examine every SharedPreferences "
            "write, SQLite query, file write and external-storage path in your map. "
            "Report credentials or tokens written unencrypted, world-accessible modes, "
            "data written to external storage, and SQL built by string concatenation "
            "(especially inside a ContentProvider, where it is remotely reachable). "
            "Say what the stored value actually is - 'stores data unencrypted' with no "
            "named value is not a finding."
        ),
        sink_families=frozenset({"prefs", "sql", "storage"}),
        skills=("vulnerability_classes",),
    ),
    AttackSurface(
        key="network_webview",
        label="Network & WebView",
        objective=(
            "Audit this app's WebViews and network layer. For every WebView: what URL "
            "does it load, is that URL attacker-influenceable, is JavaScript enabled, "
            "is a Java object bound via addJavascriptInterface, and are file-access or "
            "universal-file-access settings enabled? Read every class with "
            "@JavascriptInterface methods and list exactly what each method exposes. "
            "Also report cleartext traffic, TLS validation bypasses and missing "
            "certificate pinning."
        ),
        sink_families=frozenset({"webview", "js_bridge"}),
        skills=("network_security", "vulnerability_classes"),
    ),
    AttackSurface(
        key="native_secrets",
        label="Native code, crypto & secrets",
        objective=(
            "Audit this app's cryptography, embedded secrets and native code. Report "
            "hardcoded keys, tokens and credentials with the actual value and file, "
            "broken primitives (MD5/SHA-1/DES/RC4/ECB), hardcoded IVs or keys passed "
            "to SecretKeySpec, and sensitive values written to logcat. Inspect every "
            "native library for embedded strings and exported JNI symbols. A string "
            "that merely looks random is not a secret - say what it authenticates to."
        ),
        sink_families=frozenset({"native", "native-call", "crypto"}),
        secondary_families=frozenset({"logging"}),
        roles=frozenset({"native-bridge"}),
        skills=("offensive_android", "sdk_analysis", "native_library_analysis"),
        wants_secrets=True,
        wants_native_libs=True,
    ),
)

SURFACES_BY_KEY = {s.key: s for s in ANDROID_SURFACES}


FAMILY_TO_SURFACE: dict = {}
for _s in ANDROID_SURFACES:
    for _f in _s.sink_families | _s.secondary_families:
        FAMILY_TO_SURFACE.setdefault(_f, _s.key)
for _role_family in ("exported-activity", "exported-service",
                     "exported-receiver", "exported-provider"):
    FAMILY_TO_SURFACE.setdefault(_role_family, "component_exposure")


def guidance_for_families(families) -> Tuple[str, Tuple[str, ...]]:
    """
    Purpose:
        Map the sink families found in a region to the surfaces and skills that apply.

    Parameters:
        families: The sink families observed.

    Returns:
        The guidance text and the skills to load.

    Implementation notes:
        Order is preserved and surfaces deduplicated, so a region touching several families gets each surface's guidance once. Repeating guidance both wastes context and skews how heavily the model weights it.
    """
    keys, seen = [], set()
    for family in families:
        surface = FAMILY_TO_SURFACE.get(family)
        if surface and surface not in seen:
            seen.add(surface)
            keys.append(surface)
    if not keys:
        keys = ["component_exposure"]

    objectives, skills = [], []
    for key in keys[:3]:
        surface = SURFACES_BY_KEY[key]
        objectives.append(f"{surface.label}: {surface.objective}")
        for skill in surface.skills:
            if skill not in skills:
                skills.append(skill)
    return "\n\n".join(objectives), tuple(skills)


def surfaces_for_profile(profile_key: str) -> Tuple[AttackSurface, ...]:
    """
    Purpose:
        Return the attack surfaces for a framework profile.

    Parameters:
        profile_key: The framework profile.

    Returns:
        The surfaces.

    Implementation notes:
        Currently the Android surfaces for every profile. The surfaces are platform concepts -- exported components, WebViews, storage, network -- and they apply whether the code reaching them is Java, Dart or JavaScript. The parameter exists so a framework needing its own set can have one without changing every call site.
    """
    return ANDROID_SURFACES

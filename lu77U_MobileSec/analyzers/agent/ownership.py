#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.ownership

Purpose:
    Decide which classes in an APK are the application's own, which belong to the platform, and which come from bundled third-party SDKs.

Responsibilities:
    Derive the prefixes for each category, seed a classification from them, and propagate it across the package hierarchy.

Dependencies:
    androguard's analysis object, the vendor prefix tables.

Implementation notes:
    This is the single most consequential piece of filtering in the tool. A decompiled app is overwhelmingly library code, and an analysis that cannot tell it apart from the application's own spends its budget on code the app owner did not write and cannot change. Classification is seeded from known prefixes and then propagated, rather than decided per class by prefix alone, because an app's own code is not always under its package name -- and a library's is not always under a recognised one.

Security considerations:
    Misclassifying application code as vendor suppresses real findings, so the propagation is deliberately biased toward calling an ambiguous package application code. Vendor classification lowers a finding's severity rather than dropping it, which keeps the cost of the opposite error bounded.
"""

import collections
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ...utils.verbose import plural, verbose_print

FRAMEWORK_PREFIXES: Tuple[str, ...] = (
    "Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/", "Lkotlinx/",
    "Ldalvik/", "Lorg/xmlpull/", "Lorg/w3c/", "Lorg/xml/", "Lorg/json/",
    "Lorg/apache/", "Lorg/intellij/", "Lorg/jetbrains/", "Ljunit/",
    "Lorg/junit/", "Lorg/checkerframework/", "Lorg/reactivestreams/",
    "Lcom/google/",
)

MAX_ROUNDS = 8

APP_SHARE_MIN = 0.5
VENDOR_SHARE_MAX = 0.25

MIN_EVIDENCE = 3

APP = "app"
VENDOR = "vendor"
FRAMEWORK = "framework"

_GENERATED_CLASS_RE = re.compile(
    r"^(?:R|BuildConfig|DataBinderMapperImpl.*|Dagger.*|Hilt_.*"
    r"|.*_Impl|.*_Factory|.*_MembersInjector|.*_GeneratedInjector"
    r"|.*_HiltModules.*|.*\$\$serializer|.*_ViewBinding|.*Binding)$")


def package_of(descriptor: str) -> str:
    """
    Purpose:
        Extract the package from a class descriptor.

    Parameters:
        descriptor: The class descriptor.

    Returns:
        The package path, or a marker for the default package.

    Implementation notes:
        Inner-class suffixes are stripped first, so a nested class is attributed to the same package as its outer class rather than forming one of its own.
    """
    inner = descriptor[1:-1] if descriptor.startswith("L") and descriptor.endswith(";") else descriptor
    inner = inner.split("$", 1)[0]
    return inner.rsplit("/", 1)[0] if "/" in inner else "(default)"


def descriptor_to_fqn(descriptor: str) -> str:
    """
    Purpose:
        Convert a class descriptor to a readable fully-qualified name.

    Parameters:
        descriptor: The class descriptor.

    Returns:
        The dotted name.

    Implementation notes:
        Used wherever a class reaches a prompt or a report, since the descriptor form is bytecode notation and a reader should not have to decode it.
    """
    inner = descriptor[1:-1] if descriptor.startswith("L") and descriptor.endswith(";") else descriptor
    return inner.split("$", 1)[0].replace("/", ".")


def _effective_framework_prefixes(package: str) -> Tuple[str, ...]:
    """
    Purpose:
        Return the platform prefixes, excluding any that the app's own package sits under.

    Parameters:
        package: The app's package.

    Returns:
        The applicable framework prefixes.

    Implementation notes:
        An app whose package begins with a platform-looking prefix would otherwise have its own code classified as framework and skipped entirely. Removing the conflicting prefix is what stops that, and it is worth doing because an app published under such a package is not rare.
    """
    if not package:
        return FRAMEWORK_PREFIXES
    descriptor = "L" + package.replace(".", "/") + "/"
    return tuple(p for p in FRAMEWORK_PREFIXES if not descriptor.startswith(p))


def _vendor_prefixes() -> Tuple[str, ...]:
    """
    Purpose:
        Assemble the prefixes identifying bundled third-party SDKs.

    Returns:
        The vendor prefixes, deduplicated and sorted.

    Implementation notes:
        Combined from the graph's own table and the SDK inventory's signatures, so a library the inventory knows how to recognise is also treated as vendor code by ownership -- keeping the two consistent. Both imports are guarded, so a missing table narrows the vendor set rather than failing classification.
    """
    out: List[str] = []
    try:
        from .code_graph import _VENDOR_PREFIXES
        out.extend(_VENDOR_PREFIXES)
    except Exception:
        pass
    try:
        from ..sast.extractors.sdk_inventory import SDK_SIGNATURES
        for entry in SDK_SIGNATURES.values():
            for pkg in entry[1]:
                out.append("L" + pkg.strip("/") + "/")
    except Exception:
        pass
    return tuple(sorted(set(out)))


def _seed_kind(descriptor: str, app_prefixes: Tuple[str, ...],
               vendor_prefixes: Tuple[str, ...],
               framework_prefixes: Tuple[str, ...]) -> Optional[str]:
    """
    Purpose:
        Classify one class by prefix, where a prefix decides it.

    Parameters:
        descriptor: The class descriptor.
        app_prefixes: Prefixes identifying the app's own code.
        vendor_prefixes: Prefixes identifying bundled SDKs.
        framework_prefixes: Prefixes identifying the platform.

    Returns:
        The category, or None when no prefix applies.

    Implementation notes:
        Application prefixes are tested first, so a vendor prefix that happens to sit under the app's package does not steal the app's own classes. None is a meaningful result: it means this class must be classified by propagation rather than by prefix, which is most of them in an obfuscated app.
    """
    if descriptor.startswith(app_prefixes):
        return APP
    if descriptor.startswith(framework_prefixes):
        return FRAMEWORK
    if descriptor.startswith(vendor_prefixes):
        return VENDOR
    return None


def _app_prefixes(package: str, manifest_components: Optional[List[str]],
                  vendor_prefixes: Tuple[str, ...],
                  framework_prefixes: Tuple[str, ...]) -> Tuple[str, ...]:
    """
    Purpose:
        Derive the prefixes identifying the application's own code.

    Parameters:
        package: The app's declared package.
        manifest_components: Component class names from the manifest.
        vendor_prefixes: Known vendor prefixes.
        framework_prefixes: Known platform prefixes.

    Returns:
        The application prefixes.

    Implementation notes:
        Built from the declared package plus its first two segments, because an app's code frequently sits beside its package rather than inside it -- a shared organisation prefix with several modules under it. Manifest components extend the set, since a declared activity is definitively the app's own code. They are only accepted when they already sit under a derived prefix and are not vendor or framework, so a manifest declaring a library's component does not make that library part of the app.
    """
    out: Set[str] = set()
    if package:
        out.add("L" + package.replace(".", "/") + "/")
        parts = package.split(".")
        if len(parts) >= 2:
            out.add("L" + "/".join(parts[:2]) + "/")
    for name in manifest_components or []:
        if not name or "." not in name:
            continue
        descriptor = "L" + name.replace(".", "/") + ";"
        if descriptor.startswith(framework_prefixes) or descriptor.startswith(vendor_prefixes):
            continue
        if not any(descriptor.startswith(p) for p in out):
            continue
        out.add("L" + name.replace(".", "/").rsplit("/", 1)[0] + "/")
    return tuple(sorted(out))


def classify_packages(dx, package: str,
                      manifest_components: Optional[List[str]] = None,
                      verbose: bool = False) -> Dict[str, Any]:
    """
    Purpose:
        Classify every package in the APK as application, vendor or framework code.

    Parameters:
        dx: androguard's analysis object.
        package: The app's declared package.
        manifest_components: Component class names from the manifest.
        verbose: Traces the classification.

    Returns:
        The ownership map and its summary.

    Complexity:
        Iterates the classes several times, then propagates over packages until it settles.

    Implementation notes:
        External classes are skipped, since they are references rather than code in this APK. A package containing any class that seeds as application code is application code, even if most of its classes seed as nothing. That bias is deliberate: an obfuscated app has few recognisable classes, and requiring a majority would classify most of the application as unknown. A package seeding purely as framework is framework; vendor wins over an otherwise-unclassified package. The order of these tests is what encodes the bias toward keeping application code in scope.

    Security considerations:
        Everything the agent examines is chosen from this classification, so a package wrongly excluded here is never analysed at all.
    """
    framework_prefixes = _effective_framework_prefixes(package)
    vendor_prefixes = _vendor_prefixes()
    app_prefixes = _app_prefixes(package, manifest_components, vendor_prefixes,
                                 framework_prefixes)

    internal: Dict[str, Any] = {}
    for c in dx.get_classes():
        try:
            if c.is_external():
                continue
        except Exception:
            pass
        internal[c.name] = c

    members: Dict[str, List[str]] = collections.defaultdict(list)
    for name in internal:
        members[package_of(name)].append(name)

    owner: Dict[str, str] = {}
    for pkg, names in members.items():
        kinds = {_seed_kind(n, app_prefixes, vendor_prefixes, framework_prefixes)
                 for n in names}
        if APP in kinds:
            owner[pkg] = APP
        elif kinds == {FRAMEWORK}:
            owner[pkg] = FRAMEWORK
        elif VENDOR in kinds:
            owner[pkg] = VENDOR
    seeded_app = sum(1 for v in owner.values() if v == APP)
    seeded_vendor = sum(1 for v in owner.values() if v == VENDOR)

    inbound: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for name, klass in internal.items():
        src = package_of(name)
        try:
            targets = klass.get_xref_to()
        except Exception:
            continue
        for target in targets:
            tname = getattr(target, "name", None)
            if tname in internal:
                inbound[package_of(tname)][src] += 1

    rounds = 0
    for rounds in range(1, MAX_ROUNDS + 1):
        changed = 0
        for pkg in members:
            if pkg in owner:
                continue
            score = collections.Counter()
            for src, weight in inbound.get(pkg, {}).items():
                kind = owner.get(src)
                if kind in (APP, VENDOR):
                    score[kind] += weight
            total = score[APP] + score[VENDOR]
            if total < MIN_EVIDENCE:
                continue
            share = score[APP] / total
            if share >= APP_SHARE_MIN:
                owner[pkg] = APP
                changed += 1
            elif share <= VENDOR_SHARE_MAX:
                owner[pkg] = VENDOR
                changed += 1
        if not changed:
            break

    for pkg in sorted(members, key=lambda p: p.count("/")):
        if pkg in owner or "/" not in pkg:
            continue
        parent = pkg.rsplit("/", 1)[0]
        while True:
            if parent in owner:
                owner[pkg] = owner[parent]
                break
            if "/" not in parent:
                break
            parent = parent.rsplit("/", 1)[0]

    counts = collections.Counter(
        owner.get(package_of(n), "undecided") for n in internal)
    undecided_pkgs = [p for p in members if p not in owner]
    stats = {
        "packages": len(members),
        "rounds": rounds,
        "seeded_app_packages": seeded_app,
        "seeded_vendor_packages": seeded_vendor,
        "app_classes": counts.get(APP, 0),
        "vendor_classes": counts.get(VENDOR, 0),
        "framework_classes": counts.get(FRAMEWORK, 0),
        "undecided_classes": counts.get("undecided", 0),
        "undecided_packages": sorted(undecided_pkgs)[:40],
        "app_packages": sorted(p for p, v in owner.items() if v == APP),
    }

    verbose_print(
        f"Ownership: {plural(stats['app_classes'], 'app class', 'app classes')} kept "
        f"({stats['vendor_classes']} vendor, {stats['framework_classes']} framework, "
        f"{stats['undecided_classes']} undecided and excluded) across "
        f"{plural(stats['packages'], 'package')} in {plural(rounds, 'round')}", verbose)
    if undecided_pkgs:
        verbose_print(
            f"Ownership: {plural(len(undecided_pkgs), 'package')} undecided and left out - "
            + ", ".join(sorted(undecided_pkgs)[:8])
            + (" …" if len(undecided_pkgs) > 8 else ""), verbose)
    return {"owner": owner, "stats": stats}


def is_generated_class(descriptor: str) -> bool:
    """
    Purpose:
        Recognise classes generated by the build rather than written by a developer.

    Parameters:
        descriptor: The class descriptor.

    Returns:
        True when the class is generated.

    Implementation notes:
        Matched against the naming conventions of the common generators -- resource classes, build configuration, dependency-injection and serialisation output, view bindings. Excluding these matters because they are numerous, they are mechanically similar, and a finding in one points at the generator's template rather than at anything the developer can change.
    """
    inner = descriptor[1:-1] if descriptor.startswith("L") and descriptor.endswith(";") else descriptor
    base = inner.rsplit("/", 1)[-1].split("$", 1)[0]
    return bool(_GENERATED_CLASS_RE.match(base))


def is_app_descriptor(descriptor: str, owner: Dict[str, str]) -> bool:
    """
    Purpose:
        Report whether a class belongs to the application.

    Parameters:
        descriptor: The class descriptor.
        owner: The ownership map.

    Returns:
        True when the class is application code.

    Implementation notes:
        Resolved through the package's classification rather than by re-testing prefixes, so every caller agrees with the propagated result rather than re-deriving a possibly different answer.
    """
    if owner.get(package_of(descriptor)) != APP:
        return False
    return not is_generated_class(descriptor)

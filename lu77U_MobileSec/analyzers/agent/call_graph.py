#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.call_graph

Purpose:
    Build a method-level call graph over the app's own code, so the agent can answer the question static pattern matching cannot: is this sink actually reachable from somewhere an attacker controls.

Responsibilities:
    Model methods and their call edges, and support search, neighbour lookup, path finding and reachability.

Dependencies:
    androguard's analysis object, the sink family table in graph_tables.

Implementation notes:
    Reachability is what separates a finding from an observation. A vulnerable call in code nothing invokes is a code-quality note; the same call reachable from an exported component is a vulnerability. This graph is how the agent establishes which. Only the app's own methods are included, since a path through the entire platform and every bundled library would be both enormous and unusable -- and a path that leaves the app's code tells the reader nothing they can act on. Every traversal is bounded in depth and in result count, because the agent's context is finite and an unbounded path search over a real app does not terminate usefully.
"""

import collections
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from .graph_tables import SINK_FAMILIES as _SINK_FAMILIES
from ...utils.verbose import plural, verbose_print

MAX_NEIGHBOURS = 40

MAX_PATH_DEPTH = 12

MAX_PATHS = 5

MAX_MATCHES = 40


def method_key(class_descriptor: str, name: str, descriptor: str = "") -> str:
    """
    Purpose:
        Build the stable key identifying one method.

    Parameters:
        class_descriptor: The declaring class.
        name: The method name.
        descriptor: The method's parameter and return descriptor.

    Returns:
        The key.

    Implementation notes:
        The parameter descriptor is part of the key because overloads are distinct methods with distinct reachability, and collapsing them would report a path through the wrong one.
    """
    return f"{class_descriptor}->{name}{descriptor}"


@dataclass
class MethodNode:
    """
    Purpose:
        One method in the call graph.

    Attributes:
        Its identifying key, declaring class, name and descriptor.

    Thread-safety:
        Read-only once the graph is built.
    """
    key: str
    cls: str
    name: str
    class_descriptor: str
    file: str = ""
    signature: str = ""
    role: str = ""
    is_entry: bool = False
    sinks: Dict[str, List[str]] = field(default_factory=dict)
    callees: List[str] = field(default_factory=list)
    callers: List[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        """
        Purpose:
            Render the method readably for prompts and reports.

        Returns:
            The readable label.

        Implementation notes:
            Shortened from the descriptor form, because a full bytecode descriptor in a prompt costs context and is harder for a model to match against source than the name a reader would recognise.
        """
        return f"{self.cls}.{self.name}()"


ENTRY_METHODS = frozenset({
    "onCreate", "onStart", "onResume", "onNewIntent", "onActivityResult",
    "onReceive", "onBind", "onStartCommand", "onHandleIntent", "onHandleWork",
    "query", "insert", "update", "delete", "openFile", "openAssetFile", "call",
    "onMessageReceived", "shouldOverrideUrlLoading", "onCreateView",
})


@dataclass
class CallGraph:
    """
    Purpose:
        The app's methods and the calls between them.

    Invariants:
        Contains only the app's own methods. Every traversal is bounded, so no query can return an unbounded result or run indefinitely.

    Thread-safety:
        Read-only after construction, so the fanned-out agents can query it concurrently.
    """
    methods: Dict[str, MethodNode] = field(default_factory=dict)
    by_name: Dict[str, List[str]] = field(default_factory=dict)


    def find(self, query: str, limit: int = MAX_MATCHES) -> List[MethodNode]:
        """
        Purpose:
            Find methods matching a query, for an agent that knows a name but not a key.

        Parameters:
            query: The search text.
            limit: How many matches to return.

        Returns:
            The matching methods.

        Implementation notes:
            Bounded, because a query like a common method name matches hundreds and the agent cannot use them all. Being told a bounded set and asked to narrow is more useful than being handed everything.
        """
        q = (query or "").strip()
        if not q:
            return []
        if q in self.methods:
            return [self.methods[q]]
        exact = [self.methods[k] for k in self.by_name.get(q.lower(), [])]
        if exact:
            return exact[:limit]
        if "." in q:
            cls, _, meth = q.rpartition(".")
            hits = [n for n in self.methods.values()
                    if n.name.lower() == meth.lower()
                    and (n.cls.lower() == cls.lower() or cls.lower() in n.file.lower())]
            if hits:
                return hits[:limit]
        try:
            rx = re.compile(q, re.IGNORECASE)
        except re.error:
            rx = None
        out = [n for n in self.methods.values()
               if (rx.search(n.name) or rx.search(n.cls)) if rx] if rx else []
        if not out:
            low = q.lower()
            out = [n for n in self.methods.values()
                   if low in n.name.lower() or low in n.cls.lower()]
        return sorted(out, key=lambda n: (len(n.name), n.cls))[:limit]

    def callees(self, key: str, limit: int = MAX_NEIGHBOURS) -> List[MethodNode]:
        """
        Purpose:
            List what a method calls.

        Parameters:
            key: The method key.
            limit: How many to return.

        Returns:
            The called methods.
        """
        node = self.methods.get(key)
        if node is None:
            return []
        return [self.methods[k] for k in node.callees[:limit] if k in self.methods]

    def callers(self, key: str, limit: int = MAX_NEIGHBOURS) -> List[MethodNode]:
        """
        Purpose:
            List what calls a method.

        Parameters:
            key: The method key.
            limit: How many to return.

        Returns:
            The calling methods.

        Implementation notes:
            The direction that matters most for reachability: walking back from a sink toward an entry point is how the agent establishes whether anything can trigger it.
        """
        node = self.methods.get(key)
        if node is None:
            return []
        return [self.methods[k] for k in node.callers[:limit] if k in self.methods]


    def paths(self, source: str, target: str, max_depth: int = MAX_PATH_DEPTH,
              max_paths: int = MAX_PATHS) -> List[List[str]]:
        """
        Purpose:
            Find call paths between two methods.

        Parameters:
            source: The starting method.
            target: The method to reach.
            max_depth: How far to search.
            max_paths: How many paths to return.

        Returns:
            The paths found.

        Complexity:
            Bounded by the depth limit and the result cap.

        Implementation notes:
            Both bounds are necessary. Call graphs of real apps are dense enough that an unbounded search does not finish, and a single path is usually enough to establish reachability -- the agent needs to know a route exists, not to enumerate every route.
        """
        if source not in self.methods or target not in self.methods:
            return []
        if source == target:
            return [[source]]
        found: List[List[str]] = []
        seen: Set[str] = {source}
        queue: collections.deque = collections.deque([[source]])
        while queue and len(found) < max_paths:
            path = queue.popleft()
            if len(path) > max_depth:
                continue
            node = self.methods.get(path[-1])
            if node is None:
                continue
            for nxt in node.callees:
                if nxt == target:
                    found.append(path + [nxt])
                    if len(found) >= max_paths:
                        break
                    continue
                if nxt in seen or nxt not in self.methods:
                    continue
                seen.add(nxt)
                queue.append(path + [nxt])
        return found

    def reaches(self, source: str, target: str, max_depth: int = MAX_PATH_DEPTH) -> bool:
        """
        Purpose:
            Report whether one method can reach another.

        Parameters:
            source: The starting method.
            target: The method to reach.
            max_depth: How far to search.

        Returns:
            True when a path exists within the depth limit.

        Implementation notes:
            A bounded search, so a False result means no path within the limit rather than no path at all. The agent is told the limit so it does not read a negative as proof of unreachability.
        """
        return bool(self.paths(source, target, max_depth, max_paths=1))

    def entry_points(self) -> List[MethodNode]:
        """
        Purpose:
            List the methods an attacker can reach from outside the app.

        Returns:
            The entry-point methods.

        Implementation notes:
            These are where reachability analysis starts. A path from an entry point to a sink is what turns a pattern match into an exploitable finding, which is why they are identified separately rather than being left for the agent to infer.
        """
        return sorted((n for n in self.methods.values() if n.is_entry),
                      key=lambda n: (n.cls.lower(), n.name.lower()))

    def paths_from_entries(self, target: str, max_depth: int = MAX_PATH_DEPTH,
                           max_paths: int = MAX_PATHS) -> List[List[str]]:
        """
        Purpose:
            Find paths from any entry point to a given method.

        Parameters:
            target: The method to reach.
            max_depth: How far to search.
            max_paths: How many paths to return.

        Returns:
            The paths found.

        Implementation notes:
            The query the agent actually wants when judging a sink: not whether some particular method reaches it, but whether anything an attacker controls does.
        """
        out: List[List[str]] = []
        for entry in self.entry_points():
            if len(out) >= max_paths:
                break
            out.extend(self.paths(entry.key, target, max_depth, max_paths=1))
        return out


    def to_json(self) -> dict:
        """
        Purpose:
            Serialise the graph for checkpointing and inspection.

        Returns:
            The graph as plain data.
        """
        return {
            "methods": [
                {"key": n.key, "class": n.cls, "name": n.name, "file": n.file,
                 "signature": n.signature, "role": n.role, "is_entry": n.is_entry,
                 "sinks": n.sinks, "callees": n.callees, "callers": n.callers}
                for n in self.methods.values()
            ],
        }

    def summary(self) -> str:
        """
        Purpose:
            Summarise the graph for the agent's opening context.

        Returns:
            The summary text.

        Implementation notes:
            Gives the agent the shape of the app before it starts exploring -- how many methods, how many entry points -- so it can plan rather than discovering the scale one query at a time.
        """
        edges = sum(len(n.callees) for n in self.methods.values())
        entries = sum(1 for n in self.methods.values() if n.is_entry)
        return (f"{plural(len(self.methods), 'app method')}, {edges} call edges, "
                f"{plural(entries, 'entry point')}")


def _short(descriptor: str) -> str:
    """
    Purpose:
        Shorten a class descriptor for display.

    Parameters:
        descriptor: The class descriptor.

    Returns:
        The shortened name.
    """
    inner = descriptor[1:-1] if descriptor.startswith("L") and descriptor.endswith(";") else descriptor
    return inner.split("/")[-1]


def _file_of(descriptor: str) -> str:
    """
    Purpose:
        Derive the source file a class would have been decompiled to.

    Parameters:
        descriptor: The class descriptor.

    Returns:
        The relative source path.

    Implementation notes:
        Derived from the package path, which is how the decompiler lays its output out. This is what lets a graph node be tied back to a file the agent can read -- without it the graph would name methods the agent could not open.
    """
    inner = descriptor[1:-1] if descriptor.startswith("L") and descriptor.endswith(";") else descriptor
    return f"sources/{inner.split('$', 1)[0]}.java"


def build_call_graph(dx, app_descriptors: Sequence[str],
                     class_roles: Optional[Dict[str, str]] = None,
                     verbose: bool = False) -> Optional[CallGraph]:
    """
    Purpose:
        Build the call graph over the app's own methods.

    Parameters:
        dx: androguard's analysis object.
        app_descriptors: The classes belonging to the app.
        class_roles: Manifest roles per class, used to mark entry points.
        verbose: Traces construction.

    Returns:
        The graph, or None when it could not be built.

    Complexity:
        Linear in the number of methods and call edges within the app's classes.

    Implementation notes:
        Restricted to the app's own classes, so an edge into the platform or a bundled library terminates rather than expanding the graph into code the reader cannot change. Manifest roles are applied here rather than inferred, because what makes a method an entry point is the manifest declaring its class reachable, which the bytecode does not show. Failures around individual classes are tolerated, since androguard's shapes vary across versions and one unreadable class should cost its edges rather than the graph. Sink families come from graph_tables, the same table the code graph tags classes with, imported at module level because graph_tables is a leaf module and importing it cannot close a cycle back through code_graph.
    """
    try:
        wanted = set(app_descriptors)
        class_roles = class_roles or {}
        graph = CallGraph()

        analyses = {}
        for c in dx.get_classes():
            if c.name in wanted:
                analyses[c.name] = c

        for desc, klass in analyses.items():
            role = class_roles.get(desc, "")
            exported = role.startswith("exported")
            for m in klass.get_methods():
                try:
                    name = m.name
                    sig = str(m.descriptor) if hasattr(m, "descriptor") else ""
                except Exception:
                    continue
                key = method_key(desc, name, sig)
                graph.methods[key] = MethodNode(
                    key=key, cls=_short(desc), name=name, class_descriptor=desc,
                    file=_file_of(desc), signature=sig, role=role,
                    is_entry=exported and name in ENTRY_METHODS,
                )
                graph.by_name.setdefault(name.lower(), []).append(key)

        for desc, klass in analyses.items():
            for m in klass.get_methods():
                try:
                    key = method_key(desc, m.name,
                                     str(m.descriptor) if hasattr(m, "descriptor") else "")
                except Exception:
                    continue
                node = graph.methods.get(key)
                if node is None:
                    continue
                try:
                    xrefs = m.get_xref_to()
                except Exception:
                    continue
                for entry in xrefs:
                    try:
                        target_cls, target_m = entry[0], entry[1]
                    except Exception:
                        continue
                    tdesc = getattr(target_cls, "name", "")
                    tname = getattr(target_m, "name", "")
                    if tdesc in wanted:
                        tkey = method_key(
                            tdesc, tname,
                            str(target_m.descriptor) if hasattr(target_m, "descriptor") else "")
                        if tkey in graph.methods:
                            if tkey not in node.callees:
                                node.callees.append(tkey)
                            callee = graph.methods[tkey]
                            if key not in callee.callers:
                                callee.callers.append(key)
                        continue
                    probe = f"{tdesc}->{tname}"
                    for family, needles in _SINK_FAMILIES.items():
                        if any(n in probe for n in needles):
                            bucket = node.sinks.setdefault(family, [])
                            if tname and tname not in bucket and len(bucket) < 6:
                                bucket.append(tname)
                            break

        verbose_print(f"Call graph: {graph.summary()}", verbose)
        return graph
    except Exception as exc:
        verbose_print(f"Call graph construction failed ({exc}); "
                      "traversal tools will be unavailable", verbose)
        return None


def render_path(graph: CallGraph, path: Sequence[str]) -> str:
    """
    Purpose:
        Render a call path for a prompt or a report.

    Parameters:
        graph: The call graph.
        path: The method keys along the path.

    Returns:
        The rendered path.

    Implementation notes:
        Rendered as readable labels rather than keys, because this is the evidence a reader uses to follow the route through their own code -- which is the whole value of a reachability claim.
    """
    lines = []
    for depth, key in enumerate(path):
        node = graph.methods.get(key)
        if node is None:
            continue
        prefix = "  " * depth + ("" if depth == 0 else "-> ")
        sink = ""
        if node.sinks:
            sink = "   [" + "; ".join(
                f"{fam}: {', '.join(v[:3])}" for fam, v in node.sinks.items()) + "]"
        lines.append(f"{prefix}{node.label}  ({node.file}){sink}")
    return "\n".join(lines)

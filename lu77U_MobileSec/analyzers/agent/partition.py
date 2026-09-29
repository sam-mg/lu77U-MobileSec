#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.partition

Purpose:
    Split the code graph into regions the agent can analyse in parallel, each small enough to fit in context and coherent enough to reason about as a unit.

Responsibilities:
    Choose seeds, grow regions from them, split the oversized, merge the tiny, cap the count, and name the result.

Dependencies:
    The code graph.

Implementation notes:
    Partitioning is what makes the agent phase both feasible and thorough. A whole app does not fit in a context window, and slicing it arbitrarily gives each agent a fragment it cannot orient itself in. Growing regions outward from entry points along call edges means each agent gets a reachable slice with its own way in. Regions are seeded from exported components rather than from arbitrary nodes, so every region has an entry point at its centre and the agent examining it can ask what an attacker reaching that point can do. Determinism matters throughout: neighbours are visited in sorted order and ties are broken by key, so two runs over the same app produce the same regions. Without that, region assignment would shift between runs and reports would stop being comparable.
"""

import collections
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from ...utils.verbose import plural, verbose_print

MAX_REGION_NODES = 110

MIN_REGION_NODES = 8

MAX_REGIONS = 8

BALANCE_RATIO = 2.0


@dataclass
class Region:
    """
    Purpose:
        One slice of the graph, analysed by a single agent.

    Attributes:
        key: The region's name, used in progress, logs and checkpoints.
        members: The nodes in this region.
        seeds: The entry points it grew from.
        families: The sink families present, which select the guidance the agent gets.

    Thread-safety:
        Built before fan-out and read-only afterwards.
    """
    key: str
    members: Set[str] = field(default_factory=set)
    seeds: List[str] = field(default_factory=list)
    families: List[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        """
        Purpose:
            How many nodes the region contains.

        Returns:
            The member count.

        Implementation notes:
            Used as the budget proxy throughout: the size caps and the merge and split decisions are all expressed in nodes, because that is what correlates with the context an agent needs.
        """
        return len(self.members)


def _adjacency(graph) -> Dict[str, Set[str]]:
    """
    Purpose:
        Build an undirected adjacency map from the graph's call edges.

    Parameters:
        graph: The code graph.

    Returns:
        Neighbours per node.

    Implementation notes:
        Undirected deliberately. Region growth is about grouping related code, and a caller and its callee belong together regardless of which way the edge points -- treating it as directed would strand callers outside the region containing what they call. Self-edges and edges leaving the graph are dropped, since neither contributes to grouping.
    """
    adj: Dict[str, Set[str]] = collections.defaultdict(set)
    for key, node in graph.nodes.items():
        for target in getattr(node, "calls", ()):
            if target in graph.nodes and target != key:
                adj[key].add(target)
                adj[target].add(key)
    return adj


def _seed_rank(key: str, node, weight: int = 1) -> Tuple[int, int, int, str]:
    """
    Purpose:
        Rank a node as a candidate region seed.

    Parameters:
        key: The node key.
        node: The node.
        weight: The node's analysis cost.

    Returns:
        A sort key, best first.

    Implementation notes:
        Exported nodes with intent filters rank first, then exported ones, then those with intent actions. That ordering is the reachability hierarchy: a component an attacker can address directly is the most valuable place to start an analysis. Weight and signal count break ties toward the substantial nodes, and the key breaks the rest so the ordering is deterministic.
    """
    exported = str(node.role or "").startswith("exported")
    score = (0 if exported and node.intent_actions else
             1 if exported else
             2 if node.intent_actions else 3)
    return (score, -weight, -len(node.signals), key)


def _pick_seeds(graph, universe: Set[str],
                weights: Optional[Dict[str, int]] = None) -> List[str]:
    """
    Purpose:
        Choose the nodes to grow regions from.

    Parameters:
        graph: The code graph.
        universe: The nodes eligible for partitioning.
        weights: Per-node analysis cost.

    Returns:
        The seeds, best first.

    Implementation notes:
        Ranked rather than sampled, so when the seed count is capped it is the least valuable entry points that are dropped.
    """
    weights = weights or {}
    entries = [k for k in sorted(universe)
               if str(graph.nodes[k].role or "").startswith("exported")
               or graph.nodes[k].intent_actions]
    if not entries:
        entries = sorted(universe,
                         key=lambda k: (-len(graph.nodes[k].signals), k))[:MAX_REGIONS]
    return sorted(entries,
                 key=lambda k: _seed_rank(k, graph.nodes[k], weights.get(k, 1)))


def _grow(seeds: Sequence[str], universe: Set[str],
          adj: Dict[str, Set[str]]) -> Dict[str, int]:
    """
    Purpose:
        Grow regions outward from the seeds until every node is claimed.

    Parameters:
        seeds: The region seeds.
        universe: The nodes to partition.
        adj: The adjacency map.

    Returns:
        The owning region index per node.

    Complexity:
        Linear in nodes and edges.

    Implementation notes:
        A breadth-first expansion where the smallest region expands first, which keeps regions comparable in size without a separate balancing pass. Letting each region expand freely would give the first seed most of the graph. Neighbours are taken in sorted order so the outcome is identical between runs.
    """
    owner: Dict[str, int] = {}
    frontier: List[Tuple[int, str]] = []
    for index, seed in enumerate(seeds):
        owner[seed] = index
        frontier.append((index, seed))

    sizes = collections.Counter(owner.values())
    while frontier:
        frontier.sort(key=lambda pair: sizes[pair[0]])
        nxt: List[Tuple[int, str]] = []
        for index, node in frontier:
            for neighbour in sorted(adj.get(node, ())):
                if neighbour in universe and neighbour not in owner:
                    owner[neighbour] = index
                    sizes[index] += 1
                    nxt.append((index, neighbour))
        frontier = nxt
    return owner


def _grow_balanced(seeds: Sequence[str], universe: Set[str],
                   adj: Dict[str, Set[str]],
                   weights: Optional[Dict[str, int]] = None) -> Dict[str, int]:
    """
    Purpose:
        Grow regions balanced by analysis cost rather than by node count.

    Parameters:
        seeds: The region seeds.
        universe: The nodes to partition.
        adj: The adjacency map.
        weights: Per-node analysis cost.

    Returns:
        The owning region index per node.

    Implementation notes:
        Nodes differ enormously in how much they cost to analyse -- a large class with many sinks against a small data holder -- so equal node counts do not mean equal work. This variant expands whichever region has accumulated the least cost, which balances agent runtimes rather than region sizes. Used when weights are available; the simpler growth is the fallback.
    """
    weights = weights or {}
    owner: Dict[str, int] = {}
    cost: Dict[int, int] = {}
    queues: Dict[int, "collections.deque[str]"] = {}
    for index, seed in enumerate(seeds):
        owner[seed] = index
        cost[index] = weights.get(seed, 1)
        queues[index] = collections.deque([seed])

    while True:
        ready = [i for i, q in queues.items() if q]
        if not ready:
            break
        index = min(ready, key=lambda i: (cost[i], i))
        node = queues[index][0]
        claimed = False
        for neighbour in sorted(adj.get(node, ())):
            if neighbour in universe and neighbour not in owner:
                owner[neighbour] = index
                cost[index] += weights.get(neighbour, 1)
                queues[index].append(neighbour)
                claimed = True
                break
        if not claimed:
            queues[index].popleft()
    return owner


def _split_oversized(members: List[str], adj: Dict[str, Set[str]],
                     limit: int) -> List[List[str]]:
    """
    Purpose:
        Split a region too large for one agent into connected pieces.

    Parameters:
        members: The region's nodes.
        adj: The adjacency map.
        limit: The maximum region size.

    Returns:
        The pieces.

    Implementation notes:
        Split along connectivity rather than arbitrarily, so each piece remains a coherent slice the agent can reason about instead of an unrelated collection that happens to fit. Necessary because growth balances sizes but cannot guarantee a bound: a densely connected app can leave one region far over the limit.
    """
    if len(members) <= limit:
        return [members]
    remaining = set(members)
    out: List[List[str]] = []
    while remaining:
        start = max(sorted(remaining), key=lambda k: len(adj.get(k, ()) & remaining))
        piece, queue, seen = [], collections.deque([start]), {start}
        while queue and len(piece) < limit:
            cur = queue.popleft()
            piece.append(cur)
            for nb in sorted(adj.get(cur, ()) & remaining):
                if nb not in seen:
                    seen.add(nb)
                    queue.append(nb)
        remaining -= set(piece)
        out.append(piece)
    return out


def _rebalance_if_lopsided(owner: Dict[str, int], seeds: Sequence[str],
                           universe: Set[str], adj: Dict[str, Set[str]],
                           weights: Optional[Dict[str, int]],
                           verbose: bool) -> Dict[str, int]:
    """
    Purpose:
        Regrow the partition using cost balancing when the first attempt came out badly skewed.

    Parameters:
        owner: The current assignment.
        seeds: The region seeds.
        universe: The nodes to partition.
        adj: The adjacency map.
        weights: Per-node analysis cost.
        verbose: Traces the decision.

    Returns:
        The assignment, rebalanced when it was worth it.

    Implementation notes:
        The cheap growth is tried first and only replaced when the result is genuinely lopsided, since cost-balanced growth is more expensive and usually produces the same partition. Lopsidedness matters because the phase takes as long as its slowest region: one region holding most of the app means the parallelism bought nothing.
    """
    if not owner or len(seeds) < 2:
        return owner
    sizes = collections.Counter(owner.values())
    largest, smallest = max(sizes.values()), min(sizes.values())
    if largest / max(1, smallest) <= BALANCE_RATIO:
        return owner
    verbose_print(
        f"Partition came out {largest}/{smallest} across {len(sizes)} regions "
        f"(> {BALANCE_RATIO}x); re-growing balanced", verbose)
    return _grow_balanced(seeds, universe, adj, weights)


def partition_graph(graph, max_regions: int = MAX_REGIONS,
                    max_nodes: int = MAX_REGION_NODES,
                    verbose: bool = False,
                    weights: Optional[Dict[str, int]] = None) -> List[Region]:
    """
    Purpose:
        Partition the code graph into regions for the agent phase.

    Parameters:
        graph: The code graph.
        max_regions: How many regions to produce at most.
        max_nodes: The largest a region may be.
        verbose: Traces the partitioning.
        weights: Per-node analysis cost.

    Returns:
        The regions, named and annotated with their sink families.

    Complexity:
        Linear in nodes and edges, plus the merge and cap passes.

    Implementation notes:
        Only flagged nodes are partitioned -- those carrying a security-relevant signal. The rest of the app is still readable by the agent through its tools, but it does not need a region of its own. The pipeline is growth, then split the oversized, then merge the small, then cap the count. Each pass fixes a different failure of the previous one, and the order matters: merging before splitting would combine pieces that then have to be split again. Nodes no seed reached become their own regions rather than being dropped, so disconnected code is still analysed. Families are computed per region at the end and are what select the guidance and skills each agent receives.
    """
    universe = {k for k, n in graph.nodes.items() if n.flagged}
    if not universe:
        return []

    adj = _adjacency(graph)
    edges = sum(len(v) for v in adj.values()) // 2
    seeds = _pick_seeds(graph, universe, weights)[:max_regions]
    verbose_print(
        f"Partitioning {plural(len(universe), 'flagged node')} over "
        f"{plural(edges, 'call edge')} from {plural(len(seeds), 'entry point')}",
        verbose)

    owner = _grow(seeds, universe, adj) if seeds else {}
    owner = _rebalance_if_lopsided(owner, seeds, universe, adj, weights, verbose)
    grouped: Dict[int, List[str]] = collections.defaultdict(list)
    for node, index in owner.items():
        grouped[index].append(node)

    orphans = sorted(universe - set(owner))

    regions: List[Region] = []
    for index in sorted(grouped):
        for piece in _split_oversized(sorted(grouped[index]), adj, max_nodes):
            regions.append(Region(key="", members=set(piece),
                                  seeds=[seeds[index]] if seeds[index] in piece else []))
    for start in range(0, len(orphans), max_nodes):
        regions.append(Region(key="", members=set(orphans[start:start + max_nodes])))

    regions = _merge_small(regions, adj, max_nodes)
    regions = _cap_count(regions, adj, max_regions, max_nodes)
    for position, region in enumerate(regions, start=1):
        region.families = _families(graph, region.members)
        region.key = _name(graph, region, position)

    verbose_print(
        f"Partitioned into {plural(len(regions), 'region')}: "
        + ", ".join(f"{r.key}({r.size})" for r in regions), verbose)
    return regions


def _best_host(region: Region, hosts: List[Region], adj: Dict[str, Set[str]],
               max_nodes: int) -> Optional[Region]:
    """
    Purpose:
        Choose which region a small one should merge into.

    Parameters:
        region: The region to merge away.
        hosts: Candidate regions.
        adj: The adjacency map.
        max_nodes: The size limit.

    Returns:
        The best host, or None when none can take it.

    Implementation notes:
        Chosen by how many call edges connect the two, so a merged region stays coherent rather than becoming two unrelated halves. Candidates are considered in a deterministic order and those that would exceed the size limit are skipped, so merging cannot undo the splitting that preceded it.
    """
    best, best_links = None, -1
    for candidate in sorted(hosts, key=lambda r: sorted(r.members)[0] if r.members else ""):
        if candidate is region or candidate.size + region.size > max_nodes:
            continue
        links = sum(len(adj.get(m, set()) & candidate.members) for m in region.members)
        if links > best_links:
            best, best_links = candidate, links
    return best


def _merge_small(regions: List[Region], adj: Dict[str, Set[str]],
                 max_nodes: int) -> List[Region]:
    """
    Purpose:
        Merge regions too small to be worth their own agent.

    Parameters:
        regions: The regions.
        adj: The adjacency map.
        max_nodes: The size limit.

    Returns:
        The regions after merging.

    Implementation notes:
        Each agent costs a full prompt and several requests, so a region of a handful of nodes spends more on setup than on analysis. Merging them into a connected neighbour recovers that.
    """
    keep = [r for r in regions if r.size >= MIN_REGION_NODES]
    small = sorted((r for r in regions if r.size < MIN_REGION_NODES),
                   key=lambda r: (-r.size, sorted(r.members)[0] if r.members else ""))
    if not keep:
        if not small:
            return regions
        keep, small = [small[0]], small[1:]
    for region in small:
        host = _best_host(region, keep, adj, max_nodes)
        if host is None:
            keep.append(region)
            continue
        host.members |= region.members
        host.seeds += region.seeds
    return keep


def _cap_count(regions: List[Region], adj: Dict[str, Set[str]],
               max_regions: int, max_nodes: int) -> List[Region]:
    """
    Purpose:
        Reduce the number of regions to the configured maximum.

    Parameters:
        regions: The regions.
        adj: The adjacency map.
        max_regions: The maximum.
        max_nodes: The size limit.

    Returns:
        The regions after capping.

    Implementation notes:
        Reduced by merging rather than by dropping, so no code falls out of scope. The cap exists because each region is a separate set of provider calls and an app with hundreds of entry points would otherwise fan out beyond any sensible budget.
    """
    regions = sorted(regions, key=lambda r: (-r.size, sorted(r.members)[0] if r.members else ""))
    while len(regions) > max_regions:
        smallest = regions[-1]
        host = _best_host(smallest, regions[:-1], adj, max_nodes)
        if host is None:
            break
        host.members |= smallest.members
        host.seeds += smallest.seeds
        regions = sorted(regions[:-1],
                         key=lambda r: (-r.size, sorted(r.members)[0] if r.members else ""))
    return regions


def _families(graph, members: Set[str]) -> List[str]:
    """
    Purpose:
        Collect the sink families present in a region.

    Parameters:
        graph: The code graph.
        members: The region's nodes.

    Returns:
        The families.

    Implementation notes:
        These select the attack-surface guidance and the skills the region's agent receives, which is how one agent is told to think about WebViews and another about storage.
    """
    counter: collections.Counter = collections.Counter()
    for key in sorted(members):
        counter.update(graph.nodes[key].signals.keys())
    return [family for family, _ in sorted(counter.most_common(),
                                           key=lambda kv: (-kv[1], kv[0]))]


def _name(graph, region: Region, position: int) -> str:
    """
    Purpose:
        Name a region for progress reporting, logs and checkpoints.

    Parameters:
        graph: The code graph.
        region: The region.
        position: Its position in the list.

    Returns:
        The name.

    Implementation notes:
        Derived from the region's own content where possible, so a user watching progress sees something recognisable rather than a number. The name is also the checkpoint key, so it must be stable between runs over the same app -- which is why the partitioning above is deterministic.
    """
    if region.seeds:
        seed = graph.nodes.get(region.seeds[0])
        if seed is not None:
            return f"region-{position}-{seed.cls}"
    return f"region-{position}"

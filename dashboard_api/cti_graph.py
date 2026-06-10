"""CTI relationship graph — actors ↔ malware ↔ techniques ↔ IOCs ↔ sectors.

Builds an interactive intelligence graph from the live stores and supports the
two operations analysts actually need on one:

  * **pivot** — expand a node to its neighbours (`neighbours`), so you can walk
    out from an actor to its malware/TTPs/indicators or from an indicator back
    to the actor that uses it;
  * **path-finding** — `shortest_path` between any two nodes (BFS over the
    adjacency), e.g. how an IOC connects to a sector through an actor + a shared
    technique — the "why are these related?" question.

Shared malware/technique/sector nodes are the connective tissue: two actors
that use the same tool or TTP are linked through it, which is what makes the
graph navigable rather than a set of disjoint stars.
"""
import json
from collections import deque

NODE_GROUPS = ("actor", "malware", "technique", "ioc", "sector")
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _loads(v):
    if isinstance(v, list):
        return v
    try:
        return json.loads(v) if v else []
    except (ValueError, TypeError):
        return []


def _full_graph(conn, *, actor_limit: int, ioc_limit: int) -> tuple[dict, list]:
    """Assemble the whole graph as {node_id: node} + list of links."""
    nodes: dict[str, dict] = {}
    links: list[dict] = []

    def add_node(nid, **attrs):
        if nid not in nodes:
            nodes[nid] = {"id": nid, **attrs}
        return nid

    def link(src, dst, kind):
        links.append({"source": src, "target": dst, "kind": kind})

    actors = conn.execute(
        "SELECT name, threat_level, ioc_count, malware, ttps, sectors "
        "FROM threat_actors ORDER BY sophistication DESC LIMIT ?", (actor_limit,)).fetchall()
    for a in actors:
        aid = add_node(f"actor:{a['name']}", label=a["name"], group="actor",
                       level=a["threat_level"], size=min(34, 12 + (a["ioc_count"] or 0) // 20))
        for m in _loads(a["malware"]):
            link(aid, add_node(f"malware:{m}", label=m, group="malware", size=9), "uses")
        for t in _loads(a["ttps"]):
            link(aid, add_node(f"technique:{t}", label=t, group="technique", size=8), "employs")
        for s in _loads(a["sectors"]):
            link(aid, add_node(f"sector:{s}", label=s, group="sector", size=8), "targets")

    iocs = conn.execute(
        "SELECT value, type, actor, severity FROM iocs WHERE actor != '' "
        "ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
        "WHEN 'medium' THEN 2 ELSE 1 END DESC LIMIT ?", (ioc_limit,)).fetchall()
    for i in iocs:
        aid = f"actor:{i['actor']}"
        if aid in nodes:
            iid = add_node(f"ioc:{i['value']}", label=i["value"], group="ioc",
                           iocType=i["type"], level=i["severity"], size=6)
            link(aid, iid, "indicates")
    return nodes, links


def _adjacency(links: list[dict]) -> dict[str, set]:
    adj: dict[str, set] = {}
    for l in links:
        adj.setdefault(l["source"], set()).add(l["target"])
        adj.setdefault(l["target"], set()).add(l["source"])
    return adj


def build(conn, *, focus: str | None = None, depth: int = 2,
          actor_limit: int = 60, ioc_limit: int = 120) -> dict:
    """The graph, optionally narrowed to a `depth`-hop neighbourhood of `focus`."""
    nodes, links = _full_graph(conn, actor_limit=actor_limit, ioc_limit=ioc_limit)
    if focus and focus in nodes:
        adj = _adjacency(links)
        keep, frontier = {focus}, {focus}
        for _ in range(max(1, depth)):
            nxt: set = set()
            for n in frontier:
                nxt |= adj.get(n, set())
            keep |= nxt
            frontier = nxt
        nodes = {nid: n for nid, n in nodes.items() if nid in keep}
        links = [l for l in links if l["source"] in keep and l["target"] in keep]
    counts: dict[str, int] = {}
    for n in nodes.values():
        counts[n["group"]] = counts.get(n["group"], 0) + 1
    return {"nodes": list(nodes.values()), "links": links,
            "focus": focus, "counts": counts}


def neighbours(conn, node_id: str) -> dict:
    """Immediate neighbours of a node (one pivot hop), grouped by relationship."""
    nodes, links = _full_graph(conn, actor_limit=200, ioc_limit=600)
    if node_id not in nodes:
        return {"node": None, "neighbours": []}
    out = []
    for l in links:
        other = l["target"] if l["source"] == node_id else (l["source"] if l["target"] == node_id else None)
        if other and other in nodes:
            out.append({**nodes[other], "kind": l["kind"]})
    return {"node": nodes[node_id], "neighbours": out}


def shortest_path(conn, src: str, dst: str) -> dict:
    """BFS shortest path between two nodes. Returns the ordered node + link
    chain, or an empty path when they are not connected."""
    nodes, links = _full_graph(conn, actor_limit=200, ioc_limit=600)
    if src not in nodes or dst not in nodes:
        return {"found": False, "reason": "unknown node", "path": [], "links": []}
    if src == dst:
        return {"found": True, "path": [nodes[src]], "links": []}
    adj = _adjacency(links)
    prev: dict[str, str] = {src: ""}
    q = deque([src])
    while q:
        cur = q.popleft()
        if cur == dst:
            break
        for nb in adj.get(cur, set()):
            if nb not in prev:
                prev[nb] = cur
                q.append(nb)
    if dst not in prev:
        return {"found": False, "reason": "no path", "path": [], "links": []}
    chain = []
    cur = dst
    while cur:
        chain.append(cur)
        cur = prev[cur]
    chain.reverse()
    link_kind = {(l["source"], l["target"]): l["kind"] for l in links}
    link_kind.update({(l["target"], l["source"]): l["kind"] for l in links})
    path_links = [{"source": chain[i], "target": chain[i + 1],
                   "kind": link_kind.get((chain[i], chain[i + 1]), "linked")}
                  for i in range(len(chain) - 1)]
    return {"found": True, "path": [nodes[n] for n in chain], "links": path_links,
            "hops": len(chain) - 1}

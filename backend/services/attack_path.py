import networkx as nx
from models.database import VulnerabilityDB, ScanDB, SessionLocal
from models.schemas import AttackPath, AttackNode, AttackEdge, AttackPathsResponse

MAX_PATHS = 200  # Upper limit to prevent exponential blowup


class AttackPathService:
    """Models potential attack paths from vulnerability chains."""

    def compute_attack_paths(self, scan_id: int) -> AttackPathsResponse:
        db = SessionLocal()
        try:
            vulns = (
                db.query(VulnerabilityDB)
                .filter(VulnerabilityDB.scan_id == scan_id)
                .all()
            )

            if not vulns:
                return AttackPathsResponse(scan_id=scan_id, paths=[], total_paths=0)

            G = nx.DiGraph()

            # Build graph: host → vulnerability → potential target
            for v in vulns:
                host_id = f"host:{v.affected_host}"
                vuln_id = f"vuln:{v.cve_id or v.id}"
                service_id = f"svc:{v.affected_service or 'unknown'}:{v.affected_host}:{v.affected_port or 0}"

                # Add nodes
                G.add_node(host_id, type="host", label=v.affected_host)
                G.add_node(
                    vuln_id,
                    type="vulnerability",
                    label=v.cve_id or f"Vuln-{v.id}",
                    severity=v.severity,
                    cvss=v.cvss_score,
                )
                G.add_node(
                    service_id,
                    type="service",
                    label=f"{v.affected_service or 'unknown'}:{v.affected_port or '?'}",
                )

                # Add edges: host → service → vulnerability
                G.add_edge(host_id, service_id, label="runs")
                G.add_edge(service_id, vuln_id, label="exposes")

            # Connect hosts with critical vulns to other hosts (lateral movement)
            critical_vulns = [
                v for v in vulns if v.severity == "CRITICAL" and v.exploit_available
            ]
            hosts = list(set(v.affected_host for v in vulns))

            for cv in critical_vulns:
                for target_host in hosts:
                    if target_host != cv.affected_host:
                        src_vuln = f"vuln:{cv.cve_id or cv.id}"
                        tgt_host = f"host:{target_host}"
                        G.add_edge(src_vuln, tgt_host, label="lateral-movement")

            # Build candidate targets: only vuln and host nodes (skip service nodes)
            host_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "host"]
            target_nodes = [
                n
                for n, d in G.nodes(data=True)
                if d.get("type") in ("vulnerability", "host")
            ]

            # Find attack paths with early termination
            paths = []
            for host_id in host_nodes:
                if len(paths) >= MAX_PATHS:
                    break
                for target in target_nodes:
                    if len(paths) >= MAX_PATHS:
                        break
                    if target == host_id:
                        continue
                    try:
                        for simple_path in nx.all_simple_paths(
                            G, host_id, target, cutoff=4
                        ):
                            if len(simple_path) >= 3:
                                path_nodes = []
                                path_edges = []
                                total_cvss = 0.0

                                for node_id in simple_path:
                                    node_data = G.nodes[node_id]
                                    path_nodes.append(
                                        AttackNode(
                                            id=node_id,
                                            label=node_data.get("label", node_id),
                                            type=node_data.get("type", "unknown"),
                                            severity=node_data.get("severity"),
                                            cvss_score=node_data.get("cvss"),
                                        )
                                    )
                                    if node_data.get("cvss"):
                                        total_cvss += node_data["cvss"]

                                for i in range(len(simple_path) - 1):
                                    edge_data = G.edges[
                                        simple_path[i], simple_path[i + 1]
                                    ]
                                    path_edges.append(
                                        AttackEdge(
                                            source=simple_path[i],
                                            target=simple_path[i + 1],
                                            label=edge_data.get("label"),
                                        )
                                    )

                                risk = (
                                    "CRITICAL"
                                    if total_cvss > 15
                                    else "HIGH"
                                    if total_cvss > 10
                                    else "MEDIUM"
                                )
                                paths.append(
                                    AttackPath(
                                        path_id=f"path_{len(paths) + 1}",
                                        nodes=path_nodes,
                                        edges=path_edges,
                                        total_cvss=round(total_cvss, 1),
                                        risk_level=risk,
                                    )
                                )
                                if len(paths) >= MAX_PATHS:
                                    break
                    except nx.NodeNotFound:
                        continue

            # Deduplicate and sort by risk
            seen = set()
            unique_paths = []
            for p in paths:
                key = tuple(n.id for n in p.nodes)
                if key not in seen:
                    seen.add(key)
                    unique_paths.append(p)

            unique_paths.sort(key=lambda x: x.total_cvss, reverse=True)

            return AttackPathsResponse(
                scan_id=scan_id,
                paths=unique_paths[:20],  # Top 20 paths
                total_paths=len(unique_paths),
            )
        finally:
            db.close()


attack_path_service = AttackPathService()

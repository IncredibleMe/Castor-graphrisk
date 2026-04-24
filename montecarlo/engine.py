"""
Monte Carlo simulation engine for attack path analysis on network graphs.

Core idea (from CASTOR D4.1):
  - Represent the network as a directed graph
  - Run N (we added 10.000 by default) iterations of "what-if" attack scenarios
  - In each iteration, randomly sample attack paths from entry points to targets
  - Compute cascading attack probabilities along each path
  - Aggregate results into probability distributions per node and per path

Output feeds directly into RTLCalculator.

Key concepts:
  - entry_nodes   : where an attacker can start (e.g. internet-facing nodes)
  - target_nodes  : high-value assets the attacker wants to reach
  - attack_prob   : probability of exploiting a vulnerability on a node
                    derived from CVSS score  →  P = cvss / 10
  - cascade_prob  : probability that compromising node A leads to node B
                    derived from edge weight
"""

import random
import networkx as nx
import numpy as np
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class SimulationResult:
    """
    Holds the aggregated output of a Monte Carlo simulation run.

    Attributes:
        node_compromise_probs : P(node is compromised) per node_id
        path_probs            : P(full path succeeds) per path tuple
        cascade_probs         : P(attack cascades from node A to B) per edge
        iterations            : number of Monte Carlo iterations run
        raw_paths             : all sampled paths (for debugging / analysis)
    """
    node_compromise_probs: Dict[str, float] = field(default_factory=dict)
    path_probs:            Dict[tuple, float] = field(default_factory=dict)
    cascade_probs:         Dict[tuple, float] = field(default_factory=dict)
    iterations:            int = 0
    raw_paths:             List[list] = field(default_factory=list)


class MonteCarloEngine:
    """
    Runs Monte Carlo simulation on a network topology graph.

    Parameters:
        G            : nx.DiGraph  - the network topology (from GraphBuilder)
        iterations   : int         - number of MC iterations (default 10 000)
        entry_nodes  : list        - attacker entry points (default: all nodes)
        target_nodes : list        - high-value targets   (default: all nodes)
        seed         : int         - random seed for reproducibility

    Usage:
        mc  = MonteCarloEngine(G, iterations=10000,
                                   entry_nodes=["internet_gw"],
                                   target_nodes=["core_router"])
        results = mc.run()
    """

    #dimension 2 weights for ω_ij — must sum to 1.0
    BETA = {
        "seg":   0.25,
        "proto": 0.25,
        "bw":    0.25,
        "dist":  0.25,
    }

    #dimension 3 weights for W_target — must sum to 1.0
    GAMMA = {
        "crit": 0.5,
        "bc":   0.5,
    }

    #dimension 1 weights — a1 > a2 (exploitability > impact)
    A = {
        "p_cvss_expl": 0.40,  # P_CVSS_expl
        "iss":         0.25,  # ISS
        "epss":        0.25,  # EPSS
        "patch":       0.10,  # Patch status (0=unpatched, 1=patched)
    }

    def __init__(
        self,
        G: nx.DiGraph,
        iterations:   int = 10_000,
        entry_nodes:  Optional[List[str]] = None,
        target_nodes: Optional[List[str]] = None,
        seed:         Optional[int] = 42
    ):
        self.G            = G
        self.iterations   = iterations
        self.entry_nodes  = entry_nodes  or list(G.nodes)
        self.target_nodes = target_nodes or list(G.nodes)
        self.seed         = seed

        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

        try:
            self._diameter = nx.diameter(G)
        except Exception:
            self._diameter = 1

        #pre-compute normalised betweenness centrality for Dimension 3
        raw_bc = nx.betweenness_centrality(G, normalized=True)
        max_bc = max(raw_bc.values()) if raw_bc else 1.0
        self._bc = {
            node: (val / max_bc if max_bc > 0 else 0.0)
            for node, val in raw_bc.items()
        }

    def run(self) -> SimulationResult:
        """Execute the Monte Carlo simulation and return aggregated results."""
        result = SimulationResult(iterations=self.iterations)

        # Counters
        node_hits   = {n: 0 for n in self.G.nodes}
        edge_hits   = {e: 0 for e in self.G.edges}
        path_hits   = {}

        
        for _ in range(self.iterations):
            # 1.Pick a random entry node (for now we have only one in list)
            entry = random.choice(self.entry_nodes)
            target = random.choice(self.target_nodes)


            # 2.Simulate a random walk / attack path from entry
            path = self._simulate_attack_path(entry, target)

            if len(path) < 2:
                continue

            result.raw_paths.append(path)

            # 3.Accumulate node hits
            for node in path:
                node_hits[node] += 1

            # 4.Accumulate edge (cascade) hits
            for i in range(len(path) - 1):
                edge = (path[i], path[i + 1])
                edge_hits[edge] = edge_hits.get(edge, 0) + 1

            # 5.Accumulate path hits
            path_key = tuple(path)
            path_hits[path_key] = path_hits.get(path_key, 0) + 1

        result.node_compromise_probs = {
            n: node_hits[n] / self.iterations for n in self.G.nodes
        }
        result.cascade_probs = {
            e: count / self.iterations for e, count in edge_hits.items()
        }
        result.path_probs = {
            path: count / self.iterations for path, count in path_hits.items()
        }

        return result

    def _exploit_probability(self, node_id: str) -> float:
        """
        Dimension 1 (simplified): P_exploit = max_cvss / 10.
        Full Dimension 1 (P_CVSS_expl, ISS, EPSS, patch_status)
        will be incorporated once CVE enrichment via cve_fetcher is complete.
        """
        node_data = self.G.nodes[node_id]
        vulns     = node_data.get("vulnerabilities", [])

        if not vulns:
            return min(node_data.get("cvss", 0.0) / 10.0, 1.0)

        # Worst-case across all CVEs
        p_exploit_scores = []
        for v in vulns:
            dim1 = v.get("dim1_metrics")
            if dim1:
                # Full Dimension 1
                patch = 0.0 if not dim1.get("patched", False) else 1.0
                score = (
                    self.A["p_cvss_expl"] * dim1["P_CVSS_expl"]
                + self.A["iss"]         * dim1["ISS"]
                + self.A["epss"]        * dim1["EPSS"]
                + self.A["patch"]       * patch
                )
            else:
                # Fallback
                score = min(v.get("cvss", 0.0) / 10.0, 1.0)
            p_exploit_scores.append(score)

        return min(max(p_exploit_scores), 1.0)

    def _cascade_probability(self, src: str, dst: str, target: str) -> float:
        """
        Dimension 2: P_cascade = ω_ij × Θ_ij
 
        ω_ij = β1·seg + β2·proto + β3·bw + β4·dist(dst, target)
        Θ_ij = Π(1 - θ_c)  for all link controls on edge (src, dst)
        """
        edge_data = self.G.edges[src, dst]
       
        dist  = self._normalised_dist(dst, target)
        omega = (
            self.BETA["seg"]   * edge_data.get("seg",   0.5)
          + self.BETA["proto"] * edge_data.get("proto", 0.5)
          + self.BETA["bw"]    * edge_data.get("bw",    0.5)
          + self.BETA["dist"]  * dist
        )

        # Θ_ij: control residual factor 
        # Θ_ij = Π(1 - θ_c) — each control independently reduces cascade 
        theta = 1.0
        for effectiveness in edge_data.get("link_controls", {}).values():
            theta *= (1.0 - effectiveness)

        return omega * theta

    def _simulate_attack_path(self, start: str, target: str,
                               max_hops: int = 10) -> list:
        """
        Simulate one attack path via random walk from start toward target.
 
        At each step:
          1. Try to exploit the current node  →  P_exploit  (Dimension 1)
          2. If successful, pick a random neighbour
          3. Check if cascade succeeds        →  P_cascade  (Dimension 2)
          4. Move to neighbour or stop
 
        Returns the list of successfully compromised nodes.
        """
        path    = []
        current = start
        visited = set()
 
        for _ in range(max_hops):
            if current in visited:
                break
            visited.add(current)
 
            # Dimension 1: can the attacker exploit this node?
            p_exploit = self._exploit_probability(current)
            if random.random() > p_exploit:
                break
 
            path.append(current)
 
            # Stop if target reached
            if current == target:
                break
 
            # Pick next hop
            neighbours = [
                n for n in self.G.successors(current)
                if n not in visited
            ]
 
            #get next node depending on ω_ij × Θ_ij * dimension 3
            weights   = [
                self._cascade_probability(current, n, target) *
                self._w_target(n)
                for n in neighbours
            ]

            # Φιλτράρουμε τους ήδη επισκεφτημένους από τους neighbours
            available = [n for n in neighbours if n not in visited]
            if not available:
                break
            
            next_node = random.choices(neighbours, weights=weights, k=1)[0]  # weighted
 
            # Dimension 2: does the attack cascade to next_node?
            p_cascade = self._cascade_probability(current, next_node, target)
            if random.random() > p_cascade:
                break
 
            current = next_node
 
        return path


    def top_compromised_nodes(self, result: SimulationResult, n: int = 5) -> list:
        """Return the n nodes most likely to be compromised."""
        sorted_nodes = sorted(
            result.node_compromise_probs.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_nodes[:n]

    def top_attack_paths(self, result: SimulationResult, n: int = 5) -> list:
        """Return the n most probable attack paths."""
        sorted_paths = sorted(
            result.path_probs.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_paths[:n]
    
    def _w_target(self, node_id: str) -> float:
        """
        Dimension 3: W_target = γ1·crit(v_j) + γ2·BC_norm(v_j)
 
        Captures the strategic attractiveness of a node as an attack target:
        - crit: operational importance of the node
        - BC_norm: structural importance (hub nodes are more attractive)
        """
        crit   = self.G.nodes[node_id].get("criticality", 0.5)
        bc     = self._bc.get(node_id, 0.0)
        return self.GAMMA["crit"] * crit + self.GAMMA["bc"] * bc


    # get hop counts
    def _normalised_dist(self, node, target):
        """
        Normalised topological distance from node to target:
            dist(v_j, v_t) = 1 - h(v_j, v_t) / D
        where h is the shortest-path hop count and D is the graph diameter.
        Returns 0.0 if no path exists.
        """
        try:
            h = nx.shortest_path_length(self.G, node, target)
            return 1.0 - (h / self._diameter)
        except:
            return 0.0
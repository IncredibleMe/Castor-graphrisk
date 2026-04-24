"""
Converts Monte Carlo simulation results into RTL (Required Trust Level) values
expressed as Subjective Logic triplets: (belief, disbelief, uncertainty)

Based on CASTOR D4.1 methodology:
  - belief      (b) : minimum required trust threshold (risk-based)
  - disbelief   (d) : maximum acceptable distrust (worst-case vs best-case)
  - uncertainty (u) : lack of evidence → b + d + u = 1.0

Algorithm:
  1. CVSS scores → risk levels (1-5)
  2. Belief calculated via Equation 8.2 (baseline + risk increment)
  3. Disbelief from Equations 8.4 & 8.5:
     - d_max: worst-case (no security controls)
     - d_DTI: best-case (all security controls)
     - Weighted by P_compromise from Monte Carlo simulation
  4. Uncertainty from Equation 8.6 (remaining probability mass)

RTL = (b_RTL, d_RTL, u_RTL) sets the MINIMUM trust threshold
      that a node's ATL must exceed for trusted path selection.

Key difference from simplified approaches:
  - Uses CASTOR-compliant equations instead of ad-hoc mappings
  - Combines design-time risk assessment with runtime Monte Carlo evidence
  - No arbitrary caps on uncertainty
"""

from dataclasses import dataclass
from typing import Dict, Optional
from montecarlo.engine import SimulationResult
import networkx as nx

# ------------------------------------------------------------------
# Security control weights
# ------------------------------------------------------------------
CONTROL_WEIGHTS = {
    "secure_boot":         0.60,
    "cfi":                 0.35,
    "rollback_protection": 0.20,
    "access_control":      0.40,
}
 
# CIA numeric value → impact level 1-5
# Based on CVSS v3.x: None=0.00, Low=0.22, High=0.56
CIA_TO_LEVEL = {
    0.00: 1,   # None      → Negligible
    0.22: 2,   # Low       → Moderate
    0.56: 4,   # High      → Severe
}
 
# CIA numeric value → 5GAA impact rating (Table 10)
CIA_TO_IMPACT = {
    0.00: 0.00,   # None  → Negligible
    0.22: 0.50,   # Low   → Moderate
    0.56: 1.00,   # High  → Severe
}

@dataclass
class RTLTriplet:
    """
    A Subjective Logic trust triplet.
    Invariant: belief + disbelief + uncertainty == 1.0
    """
    node_id:         str
    belief:          float   # b  ∈ [0, 1]
    disbelief:       float   # d  ∈ [0, 1]
    uncertainty:     float   # u  ∈ [0, 1]
    risk_level:      str     # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    active_controls: list

    def __post_init__(self):
        total = round(self.belief + self.disbelief + self.uncertainty, 6)
        # assert abs(total - 1.0) < 1e-4, \
        #     f"RTL triplet must sum to 1.0, got {total} for node {self.node_id}"

    def __repr__(self):
        controls = ", ".join(self.active_controls) if self.active_controls else "none"
        return (f"RTL({self.node_id}): "
                f"b={self.belief:.3f}, d={self.disbelief:.3f}, "
                f"u={self.uncertainty:.3f}  [{self.risk_level}] controls=[{controls}]")


class RTLCalculator:
    """
    Derives per-node RTL triplets from Monte Carlo results.

    Algorithm (based on CASTOR Equations):
        1. Map CVSS → risk_level (1-5 scale)
        2. Reduce Risk based on the activated security controls
        3. Calculate belief using Equation (b_RTL = bt + (maxcontrols -1)*delta) )
        
        3. Calculate d_max (worst-case disbelief, no controls) 
            d_max = max{0.25 × (maxRisk_NoControls - 1), avgRisk_NoControls / maxRisk}  
        4. Calculate d_DTI (best-case disbelief, all controls) 
            d_DTI = max{0.25 × (maxRisk_AllControls - 1), avgRisk_AllControls / maxRisk})
        5. Combine d_max and d_DTI weighted by P_compromise from Monte Carlo
        6. Calculate uncertainty using (u_DTI = 1 - b_DTI - d_DTI )
        7. Normalise so that b + d + u = 1.0

    Parameters:
        result          : SimulationResult from MonteCarloEngine.run()
        G               : nx.DiGraph (same graph used for simulation)
        baseline_belief : b_t baseline threshold (default 0.2)

    Usage:
        calc = RTLCalculator(result, G, baseline_belief=0.2)
        rtls = calc.compute_all()
        for r in rtls.values():
            print(r)
    """

    # Risk level thresholds (based on disbelief score)
    RISK_THRESHOLDS = {
        "LOW":      (0.00, 0.25),
        "MEDIUM":   (0.25, 0.50),
        "HIGH":     (0.50, 0.75),
        "CRITICAL": (0.75, 1.00),
    }

    def __init__(
        self,
        result: SimulationResult,
        G,
        use_bc, 
        use_monte_carlo,
        baseline_belief: float = 0.2,    # ← b_t from b_RTL = b_t + ((R_max - 1) × Δ)
        bc_weight: float = 0.2 # the betweenness needs a weight (in Dimension 1)
    ):
        self.result = result
        self.G = G
        self.baseline_belief = baseline_belief
        self.bc_weight = bc_weight
        self.use_bc = use_bc
        self.use_monte_carlo = use_monte_carlo

        # Pre-compute normalised betweenness centrality for all nodes
        # BC(v) = betweenness(v) / max_betweenness (Dimension 1)
        # Used for topology-driven RTL escalation (D4.2)
        raw_bc = nx.betweenness_centrality(G.to_undirected(), normalized=True)
        max_bc = max(raw_bc.values()) if raw_bc else 1.0
        self.bc = {
            node: (val / max_bc if max_bc > 0 else 0.0)
            for node, val in raw_bc.items()
        }
        
    def compute_all(self) -> Dict[str, RTLTriplet]:
        # RTL for each node
        return {
            node_id: self.compute_node(node_id)
            for node_id in self.G.nodes
        }
    
    def compute_all_per_property(self) -> Dict[str, Dict[str, RTLTriplet]]:
        """Compute per-CIA RTL triplets for every node in the graph."""
        return {
            node_id: self.compute_node_per_property(node_id)
            for node_id in self.G.nodes
        }
    
    def compute_node_per_property(self, node_id: str) -> Dict[str, RTLTriplet]:
        """
        Compute three separate RTL triplets per node — one for each
        CIA property (Confidentiality, Integrity, Availability).
 
        Returns:
            {
                "C": RTLTriplet(...),
                "I": RTLTriplet(...),
                "A": RTLTriplet(...)
            }
        """
        node_data = self.G.nodes[node_id]
        vulns     = node_data.get("vulnerabilities", [])
 
        # Build CVE metrics (same as compute_node Step 1)
        cve_metrics = []
        for v in vulns:
            if all(k in v for k in ["AV", "AC", "PR", "UI", "C", "I", "A"]):
                P_expl = 2.0 * v["AV"] * v["AC"] * v["PR"] * v["UI"]
                cve_metrics.append({
                    "P_expl": P_expl,
                    "C": v["C"], "I": v["I"], "A": v["A"]
                })
            else:
                s = v.get("cvss", 0.0)
                cve_metrics.append({
                    "P_expl": min(s / 10.0, 1.0),
                    "C": 0.56 if s >= 7.0 else 0.22,
                    "I": 0.56 if s >= 7.0 else 0.22,
                    "A": 0.56 if s >= 7.0 else 0.22,
                })
 
        if not cve_metrics:
            s = node_data.get("cvss", 0.0)
            cve_metrics = [{
                "P_expl": min(s / 10.0, 1.0),
                "C": 0.56 if s >= 7.0 else 0.22,
                "I": 0.56 if s >= 7.0 else 0.22,
                "A": 0.56 if s >= 7.0 else 0.22,
            }]
 
        controls        = node_data.get("security_controls", {})
        active_controls = [c for c, active in controls.items() if active]
        total_reduction = sum(CONTROL_WEIGHTS[c] for c in active_controls)
 
        results = {}
        for prop in ["C", "I", "A"]:
            # R_max for this property
            r_max_list = []
            for m in cve_metrics:
                P_expl_reduced = m["P_expl"] * (1.0 - total_reduction)
                F       = max(1, min(5, round(P_expl_reduced * 5)))
                I_level = CIA_TO_LEVEL.get(m[prop], 1)
                r_max_list.append(max(F, I_level))
            R_max = max(r_max_list)
 
            # b_RTL
            delta = (1.0 - self.baseline_belief) / 5.0
            b_RTL = self.baseline_belief + (R_max - 1) * delta
 
            if self.use_bc:
                bc_node = self.bc.get(node_id, 0.0)
                b_RTL   = min(1.0, b_RTL + bc_node * self.bc_weight)
               
            # d_RTL for this property only
            max_cia = max(m[prop] for m in cve_metrics)
            I_w     = CIA_TO_IMPACT.get(max_cia, 0.0)
            d_RTL   = max(0.0, 1.0 - I_w)
 
            # # controls reduce belief requirement
            # b_RTL = max(self.baseline_belief, b_RTL * (1.0 - total_reduction))

            # controls tighten tolerance → reduce d_RTL (independent of Monte Carlo)
            d_RTL = min(1.0, d_RTL + total_reduction * (1.0 - d_RTL))
            

            # u_RTL
            u_RTL = max(0.0, 1.0 - b_RTL - d_RTL)
 
            # Monte Carlo adjustment
            if self.use_monte_carlo:
                p_compromise = self.result.node_compromise_probs.get(node_id, 0.0)
                #reduce d_RTL by controls (controls tighten tolerance → reduce d_RTL)
                d_RTL = d_RTL * (1.0 - p_compromise)

            
            u_RTL = max(0.0, 1.0 - b_RTL - d_RTL)
 
            # b_RTL, d_RTL, u_RTL = self._normalise(b_RTL, d_RTL, u_RTL)
 
            results[prop] = RTLTriplet(
                node_id=f"{node_id}_{prop}",
                belief=b_RTL,
                disbelief=d_RTL,
                uncertainty=u_RTL,
                risk_level=self._risk_level(b_RTL),
                active_controls=active_controls,
            )
 
        return results

    # #compute the RTL triplet
    # def compute_node(self, node_id: str) -> RTLTriplet:
    #     node_data = self.G.nodes[node_id]
        
    #     # ── Step 1: P_CVSS_expl and ISS per CVE ──────────────────────
    #     # Use AV/AC/PR/UI/C/I/A from JSON if available,
    #     # otherwise fall back to raw CVSS score.
    #     vulns = node_data.get("vulnerabilities", [])
    #     cve_metrics = []
    #     for v in vulns:
    #         if all(k in v for k in ["AV", "AC", "PR", "UI", "C", "I", "A"]):
    #             P_expl = 2.0 * v["AV"] * v["AC"] * v["PR"] * v["UI"]
    #             cve_metrics.append({
    #                 "cvss":  v.get("cvss", 0.0),
    #                 "P_expl": P_expl,
    #                 "C": v["C"], "I": v["I"], "A": v["A"]
    #             })
    #         else:
    #             # Fallback: approximate from CVSS base score
    #             s = v.get("cvss", 0.0)
    #             cve_metrics.append({
    #                 "cvss":   s,
    #                 "P_expl": min(s / 10.0, 1.0),
    #                 "C": 0.56 if s >= 7.0 else 0.22,
    #                 "I": 0.56 if s >= 7.0 else 0.22,
    #                 "A": 0.56 if s >= 7.0 else 0.22,
    #             })
 
    #     # If no CVEs at all, use node-level CVSS
    #     if not cve_metrics:
    #         s = node_data.get("cvss", 0.0)
    #         cve_metrics = [{
    #             "cvss":   s,
    #             "P_expl": min(s / 10.0, 1.0),
    #             "C": 0.56 if s >= 7.0 else 0.22,
    #             "I": 0.56 if s >= 7.0 else 0.22,
    #             "A": 0.56 if s >= 7.0 else 0.22,
    #         }]
 
    #     # ── Step 2: Security controls reduce risk ─────────────────────
    #     controls        = node_data.get("security_controls", {})
    #     active_controls = [c for c, active in controls.items() if active]
    #     total_reduction = sum(CONTROL_WEIGHTS[c] for c in active_controls)
 
    #     # ── Step 3: R_max(F,I) per CIA property ───────────────────────
    #     # For each CVE, compute R_max for C, I, A separately.
    #     # Feasibility F = P_expl mapped to 1-5.
    #     # Impact level from CIA_TO_LEVEL mapping.
    #     # R_max = max(F, impact_level) — worst case of feasibility and impact.
    #     # Apply controls reduction to feasibility.
    #     R_max_C_list, R_max_I_list, R_max_A_list = [], [], []
 
    #     for m in cve_metrics:
    #         # Feasibility after controls
    #         P_expl_reduced = m["P_expl"] * (1.0 - total_reduction)
    #         F = max(1, min(5, round(P_expl_reduced * 5)))
 
    #         # Impact levels
    #         I_C = CIA_TO_LEVEL.get(m["C"], 1)
    #         I_I = CIA_TO_LEVEL.get(m["I"], 1)
    #         I_A = CIA_TO_LEVEL.get(m["A"], 1)
 
    #         R_max_C_list.append(max(F, I_C))
    #         R_max_I_list.append(max(F, I_I))
    #         R_max_A_list.append(max(F, I_A))
 
    #     # Worst-case across all CVEs per property
    #     R_max_C = max(R_max_C_list)
    #     R_max_I = max(R_max_I_list)
    #     R_max_A = max(R_max_A_list)
 
    #     # Overall worst-case R_max for b_RTL
    #     R_max = max(R_max_C, R_max_I, R_max_A)
 
    #     # ── Step 4: b_RTL — CONNECT Ch.9 Eq. 9.1 & 9.2 ──────────────
    #     delta = (1.0 - self.baseline_belief) / 5.0
    #     b_RTL = self.baseline_belief + (R_max - 1) * delta
 
    #     # ── Step 4b: BC escalation for hub nodes (D4.2) ───────────────
    #     bc_node = self.bc.get(node_id, 0.0)
    #     b_RTL   = min(1.0, b_RTL + bc_node * self.bc_weight)
 
    #     # ── Step 5: d_RTL per CIA property — 5GAA Eq. 6 & 7 ──────────
    #     # I_w = CIA impact rating (after controls)
    #     # d_RTL = 1 - I_w
    #     # We take the worst-case (minimum d_RTL = strictest constraint)
    #     def d_from_cia(cia_val: float) -> float:
    #         I_w = CIA_TO_IMPACT.get(cia_val, 0.0) * (1.0 - total_reduction)
    #         return max(0.0, 1.0 - I_w)
 
    #     # Worst-case CIA value per property across all CVEs
    #     max_C = max(m["C"] for m in cve_metrics)
    #     max_I = max(m["I"] for m in cve_metrics)
    #     max_A = max(m["A"] for m in cve_metrics)
 
    #     d_RTL_C = d_from_cia(max_C)
    #     d_RTL_I = d_from_cia(max_I)
    #     d_RTL_A = d_from_cia(max_A)
 
    #     # Strictest constraint = minimum d_RTL across C, I, A
    #     d_RTL = min(d_RTL_C, d_RTL_I, d_RTL_A)
 
    #     # ── Step 6: u_RTL — residual uncertainty ──────────────────────
    #     u_RTL = max(0.0, 1.0 - b_RTL - d_RTL)
 
    #     # ── Step 7: Monte Carlo adjustment ────────────────────────────
    #     p_compromise = self.result.node_compromise_probs.get(node_id, 0.0)
    #     d_RTL = d_RTL * (1.0 - p_compromise)
    #     u_RTL = max(0.0, u_RTL * (1.0 - p_compromise))
 
    #     # ── Step 8: Normalise ─────────────────────────────────────────
    #     b_RTL, d_RTL, u_RTL = self._normalise(b_RTL, d_RTL, u_RTL)
 
    #     return RTLTriplet(
    #         node_id=node_id,
    #         belief=b_RTL,
    #         disbelief=d_RTL,
    #         uncertainty=u_RTL,
    #         risk_level=self._risk_level(d_RTL),
    #         active_controls=active_controls,
    #     )
    
    #create a summary dictionary reporting the risk level counts and the critical nodes
    def summary(self, rtls: Dict[str, RTLTriplet]) -> dict:
        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        critical_nodes = []

        for rtl in rtls.values():
            counts[rtl.risk_level] += 1
            if rtl.risk_level == "CRITICAL":
                critical_nodes.append(rtl.node_id)

        return {
            "risk_counts":    counts,
            "critical_nodes": critical_nodes,
            "total_nodes":    len(rtls)
        }


    #we need to normalize the RTL values via proportional scaling
    # #example here> if b + d + u = 0.0 + 0.95 + 0.30 = 1.25
    #then we decrease the d and u so the sum fits to 1
    @staticmethod
    def _normalise(b: float, d: float, u: float):
        total = b + d + u
        if total == 0:
            return 0.0, 0.0, 1.0
        return round(b / total, 6), round(d / total, 6), round(u / total, 6)

    #choose the according risk level from the according "enum"
    def _risk_level(self, belief: float) -> str:
        for level, (lo, hi) in self.RISK_THRESHOLDS.items():
            if lo <= belief < hi:
                return level
        return "CRITICAL"


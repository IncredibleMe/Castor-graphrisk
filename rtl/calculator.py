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


@dataclass
class RTLTriplet:
    """
    A Subjective Logic trust triplet.
    Invariant: belief + disbelief + uncertainty == 1.0
    """
    node_id:     str
    belief:      float   # b  ∈ [0, 1]
    disbelief:   float   # d  ∈ [0, 1]
    uncertainty: float   # u  ∈ [0, 1]
    risk_level:  str     # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

    def __post_init__(self):
        total = round(self.belief + self.disbelief + self.uncertainty, 6)
        assert abs(total - 1.0) < 1e-4, \
            f"RTL triplet must sum to 1.0, got {total} for node {self.node_id}"

    def __repr__(self):
        return (f"RTL({self.node_id}): "
                f"b={self.belief:.3f}, d={self.disbelief:.3f}, "
                f"u={self.uncertainty:.3f}  [{self.risk_level}]")


class RTLCalculator:
    """
    Derives per-node RTL triplets from Monte Carlo results.

    Algorithm (based on CASTOR Equations):
        1. Map CVSS → risk_level (1-5 scale)
        2. Calculate belief using Equation () (risk-based threshold)
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
        baseline_belief: float = 0.2    # ← b_t from b_RTL = b_t + ((R_max - 1) × Δ)
    ):
        self.result = result
        self.G = G
        self.baseline_belief = baseline_belief

    def compute_all(self) -> Dict[str, RTLTriplet]:
        #RTL for each node
        return {
            node_id: self.compute_node(node_id)
            for node_id in self.G.nodes
        }

    #compute the RTL triplet
    def compute_node(self, node_id: str) -> RTLTriplet:
        #Step 1: base DISBELIEF from compromise probability
        #in fact, we count how often this node was reached in 10.000 simulations
        #e.g. serverA was reached 900/10,000 times -> p_compromise = 0.09
        p_compromise = self.result.node_compromise_probs.get(node_id, 0.0)

        #Step 2: impact adjustment from CVSS
        node_data = self.G.nodes[node_id]
        cvss = node_data.get("cvss", 0.0)
        vulns = node_data.get("vulnerabilities", [])

        # #Step 2.5: compute UNCERTAINTY
        # #Nodes with few/no vulnerabilities have higher uncertainty
        # #Currently everthing hits the cap of 0.3, which meas this part needs a small refinement
        # # TODO : fix this in future steps
        # vulns = node_data.get("vulnerabilities", [])
        # evidence = len(vulns)                         #more vulnerabilities → more evidence
        # u_base  = max(0.0, 1.0 - evidence * 0.1)    #decreases uncertainty with number of evidence
        # uncertainty = min(u_base, self.uncertainty_cap)

        #Step 3: compute BELIEF = remaining value that leads d + u + b = 1
        #From our Castor equation: Δ = (1 - b_t) / 5      
        delta = (1.0 - self.baseline_belief) / 5.0

        #R_max comes from CVSS (we can later change this to use TARA for instance)
        #Map CVSS (0-10) to risk level (1-5) , 0-2→1, 2-4→2, 4-6→3, 6-8→4, 8-10→5
        risk_level = min(5, max(1, int(cvss / 2) + 1))  
        
        #Equation: b_RTL = b_t + ((R_max - 1) × Δ)
        belief = self.baseline_belief + ((risk_level - 1) * delta)

        #d_max (worst-case disbelief)
        maxRisk_NoControls = risk_level
        avgRisk_NoControls = risk_level

        #d_max = max{0.25 × (maxRisk_NoControls - 1),  
        #            avgRisk_NoControls / maxRisk} 
        d_max = max(
            0.25 * (maxRisk_NoControls - 1),
            avgRisk_NoControls / 5.0
        )

        #d_DTI = max{0.25 × (maxRisk_AllControls - 1), 
        #            avgRisk_AllControls / maxRisk}        
        security_controls = max(1, 5 - len(vulns))
        maxRisk_AllControls = max(1, risk_level - security_controls + 1)

        d_DTI = max(
            0.25 * (maxRisk_AllControls - 1),
            maxRisk_AllControls / 5.0
        )

        # *** Combine with Monte Carlo evidence ***
        # If node was frequently compromised → shift toward d_max
        # If rarely compromised → shift toward d_DTI
        disbelief = d_max * p_compromise + d_DTI * (1 - p_compromise)

        #Equation: u_DTI = 1 - b_DTI - d_DTI  
        b_DTI = 1.0 - d_max
        uncertainty = 1.0 - b_DTI - d_DTI

        #Normalise values
        belief, disbelief, uncertainty = self._normalise(belief, disbelief, uncertainty)


        return RTLTriplet(
            node_id=node_id,
            belief=belief,
            disbelief=disbelief,
            uncertainty=uncertainty,
            risk_level=self._risk_level(disbelief)
        )

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
    def _risk_level(self, disbelief: float) -> str:
        for level, (lo, hi) in self.RISK_THRESHOLDS.items():
            if lo <= disbelief < hi:
                return level
        return "CRITICAL"
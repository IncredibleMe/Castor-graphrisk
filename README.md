# graphrisk

**Monte Carlo Risk Assessment for Graph-Based Networks**

Open-source Python library for trust-aware security risk assessment on network topology graphs.  
Developed in the context of the [CASTOR](https://castor-project.eu) research project.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

---

## What it does

`graphrisk` addresses a critical gap in cybersecurity: **how to quantify trust requirements for network devices when attack paths can cascade across multiple nodes.**

Traditional risk assessment evaluates threats in isolation. `graphrisk` models the network as a **directed graph** (nodes = devices, edges = connections) and runs **Monte Carlo simulations** to calculate:

- **Cascading attack probabilities** — simulates thousands of "what-if" attack scenarios to determine how likely compromising one node leads to others
- **RTL (Required Trust Level)** — converts simulation results into Subjective Logic triplets `(belief, disbelief, uncertainty)` using CASTOR-compliant equations
- **Critical path identification** — identifies which nodes are pivoting points in multi-hop attack chains

**Key innovation:** Combines design-time risk assessment (CVSS scores, vulnerability data) with runtime Monte Carlo evidence to derive topology-aware trust thresholds.

---

## Installation

```bash
pip install graphrisk          # (once published to PyPI)

# or from source:
git clone https://github.com/castor-project/graphrisk
cd graphrisk
pip install -e .
```

**Requirements:** Python 3.9+, NetworkX, NumPy

---

## Quick Start

```python
from graphrisk import GraphBuilder, MonteCarloEngine, RTLCalculator

# 1. Build network graph from topology file
G = GraphBuilder().from_json("my_topology.json")

# 2. Run Monte Carlo simulation (10,000 attack scenarios)
mc = MonteCarloEngine(
    G, 
    iterations=10_000,
    entry_nodes=["internet_gw"],    # attacker entry points
    target_nodes=["db_server"]       # high-value assets
)
results = mc.run()

# 3. Calculate RTL per node using CASTOR equations
calc = RTLCalculator(results, G, baseline_belief=0.2)
rtls = calc.compute_all()

for node_id, rtl in rtls.items():
    print(rtl)
# Output:
# RTL(internet_gw): b=0.400, d=0.480, u=0.120  [MEDIUM]
# RTL(db_server):   b=0.600, d=0.320, u=0.080  [MEDIUM]
```

---

## Input Format

### JSON Format
```json
{
  "nodes": [
    {
      "id": "router_A",
      "cvss": 7.5,
      "layer": "network",
      "vendor": "Cisco",
      "vulnerabilities": [
        {"cve": "CVE-2023-1234", "cvss": 8.1},
        {"cve": "CVE-2023-5678", "cvss": 6.5}
      ]
    }
  ],
  "edges": [
    {
      "source": "router_A",
      "target": "router_B",
      "weight": 0.8,
      "attack_vector": "network"
    }
  ]
}
```

**Node attributes:**
- `id` — unique identifier
- `cvss` — base CVSS score (0-10)
- `layer` — infrastructure layer (network/os/firmware)
- `vendor` — hardware/software vendor
- `vulnerabilities` — list of CVEs with individual CVSS scores

**Edge attributes:**
- `source`, `target` — node IDs
- `weight` — reachability probability (0-1), used for cascade calculation
- `attack_vector` — "network" | "adjacent" | "local"

### XML Format (Holistic Risk Graph)
```python
G = GraphBuilder().from_xml("holistic_output.xml")
```
Supports XML output from the Holistic risk assessment framework.

---

## Architecture

### Module Overview

```
graphrisk/
├── graph/
│   └── builder.py          # GraphBuilder
├── montecarlo/
│   └── engine.py           # MonteCarloEngine
├── rtl/
│   └── calculator.py       # RTLCalculator
└── utils/                  # helper functions

examples/
└── simple_topology.py      # complete demo
```

---

### 1. `graph/builder.py` — GraphBuilder

**Purpose:** Constructs a NetworkX DiGraph from topology files (JSON/XML/dict).

**Key methods:**
```python
GraphBuilder().from_json(path)   # Load from JSON file
GraphBuilder().from_xml(path)    # Load from XML (Holistic format)
GraphBuilder().from_dict(data)   # Load from Python dict
```

**What it does:**
- Parses topology files into a directed graph structure
- Validates node/edge attributes
- Supports multiple input formats for flexibility

---

### 2. `montecarlo/engine.py` — MonteCarloEngine

**Purpose:** Simulates thousands of random attack paths to calculate cascading probabilities.

**Algorithm:**
```python
for iteration in range(10_000):
    1. Pick random entry node (e.g., internet gateway)
    2. Try to exploit current node → P_exploit = cvss / 10
    3. If success, pick random neighbor
    4. Try to cascade → P_cascade = edge weight
    5. If success, move to neighbor; repeat
    6. Record the attack path
```

**Output:**
```python
SimulationResult(
    node_compromise_probs = {"router_A": 0.42, "db_server": 0.09, ...},
    path_probs = {("gw", "router", "db"): 0.05, ...},
    cascade_probs = {("router_A", "router_B"): 0.38, ...}
)
```

**Key parameters:**
- `iterations` — number of simulations (default: 10,000)
- `entry_nodes` — attacker starting points
- `target_nodes` — high-value assets
- `seed` — random seed for reproducibility

---

### 3. `rtl/calculator.py` — RTLCalculator ⭐

**Purpose:** Converts Monte Carlo probabilities into RTL triplets using **CASTOR D4.1 equations**.

This is the **core innovation** of `graphrisk` — it implements the CASTOR trust assessment methodology.

---

#### RTL Calculation Algorithm (CASTOR-compliant)

The calculator implements equations from CASTOR D4.1 (Chapter 8) and 5GAA Trust Framework:

##### **Step 1: Map CVSS to Risk Level**
```python
risk_level = min(5, max(1, int(cvss / 2) + 1))
# CVSS 0-2  → risk_level 1
# CVSS 2-4  → risk_level 2
# CVSS 4-6  → risk_level 3
# CVSS 6-8  → risk_level 4
# CVSS 8-10 → risk_level 5
```

##### **Step 2: Calculate Belief (Equation 8.2)**
```python
Δ = (1 - b_t) / 5                           # Equation 8.1
b_RTL = b_t + ((risk_level - 1) × Δ)       # Equation 8.2
```
Where:
- `b_t` = baseline belief threshold (default 0.2)
- Higher risk → higher required belief

**Example:**
```
b_t = 0.2, risk_level = 4
Δ = (1 - 0.2) / 5 = 0.16
b_RTL = 0.2 + ((4 - 1) × 0.16) = 0.68
```

##### **Step 3: Calculate Worst-Case Disbelief (Equation 8.4)**
```python
d_max = max(
    0.25 × (maxRisk_NoControls - 1),
    avgRisk_NoControls / 5
)
```
Represents disbelief when **no security controls** are in place.

##### **Step 4: Calculate Best-Case Disbelief (Equation 8.5)**
```python
# Estimate security controls from vulnerability count
security_controls = max(1, 5 - len(vulnerabilities))

maxRisk_AllControls = max(1, risk_level - security_controls + 1)

d_DTI = max(
    0.25 × (maxRisk_AllControls - 1),
    maxRisk_AllControls / 5
)
```
Represents disbelief when **all security controls** are active.

##### **Step 5: Combine with Monte Carlo Evidence**
```python
# Weight by P_compromise from simulation
disbelief = d_max × P_compromise + d_DTI × (1 - P_compromise)
```

**Logic:** If Monte Carlo shows the node was frequently compromised, trust the worst-case estimate. If rarely compromised, trust the best-case.

##### **Step 6: Calculate Uncertainty (Equation 8.6)**
```python
b_DTI = 1 - d_max
uncertainty = 1 - b_DTI - d_DTI
```
No arbitrary caps — uncertainty is whatever remains after belief and disbelief.

##### **Step 7: Normalize**
```python
total = belief + disbelief + uncertainty
belief, disbelief, uncertainty = belief/total, disbelief/total, uncertainty/total
```
Ensures `b + d + u = 1.0` (Subjective Logic invariant).

---

#### Example Calculation

**Node:** `db_server`  
**Input data:**
- CVSS: 9.0
- Vulnerabilities: 1 (CVE-2021-5555, CVSS 9.8)
- P_compromise: 0.09 (from Monte Carlo)

**Step-by-step:**
```
1. risk_level = min(5, int(9.0/2) + 1) = 5

2. Δ = (1 - 0.2) / 5 = 0.16
   belief = 0.2 + ((5 - 1) × 0.16) = 0.84

3. d_max = max(0.25 × (5-1), 5/5) = max(1.0, 1.0) = 1.0

4. security_controls = max(1, 5 - 1) = 4
   maxRisk_AllControls = max(1, 5 - 4 + 1) = 2
   d_DTI = max(0.25 × (2-1), 2/5) = max(0.25, 0.4) = 0.4

5. disbelief = 1.0 × 0.09 + 0.4 × 0.91 = 0.09 + 0.364 = 0.454

6. b_DTI = 1 - 1.0 = 0
   uncertainty = 1 - 0 - 0.4 = 0.6

7. Normalize:
   total = 0.84 + 0.454 + 0.6 = 1.894
   belief = 0.84 / 1.894 = 0.444
   disbelief = 0.454 / 1.894 = 0.240
   uncertainty = 0.6 / 1.894 = 0.317

Final: RTL(db_server) = (0.444, 0.240, 0.317) [LOW]
```

---

#### RTL Risk Levels

| Risk Level | Disbelief Range | Interpretation |
|------------|-----------------|----------------|
| **LOW**      | 0.00 – 0.25     | Minimal security concerns |
| **MEDIUM**   | 0.25 – 0.50     | Moderate risk, monitoring needed |
| **HIGH**     | 0.50 – 0.75     | Significant risk, mitigation required |
| **CRITICAL** | 0.75 – 1.00     | Severe risk, immediate action needed |

---

#### Usage

```python
from graphrisk import RTLCalculator

# After running Monte Carlo simulation
calc = RTLCalculator(
    results,              # SimulationResult from MonteCarloEngine
    G,                    # NetworkX DiGraph
    baseline_belief=0.2   # b_t baseline (optional, default 0.2)
)

# Compute RTL for all nodes
rtls = calc.compute_all()

# Get summary statistics
summary = calc.summary(rtls)
print(summary)
# {
#   'risk_counts': {'LOW': 2, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 0},
#   'critical_nodes': [],
#   'total_nodes': 5
# }

# Compute RTL for single node
rtl = calc.compute_node("db_server")
print(rtl)
# RTL(db_server): b=0.444, d=0.240, u=0.317 [LOW]
```

---

## Comparison: `graphrisk` vs Traditional Risk Assessment

| Aspect | Traditional TARA | graphrisk |
|--------|-----------------|-----------|
| **Attack modeling** | Individual threats | Cascading multi-hop paths |
| **Probability source** | Manual analyst estimates | Monte Carlo simulation (10k+ scenarios) |
| **Topology awareness** | No | Yes — risk varies by network position |
| **Temporal dynamics** | Static snapshots | Probabilistic path analysis |
| **Output format** | Risk ratings (1-5) | Subjective Logic triplets (b,d,u) |
| **CASTOR compliance** | Partial | Full (Equations 8.1-8.6) |

---

## Roadmap

- [x] Graph Builder (JSON + XML)
- [x] Monte Carlo Engine (cascading attack simulation)
- [x] RTL Calculator (CASTOR D4.1 compliant)
- [ ] Markov Chain integration for temporal attack progression
- [ ] EPSS score integration (replacing static CVSS)
- [ ] Evidence weighting alignment between RTL and ATL
- [ ] Real-time topology updates
- [ ] Visualization module (attack path diagrams)
- [ ] REST API wrapper

---

## Contributing

We welcome contributions! Areas of interest:
- Markov Chain modeling for attack progression
- EPSS/KEV integration
- Performance optimization for large graphs (1000+ nodes)
- Visualization tools
- Additional input format parsers

---

## Citation

If you use `graphrisk` in your research, please cite:

```bibtex
@software{graphrisk2024,
  title = {graphrisk: Monte Carlo Risk Assessment for Graph-Based Networks},
  author = {CASTOR Project},
  year = {2024},
  url = {https://github.com/castor-project/graphrisk}
}
```

---

## License

Apache 2.0 — free for academic and commercial use.

---

## Acknowledgments

Developed as part of the **CASTOR** (Compute Continuum Architecture Supporting Trusted and Sovereign Cloud-Edge-IoT) project, funded by the European Union's Horizon Europe research and innovation program under grant agreement No. 101092861.

**References:**
- CASTOR D4.1: Architectural Specification of CASTOR Continuum-Wide Trust Assessment Framework
- 5GAA: A Framework for Dynamic Trustworthiness Assessment in Cooperative and Automated Vehicles
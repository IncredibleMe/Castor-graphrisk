# graphrisk

**Monte Carlo Risk Assessment for Graph-Based Networks**

Open-source Python library for trust-aware security risk assessment on network topology graphs.  
Developed in the context of the [CASTOR](https://castor-project.eu) research project (EU Horizon Grant 101167904).

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

---

## What it does

`graphrisk` addresses a critical gap in cybersecurity: **how to quantify trust requirements for network devices when attack paths can cascade across multiple nodes.**

Traditional risk assessment evaluates threats in isolation. `graphrisk` models the network as a **directed graph** (nodes = devices, edges = connections) and runs **Monte Carlo simulations** to calculate:

- **Cascading attack probabilities** — simulates thousands of "what-if" attack scenarios to determine how likely compromising one node leads to others
- **RTL (Required Trust Level)** — converts simulation results into Subjective Logic triplets `(belief, disbelief, uncertainty)` per CIA property (Confidentiality, Integrity, Availability), using CASTOR D4.1-compliant equations
- **Critical path identification** — identifies which nodes are pivoting points in multi-hop attack chains
- **Betweenness Centrality (BC) escalation** — optionally raises `b_RTL` for topologically critical hub nodes

**Key innovation:** Combines design-time risk assessment (CVSS scores, vulnerability data, security controls) with runtime Monte Carlo evidence and topology-aware BC escalation to derive per-CIA trust thresholds.

---

## Installation

```bash
pip install graphrisk          # (once published to PyPI)

# or from source:
git clone https://github.com/castor-project/graphrisk
cd graphrisk
pip install -e .
```

**Requirements:** Python 3.9+, NetworkX, NumPy, python-dotenv

---

## Quick Start

```python
from graph.builder import GraphBuilder
from montecarlo.engine import MonteCarloEngine
from rtl.calculator import RTLCalculator

# 1. Build network graph from topology file
builder = GraphBuilder()
G = builder.from_json("input/basic_topology.json")

# 2. Run Monte Carlo simulation (10,000 attack scenarios)
mc = MonteCarloEngine(
    G,
    iterations=10_000,
    entry_nodes=["R1"],
    target_nodes=["R4"],
    seed=42
)
results = mc.run()

# 3. Calculate RTL per node per CIA property
calc = RTLCalculator(
    results, G,
    use_bc=True,           # enable BC escalation
    use_monte_carlo=True,  # enable Monte Carlo adjustment
    baseline_belief=0.2
)
per_prop = calc.compute_all_per_property()

for node_id, props in per_prop.items():
    for prop, rtl in props.items():
        print(rtl)
# Output example:
# RTL(R1_C): b=0.520, d=0.350, u=0.130  [MEDIUM] controls=[secure_boot]
```

---

## Running the Demo

The entry point for running a full assessment is `examples/simple_topology.py`.

```bash
cd graphrisk
python examples/simple_topology.py
```

### CLI Arguments

| Argument | Type | Default | Description |
|---|---|---|---|
| `--topology` | `str` | `basic_topology` | Topology filename **without** extension, relative to `input/` |
| `--format` | `json` \| `xml` | `json` | Topology file format |
| `--entry` | `str` | `R1` | Attacker entry node ID |
| `--target` | `str` | `R2` | Attacker target node ID |

### Examples

```bash
# Default run (basic_topology.json, R1 → R2)
python examples/simple_topology.py

# Custom topology file
python examples/simple_topology.py --topology ring_topology

# XML format
python examples/simple_topology.py --topology ring_topology --format xml

# Custom entry and target nodes
python examples/simple_topology.py --entry GW1 --target DB_SERVER

# Full custom run
python examples/simple_topology.py --topology star_topology --format json --entry GW --target CORE
```

### Environment Variables

The demo automatically loads a `.env` file from the project root. Set the following variable before running:

```bash
NVD_API_KEY=your_nvd_api_key_here
```

This is used by `CVEFetcher` to enrich node vulnerability data via the NVD API.

---

## Input Format

### JSON Format
```json
{
  "nodes": [
    {
      "id": "R1",
      "cvss": 7.5,
      "layer": "network",
      "vendor": "Cisco",
      "criticality": 0.8,
      "vulnerabilities": [
        {
          "cve": "CVE-2023-1234",
          "cvss": 8.1,
          "AV": 0.85, "AC": 0.77, "PR": 0.68, "UI": 0.85,
          "C": 0.56, "I": 0.56, "A": 0.22
        }
      ],
      "security_controls": {
        "secure_boot": true,
        "access_control": false
      }
    }
  ],
  "edges": [
    {
      "source": "R1",
      "target": "R2",
      "weight": 0.8,
      "seg": 0.6,
      "proto": 0.7,
      "bw": 0.5,
      "link_controls": {
        "firewall": 0.4
      }
    }
  ]
}
```

**Node attributes:**
- `id` — unique identifier
- `cvss` — base CVSS score (0–10), used as fallback when per-CVE metrics are absent
- `layer` — infrastructure layer (`network` / `os` / `firmware`)
- `vendor` — hardware/software vendor
- `criticality` — operational importance (0–1), used in Dimension 3 target attractiveness
- `vulnerabilities` — list of CVEs; supports either raw `cvss` or full CVSS v3 vector metrics (`AV`, `AC`, `PR`, `UI`, `C`, `I`, `A`)
- `security_controls` — map of control name → boolean; supported controls: `secure_boot`, `cfi`, `rollback_protection`, `access_control`

**Edge attributes:**
- `source`, `target` — node IDs (edges are automatically made bidirectional)
- `weight` — generic reachability weight (0–1)
- `seg` — segmentation level (0–1), contributes to Dimension 2 cascade probability
- `proto` — protocol trust level (0–1)
- `bw` — bandwidth factor (0–1)
- `link_controls` — map of control name → effectiveness (0–1); e.g. `{"firewall": 0.4}`

### XML Format (Holistic Risk Graph)
```python
G = GraphBuilder().from_xml("input/holistic_output.xml")
```
Supports XML output from the Holistic risk assessment framework with `<node>` and `<edge>` elements carrying the same attributes as above.

---

## Architecture

### Module Overview

```
graphrisk/
├── graph/
│   └── builder.py              # GraphBuilder — topology loading
├── montecarlo/
│   └── engine.py               # MonteCarloEngine — attack path simulation
├── rtl/
│   ├── calculator.py           # RTLCalculator — per-CIA RTL derivation
│   └── calculator_isolated.py  # RTLCalculatorIso — isolated (no MC) variant
├── CVE_Fetcher/
│   └── cve_fetcher.py          # CVEFetcher — NVD API enrichment
├── input/                      # Topology JSON/XML files
└── examples/
    └── simple_topology.py      # Demo entry point (CLI)
```

---

### 1. `graph/builder.py` — GraphBuilder

**Purpose:** Constructs a NetworkX DiGraph from topology files (JSON / XML / dict).

```python
builder = GraphBuilder()
G = builder.from_json("input/basic_topology.json")
G = builder.from_xml("input/holistic_output.xml")
G = builder.from_dict({"nodes": [...], "edges": [...]})

print(builder.summary())
# {"nodes": 5, "edges": 12, "node_ids": ["R1", "R2", ...]}
```

Edges defined in the input file are automatically added in **both directions** (bidirectional topology assumption).

---

### 2. `montecarlo/engine.py` — MonteCarloEngine

**Purpose:** Simulates thousands of random attack paths to calculate cascading compromise probabilities.

**Three-dimensional attack model (CASTOR D4.1):**

| Dimension | What it models | Key formula |
|---|---|---|
| **Dim 1** — Exploitability | P(attacker exploits a node) | `a₁·P_CVSS_expl + a₂·ISS + a₃·EPSS + a₄·patch` |
| **Dim 2** — Cascade | P(attack propagates across an edge) | `ω_ij × Θ_ij` where `ω_ij = β₁·seg + β₂·proto + β₃·bw + β₄·dist` |
| **Dim 3** — Target attractiveness | Strategic weight of a neighbour | `γ₁·crit(v) + γ₂·BC_norm(v)` |

Default weight vectors: `A = {p_cvss_expl: 0.40, iss: 0.25, epss: 0.25, patch: 0.10}`, `BETA = {seg: 0.25, proto: 0.25, bw: 0.25, dist: 0.25}`, `GAMMA = {crit: 0.5, bc: 0.5}`.

```python
mc = MonteCarloEngine(
    G,
    iterations=10_000,    # number of MC iterations (default: 10,000)
    entry_nodes=["R1"],   # attacker starting points (default: all nodes)
    target_nodes=["R4"],  # high-value assets (default: all nodes)
    seed=42               # random seed for reproducibility
)
results = mc.run()

# Convenience methods
mc.top_compromised_nodes(results, n=5)   # list of (node, prob) tuples
mc.top_attack_paths(results, n=5)        # list of (path_tuple, prob) tuples
```

**Output — `SimulationResult`:**
- `node_compromise_probs` — `{node_id: P(compromised)}` for every node
- `path_probs` — `{path_tuple: P(path succeeded)}` for all observed paths
- `cascade_probs` — `{(src, dst): P(cascade)}` per edge
- `raw_paths` — all sampled paths (for debugging)

---

### 3. `rtl/calculator.py` — RTLCalculator

**Purpose:** Derives per-node, per-CIA RTL triplets `(b_RTL, d_RTL, u_RTL)` using CASTOR D4.1 equations.

```python
calc = RTLCalculator(
    result,                  # SimulationResult from MonteCarloEngine.run()
    G,                       # NetworkX DiGraph
    use_bc=True,             # enable BC escalation on b_RTL
    use_monte_carlo=True,    # enable Monte Carlo adjustment on d_RTL
    baseline_belief=0.2,     # b_t baseline (default: 0.2)
    bc_weight=0.2            # weight for BC contribution to b_RTL (default: 0.2)
)

# Per-CIA RTL for all nodes
per_prop = calc.compute_all_per_property()   # {node_id: {"C": RTLTriplet, "I": ..., "A": ...}}

# Aggregated RTL (worst-case across CIA) for all nodes
rtls = calc.compute_all()                    # {node_id: RTLTriplet}

# Summary
summary = calc.summary(rtls)
# {"risk_counts": {"LOW": 2, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 0},
#  "critical_nodes": [], "total_nodes": 5}
```

**RTL calculation pipeline (per CIA property):**

1. Map CVSS / CVSS-vector metrics → Feasibility `F` (1–5 scale)
2. Look up CIA impact level `I_level` from CVSS CIA values
3. `R_max = max(F, I_level)` after applying `security_controls` reduction
4. `b_RTL = b_t + (R_max - 1) × Δ` where `Δ = (1 - b_t) / 5`
5. If `use_bc`: `b_RTL += BC_norm(node) × bc_weight`
6. `d_RTL = 1 - I_w` (impact-based disbelief tolerance), tightened by active controls
7. If `use_monte_carlo`: `d_RTL × (1 - P_compromise)` — high cascade probability tightens tolerance
8. `u_RTL = max(0, 1 - b_RTL - d_RTL)`

**Security control weights:**

| Control | Reduction weight |
|---|---|
| `secure_boot` | 0.60 |
| `access_control` | 0.40 |
| `cfi` | 0.35 |
| `rollback_protection` | 0.20 |

**RTL risk levels (based on `b_RTL`):**

| Level | Belief range |
|---|---|
| LOW | 0.00 – 0.25 |
| MEDIUM | 0.25 – 0.50 |
| HIGH | 0.50 – 0.75 |
| CRITICAL | 0.75 – 1.00 |

---

## Comparison: `graphrisk` vs Traditional Risk Assessment

| Aspect | Traditional TARA | graphrisk |
|---|---|---|
| **Attack modeling** | Individual threats | Cascading multi-hop paths |
| **Probability source** | Manual analyst estimates | Monte Carlo simulation (10k+ scenarios) |
| **Topology awareness** | No | Yes — BC escalation, hop-distance weighting |
| **CIA granularity** | Aggregate score | Separate RTL triplet per C / I / A |
| **Security controls** | Binary presence | Weighted reduction factors |
| **Output format** | Risk ratings (1–5) | Subjective Logic triplets (b, d, u) |
| **CASTOR compliance** | Partial | Full (D4.1 equations) |

---

## Roadmap

- [x] Graph Builder (JSON + XML)
- [x] Monte Carlo Engine — three-dimensional attack model (Dim 1/2/3)
- [x] RTL Calculator — per-CIA, CASTOR D4.1 compliant
- [x] BC escalation for hub nodes
- [x] Security controls integration (node-level and link-level)
- [x] NVD/EPSS enrichment via CVEFetcher
- [ ] Bayesian dependency modeling for correlated node failures
- [ ] Full EPSS integration alongside CVSS in Dimension 1
- [ ] Evidence weighting alignment between RTL and ATL
- [ ] Real-time topology updates
- [ ] Visualization module (attack path diagrams)
- [ ] REST API wrapper with Olistic

---

## Citation

If you use `graphrisk` in your research, please cite:

```bibtex
@software{graphrisk2024,
  title  = {graphrisk: Monte Carlo Risk Assessment for Graph-Based Networks},
  author = {CASTOR Project},
  year   = {2024},
  url    = {https://github.com/castor-project/graphrisk}
}
```

---

## License

Apache 2.0 — free for academic and commercial use.

---

## Acknowledgments

Developed as part of the **CASTOR** project, funded by the European Union's Horizon Europe research and innovation programme under grant agreement No. 101167904.

**References:**
- CASTOR D4.1: Architectural Specification of CASTOR Continuum-Wide Trust Assessment Framework
- 5GAA: A Framework for Dynamic Trustworthiness Assessment in Cooperative and Automated Vehicles

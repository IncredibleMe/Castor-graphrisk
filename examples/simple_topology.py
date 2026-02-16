"""
Quick demo of a RTL computation on network graph using Monte-Carlo on a small 5-node network topology.

Topology:
    internet_gw  →  edge_router  →  core_router  →  db_server
                                 ↘  app_server   ↗

Configuration:
    Topology is loaded from input/simple_topology.json (default) or
    input/simple_topology.xml. Use --format=json or --format=xml to specify.

Run:
    cd graphrisk
    pip install -e .
    python examples/simple_topology.py              # Uses JSON (default)
    python examples/simple_topology.py --format=xml     # Uses XML
"""

import sys, os
import argparse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from graph.builder import GraphBuilder
from montecarlo.engine import MonteCarloEngine, SimulationResult
from rtl.calculator import RTLCalculator


def get_topology_path(format_type: str = "json") -> str:
    #Get the path to the topology configuration file
    return os.path.join(
        os.path.dirname(__file__),
        "..",
        "input",
        f"simple_topology.{format_type}"
    )


def main():
    parser = argparse.ArgumentParser(description="GraphRisk Monte Carlo Risk Assessment Demo")
    parser.add_argument(
        "--format",
        choices=["json", "xml"],
        default="json",
        help="Topology file format (default: json)"
    )
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # 1. Load network topology from file
    # ------------------------------------------------------------------
    topology_path = get_topology_path(args.format)
    
    print("=" * 60)
    print("  graphrisk - Monte Carlo Risk Assessment Demo")
    print("=" * 60)
    print(f"\nLoading topology from: {topology_path}")

    builder = GraphBuilder()
    if args.format == "json":
        G = builder.from_json(topology_path)
    else:
        G = builder.from_xml(topology_path)
    
    print(f"\n[1] Graph loaded: {builder.summary()}")

    # ------------------------------------------------------------------
    # 2. Run Monte Carlo simulation
    # ------------------------------------------------------------------
    mc = MonteCarloEngine(
        G,
        iterations=10_000,
        entry_nodes=["internet_gw"],   # attacker starts from internet
        target_nodes=["db_server"],    # wants to reach the database
        seed=42
    )

    print("\n[2] Running Monte Carlo simulation (10,000 iterations)...")
    results = mc.run()

    print("\n  Top 5 most compromised nodes:")
    for node, prob in mc.top_compromised_nodes(results, n=5):
        print(f"    {node:20s}  P={prob:.4f}")

    print("\n  Top 5 most probable attack paths:")
    for path, prob in mc.top_attack_paths(results, n=5):
        print(f"    {' → '.join(path):50s}  P={prob:.4f}")

    # ------------------------------------------------------------------
    # 3. Calculate RTL
    # ------------------------------------------------------------------
    print("\n[3] Computing RTL values...")
    calc = RTLCalculator(results, G)
    rtls = calc.compute_all()

    print("\n  RTL per node (belief | disbelief | uncertainty):")
    print(f"  {'Node':20s}  {'Belief':>8}  {'Disbelief':>10}  {'Uncertainty':>12}  {'Risk':>8}")
    print("  " + "-" * 65)
    for node_id, rtl in rtls.items():
        print(f"  {node_id:20s}  {rtl.belief:8.4f}  {rtl.disbelief:10.4f}"
              f"  {rtl.uncertainty:12.4f}  {rtl.risk_level:>8}")

    # ------------------------------------------------------------------
    # 4. Summary
    # ------------------------------------------------------------------
    print("\n[4] Risk Summary:")
    summary = calc.summary(rtls)
    for level, count in summary["risk_counts"].items():
        print(f"    {level:8s}: {count} node(s)")
    if summary["critical_nodes"]:
        print(f"\n  ⚠  CRITICAL nodes: {', '.join(summary['critical_nodes'])}")

    print("\nDone.\n")


if __name__ == "__main__":
    main()

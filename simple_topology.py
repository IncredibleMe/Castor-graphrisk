"""
RTL computation demo using Monte Carlo simulation on a network topology.

Run:
    cd graphrisk
    python examples/simple_topology.py                              # default: basic_topology.json
    python examples/simple_topology.py --topology ring_topology     # uses ring_topology.json
    python examples/simple_topology.py --topology ring_topology --format xml
"""

import sys, os
import argparse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from graph.builder import GraphBuilder
from montecarlo.engine import MonteCarloEngine, SimulationResult
from rtl.calculator import RTLCalculator
from rtl.calculator_isolated import RTLCalculatorIso
from CVE_Fetcher.cve_fetcher import CVEFetcher
from dotenv import load_dotenv


def get_topology_path(topology_name: str, format_type: str) -> str:
    return os.path.join(
        os.path.dirname(__file__),
        "..",
        "input",
        f"{topology_name}.{format_type}"
    )


def main():
    parser = argparse.ArgumentParser(description="GraphRisk Monte Carlo Risk Assessment Demo")
    parser.add_argument(
        "--topology",
        default="basic_topology",
        help="Topology filename without extension (default: basic_topology)"
    )
    parser.add_argument(
        "--format",
        choices=["json", "xml"],
        default="json",
        help="Topology file format (default: json)"
    )
    parser.add_argument(
        "--entry",
        default="R1",
        help="Attacker entry node (default: R1)"
    )
    parser.add_argument(
        "--target",
        default="R2",
        help="Attacker target node (default: R2)"
    )
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # 1. Load network topology
    # ------------------------------------------------------------------
    topology_path = get_topology_path(args.topology, args.format)

    print("=" * 60)
    print("  graphrisk - Monte Carlo Risk Assessment Demo")
    print("=" * 60)
    print(f"\nTopology : {topology_path}")
    print(f"Entry    : {args.entry}  →  Target: {args.target}")

    builder = GraphBuilder()
    if args.format == "json":
        G = builder.from_json(topology_path)
    else:
        G = builder.from_xml(topology_path)

    print(f"\n[1] Graph loaded: {builder.summary()}")

    # ------------------------------------------------------------------
    # 1a. Fetch Vulnerabilities Info from NIST
    # ------------------------------------------------------------------
    load_dotenv()  # διαβάζει το .env

    fetcher = CVEFetcher(
        nvd_api_key=os.getenv("NVD_API_KEY")
    )
    fetcher.enrich_graph(G)

    # [1b] Debug P_exploit  ← ΕΔΩ
    mc = MonteCarloEngine(G, iterations=10_000, entry_nodes=["R1"], target_nodes=["R4"])
    print(f"\n[1b] P_exploit per node:")
    for node in G.nodes:
        print(f"    {node}: P_exploit = {mc._exploit_probability(node):.4f}")

    print("\n[1e] BC per node:")
    for node, bc in mc._bc.items():
        print(f"    {node}: BC = {bc:.4f}")


    print(f"\n[1c] P_cascade per edge:")
    for src, dst in G.edges():
        p = mc._cascade_probability(src, dst, "R4")
        print(f"    {src} → {dst}: P_cascade = {p:.4f}")


    # ------------------------------------------------------------------
    # 2. Run Monte Carlo simulation
    # ------------------------------------------------------------------
    mc = MonteCarloEngine(
        G,
        iterations=10_000,
        entry_nodes=["R1"],   
        target_nodes=["R4"],
        seed=42
    )

    print("\n[2] Running Monte Carlo simulation (10,000 iterations)...")
    results = mc.run()

    print("\n  Top 10 most compromised nodes:")
    for node, prob in mc.top_compromised_nodes(results, n=10):
        print(f"    {node:20s}  P={prob:.4f}")

    print("\n  Top 10 most probable attack paths:")
    for path, prob in mc.top_attack_paths(results, n=10):
        print(f"    {' → '.join(path):50s}  P={prob:.4f}")

    print("\n  Top 10 most exploited edges:")
    for edge, prob in sorted(results.cascade_probs.items(), 
                            key=lambda x: x[1], reverse=True)[:10]:
        print(f"    {edge[0]} → {edge[1]}:  P={prob:.4f}")

    # ------------------------------------------------------------------
    # 3. Calculate RTL
    # ------------------------------------------------------------------
    print("\n[3] Computing RTL values...")
    
    #senario 1
    # calc = RTLCalculator(
    #     results, G,
    #     use_bc=False,          # ← Senario 1: xwris BC
    #     use_monte_carlo=False  # ← Senario 1: xwris Monte Carlo adjustment
    # )
    #senario 2
    calc = RTLCalculator(
        results, G,
        use_bc=True,           # ← Senario 2: me BC
        use_monte_carlo=True   # ← Senario 2: me Monte Carlo
    )


    rtls = calc.compute_all_per_property()

    # print("\n  RTL per node (belief | disbelief | uncertainty):")
    # print(f"  {'Node':20s}  {'Belief':>8}  {'Disbelief':>10}  {'Uncertainty':>12}  {'Risk':>8}")
    # print("  " + "-" * 65)
    # for node_id, rtl in rtls.items():
    #     print(f"  {node_id:20s}  {rtl.belief:8.4f}  {rtl.disbelief:10.4f}"
    #           f"  {rtl.uncertainty:12.4f}  {rtl.risk_level:>8}")

    print("\n[3] RTL per node per CIA property:")
    print(f"  {'Node':6s}  {'Prop':>4}  {'Belief':>8}  {'Disbelief':>10}  {'Uncertainty':>12}  {'Risk':>8}")
    print("  " + "-" * 55)
    per_prop = calc.compute_all_per_property()
    for node_id, props in per_prop.items():
        for prop, rtl in props.items():
            print(f"  {node_id:6s}  {prop:>4}  {rtl.belief:8.4f}  {rtl.disbelief:10.4f}  {rtl.uncertainty:12.4f}  {rtl.risk_level:>8}")

    # ------------------------------------------------------------------
    # 4. Summary
    # ------------------------------------------------------------------
    print("\n[5] Risk Summary:")
   
    #summary = calc.summary(rtls)
    
    flat_rtls = {
        f"{node_id}_{prop}": rtl
        for node_id, props in per_prop.items()
        for prop, rtl in props.items()
    }
    summary = calc.summary(flat_rtls)

    for level, count in summary["risk_counts"].items():
        print(f"    {level:8s}: {count} node(s)")
    if summary["critical_nodes"]:
        print(f"\n  ⚠  CRITICAL nodes: {', '.join(summary['critical_nodes'])}")

    print("\nDone.\n")


if __name__ == "__main__":
    main()
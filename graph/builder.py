"""
Builds a NetworkX DiGraph from different input formats:
  - JSON  (default / flexible)
  - XML   (Holistic risk graph output)
  - dict  (programmatic / inline use)

Each NODE carries:
  node_id         : unique identifier (string)
  cvss            : CVSS base score (float 0-10)
  layer           : infrastructure layer  e.g. "network", "os", "firmware"
  vendor          : hardware/software vendor tag
  vulnerabilities : list of {"cve": str, "cvss": float} dicts

Each EDGE carries:
  weight          : reachability / connection strength  (float 0-1)
  attack_vector   : "network" | "adjacent" | "local"

Input Files:
  Topology configuration files are stored in the 'input/' directory.
"""

import json
import xml.etree.ElementTree as ET
import networkx as nx


class GraphBuilder:
    """
    Builds a directed NetworkX graph representing the network topology.
    Supports JSON, XML and dict inputs.
    """

    def __init__(self):
        self.G = nx.DiGraph()

    # Public API
    def from_json(self, path: str) -> nx.DiGraph:
        """Load graph from a JSON file."""
        with open(path, "r") as f:
            data = json.load(f)
        return self._build(data)

    def from_xml(self, path: str) -> nx.DiGraph:
        """Load graph from XML file. Parses <node> and <edge> elements."""
        tree = ET.parse(path)
        root = tree.getroot()
        data = self._parse_xml(root)
        return self._build(data)

    def from_dict(self, data: dict) -> nx.DiGraph:
        """Load graph directly from a Python dict (same schema as JSON)."""
        return self._build(data)

    def _parse_xml(self, root) -> dict:
        """Convert XML root element to internal dict format.
        Adjust attribute names to match the actual Holistic XML schema."""
        data = {"nodes": [], "edges": []}

        for el in root.findall(".//node"):
            node = {
                "id":    el.get("id", "unknown"),
                "cvss":  float(el.get("cvss", 0.0)),
                "layer": el.get("layer", "network"),
                "vendor": el.get("vendor", "unknown"),
                "vulnerabilities": []
            }
            for v in el.findall("vulnerability"):
                node["vulnerabilities"].append({
                    "cve":  v.get("cve", ""),
                    "cvss": float(v.get("cvss", 0.0))
                })
            data["nodes"].append(node)

        for el in root.findall(".//edge"):
            data["edges"].append({
                "source":        el.get("source"),
                "target":        el.get("target"),
                "weight":        float(el.get("weight", 0.5)),
                "attack_vector": el.get("attack_vector", "network")
            })

        return data

    def _build(self, data: dict) -> nx.DiGraph:
        """Populate the internal DiGraph from the normalised dict."""
        for node in data.get("nodes", []):
            self.G.add_node(
                node["id"],
                cvss=node.get("cvss", 0.0),
                layer=node.get("layer", "network"),
                vendor=node.get("vendor", "unknown"),
                criticality=node.get("criticality", 0.5),
                vulnerabilities=node.get("vulnerabilities", []),
                security_controls=node.get("security_controls", {})
            )
 
        for edge in data.get("edges", []):
            props = {
                "weight":        edge.get("weight", 0.5),
                "seg":           edge.get("seg",    0.5),
                "proto":         edge.get("proto",  0.5),
                "bw":            edge.get("bw",     0.5),
                "link_controls": edge.get("link_controls", {})
            }
            # Forward edge
            self.G.add_edge(edge["source"], edge["target"], **props)
            # Reverse edge — same properties (bidirectional topology)
            self.G.add_edge(edge["target"], edge["source"], **props)
 
        return self.G

    def summary(self) -> dict:
        """Return a quick summary of the loaded graph."""
        return {
            "nodes": self.G.number_of_nodes(),
            "edges": self.G.number_of_edges(),
            "node_ids": list(self.G.nodes)
        }
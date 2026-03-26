"""
cve_fetcher.py
==============
Fetches CVE metrics from NVD and EPSS APIs and enriches
the graph nodes with Dimension 1 properties needed for
the Monte Carlo simulation.

APIs used:
  NVD  : https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE-ID>
  EPSS : https://api.first.org/data/v1/epss?cve=<CVE-ID>

CVSS v3.x metric values used:
  AV  (Attack Vector)      : Network=0.85, Adjacent=0.62, Local=0.55, Physical=0.20
  AC  (Attack Complexity)  : Low=0.77,     High=0.44
  PR  (Privileges Required): None=0.85,    Low=0.62,      High=0.27
  UI  (User Interaction)   : None=0.85,    Required=0.62
  C/I/A (Impact)           : None=0.00,    Low=0.22,      High=0.56

Usage:
    fetcher = CVEFetcher()

    # Enrich a single CVE
    metrics = fetcher.fetch("CVE-2023-38802")
    print(metrics)

    # Enrich all CVEs in a NetworkX graph
    fetcher.enrich_graph(G)
"""

import time
import requests


# ------------------------------------------------------------------
# CVSS v3.x metric string → numeric value mappings
# ------------------------------------------------------------------
AV_MAP  = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.20}
AC_MAP  = {"LOW": 0.77,  "HIGH": 0.44}
PR_MAP  = {"NONE": 0.85, "LOW": 0.62,  "HIGH": 0.27}
UI_MAP  = {"NONE": 0.85, "REQUIRED": 0.62}
CIA_MAP = {"NONE": 0.00, "LOW": 0.22,  "HIGH": 0.56}


class CVEFetcher:
    """
    Fetches and caches CVE metrics from NVD and EPSS.

    Parameters:
        nvd_api_key : optional NVD API key (increases rate limit from 5 to 50 req/30s)
        delay       : seconds to wait between requests (default 1.0 — NVD rate limit)
    """

    NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, nvd_api_key: str = None, delay: float = 1.0):
        self.nvd_api_key = nvd_api_key
        self.delay       = delay
        self._cache      = {}   # CVE ID → metrics dict

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch(self, cve_id: str) -> dict:
        """
        Fetch metrics for a single CVE ID.
        Returns a dict with keys:
            cve, cvss, AV, AC, PR, UI, C, I, A,
            P_CVSS_expl, ISS, EPSS, patched
        Returns None if the CVE cannot be fetched.
        """
        if cve_id in self._cache:
            return self._cache[cve_id]

        metrics = self._fetch_nvd(cve_id)
        if metrics is None:
            return None

        metrics["EPSS"]    = self._fetch_epss(cve_id)
        metrics["patched"] = False   # default — patch status unknown at fetch time

        # ── Dimension 1 derived values ────────────────────────────────
        # P_CVSS_expl = 2 × AV × AC × PR × UI  (CVSS v3.x spec)
        metrics["P_CVSS_expl"] = (
            2.0
            * metrics["AV"]
            * metrics["AC"]
            * metrics["PR"]
            * metrics["UI"]
        )

        # ISS = 1 - (1-C)(1-I)(1-A)
        metrics["ISS"] = 1.0 - (
            (1.0 - metrics["C"])
            * (1.0 - metrics["I"])
            * (1.0 - metrics["A"])
        )

        self._cache[cve_id] = metrics
        return metrics

    def enrich_graph(self, G) -> None:
        """
        Enrich all CVEs in every node of a NetworkX graph.
        Adds 'dim1_metrics' to each vulnerability entry in node_data.

        Example node_data after enrichment:
            {
                "vulnerabilities": [
                    {
                        "cve": "CVE-2023-38802",
                        "cvss": 8.8,
                        "dim1_metrics": {
                            "P_CVSS_expl": 1.43,
                            "ISS": 0.91,
                            "EPSS": 0.43,
                            "patched": False,
                            "AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85,
                            "C": 0.56,  "I": 0.56,  "A": 0.56
                        }
                    }
                ]
            }
        """
        for node_id in G.nodes:
            node_data = G.nodes[node_id]
            vulns     = node_data.get("vulnerabilities", [])

            for vuln in vulns:
                cve_id = vuln.get("cve", "")
                if not cve_id:
                    continue

                # ── Αν τα metrics υπάρχουν ήδη στο JSON → παράλειψε το fetch
                if all(k in vuln for k in ["AV", "AC", "PR", "UI", "C", "I", "A"]):
                    print(f"  {cve_id} — metrics found in JSON, skipping fetch")
                    # Υπολόγισε μόνο P_CVSS_expl και ISS
                    vuln["dim1_metrics"] = {
                        "P_CVSS_expl": round(2.0 * vuln["AV"] * vuln["AC"] * vuln["PR"] * vuln["UI"], 4),
                        "ISS":         round(1.0 - (1-vuln["C"]) * (1-vuln["I"]) * (1-vuln["A"]), 4),
                        "EPSS":        vuln.get("EPSS", 0.0),
                        "patched":     vuln.get("patched", False),
                        "AV": vuln["AV"], "AC": vuln["AC"],
                        "PR": vuln["PR"], "UI": vuln["UI"],
                        "C":  vuln["C"],  "I":  vuln["I"],  "A": vuln["A"],
                    }
                    continue

                # ── Αλλιώς → fetch από NVD
                print(f"  Fetching {cve_id} for node {node_id}...")
                metrics = self.fetch(cve_id)
                if metrics:
                    vuln["dim1_metrics"] = { ... }  # όπως πριν
                else:
                    vuln["dim1_metrics"] = self._fallback(vuln.get("cvss", 5.0))

                time.sleep(self.delay)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _fetch_nvd(self, cve_id: str) -> dict | None:
        """Fetch CVSS metrics from NVD API."""
        headers = {
            "User-Agent": "graphrisk/1.0 (CASTOR research project)",
            "Accept": "application/json"
        }
        # if self.nvd_api_key:
        #     headers["apiKey"] = self.nvd_api_key

        try:
            resp = requests.get(
                self.NVD_URL,
                params={"cveId": cve_id},
                headers=headers,
                timeout=10
            )
            resp.raise_for_status()
            data = resp.json()

            vuln    = data["vulnerabilities"][0]["cve"]
            metrics = vuln["metrics"]

            # Prefer CVSSv3.1, fall back to v3.0
            cvss_list = (
                metrics.get("cvssMetricV31")
                or metrics.get("cvssMetricV30")
                or []
            )
            if not cvss_list:
                print(f"  WARNING: no CVSSv3 data for {cve_id}")
                return None

            cvss_data = cvss_list[0]["cvssData"]

            return {
                "cve":  cve_id,
                "cvss": cvss_data.get("baseScore", 0.0),
                "AV":   AV_MAP.get(cvss_data.get("attackVector",        "").upper(), 0.5),
                "AC":   AC_MAP.get(cvss_data.get("attackComplexity",    "").upper(), 0.5),
                "PR":   PR_MAP.get(cvss_data.get("privilegesRequired",  "").upper(), 0.5),
                "UI":   UI_MAP.get(cvss_data.get("userInteraction",     "").upper(), 0.5),
                "C":    CIA_MAP.get(cvss_data.get("confidentialityImpact","").upper(),0.5),
                "I":    CIA_MAP.get(cvss_data.get("integrityImpact",    "").upper(), 0.5),
                "A":    CIA_MAP.get(cvss_data.get("availabilityImpact", "").upper(), 0.5),
            }

        except Exception as e:
            print(f"  ERROR fetching NVD data for {cve_id}: {e}")
            return None

    def _fetch_epss(self, cve_id: str) -> float:
        """Fetch EPSS score from FIRST API. Returns 0.0 on failure."""
        try:
            resp = requests.get(
                self.EPSS_URL,
                params={"cve": cve_id},
                timeout=10
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get("data"):
                return float(data["data"][0].get("epss", 0.0))
            return 0.0

        except Exception as e:
            print(f"  ERROR fetching EPSS for {cve_id}: {e}")
            return 0.0

    def _fallback(self, cvss_score: float) -> dict:
        """
        Generate approximate Dimension 1 metrics from a CVSS base score alone.
        Used when NVD API is unavailable.
        """
        # Approximate: high CVSS → high exploitability and impact
        approx = min(1.0, cvss_score / 10.0)
        return {
            "P_CVSS_expl": round(approx * 1.5, 4),
            "ISS":         round(approx,        4),
            "EPSS":        0.0,
            "patched":     False,
            "AV":  0.85 if cvss_score >= 7.0 else 0.62,
            "AC":  0.77,
            "PR":  0.85,
            "UI":  0.85,
            "C":   0.56 if cvss_score >= 7.0 else 0.22,
            "I":   0.56 if cvss_score >= 7.0 else 0.22,
            "A":   0.56 if cvss_score >= 7.0 else 0.22,
        }
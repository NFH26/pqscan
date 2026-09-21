#!/usr/bin/env python3
"""Regenerate pqc_scan/rules/ism_controls.txt from ASD's published OSCAL catalog.

The ISM is reissued quarterly and control numbers are retired, so a citation that was correct
last quarter can quietly stop being correct. Keeping a local copy of the identifiers lets the
self-test verify every control PQScan cites without a network call, and this script is how the
copy is refreshed when a new ISM lands.

    python tools/refresh_ism_controls.py

The catalog is published by ASD under CC BY 4.0.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

CATALOG_URL = (
    "https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal/main/ISM_catalog.json"
)
DESTINATION = Path(__file__).resolve().parent.parent / "pqc_scan" / "rules" / "ism_controls.txt"


def main() -> int:
    with urllib.request.urlopen(CATALOG_URL, timeout=60) as response:
        catalog = json.load(response)["catalog"]

    rows: dict[str, tuple[str, str]] = {}

    def walk(group: dict, section: str) -> None:
        for control in group.get("controls", []) or []:
            prose = " ".join(p.get("prose", "") for p in control.get("parts", []) or []).strip()
            rows[control["id"].upper()] = (section, prose)
            walk(control, section)
        for child in group.get("groups", []) or []:
            walk(child, child.get("title", section))

    for group in catalog.get("groups", []):
        walk(group, group.get("title", ""))

    metadata = catalog["metadata"]
    lines = [
        "# ASD ISM control identifiers, extracted from ASD's OSCAL catalog.",
        f"# catalog version: {metadata.get('version')}  published: {metadata.get('last-modified')}",
        "# source: https://github.com/AustralianCyberSecurityCentre/ism-oscal (CC BY 4.0)",
        "# Regenerate with: python tools/refresh_ism_controls.py",
        f"# controls: {len(rows)}",
        "",
    ]
    lines.extend(f"{key}\t{rows[key][0]}\t{rows[key][1][:200]}" for key in sorted(rows))
    DESTINATION.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} controls to {DESTINATION}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

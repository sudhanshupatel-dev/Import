"""
App Comparison Module
Compares two versions of the same app and generates diff reports
"""
import json
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict


@dataclass
class TestDiff:
    test_id: str
    test_name: str
    category: str
    status_a: str
    status_b: str
    change: str  # "improved", "regressed", "unchanged", "new", "removed"
    severity: str


class AppComparator:
    """Compare two scan results of the same app."""

    def compare(self, scan_a: Dict, scan_b: Dict) -> Dict:
        """Compare two scan reports and generate a diff."""
        results_a = {r["test_id"]: r for r in scan_a.get("results", [])}
        results_b = {r["test_id"]: r for r in scan_b.get("results", [])}

        all_test_ids = set(results_a.keys()) | set(results_b.keys())
        diffs = []

        for test_id in sorted(all_test_ids):
            ra = results_a.get(test_id)
            rb = results_b.get(test_id)

            if ra and rb:
                # Both versions have this test
                change = "unchanged"
                if ra["status"] != rb["status"]:
                    # Determine if it improved or regressed
                    severity_order = {"FAIL": 0, "WARNING": 1, "PASS": 2, "INFO": 3}
                    a_score = severity_order.get(ra["status"], 1)
                    b_score = severity_order.get(rb["status"], 1)
                    if b_score > a_score:
                        change = "improved"
                    else:
                        change = "regressed"

                diffs.append(TestDiff(
                    test_id=test_id,
                    test_name=ra["test_name"],
                    category=ra["category"],
                    status_a=ra["status"],
                    status_b=rb["status"],
                    change=change,
                    severity=ra["severity"],
                ))
            elif ra:
                diffs.append(TestDiff(
                    test_id=test_id,
                    test_name=ra["test_name"],
                    category=ra["category"],
                    status_a=ra["status"],
                    status_b="N/A",
                    change="removed",
                    severity=ra["severity"],
                ))
            elif rb:
                diffs.append(TestDiff(
                    test_id=test_id,
                    test_name=rb["test_name"],
                    category=rb["category"],
                    status_a="N/A",
                    status_b=rb["status"],
                    change="new",
                    severity=rb["severity"],
                ))

        # Calculate comparison summary
        improved = sum(1 for d in diffs if d.change == "improved")
        regressed = sum(1 for d in diffs if d.change == "regressed")
        unchanged = sum(1 for d in diffs if d.change == "unchanged")

        # Risk score comparison
        risk_a = scan_a.get("risk_score", 0)
        risk_b = scan_b.get("risk_score", 0)
        risk_change = risk_b - risk_a

        return {
            "scan_a": {
                "id": scan_a.get("file_info", {}).get("file_name", "Unknown"),
                "version": scan_a.get("file_info", {}).get("version_name",
                         scan_a.get("file_info", {}).get("version", "Unknown")),
                "risk_score": risk_a,
                "risk_level": scan_a.get("risk_level", "Unknown"),
            },
            "scan_b": {
                "id": scan_b.get("file_info", {}).get("file_name", "Unknown"),
                "version": scan_b.get("file_info", {}).get("version_name",
                         scan_b.get("file_info", {}).get("version", "Unknown")),
                "risk_score": risk_b,
                "risk_level": scan_b.get("risk_level", "Unknown"),
            },
            "diffs": [asdict(d) for d in diffs],
            "summary": {
                "total_tests": len(diffs),
                "improved": improved,
                "regressed": regressed,
                "unchanged": unchanged,
                "new": sum(1 for d in diffs if d.change == "new"),
                "removed": sum(1 for d in diffs if d.change == "removed"),
                "risk_change": risk_change,
                "risk_trend": "improved" if risk_change < 0 else "regressed" if risk_change > 0 else "unchanged",
            }
        }

    def compare_activities(self, scan_a: Dict, scan_b: Dict) -> Dict:
        """Compare exported activities/screens between two versions."""
        # Extract activity info from manifest data
        activities_a = set()
        activities_b = set()

        # Try to extract from scan results
        for r in scan_a.get("results", []):
            if "IPC" in r.get("test_name", "") or "Activity" in r.get("test_name", ""):
                details = r.get("details", "")
                for line in details.split("\n"):
                    line = line.strip()
                    if line and ("Activity" in line or "activity" in line):
                        activities_a.add(line)

        for r in scan_b.get("results", []):
            if "IPC" in r.get("test_name", "") or "Activity" in r.get("test_name", ""):
                details = r.get("details", "")
                for line in details.split("\n"):
                    line = line.strip()
                    if line and ("Activity" in line or "activity" in line):
                        activities_b.add(line)

        added = activities_b - activities_a
        removed = activities_a - activities_b

        return {
            "version_a": scan_a.get("file_info", {}).get("version_name", "Unknown"),
            "version_b": scan_b.get("file_info", {}).get("version_name", "Unknown"),
            "total_a": len(activities_a),
            "total_b": len(activities_b),
            "added": list(added),
            "removed": list(removed),
            "common": list(activities_a & activities_b),
            "added_count": len(added),
            "removed_count": len(removed),
        }

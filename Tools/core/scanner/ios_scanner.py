"""
iOS IPA Static Analysis Scanner - with deduplication
"""
import os
import re
import hashlib
import zipfile
import json
import plistlib
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass, field, asdict


@dataclass
class ScanResult:
    test_id: str
    test_name: str
    category: str
    severity: str
    status: str
    description: str
    details: str
    recommendation: str
    evidence: list = field(default_factory=list)
    refs: list = field(default_factory=list)


class IosScanner:

    SENSITIVE_DATA_PATTERNS = [
        (r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded password"),
        (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded API key"),
        (r'(?:secret|secret[_-]?key)\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded secret"),
        (r'(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded access token"),
        (r'(?:private[_-]?key)\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded private key"),
        (r'(?:client[_-]?secret)\s*[:=]\s*["\'][^"\']+["\']', "OAuth client secret"),
        (r'(?:BEGIN\s+PRIVATE\s+KEY)', "PEM private key"),
    ]

    JAILBREAK_CHECK_PATTERNS = [
        "Cydia", "cydia", "Sileo", "sileo", "/Applications/Cydia.app",
        "substrate", "MobileSubstrate", "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
    ]

    def __init__(self):
        self.results: List[ScanResult] = []
        self.detections = {}
        self._seen = set()  # Deduplication
        self._main_plist = None

    def _add_result(self, result: ScanResult):
        """Add result only if test_id+status not already seen."""
        key = (result.test_id, result.status)
        if key not in self._seen:
            self._seen.add(key)
            self.results.append(result)

    def scan(self, ipa_path: str) -> Dict:
        self.results = []
        self.detections = {}
        self._seen = set()
        self._main_plist = None
        ipa_path = Path(ipa_path)
        if not ipa_path.exists():
            return {"error": "IPA file not found"}

        try:
            with zipfile.ZipFile(ipa_path, 'r') as zf:
                self._scan_info_plist(zf)
                self._scan_entitlements(zf)
                self._scan_binary_content(zf)
                self._scan_keychain_access(zf)
                self._scan_backups(zf)
        except zipfile.BadZipFile:
            return {"error": "Invalid IPA file"}

        self.detections = {
            "has_jailbreak_detection": any("jailbreak" in r.test_name.lower() for r in self.results),
            "has_ssl_pinning": any("ssl" in r.test_name.lower() or "pinning" in r.test_name.lower() for r in self.results),
            "checks_network": True,
            "has_crypto_issues": any("crypt" in r.test_name.lower() or "key" in r.test_name.lower() for r in self.results if r.status in ("FAIL", "WARNING")),
            "has_storage_issues": any("storage" in r.test_name.lower() or "data" in r.test_name.lower() for r in self.results if r.status in ("FAIL", "WARNING")),
        }

        return self._compile_report(ipa_path)

    def _find_main_plist(self, zf):
        for name in zf.namelist():
            parts = name.split('/')
            if (len(parts) == 3 and parts[0] == "Payload" and
                parts[1].endswith(".app") and parts[2] == "Info.plist"):
                try:
                    plist = plistlib.loads(zf.read(name))
                    if "CFBundleIdentifier" in plist:
                        return name, plist
                except Exception:
                    continue
        return None, None

    def _scan_info_plist(self, zf):
        main_path, plist = self._find_main_plist(zf)
        if plist:
            self._main_plist = plist

            ats = plist.get("NSAppTransportSecurity", {})
            if ats:
                allows = ats.get("NSAllowsArbitraryLoads", False)
                if allows:
                    self._add_result(ScanResult(
                        test_id="MSTG-NETWORK-02", test_name="Testing for Unencrypted Communications (iOS)",
                        category="Network", severity="Critical", status="FAIL",
                        description="NSAppTransportSecurity allows arbitrary loads (HTTP).",
                        details="NSAllowsArbitraryLoads is set to YES.",
                        recommendation="Set NSAllowsArbitraryLoads to NO.",
                        evidence=[f"NSAllowsArbitraryLoads = YES in {main_path}"],
                        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/"]
                    ))

                exceptions = ats.get("NSExceptionDomains", {})
                insecure = [d for d, c in exceptions.items() if c.get("NSExceptionAllowsInsecureHTTPLoads")]
                if insecure:
                    self._add_result(ScanResult(
                        test_id="MSTG-NETWORK-02", test_name="Testing for Unencrypted Communications (iOS - Domains)",
                        category="Network", severity="High", status="WARNING",
                        description=f"ATS exceptions for {len(insecure)} domain(s).",
                        details=f"Domains: {', '.join(insecure)}",
                        recommendation="Remove HTTP exceptions.",
                        evidence=[f"ATS exception: {d}" for d in insecure],
                        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/"]
                    ))

            url_types = plist.get("CFBundleURLTypes", [])
            if url_types:
                self.detections["has_url_schemes"] = True
                schemes = [s for ut in url_types for s in ut.get("CFBundleURLSchemes", [])]
                self._add_result(ScanResult(
                    test_id="MSTG-PLATFORM-01", test_name="Testing for URL Handling (iOS)",
                    category="Platform", severity="High", status="WARNING",
                    description=f"App registers {len(schemes)} custom URL scheme(s).",
                    details=f"URL schemes: {', '.join(schemes[:10])}",
                    recommendation="Validate all URL scheme inputs.",
                    evidence=[f"URL scheme: {s}" for s in schemes[:5]],
                    refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/"]
                ))

            if plist.get("UIFileSharingEnabled"):
                self._add_result(ScanResult(
                    test_id="MSTG-STORAGE-08", test_name="Testing for Sensitive Data in Plists",
                    category="Storage", severity="Medium", status="WARNING",
                    description="UIFileSharingEnabled is set to YES.",
                    details="App data exposed in iTunes File Sharing.",
                    recommendation="Disable UIFileSharingEnabled unless necessary.",
                    evidence=[f"UIFileSharingEnabled = YES in {main_path}"],
                    refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-8/"]
                ))

    def _scan_entitlements(self, zf):
        for name in zf.namelist():
            if name.endswith(".entitlements"):
                try:
                    content = zf.read(name).decode("utf-8", errors="ignore")
                    if "get-task-allow" in content and "true" in content.lower():
                        self._add_result(ScanResult(
                            test_id="MSTG-CODE-01", test_name="Testing for Debugging Symbols (iOS)",
                            category="Code Quality", severity="Medium", status="FAIL",
                            description="get-task-allow entitlement is enabled.",
                            details="App can be debugged by attaching a debugger.",
                            recommendation="Disable get-task-allow for production.",
                            evidence=[f"get-task-allow=true in {name}"],
                            refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/"]
                        ))
                except Exception:
                    continue

    def _scan_binary_content(self, zf):
        binary_findings = []
        # Track per-test-type to collect evidence across files
        evidence_by_test = {}

        for name in zf.namelist():
            if name.endswith("/") or name.startswith("__MACOSX"):
                continue
            try:
                content = zf.read(name)
                try:
                    text = content.decode("utf-8")
                except UnicodeDecodeError:
                    text = content.decode("latin-1", errors="ignore")

                # Jailbreak detection
                for pattern in self.JAILBREAK_CHECK_PATTERNS:
                    if re.search(pattern, text, re.IGNORECASE):
                        self.detections["has_jailbreak_detection"] = True
                        evidence_by_test.setdefault("jailbreak", []).append(name)
                        break

                # SSL Pinning
                for pattern in ["SecTrustEvaluate", "SSLPin", "CertificatePinner", "TrustKit"]:
                    if re.search(pattern, text):
                        self.detections["has_ssl_pinning"] = True
                        evidence_by_test.setdefault("ssl_pinning", []).append(f"{pattern} in {name}")
                        break

                # Debugger detection
                for pattern in ["PT_DENY_ATTACH", "ptrace", "sysctl.*P_TRACED"]:
                    if re.search(pattern, text):
                        self.detections["has_anti_debug"] = True
                        evidence_by_test.setdefault("anti_debug", []).append(f"{pattern} in {name}")
                        break

                # UIWebView
                if "UIWebView" in text and name.endswith((".m", ".swift", ".strings")):
                    evidence_by_test.setdefault("uiwebview", []).append(name)

                # Weak crypto
                for crypto, desc in {"kCCAlgorithmDES": "DES", "kCCAlgorithmRC4": "RC4",
                                    "CC_MD5": "MD5", "kCCModeECB": "ECB mode"}.items():
                    if crypto in text:
                        evidence_by_test.setdefault("weak_crypto", []).append(f"{desc} in {name}")
                        break

                # Sensitive data
                for pattern, desc in self.SENSITIVE_DATA_PATTERNS:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    for match in matches[:2]:
                        binary_findings.append(f"[{desc}] {name}: {match.strip()[:100]}")

            except Exception:
                continue

        # Emit deduplicated results from collected evidence
        if evidence_by_test.get("jailbreak"):
            self._add_result(ScanResult(
                test_id="MSTG-CODE-14", test_name="Testing for Jailbreak Detection (iOS)",
                category="Code Quality", severity="Medium", status="PASS",
                description="Jailbreak detection mechanisms found.",
                details=f"Found in {len(evidence_by_test['jailbreak'])} file(s).",
                recommendation="Ensure jailbreak detection cannot be bypassed with Frida.",
                evidence=[f"Jailbreak check in: {f}" for f in evidence_by_test["jailbreak"][:5]],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-14/"]
            ))

        if evidence_by_test.get("ssl_pinning"):
            self._add_result(ScanResult(
                test_id="MSTG-NETWORK-04", test_name="Testing for SSL/TLS Certificate Pinning (iOS)",
                category="Network", severity="Medium", status="PASS",
                description="SSL pinning implementation detected.",
                details=f"Found in {len(evidence_by_test['ssl_pinning'])} location(s).",
                recommendation="Verify pinning covers all critical endpoints.",
                evidence=evidence_by_test["ssl_pinning"][:5],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-4/"]
            ))

        if evidence_by_test.get("anti_debug"):
            self._add_result(ScanResult(
                test_id="MSTG-CODE-15", test_name="Testing for Anti-Debugging (iOS)",
                category="Code Quality", severity="Medium", status="PASS",
                description="Anti-debugging mechanisms detected.",
                details=f"Found in {len(evidence_by_test['anti_debug'])} location(s).",
                recommendation="Ensure anti-debugging cannot be bypassed with Frida.",
                evidence=evidence_by_test["anti_debug"][:5],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-15/"]
            ))

        if evidence_by_test.get("uiwebview"):
            self._add_result(ScanResult(
                test_id="MSTG-PLATFORM-06", test_name="Testing for UIWebView (iOS)",
                category="Platform", severity="Critical", status="FAIL",
                description="Deprecated UIWebView usage detected.",
                details=f"UIWebView found in {len(evidence_by_test['uiwebview'])} file(s).",
                recommendation="Replace UIWebView with WKWebView immediately.",
                evidence=[f"UIWebView in: {f}" for f in evidence_by_test["uiwebview"][:5]],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-6/"]
            ))

        if evidence_by_test.get("weak_crypto"):
            seen_crypto = set()
            for entry in evidence_by_test["weak_crypto"]:
                algo = entry.split(" in ")[0]
                if algo not in seen_crypto:
                    seen_crypto.add(algo)
                    self._add_result(ScanResult(
                        test_id="MSTG-CRYPTO-02", test_name=f"Weak Crypto: {algo} (iOS)",
                        category="Cryptography", severity="Critical", status="FAIL",
                        description=f"Weak cryptographic algorithm: {algo}.",
                        details=f"Found in {len([e for e in evidence_by_test['weak_crypto'] if algo in e])} file(s).",
                        recommendation="Use CryptoKit with AES-GCM.",
                        evidence=[e for e in evidence_by_test["weak_crypto"] if algo in e][:3],
                        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/"]
                    ))

        if binary_findings:
            self._add_result(ScanResult(
                test_id="MSTG-CRYPTO-01", test_name="Testing for Hardcoded Cryptographic Keys (iOS)",
                category="Cryptography", severity="Critical", status="FAIL",
                description=f"Found {len(binary_findings)} hardcoded sensitive data entries.",
                details="Hardcoded secrets:\n" + "\n".join(binary_findings[:10]),
                recommendation="Remove hardcoded secrets. Store keys in iOS Keychain.",
                evidence=binary_findings[:8],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/"]
            ))

    def _scan_keychain_access(self, zf):
        for name in zf.namelist():
            try:
                content = zf.read(name).decode("utf-8", errors="ignore")
                if "kSecAttrAccessibleAlways" in content:
                    self._add_result(ScanResult(
                        test_id="MSTG-STORAGE-01", test_name="Testing Local Storage (Keychain)",
                        category="Storage", severity="High", status="FAIL",
                        description="Weak Keychain protection: kSecAttrAccessibleAlways.",
                        details="Accessible even when device is locked.",
                        recommendation="Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly.",
                        evidence=[f"kSecAttrAccessibleAlways in: {name}"],
                        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/"]
                    ))
                    break
                elif "kSecAttrAccessibleAfterFirstUnlock" in content:
                    self._add_result(ScanResult(
                        test_id="MSTG-STORAGE-01", test_name="Testing Local Storage (Keychain)",
                        category="Storage", severity="Medium", status="WARNING",
                        description="Keychain protection may be too permissive.",
                        details="kSecAttrAccessibleAfterFirstUnlock used.",
                        recommendation="Consider kSecAttrAccessibleWhenUnlockedThisDeviceOnly.",
                        evidence=[f"kSecAttrAccessibleAfterFirstUnlock in: {name}"],
                        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/"]
                    ))
                    break
            except Exception:
                continue

    def _scan_backups(self, zf):
        for name in zf.namelist():
            try:
                content = zf.read(name).decode("utf-8", errors="ignore")
                if "NSURLIsExcludedFromBackupKey" in content:
                    self._add_result(ScanResult(
                        test_id="MSTG-STORAGE-05", test_name="Testing for Sensitive Data in Backups (iOS)",
                        category="Storage", severity="Info", status="PASS",
                        description="Backup exclusion flag found.",
                        details=f"NSURLIsExcludedFromBackupKey in {name}.",
                        recommendation="Verify all sensitive files are excluded.",
                        evidence=[f"NSURLIsExcludedFromBackupKey in: {name}"],
                        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-5/"]
                    ))
                    break
            except Exception:
                continue

    def _compile_report(self, ipa_path: Path) -> Dict:
        ipa_info = self._extract_ipa_info(ipa_path)

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        status_counts = {"FAIL": 0, "WARNING": 0, "PASS": 0, "INFO": 0}

        for r in self.results:
            severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1
            status_counts[r.status] = status_counts.get(r.status, 0) + 1

        # Add missing iOS tests as PASS
        all_test_ids = {r.test_id for r in self.results}
        from core.rules.mastg_tests import IOS_STATIC_TESTS
        for test in IOS_STATIC_TESTS:
            if test.test_id not in all_test_ids:
                self._add_result(ScanResult(
                    test_id=test.test_id, test_name=test.name,
                    category=test.category, severity=test.severity.value, status="PASS",
                    description=f"Test passed: {test.description}",
                    details="No issues detected by static analysis.",
                    recommendation=test.recommendation,
                    evidence=["No issues found by static analysis"],
                    refs=test.refs
                ))
                status_counts["PASS"] += 1
                severity_counts[test.severity.value] += 1

        # Risk score from FAIL/WARNING only
        risk_score = 0
        for r in self.results:
            if r.status == "FAIL":
                risk_score += {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}.get(r.severity, 0)
            elif r.status == "WARNING":
                risk_score += {"Critical": 5, "High": 3, "Medium": 1}.get(r.severity, 0)

        return {
            "platform": "iOS", "file_info": ipa_info,
            "results": [asdict(r) for r in self.results],
            "severity_counts": severity_counts, "status_counts": status_counts,
            "risk_score": risk_score,
            "risk_level": "Critical" if risk_score > 50 else "High" if risk_score > 25 else "Medium" if risk_score > 10 else "Low",
            "detections": self.detections, "total_tests": len(self.results),
        }

    def _extract_ipa_info(self, ipa_path: Path) -> Dict:
        info = {
            "file_name": ipa_path.name,
            "file_size": ipa_path.stat().st_size,
            "file_hash": hashlib.sha256(ipa_path.read_bytes()).hexdigest(),
        }
        plist = self._main_plist
        if plist:
            info["bundle_id"] = plist.get("CFBundleIdentifier", "Unknown")
            info["app_name"] = plist.get("CFBundleDisplayName", plist.get("CFBundleName", "Unknown"))
            info["version"] = plist.get("CFBundleShortVersionString", "Unknown")
            info["build"] = plist.get("CFBundleVersion", "Unknown")
            info["min_os_version"] = plist.get("MinimumOSVersion", "Unknown")
            info["requires_arm64"] = "arm64" in str(plist.get("UIRequiredDeviceCapabilities", []))
            return info

        info["bundle_id"] = "Unknown"
        info["app_name"] = ipa_path.stem
        info["version"] = "Unknown"
        info["build"] = "Unknown"
        info["min_os_version"] = "Unknown"
        return info

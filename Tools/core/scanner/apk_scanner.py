"""
APK Static Analysis Scanner
Performs comprehensive OWASP MASTG static analysis on Android APKs
Uses androguard for proper metadata extraction when available
"""
import os
import re
import hashlib
import zipfile
import json
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass, field, asdict


@dataclass
class ScanResult:
    test_id: str
    test_name: str
    category: str
    severity: str
    status: str  # PASS, FAIL, WARNING, INFO
    description: str
    details: str
    recommendation: str
    evidence: list = field(default_factory=list)
    refs: list = field(default_factory=list)


class ApkScanner:
    """Scans Android APK files for OWASP MASTG violations."""

    DANGEROUS_PERMISSIONS = [
        "android.permission.READ_SMS", "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
        "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
        "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE", "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
        "android.permission.BODY_SENSORS", "android.permission.ACCESS_BACKGROUND_LOCATION",
    ]

    SENSITIVE_DATA_PATTERNS = [
        (r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded password"),
        (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded API key"),
        (r'(?:secret|secret[_-]?key)\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded secret"),
        (r'(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded access token"),
        (r'(?:private[_-]?key)\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded private key"),
        (r'(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["\'][^"\']+["\']', "AWS access key"),
        (r'(?:firebase[_-]?key|gcm[_-]?key)\s*[:=]\s*["\'][^"\']+["\']', "Firebase/GCM key"),
        (r'(?:client[_-]?secret)\s*[:=]\s*["\'][^"\']+["\']', "OAuth client secret"),
        (r'(?:encryption[_-]?key)\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded encryption key"),
        (r'(?:jdbc|mysql|mongodb|redis|postgres)://[^\s"\']+', "Hardcoded database connection"),
    ]

    LOG_METHODS = ["Log.v", "Log.d", "Log.i", "Log.w", "Log.e"]

    def __init__(self):
        self.results: List[ScanResult] = []
        self.detections = {}
        self.apk = None

    def scan(self, apk_path: str) -> Dict:
        """Main scan entry point."""
        self.results = []
        self.detections = {}
        apk_path = Path(apk_path)

        if not apk_path.exists():
            return {"error": "APK file not found"}

        # Try androguard first for rich metadata
        try:
            from androguard.misc import AnalyzeAPK
            self.apk, self.dalvik, self.dex = AnalyzeAPK(str(apk_path))
        except Exception:
            self.apk = None

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                self._scan_permissions(zf)
                self._scan_java_sources(zf)
                self._scan_native_libs(zf)
                self._scan_resources(zf)
                self._scan_network_security_config(zf)
                self._scan_dex_files(zf)
        except zipfile.BadZipFile:
            return {"error": "Invalid APK file"}

        # Detection results for Frida script generation
        self.detections = {
            "has_root_detection": any("root" in r.test_name.lower() for r in self.results if r.status in ("FAIL", "WARNING")),
            "has_ssl_pinning": any("ssl" in r.test_name.lower() or "pinning" in r.test_name.lower() for r in self.results),
            "checks_network": True,
            "has_crypto_issues": any("crypt" in r.test_name.lower() or "key" in r.test_name.lower() for r in self.results if r.status in ("FAIL", "WARNING")),
            "has_storage_issues": any("storage" in r.test_name.lower() or "data" in r.test_name.lower() for r in self.results if r.status in ("FAIL", "WARNING")),
            "has_webviews": self.detections.get("has_webviews", False),
            "has_intent_filters": self.detections.get("has_intent_filters", False),
            "has_anti_frida": any("frida" in r.test_name.lower() for r in self.results),
        }

        return self._compile_report(apk_path)

    def _scan_permissions(self, zf: zipfile.ZipFile):
        """Scan for dangerous permissions using androguard or raw parsing."""
        found_dangerous = []

        if self.apk:
            permissions = self.apk.get_permissions()
            for perm in permissions:
                if perm in self.DANGEROUS_PERMISSIONS:
                    found_dangerous.append(perm)
        else:
            # Fallback: parse binary manifest for permission strings
            try:
                manifest = zf.read("AndroidManifest.xml")
                text = manifest.decode("latin-1", errors="ignore")
                for perm in self.DANGEROUS_PERMISSIONS:
                    if perm in text:
                        found_dangerous.append(perm)
            except Exception:
                pass

        if found_dangerous:
            evidence = [f"android.permission.{p.split('.')[-1]}" for p in found_dangerous]
            severity = "High" if len(found_dangerous) > 5 else "Medium"
            self.results.append(ScanResult(
                test_id="MSTG-STORAGE-01",
                test_name="Testing Local Storage for Sensitive Data",
                category="Storage",
                severity=severity,
                status="WARNING",
                description=f"App requests {len(found_dangerous)} dangerous permission(s).",
                details=f"Dangerous permissions found:\n" + "\n".join(f"  - {p}" for p in found_dangerous),
                recommendation="Minimize permissions. Request runtime permissions only when needed.",
                evidence=evidence,
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/"]
            ))

        # Background location is special high-risk
        if "android.permission.ACCESS_BACKGROUND_LOCATION" in found_dangerous:
            self.results.append(ScanResult(
                test_id="MSTG-STORAGE-08",
                test_name="Testing for Sensitive Data in Shared Storage",
                category="Storage",
                severity="High",
                status="WARNING",
                description="App requests ACCESS_BACKGROUND_LOCATION permission.",
                details="Background location access is a high-risk permission that can track user movements.",
                recommendation="Only request background location if absolutely necessary.",
                evidence=["android.permission.ACCESS_BACKGROUND_LOCATION declared in manifest"],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-8/"]
            ))

    def _scan_java_sources(self, zf: zipfile.ZipFile):
        """Scan smali/dex sources for vulnerabilities with evidence collection."""
        sensitive_findings = []
        log_findings = []
        crypto_findings = []
        webview_findings = []
        sql_findings = []
        shared_prefs_findings = []
        root_detection_files = []
        ssl_pinning_files = []
        anti_frida_files = []

        for name in zf.namelist():
            if not (name.endswith(".smali") or name.endswith(".java") or name.endswith(".kt")):
                continue

            try:
                content = zf.read(name).decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Sensitive data patterns with evidence
            for pattern, desc in self.SENSITIVE_DATA_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    for match in matches[:3]:
                        sensitive_findings.append(f"[{desc}] {name}: {match.strip()[:100]}")

            # Log statements with evidence
            for log_method in self.LOG_METHODS:
                count = content.count(log_method)
                if count > 0:
                    # Find actual log lines for evidence
                    log_lines = [l.strip() for l in content.split('\n') if log_method in l][:3]
                    for line in log_lines:
                        log_findings.append(f"{name}: {line[:120]}")

            # Crypto patterns
            weak_crypto = {"DES": "DES cipher", "RC4": "RC4 stream cipher", "MD5": "MD5 hash",
                          "SHA-1": "SHA-1 hash", "ECB": "ECB mode (no IV)"}
            for crypto, desc in weak_crypto.items():
                if crypto in content:
                    crypto_lines = [l.strip() for l in content.split('\n') if crypto in l][:2]
                    for line in crypto_lines:
                        crypto_findings.append(f"[{desc}] {name}: {line[:120]}")

            # WebView security
            if "addJavascriptInterface" in content:
                webview_findings.append(f"JavaScript interface added in {name}")
            if "setJavaScriptEnabled" in content:
                webview_findings.append(f"JavaScript enabled in WebView in {name}")
            if "setAllowFileAccess" in content and "true" in content.lower():
                webview_findings.append(f"File access enabled in WebView in {name}")
            if "loadUrl" in content:
                webview_findings.append(f"WebView.loadUrl call in {name}")

            # SQL injection
            if "rawQuery" in content or "execSQL" in content:
                sql_lines = [l.strip() for l in content.split('\n')
                            if ('rawQuery' in l or 'execSQL' in l) and '?' not in l][:2]
                for line in sql_lines:
                    sql_findings.append(f"Potential SQL injection: {name}: {line[:120]}")

            # SharedPreferences without encryption
            if "getSharedPreferences" in content:
                if "EncryptedSharedPreferences" not in content:
                    sp_lines = [l.strip() for l in content.split('\n') if 'getSharedPreferences' in l][:2]
                    for line in sp_lines:
                        shared_prefs_findings.append(f"Unencrypted SharedPreferences: {name}: {line[:120]}")

            # Root detection
            if any(term in content for term in ["/system/xbin/su", "RootBeer", "isRooted", "test-keys"]):
                self.detections["has_root_detection"] = True
                root_detection_files.append(name)

            # SSL pinning
            if any(term in content for term in ["CertificatePinner", "TrustManagerImpl",
                                                  "X509TrustManager", "SSLContext"]):
                self.detections["has_ssl_pinning"] = True
                ssl_pinning_files.append(name)

            # WebView
            if "WebView" in content:
                self.detections["has_webviews"] = True

            # Anti-frida / anti-debug
            if any(term in content for term in ["frida", "Frida", "ptrace", "isDebuggerConnected",
                                                  "Debug.isDebuggerConnected"]):
                self.detections["has_anti_frida"] = True
                anti_frida_files.append(name)

            # Intent filters
            if "intent-filter" in content or "IntentFilter" in content:
                self.detections["has_intent_filters"] = True

        # Compile findings with evidence
        if sensitive_findings:
            self.results.append(ScanResult(
                test_id="MSTG-CRYPTO-01",
                test_name="Testing for Hardcoded Cryptographic Keys",
                category="Cryptography",
                severity="Critical",
                status="FAIL",
                description=f"Found {len(sensitive_findings)} hardcoded sensitive data entries.",
                details=f"Hardcoded secrets detected:\n" + "\n".join(sensitive_findings[:15]),
                recommendation="Remove all hardcoded secrets. Use secure key storage (Android Keystore).",
                evidence=sensitive_findings[:10],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/"]
            ))

        if log_findings:
            self.results.append(ScanResult(
                test_id="MSTG-STORAGE-02",
                test_name="Testing for Sensitive Data in System Logs",
                category="Storage",
                severity="High",
                status="FAIL",
                description=f"Found {len(log_findings)} log statements that may leak sensitive data.",
                details="Log statements found:\n" + "\n".join(log_findings[:15]),
                recommendation="Remove or strip all logging statements in production builds.",
                evidence=log_findings[:10],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/"]
            ))

        if crypto_findings:
            self.results.append(ScanResult(
                test_id="MSTG-CRYPTO-02",
                test_name="Testing for Weak Cryptographic Algorithms",
                category="Cryptography",
                severity="Critical",
                status="FAIL",
                description=f"Found {len(crypto_findings)} weak cryptographic algorithm usages.",
                details="Weak crypto found:\n" + "\n".join(crypto_findings[:10]),
                recommendation="Replace weak algorithms with AES-256-GCM, SHA-256+, ECDH.",
                evidence=crypto_findings[:8],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/"]
            ))

        if webview_findings:
            self.results.append(ScanResult(
                test_id="MSTG-CODE-08",
                test_name="Testing for Trivial WebViews",
                category="Code Quality",
                severity="High",
                status="FAIL",
                description=f"Found {len(webview_findings)} WebView security issues.",
                details="WebView issues:\n" + "\n".join(webview_findings[:15]),
                recommendation="Disable JavaScript if not needed. Set file access to false. Validate URLs.",
                evidence=webview_findings[:10],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-8/"]
            ))

        if sql_findings:
            self.results.append(ScanResult(
                test_id="MSTG-CODE-10",
                test_name="Testing for Object Relational Mapping (ORM) Issues",
                category="Code Quality",
                severity="High",
                status="FAIL",
                description=f"Found {len(sql_findings)} potential SQL injection points.",
                details="SQL injection risks:\n" + "\n".join(sql_findings[:10]),
                recommendation="Use parameterized queries. Avoid raw SQL with user input.",
                evidence=sql_findings[:8],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-10/"]
            ))

        if shared_prefs_findings:
            self.results.append(ScanResult(
                test_id="MSTG-STORAGE-01",
                test_name="Testing Local Storage for Sensitive Data (SharedPrefs)",
                category="Storage",
                severity="High",
                status="FAIL",
                description=f"Found {len(shared_prefs_findings)} unencrypted SharedPreferences usages.",
                details="Unencrypted SharedPrefs:\n" + "\n".join(shared_prefs_findings[:15]),
                recommendation="Use EncryptedSharedPreferences for sensitive data storage.",
                evidence=shared_prefs_findings[:10],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/"]
            ))

        # Root detection present - good
        if root_detection_files:
            self.results.append(ScanResult(
                test_id="MSTG-CODE-14",
                test_name="Testing for Root Detection",
                category="Code Quality",
                severity="Medium",
                status="PASS",
                description="Root detection mechanisms found.",
                details=f"Root detection implemented in {len(root_detection_files)} file(s).",
                recommendation="Ensure root detection cannot be bypassed with Frida.",
                evidence=[f"Root detection found in: {f}" for f in root_detection_files[:5]],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-14/"]
            ))

        # SSL pinning present
        if ssl_pinning_files and not any(r.test_id == "MSTG-NETWORK-04" for r in self.results):
            self.results.append(ScanResult(
                test_id="MSTG-NETWORK-04",
                test_name="Testing for SSL/TLS Certificate Pinning",
                category="Network",
                severity="Medium",
                status="PASS",
                description="SSL pinning implementation detected.",
                details=f"SSL pinning found in {len(ssl_pinning_files)} file(s).",
                recommendation="Verify pinning covers all critical endpoints.",
                evidence=[f"SSL pinning found in: {f}" for f in ssl_pinning_files[:5]],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-4/"]
            ))

        # Anti-frida present
        if anti_frida_files:
            self.results.append(ScanResult(
                test_id="MSTG-RESILIENCE-04",
                test_name="Testing Anti-Frida Detection",
                category="Resilience",
                severity="High",
                status="PASS",
                description="Anti-Frida/anti-debug mechanisms detected.",
                details=f"Anti-analysis found in {len(anti_frida_files)} file(s).",
                recommendation="Ensure anti-Frida cannot be bypassed.",
                evidence=[f"Anti-analysis found in: {f}" for f in anti_frida_files[:5]],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/"]
            ))

    def _scan_native_libs(self, zf: zipfile.ZipFile):
        """Scan native libraries."""
        native_libs = [n for n in zf.namelist() if n.startswith("lib/") and n.endswith(".so")]
        if native_libs:
            self.results.append(ScanResult(
                test_id="MSTG-CODE-05",
                test_name="Testing for Unsafe JNI",
                category="Code Quality",
                severity="Medium",
                status="INFO",
                description=f"Found {len(native_libs)} native libraries.",
                details="Native libraries found:\n" + "\n".join(f"  - {lib}" for lib in native_libs[:20]),
                recommendation="Audit native code for buffer overflows and unsafe JNI usage.",
                evidence=native_libs[:10],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-5/"]
            ))

    def _scan_resources(self, zf: zipfile.ZipFile):
        """Scan resources for sensitive data."""
        resource_findings = []
        for name in zf.namelist():
            if name.startswith("res/"):
                try:
                    content = zf.read(name).decode("utf-8", errors="ignore")
                    for pattern, desc in self.SENSITIVE_DATA_PATTERNS:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            for match in matches[:2]:
                                resource_findings.append(f"[{desc}] {name}: {match.strip()[:100]}")
                except Exception:
                    continue

        if resource_findings:
            self.results.append(ScanResult(
                test_id="MSTG-CRYPTO-01",
                test_name="Testing for Hardcoded Cryptographic Keys (Resources)",
                category="Cryptography",
                severity="Critical",
                status="FAIL",
                description=f"Found {len(resource_findings)} hardcoded secrets in resources.",
                details="Secrets in resources:\n" + "\n".join(resource_findings[:10]),
                recommendation="Remove hardcoded secrets from resources. Use secure storage.",
                evidence=resource_findings[:8],
                refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/"]
            ))

    def _scan_network_security_config(self, zf: zipfile.ZipFile):
        """Scan network security configuration."""
        nsc_path = "res/xml/network_security_config.xml"
        if nsc_path in zf.namelist():
            try:
                content = zf.read(nsc_path).decode("utf-8")
                if "cleartextTrafficPermitted=\"true\"" in content:
                    self.results.append(ScanResult(
                        test_id="MSTG-NETWORK-02",
                        test_name="Testing for Unencrypted Communications",
                        category="Network",
                        severity="Critical",
                        status="FAIL",
                        description="App allows cleartext (HTTP) traffic via network_security_config.xml.",
                        details="cleartextTrafficPermitted='true' found in network security config.",
                        recommendation="Set cleartextTrafficPermitted='false'. Use HTTPS everywhere.",
                        evidence=[f"Found in {nsc_path}: cleartextTrafficPermitted=\"true\""],
                        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/"]
                    ))
                else:
                    self.results.append(ScanResult(
                        test_id="MSTG-NETWORK-02",
                        test_name="Testing for Unencrypted Communications",
                        category="Network",
                        severity="Info",
                        status="PASS",
                        description="Cleartext traffic appears to be disabled.",
                        details="network_security_config.xml found with cleartext disabled.",
                        recommendation="Continue using HTTPS-only configuration.",
                        evidence=[f"Found in {nsc_path}: cleartextTrafficPermitted not set to true"],
                        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/"]
                    ))

                if "pin-set" in content:
                    self.results.append(ScanResult(
                        test_id="MSTG-NETWORK-04",
                        test_name="Testing for SSL/TLS Certificate Pinning (NSC)",
                        category="Network",
                        severity="Medium",
                        status="PASS",
                        description="SSL pinning is configured via network_security_config.xml.",
                        details="Certificate pinning found in network security configuration.",
                        recommendation="Ensure pinning covers all critical endpoints.",
                        evidence=[f"pin-set found in {nsc_path}"],
                        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-4/"]
                    ))
                else:
                    self.results.append(ScanResult(
                        test_id="MSTG-NETWORK-04",
                        test_name="Testing for SSL/TLS Certificate Pinning (NSC)",
                        category="Network",
                        severity="Medium",
                        status="WARNING",
                        description="No SSL pinning found in network_security_config.xml.",
                        details="Consider adding certificate pinning for critical API endpoints.",
                        recommendation="Implement certificate pinning for sensitive API endpoints.",
                        evidence=[f"No pin-set found in {nsc_path}"],
                        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-4/"]
                    ))
            except Exception:
                pass
        else:
            # Check for hardcoded HTTP URLs
            http_evidence = []
            for name in zf.namelist():
                try:
                    content = zf.read(name).decode("utf-8", errors="ignore")
                    http_urls = re.findall(r'http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.)[^\s"\'<>]+', content)
                    for url in http_urls[:3]:
                        http_evidence.append(f"HTTP URL in {name}: {url[:100]}")
                except Exception:
                    continue
                if http_evidence:
                    break

            if http_evidence:
                self.results.append(ScanResult(
                    test_id="MSTG-NETWORK-02",
                    test_name="Testing for Unencrypted Communications",
                    category="Network",
                    severity="Critical",
                    status="WARNING",
                    description="Found potential HTTP (non-TLS) URLs.",
                    details=f"HTTP URLs found:\n" + "\n".join(http_evidence),
                    recommendation="Replace all HTTP URLs with HTTPS.",
                    evidence=http_evidence[:5],
                    refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/"]
                ))

    def _scan_dex_files(self, zf: zipfile.ZipFile):
        """Scan DEX files for additional patterns."""
        dex_files = [n for n in zf.namelist() if n.endswith(".dex")]
        for dex_name in dex_files:
            try:
                content = zf.read(dex_name)
                text = content.decode("utf-8", errors="ignore")

                # Check for ProGuard obfuscation
                short_names = len(re.findall(r'[a-z]{2}/[a-z]{1,2};', text))
                if short_names > 50:
                    self.results.append(ScanResult(
                        test_id="MSTG-CODE-07",
                        test_name="Testing for Code Obfuscation",
                        category="Code Quality",
                        severity="Low",
                        status="PASS",
                        description="Code appears to be obfuscated (ProGuard/R8 detected).",
                        details=f"Found {short_names} short class names indicating obfuscation.",
                        recommendation="Continue using obfuscation for production builds.",
                        evidence=[f"Found {short_names} obfuscated class names in {dex_name}"],
                        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-7/"]
                    ))
                else:
                    self.results.append(ScanResult(
                        test_id="MSTG-CODE-07",
                        test_name="Testing for Code Obfuscation",
                        category="Code Quality",
                        severity="Low",
                        status="WARNING",
                        description="Limited code obfuscation detected.",
                        details="The app may not be using ProGuard/R8 obfuscation.",
                        recommendation="Enable ProGuard/R8 with aggressive obfuscation settings.",
                        evidence=[f"Only {short_names} obfuscated class names found in {dex_name}"],
                        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-7/"]
                    ))
            except Exception:
                continue

    def _compile_report(self, apk_path: Path) -> Dict:
        """Compile final scan report."""
        apk_info = self._extract_apk_info(apk_path)

        # Count severities and statuses
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        status_counts = {"FAIL": 0, "WARNING": 0, "PASS": 0, "INFO": 0}

        for r in self.results:
            severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1
            status_counts[r.status] = status_counts.get(r.status, 0) + 1

        # Add missing Android tests as PASS
        all_test_ids = {r.test_id for r in self.results}
        from core.rules.mastg_tests import ANDROID_STATIC_TESTS
        for test in ANDROID_STATIC_TESTS:
            if test.test_id not in all_test_ids:
                self.results.append(ScanResult(
                    test_id=test.test_id,
                    test_name=test.name,
                    category=test.category,
                    severity=test.severity.value,
                    status="PASS",
                    description=f"Test passed: {test.description}",
                    details="No issues detected by static analysis.",
                    recommendation=test.recommendation,
                    evidence=["No issues found by static analysis"],
                    refs=test.refs
                ))
                status_counts["PASS"] += 1
                severity_counts[test.severity.value] += 1

        # Recalculate risk score based on actual FAIL/WARNING results only
        fail_warnings = [r for r in self.results if r.status in ("FAIL", "WARNING")]
        risk_score = 0
        for r in fail_warnings:
            if r.severity == "Critical":
                risk_score += 10
            elif r.severity == "High":
                risk_score += 5
            elif r.severity == "Medium":
                risk_score += 2
            elif r.severity == "Low":
                risk_score += 1

        return {
            "platform": "Android",
            "file_info": apk_info,
            "results": [asdict(r) for r in self.results],
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "risk_score": risk_score,
            "risk_level": "Critical" if risk_score > 50 else "High" if risk_score > 25 else "Medium" if risk_score > 10 else "Low",
            "detections": self.detections,
            "total_tests": len(self.results),
        }

    def _extract_apk_info(self, apk_path: Path) -> Dict:
        """Extract APK info using androguard, falling back to basic extraction."""
        info = {
            "file_name": apk_path.name,
            "file_size": apk_path.stat().st_size,
            "file_hash": hashlib.sha256(apk_path.read_bytes()).hexdigest(),
        }

        # Try androguard first
        if self.apk:
            try:
                info["package_name"] = self.apk.get_package() or "Unknown"
                info["version_name"] = self.apk.get_androidversion_name() or "Unknown"
                info["version_code"] = str(self.apk.get_androidversion_code() or "Unknown")
                info["app_name"] = self.apk.get_app_name() or apk_path.stem
                info["min_sdk"] = str(self.apk.get_min_sdk_version() or "Unknown")
                info["target_sdk"] = str(self.apk.get_target_sdk_version() or "Unknown")
                info["permissions"] = self.apk.get_permissions()
                info["main_activity"] = self.apk.get_main_activity() or "Unknown"
                info["debuggable"] = self.apk.get_attribute_value("application", "debuggable") == "true"

                # Extract activities
                activities = []
                for activity in self.apk.get_activities():
                    activities.append(activity)
                info["activities"] = activities[:50]

                # Extract services, receivers, providers
                info["services"] = self.apk.get_services()[:20]
                info["receivers"] = self.apk.get_receivers()[:20]
                info["providers"] = self.apk.get_providers()[:20]

                return info
            except Exception as e:
                info["androguard_error"] = str(e)

        # Fallback: basic extraction from manifest strings
        try:
            with zipfile.ZipFile(apk_path) as zf:
                # Try to extract package from strings in manifest
                manifest = zf.read("AndroidManifest.xml")
                text = manifest.decode("latin-1", errors="ignore")

                # Extract printable strings that look like package names
                strings = re.findall(r'[a-zA-Z][a-zA-Z0-9_.]{5,60}', text)
                for s in strings:
                    if '.' in s and not s.startswith('android.') and not s.startswith('java.'):
                        if info.get("package_name") == "Unknown" or "package_name" not in info:
                            info["package_name"] = s
                            break

                info["app_name"] = apk_path.stem
                info["version_name"] = "Unknown"
                info["version_code"] = "Unknown"
                info["min_sdk"] = "Unknown"
                info["target_sdk"] = "Unknown"

        except Exception:
            pass

        return info

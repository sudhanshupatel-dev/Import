"""
OWASP MASTG (Mobile Application Security Testing Guide) Rules Engine
Based on OWASP MASTG v1 (Jan 2024+)
Covers Android & iOS static analysis tests
"""
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
import re


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Platform(Enum):
    ANDROID = "Android"
    IOS = "iOS"
    BOTH = "Both"


@dataclass
class MastgTest:
    test_id: str
    name: str
    category: str
    platform: Platform
    severity: Severity
    description: str
    recommendation: str
    frida_scripts: list = field(default_factory=list)
    refs: list = field(default_factory=list)


# ─── Android MASTG Static Tests ──────────────────────────────────────

ANDROID_STATIC_TESTS = [
    # MSTG-STORAGE
    MastgTest(
        test_id="MSTG-STORAGE-01",
        name="Testing Local Storage for Sensitive Data",
        category="Storage",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if app stores sensitive data in SharedPreferences, SQLite, Realm, or other local storage without encryption.",
        recommendation="Use EncryptedSharedPreferences or encrypt data before storing. Avoid storing sensitive data in plaintext.",
        frida_scripts=["root_detection", "storage_monitor"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-02",
        name="Testing for Sensitive Data in System Logs",
        category="Storage",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if app logs sensitive information (passwords, tokens, PII) to system logs accessible by other apps.",
        recommendation="Remove all Log.d/Log.v statements in production. Use ProGuard/R8 to strip logging.",
        frida_scripts=["log_monitor"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-03",
        name="Testing for Sensitive Data in Clipboard",
        category="Storage",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if sensitive data can be copied to clipboard and accessed by other applications.",
        recommendation="Disable clipboard for sensitive fields using custom buffers.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-3/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-04",
        name="Testing for Sensitive Data in Temp Files",
        category="Storage",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check for sensitive data written to temporary files or cache directories.",
        recommendation="Delete temp files after use. Don't store sensitive data in temp files.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-4/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-05",
        name="Testing for Sensitive Data Backups",
        category="Storage",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if allowBackup is enabled, which allows attackers to extract app data via ADB backup.",
        recommendation="Set android:allowBackup='false' in AndroidManifest.xml.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-5/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-06",
        name="Testing for Sensitive Data in Keyboard Cache",
        category="Storage",
        platform=Platform.ANDROID,
        severity=Severity.LOW,
        description="Check if sensitive input fields have autocomplete/keyboard cache enabled.",
        recommendation="Set android:inputType='textNoSuggestions' and android:completionHint for sensitive fields.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-6/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-07",
        name="Testing for Exposed IPC Interfaces",
        category="Storage",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if exported Content Providers, Services, Broadcast Receivers, or Activities expose sensitive data.",
        recommendation="Set exported='false' for internal components. Use permissions for exported components.",
        frida_scripts=["ipc_monitor"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-7/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-08",
        name="Testing for Sensitive Data in Shared Storage",
        category="Storage",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if sensitive data is stored in external shared storage accessible by other apps.",
        recommendation="Use app-specific storage (getExternalFilesDir) or internal storage.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-8/"]
    ),

    # MSTG-CRYPTO
    MastgTest(
        test_id="MSTG-CRYPTO-01",
        name="Testing for Hardcoded Cryptographic Keys",
        category="Cryptography",
        platform=Platform.ANDROID,
        severity=Severity.CRITICAL,
        description="Check for hardcoded encryption keys, IVs, or secrets in the source code or resources.",
        recommendation="Store keys in Android Keystore. Never hardcode keys.",
        frida_scripts=["key_extraction"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/"]
    ),
    MastgTest(
        test_id="MSTG-CRYPTO-02",
        name="Testing for Weak Cryptographic Algorithms",
        category="Cryptography",
        platform=Platform.ANDROID,
        severity=Severity.CRITICAL,
        description="Check for use of broken algorithms (MD5, SHA1, DES, RC4, ECB mode).",
        recommendation="Use AES-256-GCM, SHA-256+ for hashing, ECDH for key exchange.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/"]
    ),
    MastgTest(
        test_id="MSTG-CRYPTO-03",
        name="Testing for Insecure Cryptographic Implementation",
        category="Cryptography",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check for custom crypto implementations, improper IV usage, or non-random salts.",
        recommendation="Use standard crypto libraries (BouncyCastle, Tink). Generate random IVs/salts.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-3/"]
    ),
    MastgTest(
        test_id="MSTG-CRYPTO-04",
        name="Testing for Insufficiently Protected Keys",
        category="Cryptography",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if cryptographic keys are properly protected at rest (not in SharedPreferences/SQLite).",
        recommendation="Use Android Keystore or hardware-backed keystores.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-4/"]
    ),

    # MSTG-AUTH
    MastgTest(
        test_id="MSTG-AUTH-01",
        name="Testing for Local Authentication",
        category="Authentication",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if biometric/PIN authentication is implemented correctly with FingerprintManager/BiometricPrompt.",
        recommendation="Use BiometricPrompt API. Don't store biometric data locally.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/"]
    ),
    MastgTest(
        test_id="MSTG-AUTH-02",
        name="Testing for Network Authentication",
        category="Authentication",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if authentication tokens are properly handled (expiry, refresh, storage).",
        recommendation="Use OAuth 2.0 / OIDC. Store tokens in Android Keystore. Implement token refresh.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-2/"]
    ),
    MastgTest(
        test_id="MSTG-AUTH-03",
        name="Testing for Re-Authentication",
        category="Authentication",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if sensitive operations require re-authentication.",
        recommendation="Require biometric/PIN for sensitive operations (payment, profile change).",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-3/"]
    ),
    MastgTest(
        test_id="MSTG-AUTH-04",
        name="Testing for Biometric Authentication",
        category="Authentication",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if biometric authentication is implemented with proper fallback and error handling.",
        recommendation="Use AndroidX Biometric library. Implement proper fallback for sensor failures.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-4/"]
    ),
    MastgTest(
        test_id="MSTG-AUTH-05",
        name="Testing for Biometric Authentication Bypass",
        category="Authentication",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if biometric can be bypassed via Frida hook or accessibility service.",
        recommendation="Implement liveness detection. Use server-side validation of biometric result.",
        frida_scripts=["biometric_bypass"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-5/"]
    ),
    MastgTest(
        test_id="MSTG-AUTH-06",
        name="Testing for Two-Factor Authentication",
        category="Authentication",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if 2FA is implemented and how it handles enrollment flow.",
        recommendation="Implement TOTP or push-based 2FA. Don't allow bypass during re-login.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-6/"]
    ),
    MastgTest(
        test_id="MSTG-AUTH-07",
        name="Testing for Sensitive Actions Authentication",
        category="Authentication",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if sensitive actions (delete account, change password, payment) require fresh authentication.",
        recommendation="Require password/biometric confirmation before destructive actions.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-7/"]
    ),
    MastgTest(
        test_id="MSTG-AUTH-08",
        name="Testing for Stateful Authentication",
        category="Authentication",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if session is properly invalidated on logout and device de-registration.",
        recommendation="Invalidate all tokens on logout. Implement device management.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-8/"]
    ),
    MastgTest(
        test_id="MSTG-AUTH-09",
        name="Testing for Session Management",
        category="Authentication",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check session timeout, renewal, and invalidation mechanisms.",
        recommendation="Implement session timeout. Renew tokens before expiry. Invalidate server-side on logout.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-9/"]
    ),
    MastgTest(
        test_id="MSTG-AUTH-10",
        name="Testing for Logout Functionality",
        category="Authentication",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if logout properly clears tokens, sessions, and cached sensitive data.",
        recommendation="Clear all tokens, session data, and cached credentials on logout.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-10/"]
    ),

    # MSTG-NETWORK
    MastgTest(
        test_id="MSTG-NETWORK-01",
        name="Testing for Data Exfiltration",
        category="Network",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if app sends excessive data to servers or third-party services.",
        recommendation="Audit all network calls. Minimize data sent. Review third-party SDKs.",
        frida_scripts=["network_monitor"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/"]
    ),
    MastgTest(
        test_id="MSTG-NETWORK-02",
        name="Testing for Unencrypted Communications",
        category="Network",
        platform=Platform.ANDROID,
        severity=Severity.CRITICAL,
        description="Check if app uses HTTP instead of HTTPS. Check network_security_config.xml.",
        recommendation="Use HTTPS everywhere. Configure network_security_config.xml with Certificate Pinning.",
        frida_scripts=["ssl_pinning_test"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/"]
    ),
    MastgTest(
        test_id="MSTG-NETWORK-03",
        name="Testing for Unencrypted Sensitive Data Transmission",
        category="Network",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if sensitive data (credentials, tokens) is sent over unencrypted channels.",
        recommendation="Never send sensitive data over HTTP. Use TLS 1.2+ with strong cipher suites.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-3/"]
    ),
    MastgTest(
        test_id="MSTG-NETWORK-04",
        name="Testing for SSL/TLS Certificate Pinning",
        category="Network",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if SSL/TLS certificate pinning is implemented correctly.",
        recommendation="Implement certificate pinning using Network Security Config or OkHttp CertificatePinner.",
        frida_scripts=["ssl_pinning_bypass"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-4/"]
    ),
    MastgTest(
        test_id="MSTG-NETWORK-05",
        name="Testing for Outdated TLS Versions",
        category="Network",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if app supports TLS 1.0/1.1 or weak cipher suites.",
        recommendation="Enforce TLS 1.2+ minimum. Use strong cipher suites.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-5/"]
    ),
    MastgTest(
        test_id="MSTG-NETWORK-06",
        name="Testing for Mutual TLS",
        category="Network",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if mTLS is implemented for high-security communications.",
        recommendation="Implement mTLS for API calls involving sensitive operations.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-6/"]
    ),
    MastgTest(
        test_id="MSTG-NETWORK-07",
        name="Testing for Weak TLS Certificates",
        category="Network",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if certificate is valid, not self-signed, and uses strong key (RSA 2048+ or ECC).",
        recommendation="Use valid certificates from trusted CAs. Use RSA 2048+ or ECC P-256+.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-7/"]
    ),

    # MSTG-PLATFORM
    MastgTest(
        test_id="MSTG-PLATFORM-01",
        name="Testing for URL Handling",
        category="Platform",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if app registers intent filters that could be hijacked (deep links, custom schemes).",
        recommendation="Validate all incoming URLs. Use verified deep links. Don't auto-execute based on URL params.",
        frida_scripts=["intent_monitor"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/"]
    ),
    MastgTest(
        test_id="MSTG-PLATFORM-02",
        name="Testing for Custom URL Schemes",
        category="Platform",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if custom URL schemes handle sensitive data in parameters exposed to other apps.",
        recommendation="Don't pass sensitive data in URL scheme parameters. Use Universal Links with App Links.",
        frida_scripts=["scheme_interceptor"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/"]
    ),
    MastgTest(
        test_id="MSTG-PLATFORM-03",
        name="Testing for Intent Sniffing",
        category="Platform",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if sensitive data is passed via Intents that can be intercepted.",
        recommendation="Use explicit Intents. Validate Intent data. Don't expose sensitive data via implicit Intents.",
        frida_scripts=["intent_sniffer"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/"]
    ),
    MastgTest(
        test_id="MSTG-PLATFORM-04",
        name="Testing for Tapjacking",
        category="Platform",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if app is vulnerable to tapjacking/overlay attacks on sensitive screens.",
        recommendation="Use android:filterTouchesWhenObscured='true' on sensitive views.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-4/"]
    ),
    MastgTest(
        test_id="MSTG-PLATFORM-05",
        name="Testing for Play Integrity",
        category="Platform",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if app uses Play Integrity API / SafetyNet for device attestation.",
        recommendation="Use Play Integrity API for device attestation before sensitive operations.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-5/"]
    ),
    MastgTest(
        test_id="MSTG-PLATFORM-06",
        name="Testing for Screen Overlay",
        category="Platform",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if app detects/prevents screen overlay attacks.",
        recommendation="Implement overlay detection. Use SYSTEM_ALERT_WINDOW permission checks.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-6/"]
    ),
    MastgTest(
        test_id="MSTG-PLATFORM-07",
        name="Testing for Keychain Access Groups",
        category="Platform",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if content providers use proper access controls and permissions.",
        recommendation="Set permissions on providers. Validate calling package. Use grantUriPermissions carefully.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-7/"]
    ),

    # MSTG-CODE
    MastgTest(
        test_id="MSTG-CODE-01",
        name="Testing for Debugging Symbols",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if app has debugging symbols enabled (debuggable flag).",
        recommendation="Set android:debuggable='false'. Strip symbols with ProGuard/R8.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-02",
        name="Testing for Debugging Code",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check for debugging code, test endpoints, or backdoors left in production builds.",
        recommendation="Remove all debug code. Use build variants for debug/release.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-2/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-03",
        name="Testing for Exception Handling",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.LOW,
        description="Check if app catches exceptions properly without leaking sensitive information.",
        recommendation="Catch specific exceptions. Don't log sensitive data in catch blocks.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-04",
        name="Testing for Memory Management",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.LOW,
        description="Check for proper memory management (cursor closing, stream closing).",
        recommendation="Use try-with-resources. Close all resources in finally blocks.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-05",
        name="Testing for Unsafe JNI",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check for unsafe JNI usage that could lead to memory corruption or code injection.",
        recommendation="Validate all JNI inputs. Use proper bounds checking.",
        frida_scripts=["jni_monitor"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-5/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-06",
        name="Testing for Input Validation",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if app validates input from all sources (intents, content providers, user input).",
        recommendation="Validate all input. Use ContentProvider.query with selection args.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-6/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-07",
        name="Testing for Code Obfuscation",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.LOW,
        description="Check if code is obfuscated (ProGuard/R8).",
        recommendation="Enable ProGuard/R8 with aggressive settings.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-7/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-08",
        name="Testing for Trivial WebViews",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check for WebViews with JavaScript enabled, file access, or dangerous intent handlers.",
        recommendation="Disable JavaScript if not needed. Set file access to false. Validate all URLs.",
        frida_scripts=["webview_monitor"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-8/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-09",
        name="Testing for Broken Object Level Authorization",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if API endpoints properly validate object-level access.",
        recommendation="Implement server-side object-level authorization checks.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-9/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-10",
        name="Testing for Object Relational Mapping (ORM) Issues",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check for SQL injection in ORM or raw queries.",
        recommendation="Use parameterized queries. Avoid raw SQL with user input.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-10/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-11",
        name="Testing for Excessive Network Requests",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.LOW,
        description="Check if app makes excessive requests that could be used for tracking.",
        recommendation="Minimize third-party requests. Audit all network endpoints.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-11/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-12",
        name="Testing for Sensitive Data in Debug Mode",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if app behaves differently or leaks data in debug/development mode.",
        recommendation="Guard all debug functionality with BuildConfig.DEBUG checks.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-12/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-13",
        name="Testing for Local Encryption Keys",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if encryption keys are properly generated and stored using secure random.",
        recommendation="Use SecureRandom for key generation. Store in Android Keystore.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-13/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-14",
        name="Testing for Root Detection",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if app implements root detection and how effective it is.",
        recommendation="Implement multi-layered root detection. Combine file checks, su binary checks, SafetyNet.",
        frida_scripts=["root_detection_test"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-14/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-15",
        name="Testing for Debugger Detection",
        category="Code Quality",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if app detects and prevents debugger attachment.",
        recommendation="Use ptrace, isDebuggerConnected, and timing checks.",
        frida_scripts=["debugger_detection"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-15/"]
    ),

    # MSTG-RESILIENCE
    MastgTest(
        test_id="MSTG-RESILIENCE-01",
        name="Testing Anti-Reverse Engineering",
        category="Resilience",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if app has anti-tampering and anti-reverse engineering measures.",
        recommendation="Implement integrity checks, signature verification, and anti-debugging.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/"]
    ),
    MastgTest(
        test_id="MSTG-RESILIENCE-02",
        name="Testing for Root Detection Bypass",
        category="Resilience",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if root detection can be bypassed with common tools (Frida, Xposed).",
        recommendation="Use multiple detection methods. Check for Frida/Xposed artifacts.",
        frida_scripts=["root_bypass_test"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/"]
    ),
    MastgTest(
        test_id="MSTG-RESILIENCE-03",
        name="Testing for Code Integrity Checks",
        category="Resilience",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if app verifies its own integrity (checksum, signature verification).",
        recommendation="Implement APK signature verification. Check file integrity at runtime.",
        frida_scripts=["tamper_detection"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/"]
    ),
    MastgTest(
        test_id="MSTG-RESILIENCE-04",
        name="Testing Anti-Frida Detection",
        category="Resilience",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if app detects Frida agent and blocks hooking attempts.",
        recommendation="Check for Frida ports, library injection, and dynamic analysis indicators.",
        frida_scripts=["frida_detection_test"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/"]
    ),
    MastgTest(
        test_id="MSTG-RESILIENCE-05",
        name="Testing for Anti-Hooking",
        category="Resilience",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if app detects function hooking frameworks (Xposed, Substrate).",
        recommendation="Check for hooking framework artifacts. Use native integrity checks.",
        frida_scripts=["hook_detection"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-5/"]
    ),
    MastgTest(
        test_id="MSTG-RESILIENCE-06",
        name="Testing for Anti-Repackaging",
        category="Resilience",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if app verifies its signature at runtime to detect repackaging.",
        recommendation="Verify APK signature at runtime. Implement tamper detection.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-6/"]
    ),
    MastgTest(
        test_id="MSTG-RESILIENCE-07",
        name="Testing for Anti-Tampering",
        category="Resilience",
        platform=Platform.ANDROID,
        severity=Severity.MEDIUM,
        description="Check if app detects file modification and tampering attempts.",
        recommendation="Implement file integrity checks. Use checksums for critical files.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-7/"]
    ),
    MastgTest(
        test_id="MSTG-RESILIENCE-08",
        name="Testing for Anti-Dynamic Analysis",
        category="Resilience",
        platform=Platform.ANDROID,
        severity=Severity.HIGH,
        description="Check if app detects dynamic analysis tools (Frida, Cydia Substrate, Xposed).",
        recommendation="Implement comprehensive anti-dynamic analysis with multiple detection layers.",
        frida_scripts=["dynamic_analysis_detection"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-8/"]
    ),
]


# ─── iOS MASTG Static Tests ──────────────────────────────────────────

IOS_STATIC_TESTS = [
    # MSTG-STORAGE (iOS)
    MastgTest(
        test_id="MSTG-STORAGE-01",
        name="Testing Local Storage for Sensitive Data (Keychain)",
        category="Storage",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if app stores sensitive data in Keychain with proper protection levels.",
        recommendation="Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly or stricter protection.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-02",
        name="Testing for Sensitive Data in System Logs (iOS)",
        category="Storage",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if NSLog/OSLog contains sensitive data accessible via device logs.",
        recommendation="Use os_log with privacy flags. Remove NSLog in production.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-03",
        name="Testing for Sensitive Data in Clipboard (iOS)",
        category="Storage",
        platform=Platform.IOS,
        severity=Severity.MEDIUM,
        description="Check if sensitive data is copied to clipboard accessible by other apps.",
        recommendation="Use UIBoard.generalPasteboard.string = nil after reading. Set expiration.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-3/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-05",
        name="Testing for Sensitive Data in Backups (iOS)",
        category="Storage",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if iTunes/iCloud backup includes sensitive data.",
        recommendation="Mark sensitive files with NSURLIsExcludedFromBackupKey. Set backup exclusion flags.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-5/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-06",
        name="Testing for Sensitive Data in Keyboard Cache (iOS)",
        category="Storage",
        platform=Platform.IOS,
        severity=Severity.LOW,
        description="Check if sensitive input fields cache data in keyboard dictionaries.",
        recommendation="Set secureTextEntry for sensitive fields. Clear keyboard caches.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-6/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-07",
        name="Testing for Exposed IPC Mechanisms (iOS)",
        category="Storage",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if app registers URL schemes or exposes data via App Extensions unsafely.",
        recommendation="Validate all URL scheme inputs. Use Universal Links instead of custom schemes.",
        frida_scripts=["url_scheme_interceptor"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-7/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-08",
        name="Testing for Sensitive Data in Plists",
        category="Storage",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check for sensitive data in plist files, UserDefaults, or SQLite databases.",
        recommendation="Never store sensitive data in plaintext plists. Use Keychain for sensitive values.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-8/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-09",
        name="Testing for Sensitive Data in Snapshots",
        category="Storage",
        platform=Platform.IOS,
        severity=Severity.MEDIUM,
        description="Check if app renders sensitive data in screenshots or app switcher previews.",
        recommendation="Set UIApplication.shared.keyWindow?.rootViewController?.view.layer.snapshotView.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-9/"]
    ),
    MastgTest(
        test_id="MSTG-STORAGE-10",
        name="Testing for Sensitive Data in Device Information",
        category="Storage",
        platform=Platform.IOS,
        severity=Severity.MEDIUM,
        description="Check if app accesses and logs device identifiers (UDID, IMEI) unnecessarily.",
        recommendation="Don't use UDID/IMEI. Use identifierForVendor if needed.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-10/"]
    ),

    # MSTG-CRYPTO (iOS)
    MastgTest(
        test_id="MSTG-CRYPTO-01",
        name="Testing for Hardcoded Cryptographic Keys (iOS)",
        category="Cryptography",
        platform=Platform.IOS,
        severity=Severity.CRITICAL,
        description="Check for hardcoded keys in binary, plists, or source code.",
        recommendation="Store keys in iOS Keychain. Generate keys using Security framework.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/"]
    ),
    MastgTest(
        test_id="MSTG-CRYPTO-02",
        name="Testing for Weak Cryptographic Algorithms (iOS)",
        category="Cryptography",
        platform=Platform.IOS,
        severity=Severity.CRITICAL,
        description="Check for use of weak algorithms (MD5, SHA1, DES) via CommonCrypto or OpenSSL.",
        recommendation="Use CryptoKit framework with AES-GCM, SHA-256+.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/"]
    ),
    MastgTest(
        test_id="MSTG-CRYPTO-03",
        name="Testing for Insecure Crypto Implementation (iOS)",
        category="Cryptography",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check for improper use of CommonCrypto (wrong modes, missing IVs, ECB mode).",
        recommendation="Use CryptoKit. Use kCCModeGCM for authenticated encryption.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-3/"]
    ),
    MastgTest(
        test_id="MSTG-CRYPTO-04",
        name="Testing for Keychain Key Protection (iOS)",
        category="Cryptography",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if Keychain items use proper access control (biometric, passcode).",
        recommendation="Use kSecAttrAccessControl with SecAccessControlCreateWithFlags.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-4/"]
    ),

    # MSTG-AUTH (iOS)
    MastgTest(
        test_id="MSTG-AUTH-01",
        name="Testing for Local Authentication (Face ID/Touch ID)",
        category="Authentication",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if biometric authentication is implemented correctly using LAContext.",
        recommendation="Use LAContext with proper error handling and fallback.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/"]
    ),
    MastgTest(
        test_id="MSTG-AUTH-02",
        name="Testing for Network Authentication (iOS)",
        category="Authentication",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if authentication tokens are properly stored in Keychain.",
        recommendation="Store auth tokens in Keychain with appropriate protection levels.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-2/"]
    ),
    MastgTest(
        test_id="MSTG-AUTH-05",
        name="Testing for Biometric Bypass (iOS)",
        category="Authentication",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if biometric auth can be bypassed via Frida or device manipulation.",
        recommendation="Implement server-side validation of biometric results.",
        frida_scripts=["ios_biometric_bypass"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-5/"]
    ),
    MastgTest(
        test_id="MSTG-AUTH-09",
        name="Testing for Session Management (iOS)",
        category="Authentication",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check session timeout and renewal mechanisms for iOS app.",
        recommendation="Implement proper session lifecycle with token refresh.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-9/"]
    ),

    # MSTG-NETWORK (iOS)
    MastgTest(
        test_id="MSTG-NETWORK-02",
        name="Testing for Unencrypted Communications (iOS)",
        category="Network",
        platform=Platform.IOS,
        severity=Severity.CRITICAL,
        description="Check if app uses HTTP instead of HTTPS. Check App Transport Security settings.",
        recommendation="Set NSAppTransportSecurity to require HTTPS. Configure exception domains properly.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/"]
    ),
    MastgTest(
        test_id="MSTG-NETWORK-04",
        name="Testing for SSL/TLS Certificate Pinning (iOS)",
        category="Network",
        platform=Platform.IOS,
        severity=Severity.MEDIUM,
        description="Check if SSL pinning is implemented via URLSession delegate or TrustKit.",
        recommendation="Implement SSL pinning with URLSessionDelegate or TrustKit.",
        frida_scripts=["ios_ssl_pinning_bypass"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-4/"]
    ),
    MastgTest(
        test_id="MSTG-NETWORK-05",
        name="Testing for Outdated TLS (iOS)",
        category="Network",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if app allows connection to servers with weak TLS configurations.",
        recommendation="Enforce TLS 1.2+. Use NSURLSession with strong security settings.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-5/"]
    ),

    # MSTG-PLATFORM (iOS)
    MastgTest(
        test_id="MSTG-PLATFORM-01",
        name="Testing for URL Handling (iOS)",
        category="Platform",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if app registers custom URL schemes or Universal Links unsafely.",
        recommendation="Validate all URL scheme inputs. Use Universal Links for deep linking.",
        frida_scripts=["ios_url_handler"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/"]
    ),
    MastgTest(
        test_id="MSTG-PLATFORM-02",
        name="Testing for Custom URL Schemes (iOS)",
        category="Platform",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if custom URL schemes expose sensitive data or execute commands.",
        recommendation="Don't pass sensitive data in URL schemes. Validate all parameters.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/"]
    ),
    MastgTest(
        test_id="MSTG-PLATFORM-03",
        name="Testing for Pasteboard (iOS)",
        category="Platform",
        platform=Platform.IOS,
        severity=Severity.MEDIUM,
        description="Check if sensitive data is placed in the pasteboard accessible by other apps.",
        recommendation="Clear pasteboard after use. Don't put sensitive data in shared pasteboard.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/"]
    ),
    MastgTest(
        test_id="MSTG-PLATFORM-05",
        name="Testing for App Extension Data Sharing (iOS)",
        category="Platform",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if app extensions share data unsafely with the main app.",
        recommendation="Use App Groups with proper entitlements. Don't share sensitive data.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-5/"]
    ),
    MastgTest(
        test_id="MSTG-PLATFORM-06",
        name="Testing for UIWebView (iOS)",
        category="Platform",
        platform=Platform.IOS,
        severity=Severity.CRITICAL,
        description="Check if app uses deprecated UIWebView (has unfixed security vulnerabilities).",
        recommendation="Replace UIWebView with WKWebView. UIWebView is deprecated and insecure.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-6/"]
    ),
    MastgTest(
        test_id="MSTG-PLATFORM-07",
        name="Testing for WKWebView Security (iOS)",
        category="Platform",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check WKWebView configuration for JavaScript, file access, and navigation policies.",
        recommendation="Disable WKPreferences.allowsInlineMediaPlayback. Set WKNavigationDelegate for URL validation.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-7/"]
    ),

    # MSTG-CODE (iOS)
    MastgTest(
        test_id="MSTG-CODE-01",
        name="Testing for Debugging Symbols (iOS)",
        category="Code Quality",
        platform=Platform.IOS,
        severity=Severity.MEDIUM,
        description="Check if app has dSYM symbols and debug capabilities enabled.",
        recommendation="Strip debug symbols. Set STRIP_INSTALLED_PRODUCT = YES.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-02",
        name="Testing for Debugger Detection (iOS)",
        category="Code Quality",
        platform=Platform.IOS,
        severity=Severity.MEDIUM,
        description="Check if app detects debugger attachment via sysctl or ptrace.",
        recommendation="Use ptrace(PT_DENY_ATTACH) or sysctl for debugger detection.",
        frida_scripts=["ios_debugger_detection"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-2/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-07",
        name="Testing for Code Obfuscation (iOS)",
        category="Code Quality",
        platform=Platform.IOS,
        severity=Severity.LOW,
        description="Check if app has proper code obfuscation and symbol stripping.",
        recommendation="Enable compiler optimizations. Strip unused symbols.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-7/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-08",
        name="Testing for WebView Security (iOS)",
        category="Code Quality",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check WKWebView for JavaScript injection, file access, and navigation vulnerabilities.",
        recommendation="Disable file access. Validate navigation URLs. Use WKContentWorld for isolation.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-8/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-14",
        name="Testing for Jailbreak Detection (iOS)",
        category="Code Quality",
        platform=Platform.IOS,
        severity=Severity.MEDIUM,
        description="Check if app detects jailbroken devices and how effective the detection is.",
        recommendation="Combine file checks, URL scheme checks, and sandbox integrity checks.",
        frida_scripts=["ios_jailbreak_detection_test"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-14/"]
    ),
    MastgTest(
        test_id="MSTG-CODE-15",
        name="Testing for Anti-Debugging (iOS)",
        category="Code Quality",
        platform=Platform.IOS,
        severity=Severity.MEDIUM,
        description="Check if app prevents debugger attachment and dynamic analysis.",
        recommendation="Use multiple anti-debug techniques: ptrace, sysctl, signals.",
        frida_scripts=["ios_anti_debug"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-CODE-15/"]
    ),

    # MSTG-RESILIENCE (iOS)
    MastgTest(
        test_id="MSTG-RESILIENCE-01",
        name="Testing Anti-Reverse Engineering (iOS)",
        category="Resilience",
        platform=Platform.IOS,
        severity=Severity.MEDIUM,
        description="Check if app has anti-tampering and binary protection measures.",
        recommendation="Enable PIE, ARC, and code signing. Use obfuscation tools.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/"]
    ),
    MastgTest(
        test_id="MSTG-RESILIENCE-02",
        name="Testing for Jailbreak Bypass (iOS)",
        category="Resilience",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if jailbreak detection can be bypassed with Frida or tweaks.",
        recommendation="Implement multi-layered detection with native checks.",
        frida_scripts=["ios_jailbreak_bypass"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/"]
    ),
    MastgTest(
        test_id="MSTG-RESILIENCE-04",
        name="Testing for Frida Detection (iOS)",
        category="Resilience",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if app detects Frida's presence via port scanning, library checks, or named pipes.",
        recommendation="Check for Frida server port, /usr/sbin/frida-server, and frida-named-pipe.",
        frida_scripts=["ios_frida_detection_test"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/"]
    ),
    MastgTest(
        test_id="MSTG-RESILIENCE-05",
        name="Testing for dylib Injection (iOS)",
        category="Resilience",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if app detects dynamic library injection via DYLD_INSERT_LIBRARIES.",
        recommendation="Check DYLD environment variables. Use code signing to prevent injection.",
        frida_scripts=["ios_dylib_detection"],
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-5/"]
    ),
    MastgTest(
        test_id="MSTG-RESILIENCE-08",
        name="Testing for Anti-Dynamic Analysis (iOS)",
        category="Resilience",
        platform=Platform.IOS,
        severity=Severity.HIGH,
        description="Check if app detects and prevents dynamic analysis tools.",
        recommendation="Combine multiple detection methods: port scanning, file checks, process enumeration.",
        refs=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-8/"]
    ),
]


def get_all_tests():
    return ANDROID_STATIC_TESTS + IOS_STATIC_TESTS

def get_android_tests():
    return ANDROID_STATIC_TESTS

def get_ios_tests():
    return IOS_STATIC_TESTS

def get_tests_by_category(category: str):
    return [t for t in get_all_tests() if t.category.lower() == category.lower()]

def get_tests_by_platform(platform: Platform):
    return [t for t in get_all_tests() if t.platform == platform or t.platform == Platform.BOTH]

def get_tests_by_severity(severity: Severity):
    return [t for t in get_all_tests() if t.severity == severity]

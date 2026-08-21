"""
Frida Script Generator
Generates contextual Frida scripts based on detected security controls
"""
from typing import List, Dict, Optional


class FridaScriptGenerator:
    """Generate Frida scripts based on detected security measures in the app."""

    # ─── Root/Jailbreak Detection Bypass Scripts ──────────────────────

    ANDROID_ROOT_BYPASS = """
// [MobiScan] Android Root Detection Bypass Script
// Bypasses common root detection mechanisms

Java.perform(function () {
    console.log("[*] Starting Android Root Detection Bypass...");

    // --- Bypass rootBeer ---
    try {
        var rootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        rootBeer.isRooted.implementation = function () {
            console.log("[+] Bypassed rootBeer.isRooted()");
            return false;
        };
        console.log("[+] rootBeer hooked");
    } catch (e) { console.log("[-] rootBeer not found"); }

    // --- Bypass File.exists() for su binary paths ---
    var File = Java.use("java.io.File");
    var suPaths = [
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/su/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/system/usr/we-need-root/su",
        "/cache/su",
        "/data/su",
        "/dev/su",
    ];

    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (suPaths.indexOf(path) !== -1) {
            console.log("[+] Bypassed File.exists() for: " + path);
            return false;
        }
        return this.exists();
    };

    // --- Bypass Runtime.exec() for 'su' commands ---
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[+] Blocked Runtime.exec: " + cmd);
            throw Java.use("java.io.IOException").$new("Cannot run program");
        }
        return this.exec(cmd);
    };

    // --- Bypass Process class ---
    var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    ProcessBuilder.start.implementation = function () {
        var cmd = this.command.value;
        if (cmd && cmd.toString().indexOf("su") !== -1) {
            console.log("[+] Blocked ProcessBuilder for: " + cmd);
            throw Java.use("java.io.IOException").$new("Cannot run program");
        }
        return this.start();
    };

    // --- Bypass Build-tags check ---
    var Build = Java.use("android.os.Build");
    var TAGS = Build.TAGS.value;
    if (TAGS && TAGS.indexOf("test-keys") !== -1) {
        Build.TAGS.value = "release-keys";
        console.log("[+] Changed Build.TAGS from test-keys to release-keys");
    }

    // --- Bypass System properties ---
    var System = Java.use("java.lang.System");
    System.getProperty.overload("java.lang.String").implementation = function (key) {
        if (key === "ro.debuggable" || key === "ro.secure") {
            console.log("[+] Bypassed System.getProperty: " + key);
            return "0";
        }
        return this.getProperty(key);
    };

    // --- Bypass PackageManager.getPackageInfo ---
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkg, flags) {
        if (pkg === "com.topjohnwu.magisk" || pkg === "eu.chainfire.supersu" ||
            pkg === "com.koushikdutta.superuser" || pkg === "com.thirdparty.superuser" ||
            pkg === "com.noshufou.android.su" || pkg === "com.devadvance.rootcloak" ||
            pkg === "com.devadvance.rootcloakplus" || pkg === "com.saurik.substrate" ||
            pkg === "com.amphoras.hidemyroot" || pkg === "com.fdfirewall.hidemyroot") {
            console.log("[+] Bypassed getPackageInfo for root package: " + pkg);
            throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new("Package not found");
        }
        return this.getPackageInfo(pkg, flags);
    };

    console.log("[*] Android Root Detection Bypass loaded successfully!");
});
"""

    IOS_JAILBREAK_BYPASS = """
// [MobiScan] iOS Jailbreak Detection Bypass Script
// Bypasses common jailbreak detection mechanisms

ObjC.implement(ObjC.classes.NSString['-.writeString:'], function (impl) {
    return function (args) {
        var str = new ObjC.Object(args[2]).toString();
        if (str.indexOf('cydia') !== -1 || str.indexOf('jailbreak') !== -1 ||
            str.indexOf('/bin/bash') !== -1 || str.indexOf('apt.dylib') !== -1) {
            console.log('[+] Blocked writeString: ' + str);
            return;
        }
        return impl.apply(this, args);
    };
});

// --- Bypass fileExistsAtPath: ---
if (ObjC.classes.NSFileManager) {
    Interceptor.attach(
        ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
            onEnter: function (args) {
                this.path = ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                var blacklist = [
                    '/Applications/Cydia.app',
                    '/Library/MobileSubstrate/MobileSubstrate.dylib',
                    '/bin/bash',
                    '/usr/sbin/sshd',
                    '/etc/apt',
                    '/private/var/lib/apt/',
                    '/usr/bin/ssh',
                    '/private/var/stash',
                    '/private/var/tmp/cydia.log',
                    '/var/mobile/Library/Preferences/me.jjolano.shadow.plist',
                    '/Applications/Sileo.app',
                    '/Library/dpkg',
                    '/private/var/lib/cydia',
                ];
                if (blacklist.indexOf(this.path) !== -1) {
                    console.log('[+] Bypassed fileExistsAtPath: ' + this.path);
                    retval.replace(0x0);
                }
            }
        }
    );
}

// --- Bypass canOpenURL: (Cydia URL scheme) ---
if (ObjC.classes.UIApplication) {
    Interceptor.attach(
        ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
            onEnter: function (args) {
                var url = ObjC.Object(args[2]).toString();
                if (url.indexOf('cydia://') !== -1 || url.indexOf('sileo://') !== -1 ||
                    url.indexOf('activator://') !== -1) {
                    console.log('[+] Bypassed canOpenURL: ' + url);
                    this.blocked = true;
                }
            },
            onLeave: function (retval) {
                if (this.blocked) {
                    retval.replace(0x0);
                }
            }
        }
    );
}

// --- Bypass getattr for sensitive paths ---
Interceptor.attach(Module.findExportByName(null, 'getattr'), {
    onEnter: function (args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function (retval) {
        if (this.path && (
            this.path.indexOf('/private/var/') !== -1 &&
            (this.path.indexOf('cydia') !== -1 || this.path.indexOf('stash') !== -1)
        )) {
            retval.replace(-1);
        }
    }
});

console.log('[*] iOS Jailbreak Detection Bypass loaded successfully!');
"""

    # ─── SSL Pinning Bypass Scripts ───────────────────────────────────

    ANDROID_SSL_PINNING_BYPASS = """
// [MobiScan] Android SSL/TLS Certificate Pinning Bypass Script

Java.perform(function () {
    console.log("[*] Starting SSL Pinning Bypass...");

    // --- TrustManagerImpl (conscrypt) ---
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain,
            host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] Bypassed TrustManagerImpl.verifyChain for: " + host);
            return untrustedChain;
        };
        console.log("[+] TrustManagerImpl hooked");
    } catch (e) { console.log("[-] TrustManagerImpl not found"); }

    // --- OkHttp3 CertificatePinner ---
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
            console.log("[+] Bypassed OkHttp3 CertificatePinner.check for: " + hostname);
        };
        console.log("[+] OkHttp3 CertificatePinner hooked");
    } catch (e) { console.log("[-] OkHttp3 CertificatePinner not found"); }

    // --- OkHttp3 CertificatePinner (Kotlin) ---
    try {
        var CertPinnerKt = Java.use("okhttp3.CertificatePinner");
        CertPinnerKt["check$okhttp"].implementation = function (hostname, peerCertificates) {
            console.log("[+] Bypassed OkHttp3 CertificatePinner.check$okhttp for: " + hostname);
        };
    } catch (e) {}

    // --- WebViewClient ---
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            console.log("[+] Bypassed WebViewClient.onReceivedSslError");
            handler.proceed();
        };
    } catch (e) { console.log("[-] WebViewClient not found"); }

    // --- SSLSocket ---
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom").implementation = function (km, tm, sr) {
            console.log("[+] Bypassed SSLContext.init - using TrustAllManager");
            var TrustAll = Java.registerClass({
                name: "com.mobiscan.TrustAllManager",
                implements: [Java.use("javax.net.ssl.X509TrustManager")],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            this.init(km, [TrustAll.$new()], sr);
        };
    } catch (e) { console.log("[-] SSLContext not found"); }

    // --- HostnameVerifier ---
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HttpsURLConnection");
        HostnameVerifier.setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
            console.log("[+] Bypassed HostnameVerifier");
        };
    } catch (e) {}

    // --- TrustManagerFactory ---
    try {
        var TMF = Java.use("javax.net.ssl.TrustManagerFactory");
        TMF.getTrustManagers.implementation = function () {
            console.log("[+] Bypassed TrustManagerFactory.getTrustManagers");
            var TrustAll = Java.registerClass({
                name: "com.mobiscan.TrustAllTMF",
                implements: [Java.use("javax.net.ssl.X509TrustManager")],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            return [TrustAll.$new()];
        };
    } catch (e) {}

    // --- Network Security Config bypass ---
    try {
        var NetworkSecurityConfig = Java.use("android.security.NetworkSecurityConfig");
        NetworkSecurityConfig.isCleartextTrafficPermitted.overload("java.lang.String").implementation = function (hostname) {
            console.log("[+] Bypassed isCleartextTrafficPermitted for: " + hostname);
            return true;
        };
    } catch (e) {}

    console.log("[*] SSL Pinning Bypass loaded successfully!");
});
"""

    IOS_SSL_PINNING_BYPASS = """
// [MobiScan] iOS SSL/TLS Certificate Pinning Bypass Script

ObjC.implement(ObjC.classes.NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'],
    function (impl) {
        return function (session, challenge, completionHandler) {
            var protectionSpace = challenge.protectionSpace();
            var authMethod = protectionSpace.authenticationMethod().toString();

            if (authMethod === 'NSURLAuthenticationMethodServerTrust') {
                var serverTrust = protectionSpace.serverTrust();
                var host = protectionSpace.host().toString();
                console.log('[+] Bypassed SSL pin for: ' + host);

                var credential = ObjC.classes.NSURLCredential
                    .credentialForTrust_(serverTrust);
                completionHandler.implementation(
                    0, // NSURLSessionAuthChallengeUseCredential
                    credential
                );
            } else {
                return impl.apply(this, arguments);
            }
        };
    }
);

// --- TrustKit ---
if (ObjC.classes.TSKPinVerifier) {
    Interceptor.attach(ObjC.classes.TSKPinVerifier['+ pinVerifierForServerTrust:domain:'].implementation, {
        onLeave: function (retval) {
            retval.replace(0x1);
            console.log('[+] Bypassed TrustKit pinning');
        }
    });
}

// --- Alamofire ---
if (ObjC.classes.AFSecurityPolicy) {
    Interceptor.attach(ObjC.classes.AFSecurityPolicy['- evaluateServerTrust:forDomain:'].implementation, {
        onLeave: function (retval) {
            retval.replace(0x1);
            console.log('[+] Bypassed Alamofire SSL pinning');
        }
    });
}

console.log('[*] iOS SSL Pinning Bypass loaded successfully!');
"""

    # ─── Network Monitoring Scripts ───────────────────────────────────

    ANDROID_NETWORK_MONITOR = """
// [MobiScan] Android Network Traffic Monitor
// Monitors all HTTP/HTTPS requests

Java.perform(function () {
    console.log("[*] Starting Network Traffic Monitor...");

    // --- OkHttp3 Interceptor ---
    try {
        var Buffer = Java.use("okio.Buffer");
        var Interceptor = Java.use("okhttp3.Interceptor");
        var OkHttpClient = Java.use("okhttp3.OkHttpClient$Builder");

        // Hook the real call
        var RealCall = Java.use("okhttp3.RealCall");
        RealCall.execute.implementation = function () {
            var req = this.request();
            console.log("[HTTP] " + req.method() + " " + req.url());
            var headers = req.headers();
            for (var i = 0; i < headers.size(); i++) {
                console.log("  " + headers.name(i) + ": " + headers.value(i));
            }
            return this.execute();
        };
        console.log("[+] OkHttp3 RealCall hooked");
    } catch (e) { console.log("[-] OkHttp3 not found"); }

    // --- HttpURLConnection ---
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            console.log("[HTTP] Opening connection to: " + this.toString());
            return this.openConnection();
        };
    } catch (e) {}

    // --- Retrofit ---
    try {
        var HttpLoggingInterceptor = Java.use("okhttp3.internal.http.BridgeInterceptor");
        HttpLoggingInterceptor.intercept.implementation = function (chain) {
            var req = chain.request();
            console.log("[Retrofit] " + req.method() + " " + req.url());
            return this.intercept(chain);
        };
    } catch (e) {}

    console.log("[*] Network Monitor loaded successfully!");
});
"""

    IOS_NETWORK_MONITOR = """
// [MobiScan] iOS Network Traffic Monitor

// --- NSURLSession ---
var NSURLSessionDataDelegate = ObjC.protocols['NSURLSessionDataDelegate'];
if (NSURLSessionDataDelegate) {
    var classes = Object.keys(ObjC.classes).filter(function (name) {
        return ObjC.classes[name].conformsToProtocol('NSURLSessionDataDelegate');
    });
    console.log('[*] Found ' + classes.length + ' classes conforming to NSURLSessionDataDelegate');
}

// --- NSURLConnection delegate ---
Interceptor.attach(
    ObjC.classes.NSURLConnection['+ connectionWithRequest:delegate:'].implementation, {
        onEnter: function (args) {
            var request = new ObjC.Object(args[2]);
            console.log('[HTTP] Connection to: ' + request.URL().absoluteString().toString());
        }
    }
);

console.log('[*] iOS Network Monitor loaded successfully!');
"""

    # ─── Key Extraction Scripts ───────────────────────────────────────

    ANDROID_KEY_EXTRACTION = """
// [MobiScan] Android Key/Secret Extraction Script
// Extracts hardcoded secrets from SharedPreferences, strings, etc.

Java.perform(function () {
    console.log("[*] Starting Key/Secret Extraction...");

    // --- SharedPreferences monitor ---
    var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
    SharedPreferencesImpl.getString.implementation = function (key, defValue) {
        var result = this.getString(key, defValue);
        if (result && result.length > 8) {
            console.log("[SharedPrefs] " + key + " = " + result);
        }
        return result;
    };

    SharedPreferencesImpl.getInt.implementation = function (key, defValue) {
        var result = this.getInt(key, defValue);
        console.log("[SharedPrefs] " + key + " = " + result);
        return result;
    };

    // --- KeyStore ---
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.getKey.implementation = function (alias, password) {
            console.log("[KeyStore] getKey: " + alias);
            if (password) {
                console.log("[KeyStore] password: " + password);
            }
            return this.getKey(alias, password);
        };
        console.log("[+] KeyStore.getKey hooked");
    } catch (e) {}

    // --- SecretKey ---
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
            var hexKey = '';
            for (var i = 0; i < key.length; i++) {
                hexKey += ('0' + (key[i] & 0xFF).toString(16)).slice(-2);
            }
            console.log("[SECRET KEY] Algorithm: " + algo);
            console.log("[SECRET KEY] Hex: " + hexKey);
            console.log("[SECRET KEY] Base64: " + Java.use("android.util.Base64")
                .encodeToString(key, 0));
            return this.$init(key, algo);
        };
    } catch (e) {}

    // --- WebView URL sniffing ---
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            console.log("[WebView] Loading: " + url);
            return this.loadUrl(url);
        };
        WebView.postUrl.overload("java.lang.String", "[B").implementation = function (url, data) {
            console.log("[WebView] POST to: " + url);
            return this.postUrl(url, data);
        };
    } catch (e) {}

    console.log("[*] Key Extraction loaded successfully!");
});
"""

    IOS_KEY_EXTRACTION = """
// [MobiScan] iOS Key/Secret Extraction Script

// --- Keychain access monitoring ---
Interceptor.attach(
    ObjC.classes.SecItemCopyMatching, {
        onEnter: function (args) {
            var query = new ObjC.Object(args[0]);
            console.log('[Keychain] Query: ' + query.toString());
        },
        onLeave: function (retval) {
            console.log('[Keychain] Result code: ' + retval);
        }
    }
);

// --- UserDefaults monitoring ---
var NSUserDefaults = ObjC.classes.NSUserDefaults;
Interceptor.attach(
    NSUserDefaults['- objectForKey:'].implementation, {
        onEnter: function (args) {
            var key = new ObjC.Object(args[2]).toString();
            if (key.indexOf('token') !== -1 || key.indexOf('key') !== -1 ||
                key.indexOf('secret') !== -1 || key.indexOf('auth') !== -1 ||
                key.indexOf('password') !== -1 || key.indexOf('session') !== -1) {
                var value = new ObjC.Object(
                    NSUserDefaults['- objectForKey:'](args[2])
                ).toString();
                console.log('[UserDefaults] ' + key + ' = ' + value);
            }
        }
    }
);

console.log('[*] iOS Key Extraction loaded successfully!');
"""

    # ─── Input Validation / WebView Scripts ───────────────────────────

    ANDROID_WEBVIEW_MONITOR = """
// [MobiScan] Android WebView Security Monitor

Java.perform(function () {
    console.log("[*] Starting WebView Security Monitor...");

    var WebView = Java.use("android.webkit.WebView");

    // --- JavaScript interface monitoring ---
    WebView.addJavascriptInterface.overload("java.lang.Object", "java.lang.String").implementation = function (obj, name) {
        console.log("[WebView] addJavascriptInterface: " + name + " -> " + obj.getClass().getName());
        var methods = obj.getClass().getMethods();
        for (var i = 0; i < methods.length; i++) {
            console.log("  [JS Bridge] " + methods[i].getName() + "(" +
                methods[i].getParameterTypes().length + " params)");
        }
        return this.addJavascriptInterface(obj, name);
    };

    // --- URL loading ---
    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("[WebView] loadUrl: " + url);
        return this.loadUrl(url);
    };

    WebView.loadData.overload("java.lang.String", "java.lang.String", "java.lang.String")
        .implementation = function (data, mimeType, encoding) {
        console.log("[WebView] loadData: " + data.substring(0, 200));
        return this.loadData(data, mimeType, encoding);
    };

    // --- Settings monitoring ---
    var WebSettings = Java.use("android.webkit.WebSettings");
    WebSettings.setJavaScriptEnabled.implementation = function (flag) {
        console.log("[WebView] setJavaScriptEnabled: " + flag);
        return this.setJavaScriptEnabled(flag);
    };

    WebSettings.setAllowFileAccess.implementation = function (flag) {
        console.log("[WebView] setAllowFileAccess: " + flag);
        return this.setAllowFileAccess(flag);
    };

    console.log("[*] WebView Monitor loaded successfully!");
});
"""

    # ─── IPC / Intent Monitoring ──────────────────────────────────────

    ANDROID_INTENT_MONITOR = """
// [MobiScan] Android Intent/IPC Monitor

Java.perform(function () {
    console.log("[*] Starting Intent/IPC Monitor...");

    // --- Activity onCreate ---
    var Activity = Java.use("android.app.Activity");
    Activity.onCreate.overload("android.os.Bundle").implementation = function (bundle) {
        var intent = this.getIntent();
        if (intent) {
            var action = intent.getAction();
            var data = intent.getDataString();
            console.log("[Activity] " + this.getClass().getName() + ".onCreate");
            if (action) console.log("  Action: " + action);
            if (data) console.log("  Data: " + data);
            var extras = intent.getExtras();
            if (extras) {
                var keys = extras.keySet().iterator();
                while (keys.hasNext()) {
                    var key = keys.next();
                    console.log("  Extra: " + key + " = " + extras.get(key));
                }
            }
        }
        this.onCreate(bundle);
    };

    // --- Intent getExtra monitoring ---
    var Intent = Java.use("android.content.Intent");
    Intent.getStringExtra.overload("java.lang.String").implementation = function (name) {
        var result = this.getStringExtra(name);
        if (result) {
            console.log("[Intent] getStringExtra: " + name + " = " + result);
        }
        return result;
    };

    console.log("[*] Intent Monitor loaded successfully!");
});
"""

    # ─── Frida Detection Test Script ──────────────────────────────────

    FRIDA_DETECTION_TEST = """
// [MobiScan] Frida Detection Test Script
// Tests if the app detects Frida by checking common indicators

(function () {
    console.log("[*] Running Frida Detection Tests...");

    // Test 1: Port scanning (Frida default port 27042)
    var Socket = Java.use("java.net.Socket");
    Socket.$init.overload("java.lang.String", "int").implementation = function (host, port) {
        if (port === 27042 || port === 27043) {
            console.log("[!] App detected Frida port probe: " + host + ":" + port);
        }
        return this.$init(host, port);
    };

    // Test 2: Library loading check
    var System = Java.use("java.lang.System");
    System.loadLibrary.overload("java.lang.String").implementation = function (libname) {
        console.log("[Library] Loading: " + libname);
        return this.loadLibrary(libname);
    };

    // Test 3: Process name check
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
        var result = this.isDebuggerConnected();
        console.log("[Detection] isDebuggerConnected: " + result);
        return result;
    };

    // Test 4: File existence checks (root detection + Frida detection)
    var File = Java.use("java.io.File");
    var suspiciousPaths = [
        "/proc/self/maps",
        "/proc/self/fd",
        "/data/local/tmp/frida-agent",
        "/usr/lib/frida",
    ];

    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (suspiciousPaths.indexOf(path) !== -1) {
            console.log("[Detection] Checking: " + path);
        }
        return this.exists();
    };

    console.log("[*] Frida Detection Tests loaded!");
})();
"""

    @classmethod
    def generate_for_android(cls, detection_results: Dict) -> str:
        """Generate comprehensive Frida script based on Android scan results."""
        scripts = ["// [MobiScan] Generated Frida Script Bundle"]
        scripts.append("// Auto-generated based on static analysis results")
        scripts.append("// Usage: frida -U -f <package> -l mobiscan_frida.js --no-pause\n")

        # Always include root bypass if root detection found
        if detection_results.get("has_root_detection"):
            scripts.append(cls.ANDROID_ROOT_BYPASS)

        # SSL pinning bypass if detected
        if detection_results.get("has_ssl_pinning"):
            scripts.append(cls.ANDROID_SSL_PINNING_BYPASS)

        # Network monitoring for traffic analysis
        if detection_results.get("checks_network"):
            scripts.append(cls.ANDROID_NETWORK_MONITOR)

        # Key extraction if crypto/storage issues found
        if detection_results.get("has_crypto_issues") or detection_results.get("has_storage_issues"):
            scripts.append(cls.ANDROID_KEY_EXTRACTION)

        # WebView monitoring
        if detection_results.get("has_webviews"):
            scripts.append(cls.ANDROID_WEBVIEW_MONITOR)

        # Intent/IPC monitoring
        if detection_results.get("has_intent_filters"):
            scripts.append(cls.ANDROID_INTENT_MONITOR)

        # Frida detection testing
        if detection_results.get("has_anti_frida"):
            scripts.append(cls.FRIDA_DETECTION_TEST)

        # Always include network + root bypass as baseline
        if not scripts or len(scripts) <= 2:
            scripts.append(cls.ANDROID_ROOT_BYPASS)
            scripts.append(cls.ANDROID_NETWORK_MONITOR)

        return "\n".join(scripts)

    @classmethod
    def generate_for_ios(cls, detection_results: Dict) -> str:
        """Generate comprehensive Frida script based on iOS scan results."""
        scripts = ["// [MobiScan] Generated Frida Script Bundle (iOS)"]
        scripts.append("// Auto-generated based on static analysis results")
        scripts.append("// Usage: frida -U -f <bundle_id> -l mobiscan_frida.js\n")

        if detection_results.get("has_jailbreak_detection"):
            scripts.append(cls.IOS_JAILBREAK_BYPASS)

        if detection_results.get("has_ssl_pinning"):
            scripts.append(cls.IOS_SSL_PINNING_BYPASS)

        if detection_results.get("checks_network"):
            scripts.append(cls.IOS_NETWORK_MONITOR)

        if detection_results.get("has_crypto_issues"):
            scripts.append(cls.IOS_KEY_EXTRACTION)

        if not scripts or len(scripts) <= 2:
            scripts.append(cls.IOS_JAILBREAK_BYPASS)
            scripts.append(cls.IOS_NETWORK_MONITOR)

        return "\n".join(scripts)

    @classmethod
    def get_all_scripts(cls) -> Dict[str, str]:
        return {
            "android_root_bypass": cls.ANDROID_ROOT_BYPASS,
            "android_ssl_pinning_bypass": cls.ANDROID_SSL_PINNING_BYPASS,
            "android_network_monitor": cls.ANDROID_NETWORK_MONITOR,
            "android_key_extraction": cls.ANDROID_KEY_EXTRACTION,
            "android_webview_monitor": cls.ANDROID_WEBVIEW_MONITOR,
            "android_intent_monitor": cls.ANDROID_INTENT_MONITOR,
            "ios_jailbreak_bypass": cls.IOS_JAILBREAK_BYPASS,
            "ios_ssl_pinning_bypass": cls.IOS_SSL_PINNING_BYPASS,
            "ios_network_monitor": cls.IOS_NETWORK_MONITOR,
            "ios_key_extraction": cls.IOS_KEY_EXTRACTION,
            "frida_detection_test": cls.FRIDA_DETECTION_TEST,
        }

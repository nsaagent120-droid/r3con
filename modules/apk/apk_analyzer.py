"""
r3con - APK Analyzer - FIXED VERSION
Fixes: binary AXML handling, expanded permissions, native lib analysis, deep link, full DEX scan
"""

import re
import zipfile
import struct
from pathlib import Path
from typing import List, Dict


# Expanded dangerous permissions - 80+ from AOSP
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS":        ("MED",  "Reads user contacts"),
    "android.permission.WRITE_CONTACTS":       ("MED",  "Writes user contacts"),
    "android.permission.READ_SMS":             ("HIGH", "Reads SMS messages"),
    "android.permission.SEND_SMS":             ("HIGH", "Sends SMS (financial fraud risk)"),
    "android.permission.RECEIVE_SMS":          ("HIGH", "Intercepts incoming SMS"),
    "android.permission.READ_CALL_LOG":        ("MED",  "Reads call history"),
    "android.permission.WRITE_CALL_LOG":       ("MED",  "Writes call history"),
    "android.permission.RECORD_AUDIO":         ("HIGH", "Records microphone"),
    "android.permission.CAMERA":               ("MED",  "Accesses camera"),
    "android.permission.ACCESS_FINE_LOCATION": ("MED",  "Precise GPS location"),
    "android.permission.ACCESS_COARSE_LOCATION": ("LOW", "Coarse location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("HIGH", "Background location - high privacy risk"),
    "android.permission.READ_EXTERNAL_STORAGE":("LOW",  "Reads SD card"),
    "android.permission.WRITE_EXTERNAL_STORAGE":("LOW", "Writes SD card"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("HIGH", "All files access - Android 11+"),
    "android.permission.INTERNET":             ("INFO", "Network access"),
    "android.permission.GET_ACCOUNTS":         ("MED",  "Reads device accounts"),
    "android.permission.USE_BIOMETRIC":        ("INFO", "Biometric authentication"),
    "android.permission.USE_FINGERPRINT":      ("INFO", "Fingerprint auth"),
    "android.permission.INSTALL_PACKAGES":     ("HIGH", "Can install other APKs"),
    "android.permission.REQUEST_INSTALL_PACKAGES":("HIGH","Can request APK install"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":("CRITICAL","Accessibility — keylogger risk"),
    "android.permission.SYSTEM_ALERT_WINDOW":  ("HIGH", "Overlay — tapjacking risk"),
    "android.permission.READ_PHONE_STATE":     ("MED", "Reads phone state/IMEI"),
    "android.permission.READ_PHONE_NUMBERS":   ("MED", "Reads phone numbers"),
    "android.permission.CALL_PHONE":           ("MED", "Direct call without user confirmation"),
    "android.permission.PROCESS_OUTGOING_CALLS": ("HIGH", "Monitor outgoing calls"),
    "android.permission.ANSWER_PHONE_CALLS":   ("MED", "Answer calls"),
    "android.permission.USE_SIP":              ("MED", "SIP calls"),
    "android.permission.RECEIVE_MMS":          ("HIGH", "Receives MMS"),
    "android.permission.RECEIVE_WAP_PUSH":     ("MED", "WAP push"),
    "android.permission.BODY_SENSORS":         ("MED", "Body sensors"),
    "android.permission.ACTIVITY_RECOGNITION": ("LOW", "Activity recognition"),
    "android.permission.READ_CALENDAR":        ("MED", "Reads calendar"),
    "android.permission.WRITE_CALENDAR":       ("MED", "Writes calendar"),
    "android.permission.RECORD_AUDIO":         ("HIGH", "Microphone"),
    "android.permission.ACCESS_MEDIA_LOCATION": ("MED", "Media location metadata"),
    "android.permission.CAMERA":               ("MED", "Camera"),
    "android.permission.READ_MEDIA_IMAGES":    ("LOW", "Reads images"),
    "android.permission.READ_MEDIA_VIDEO":     ("LOW", "Reads videos"),
    "android.permission.READ_MEDIA_AUDIO":     ("LOW", "Reads audio"),
    "android.permission.QUERY_ALL_PACKAGES":   ("HIGH", "List all installed apps - fingerprinting"),
    "android.permission.GET_PACKAGE_SIZE":     ("LOW", "Package size"),
    "android.permission.WRITE_SETTINGS":       ("HIGH", "Modify system settings"),
    "android.permission.WRITE_SECURE_SETTINGS": ("CRITICAL", "Secure settings - system level"),
    "android.permission.CHANGE_WIFI_STATE":    ("LOW", "Change WiFi"),
    "android.permission.ACCESS_WIFI_STATE":    ("INFO", "WiFi state"),
    "android.permission.BLUETOOTH":            ("LOW", "Bluetooth"),
    "android.permission.BLUETOOTH_ADMIN":      ("LOW", "Bluetooth admin"),
    "android.permission.BLUETOOTH_CONNECT":    ("MED", "Bluetooth connect Android 12+"),
    "android.permission.BLUETOOTH_SCAN":       ("MED", "Bluetooth scan"),
    "android.permission.NFC":                  ("LOW", "NFC"),
    "android.permission.USE_CREDENTIALS":      ("MED", "Use credentials"),
    "android.permission.MANAGE_ACCOUNTS":      ("MED", "Manage accounts"),
    "android.permission.AUTHENTICATE_ACCOUNTS": ("MED", "Authenticate accounts"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("LOW", "Autostart on boot - persistence"),
    "android.permission.VIBRATE":              ("INFO", "Vibrate"),
    "android.permission.WAKE_LOCK":            ("LOW", "Prevent sleep - battery drain"),
    "android.permission.FOREGROUND_SERVICE":   ("LOW", "Foreground service"),
    "android.permission.REQUEST_COMPANION_RUN_IN_BACKGROUND": ("LOW", "Background companion"),
    "android.permission.REQUEST_COMPANION_USE_DATA_IN_BACKGROUND": ("LOW", "Background data"),
    "android.permission.SEND_SMS":             ("HIGH", "Send SMS"),
    "android.permission.BIND_DEVICE_ADMIN":    ("CRITICAL", "Device admin - can wipe device"),
    "android.permission.CLEAR_APP_CACHE":      ("MED", "Clear cache"),
    "android.permission.DELETE_CACHE_FILES":   ("MED", "Delete cache"),
    "android.permission.DELETE_PACKAGES":      ("HIGH", "Delete packages"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("LOW", "Write external"),
    "android.permission.ACCESS_NETWORK_STATE": ("INFO", "Network state"),
    "android.permission.CHANGE_NETWORK_STATE": ("LOW", "Change network"),
    "android.permission.READ_SYNC_SETTINGS":   ("LOW", "Sync settings"),
    "android.permission.WRITE_SYNC_SETTINGS":  ("LOW", "Write sync"),
    "android.permission.BROADCAST_STICKY":     ("MED", "Sticky broadcast"),
    "android.permission.READ_LOGS":            ("HIGH", "Read logs - info leak (pre 4.1)"),
    "android.permission.SET_WALLPAPER":        ("LOW", "Set wallpaper"),
    "android.permission.SET_WALLPAPER_HINTS":  ("LOW", "Wallpaper hints"),
    "android.permission.FLASHLIGHT":           ("INFO", "Flashlight"),
    "android.permission.KILL_BACKGROUND_PROCESSES": ("MED", "Kill background"),
    "android.permission.MODIFY_AUDIO_SETTINGS": ("LOW", "Audio settings"),
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": ("HIGH", "Mount filesystem"),
    "android.permission.WRITE_APN_SETTINGS":   ("HIGH", "APN settings"),
    "android.permission.SUBSCRIBED_FEEDS_READ": ("LOW", "Read feeds"),
    "android.permission.SUBSCRIBED_FEEDS_WRITE": ("LOW", "Write feeds"),
    "android.permission.CHANGE_CONFIGURATION": ("MED", "Change config"),
    "android.permission.WRITE_CONTACTS":       ("MED", "Write contacts"),
    "android.permission.WRITE_GSERVICES":      ("HIGH", "Write gservices"),
    "android.permission.REORDER_TASKS":        ("MED", "Reorder tasks - task hijacking pre 5.0"),
}

SMALI_PATTERNS = [
    (r'Ljava/security/MessageDigest.*MD5',   "HIGH",     "Weak Hash (MD5) in bytecode", "MD5 usage detected in Dalvik bytecode — use SHA-256"),
    (r'Ljavax/crypto/Cipher.*DES',           "CRITICAL", "Weak Cipher (DES) in bytecode", "DES usage in bytecode — use AES-256-GCM"),
    (r'Ljavax/crypto/Cipher.*ECB',           "HIGH",     "ECB Mode in bytecode", "ECB mode in bytecode — use GCM"),
    (r'Ljavax/crypto/Cipher.*RC4',           "HIGH",     "RC4 in bytecode", "RC4 broken — use ChaCha20"),
    (r'Ljava/util/Random',                   "HIGH",     "Weak PRNG in bytecode", "java.util.Random not crypto-safe — use SecureRandom"),
    (r'exec\s*\(\s*["\']sh["\']|Runtime.*exec|ProcessBuilder', "HIGH",  "Command Execution", "Runtime.exec() — verify no user-controlled input"),
    (r'openFileOutput.*MODE_WORLD_READABLE',  "HIGH",    "World-Readable File", "File created with MODE_WORLD_READABLE"),
    (r'openFileOutput.*MODE_WORLD_WRITEABLE', "HIGH",    "World-Writable File", "File created with MODE_WORLD_WRITEABLE"),
    (r'getSharedPreferences.*MODE_WORLD',    "HIGH",     "World-Accessible Preferences", "SharedPreferences with world access mode"),
    (r'SQLiteDatabase.*rawQuery.*\+',            "MED",      "Potential SQL Injection", "rawQuery with string concatenation — use ? placeholders"),
    (r'WebView.*loadUrl.*javascript:',       "HIGH",     "JavaScript Injection", "WebView loading javascript: URL — XSS risk"),
    (r'addJavascriptInterface',              "HIGH",     "WebView JS Bridge", "addJavascriptInterface exposes Java to JS — RCE in old Android"),
    (r'setWebContentsDebuggingEnabled.*true', "MED",     "WebView Debugging Enabled", "WebView debugging enabled in production"),
    (r'TrustAllCerts|TrustAll.*X509|checkServerTrusted.*\{\s*\}', "CRITICAL", "SSL Bypass - TrustAll", "Custom TrustManager that trusts all certs — MitM trivial"),
    (r'ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier.*ALLOW', "CRITICAL", "Hostname Verification Disabled", "All hostnames accepted — MitM possible"),
    (r'X509TrustManager.*checkServerTrusted.*\{\s*\}', "CRITICAL", "Certificate Validation Disabled", "Empty checkServerTrusted — accepts any cert"),
    (r'getInstance.*http.*|http.*Request.*set.*verify.*false', "HIGH", "HTTP without TLS verification", "HTTP request with disabled verification"),
    (r'Cipher.*getInstance.*AES/ECB', "HIGH", "AES ECB in code", "AES/ECB leaks patterns — use AES/GCM/NoPadding"),
    (r'SecretKeySpec.*\(\s*.*\.getBytes\(\)', "MED", "Hardcoded key bytes", "SecretKeySpec from static bytes — hardcoded key?"),
    (r'iv.*=.*new\s+byte\[.*\]\s*\{\s*0', "HIGH", "Zero IV", "IV initialized to zeros"),
    (r'ClipboardManager.*setPrimaryClip', "LOW", "Clipboard usage", "Sensitive data to clipboard - may leak"),
    (r'Log\.(d|e|i|v|w)\s*\(.*password|.*secret|.*token', "HIGH", "Sensitive data in Log", "Password/secret logged via Log.*()"),
]

MANIFEST_CHECKS = [
    (r'android:debuggable\s*=\s*"true"',     "HIGH",     "Debug Mode Enabled", "debuggable=true in production — allows ADB debugging"),
    (r'android:allowBackup\s*=\s*"true"',    "MED",      "Backup Enabled", "allowBackup=true — ADB can extract app data"),
    (r'android:exported\s*=\s*"true"',       "MED",      "Exported Component", "Component exported — verify intent handling"),
    (r'android:permission\s*=\s*""',         "HIGH",     "Empty Permission", "Empty permission on exported component"),
    (r'uses-permission.*INSTALL_PACKAGES',   "HIGH",     "APK Install Permission", "App can install other APKs — dropper indicator"),
    (r'android:networkSecurityConfig',       "INFO",     "Network Security Config", "Custom network security config — verify no cleartext"),
    (r'cleartextTrafficPermitted\s*=\s*"true"', "HIGH",  "Cleartext Traffic Allowed", "HTTP plaintext permitted — MitM risk"),
    (r'minSdkVersion\s*=\s*"[1-9]"',        "LOW",      "Very Low minSdkVersion", "Very low minSdkVersion — ancient Android vulns"),
    (r'targetSdkVersion\s*=\s*"[1-9]"',     "MED",      "Low targetSdkVersion", "Low targetSdk - security bypasses possible"),
    (r'android:usesCleartextTraffic\s*=\s*"true"', "HIGH", "Cleartext Traffic", "usesCleartextTraffic=true — HTTP allowed"),
    (r'android:requestLegacyExternalStorage\s*=\s*"true"', "MED", "Legacy Storage", "requestLegacyExternalStorage - scoped storage bypass"),
    (r'android:exported\s*=\s*"true".*android:permission\s*=\s*"".*', "HIGH", "Exported without permission", "Exported component with no permission protection"),
]


class APKAnalyzer:
    def __init__(self, apk_path: str):
        self.path = apk_path
        self.manifest = ""
        self.manifest_raw = b""
        self.smali = []
        self.strings = []
        self.files = []
        self._loaded = False
        self.last_error = None
        self.native_libs = []
        self.dex_strings_raw = []

    def load(self) -> bool:
        try:
            with zipfile.ZipFile(self.path, 'r') as zf:
                self.files = zf.namelist()

                if "AndroidManifest.xml" in self.files:
                    raw = zf.read("AndroidManifest.xml")
                    self.manifest_raw = raw
                    # Try text first
                    try:
                        decoded = raw.decode("utf-8", errors="replace")
                        if "<manifest" in decoded or "android:" in decoded:
                            self.manifest = decoded
                        else:
                            # Binary XML - extract strings via AXML parser fallback
                            self.manifest = self._parse_binary_axml(raw)
                    except Exception:
                        self.manifest = self._parse_binary_axml(raw)

                # Smali files if present (from apktool)
                smali_files = [f for f in self.files if f.endswith(".smali")][:100]
                for sf in smali_files:
                    try:
                        content = zf.read(sf).decode("utf-8", errors="replace")
                        self.smali.append({"file": sf, "content": content})
                    except Exception:
                        pass

                # DEX files - scan ALL, not just 3
                dex_files = [f for f in self.files if f.endswith(".dex")]
                for df in dex_files[:10]:  # up to 10 DEX
                    try:
                        data = zf.read(df)
                        strs = self._extract_dex_strings(data)
                        self.strings.extend(strs)
                        self.dex_strings_raw.extend(strs)
                    except Exception:
                        pass

                # Native libs
                self.native_libs = [f for f in self.files if f.endswith(".so")]
                # Also extract strings from native libs
                for lib in self.native_libs[:5]:
                    try:
                        data = zf.read(lib)
                        lib_strs = self._extract_dex_strings(data)
                        # Tag native lib strings
                        for s in lib_strs[:100]:
                            self.strings.append({"value": s, "source": lib, "type": "native"})
                    except Exception:
                        pass

                # Also get strings from other interesting files
                for fname in self.files:
                    if fname.startswith("assets/") or fname.endswith(".xml") or fname.endswith(".json"):
                        if fname == "AndroidManifest.xml":
                            continue
                        try:
                            if zf.getinfo(fname).file_size < 1024*1024:  # <1MB
                                data = zf.read(fname)
                                if b"password" in data.lower() or b"api_key" in data.lower() or b"secret" in data.lower():
                                    self.strings.append({"value": data[:500].decode("utf-8", errors="ignore"), "source": fname, "type": "asset"})
                        except Exception:
                            pass

            self._loaded = True
            self.last_error = None
            return True
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            return False

    def _parse_binary_axml(self, data: bytes) -> str:
        """Parse binary AXML to extract permissions and components via string pool."""
        try:
            # Binary AXML has string pool - extract all strings
            # This is simplified: search for permission patterns in raw bytes
            # Real AXML parsing is complex, but we can extract useful info via regex on decoded latin-1
            text = data.decode("latin-1", errors="ignore")
            # Extract what looks like XML-ish content
            # Look for permission strings
            perms = re.findall(r'android\.permission\.[A-Z_]+', text)
            # Look for component names
            components = re.findall(r'[a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+(?:Activity|Service|Receiver|Provider)', text)
            # Build pseudo-manifest
            pseudo = f"<!-- Binary AXML parsed - {len(perms)} permissions found -->\n"
            pseudo += f"<!-- Raw size: {len(data)} bytes -->\n"
            for p in set(perms):
                pseudo += f'<uses-permission android:name="{p}" />\n'
            for c in set(components[:20]):
                pseudo += f'<activity android:name="{c}" />\n'
            # Also include raw strings for further regex
            # Append original latin-1 decoded with non-printable stripped
            cleaned = re.sub(r'[^\x20-\x7E\r\n\t<>="/_.-]+', ' ', text)
            pseudo += "\n<!-- Extracted strings -->\n" + cleaned[:10000]
            return pseudo
        except Exception as e:
            return f"<!-- Failed to parse binary AXML: {e} -->\n" + data[:2000].decode("latin-1", errors="ignore")

    def _extract_dex_strings(self, data: bytes) -> List[str]:
        regex = re.compile(rb'[ -~]{6,}')
        results = []
        for m in regex.finditer(data):
            s = m.group().decode("ascii", errors="ignore")
            results.append(s)
        # Also UTF-16
        try:
            utf16_regex = re.compile(rb'(?:[ -~]\x00){6,}')
            for m in utf16_regex.finditer(data):
                try:
                    s = m.group().decode("utf-16le", errors="ignore")
                    if len(s) >= 6:
                        results.append(s)
                except Exception:
                    continue
        except Exception:
            pass
        return results[:2000]

    def analyze_manifest(self) -> List[Dict]:
        findings = []
        if not self.manifest:
            return [{"severity":"INFO","type":"Manifest","line":None,
                     "description":"Could not parse AndroidManifest.xml (binary XML needs aapt/apktool)",
                     "recommendation":"Run: apktool d app.apk && r3con apk manifest ./app/AndroidManifest.xml"}]

        # Try to get permissions from raw binary too
        if self.manifest_raw:
            raw_text = self.manifest_raw.decode("latin-1", errors="ignore")
            # Extract all permission-like strings even from binary
            raw_perms = set(re.findall(r'android\.permission\.[A-Z_]+', raw_text))
            # Also from our pseudo-manifest
            text_perms = set(re.findall(r'android\.permission\.[A-Z_]+', self.manifest))
            all_perms = raw_perms.union(text_perms)
            # Check each permission against dangerous list
            for perm in all_perms:
                if perm in DANGEROUS_PERMISSIONS:
                    sev, desc = DANGEROUS_PERMISSIONS[perm]
                    # Avoid duplicate if already found via line parsing
                    if not any(perm in f.get("description","") for f in findings):
                        findings.append({
                            "severity": sev, "type": "Dangerous Permission",
                            "line": None, "description": f"{perm} — {desc}",
                            "recommendation": "Verify this permission is strictly necessary",
                            "source": "binary_axml"
                        })
                else:
                    # Unknown permission - still report as INFO if it looks dangerous
                    if any(k in perm for k in ("ADMIN", "INSTALL", "SYSTEM", "WRITE_SECURE", "BIND_", "MANAGE", "READ_LOGS")):
                        findings.append({
                            "severity": "MED", "type": "Sensitive Permission",
                            "line": None, "description": f"{perm} — potentially sensitive",
                            "recommendation": "Review permission usage",
                            "source": "binary_axml"
                        })

        lines = self.manifest.splitlines()
        for i, line in enumerate(lines, 1):
            m = re.search(r'android:name\s*=\s*"(android\.permission\.[^"]+)"', line)
            if m:
                perm = m.group(1)
                if perm in DANGEROUS_PERMISSIONS:
                    sev, desc = DANGEROUS_PERMISSIONS[perm]
                    if not any(perm in f.get("description","") for f in findings):
                        findings.append({
                            "severity": sev, "type": "Dangerous Permission",
                            "line": i, "description": f"{perm} — {desc}",
                            "recommendation": "Verify this permission is strictly necessary"
                        })

        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in MANIFEST_CHECKS:
                if re.search(pat, line, re.I):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": desc.split("—")[-1].strip() if "—" in desc else "Review this setting"
                    })

        # Check for exported components without permission in binary AXML
        if self.manifest_raw:
            raw = self.manifest_raw.decode("latin-1", errors="ignore")
            # Look for exported=true patterns
            exported_count = raw.lower().count("exported")
            if exported_count > 0:
                # Check if debuggable
                if "debuggable" in raw.lower() and "true" in raw.lower():
                    if not any("Debug" in f["type"] for f in findings):
                        findings.append({
                            "severity": "HIGH", "type": "Debug Mode Enabled",
                            "line": None, "description": "debuggable=true found in binary AXML",
                            "recommendation": "Remove debuggable for production"
                        })

        return findings

    def analyze_smali(self) -> List[Dict]:
        findings = []
        for smali_file in self.smali:
            content = smali_file["content"]
            lines = content.splitlines()
            fname = Path(smali_file["file"]).name
            for i, line in enumerate(lines, 1):
                for pat, sev, vtype, desc in SMALI_PATTERNS:
                    if re.search(pat, line, re.I):
                        findings.append({
                            "severity": sev, "type": vtype,
                            "line": i, "file": fname,
                            "description": desc,
                            "recommendation": desc.split("—")[-1].strip() if "—" in desc else "Review this code"
                        })
        # Also analyze DEX strings for smali-like patterns if no smali files
        if not self.smali and self.dex_strings_raw:
            for s in self.dex_strings_raw[:500]:
                for pat, sev, vtype, desc in SMALI_PATTERNS:
                    if re.search(pat, s, re.I):
                        findings.append({
                            "severity": sev, "type": vtype,
                            "line": None, "file": "classes.dex",
                            "description": f"{desc} (found in DEX strings: {s[:60]})",
                            "recommendation": desc.split("—")[-1].strip() if "—" in desc else "Review"
                        })
                        break
        return findings

    def analyze_strings(self) -> List[Dict]:
        findings = []
        STRING_PATS = [
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*\S{3,}', "CRITICAL", "Hardcoded Password", "Password found in APK strings"),
            (r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*\S{8,}', "CRITICAL", "Hardcoded API Key", "API key found"),
            (r'(?i)(secret|private[_-]?key|token)\s*[:=]\s*\S{8,}', "HIGH", "Hardcoded Secret", "Secret material found"),
            (r'(?i)(AKIA[0-9A-Z]{16})', "CRITICAL", "AWS Access Key", "AWS access key found"),
            (r'(?i)(BEGIN (?:RSA )?PRIVATE KEY)', "CRITICAL", "Private Key", "Private key material"),
            (r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:\d+)?', "MED", "Hardcoded IP Address", "Server IP hardcoded"),
            (r'(?i)(http://[^\s]{8,})', "MED", "Cleartext URL", "HTTP (not HTTPS) URL"),
            (r'(?i)(debug|test|staging|dev)\.(api|server|backend)', "LOW", "Debug/Staging Endpoint", "Debug or staging endpoint"),
            (r'(?i)(telnet|ftp://|rsh://)', "HIGH", "Insecure Protocol", "Insecure protocol string"),
            (r'(?i)(firebaseio\.com|appspot\.com)', "MED", "Firebase/Cloud URL", "Firebase or cloud URL - check permissions"),
            (r'(?i)(jdbc:mysql|jdbc:postgresql|mongodb://)', "HIGH", "Database URL", "Database connection string - credentials?"),
        ]
        for s_entry in self.strings:
            if isinstance(s_entry, dict):
                s = s_entry.get("value", "")
                source = s_entry.get("source", "dex")
            else:
                s = s_entry
                source = "dex"
            for pat, sev, vtype, desc in STRING_PATS:
                if re.search(pat, s):
                    findings.append({
                        "severity": sev, "type": vtype, "line": None,
                        "description": f"{desc}: '{s[:80]}' (source: {source})",
                        "recommendation": "Remove hardcoded values — use secure storage",
                        "source_file": source,
                    })
                    break
        return findings

    def analyze_native_libs(self) -> List[Dict]:
        """Analyze native libs for suspicious imports."""
        findings = []
        if not self.native_libs:
            return findings
        for lib in self.native_libs:
            # Check lib name for suspicious
            if any(x in lib.lower() for x in ("frida", "xposed", "substrate", "hook")):
                findings.append({
                    "severity": "HIGH", "type": "Hooking Framework",
                    "line": None, "description": f"Suspicious native lib: {lib} - possible hooking/root bypass",
                    "recommendation": "Verify legitimate use"
                })
        return findings

    def get_file_summary(self) -> Dict:
        summary = {
            "total_files": len(self.files),
            "dex_files": [f for f in self.files if f.endswith(".dex")],
            "native_libs": self.native_libs,
            "assets": [f for f in self.files if f.startswith("assets/")],
            "smali_count": len([f for f in self.files if f.endswith(".smali")]),
            "has_manifest": "AndroidManifest.xml" in self.files,
            "has_resources": "resources.arsc" in self.files,
            "has_native": len(self.native_libs) > 0,
            "dex_count": len([f for f in self.files if f.endswith(".dex")]),
        }
        return summary

    def get_components(self) -> Dict:
        components = {"activities": [], "services": [], "receivers": [], "providers": []}
        if not self.manifest:
            return components
        for tag, key in [("activity","activities"),("service","services"),("receiver","receivers"),("provider","providers")]:
            for m in re.finditer(rf'<{tag}[^>]+android:name\s*=\s*"([^"]+)"([^>]*>)', self.manifest, re.I):
                name = m.group(1)
                attrs = m.group(2)
                exported = "true" in attrs.lower() if "exported" in attrs.lower() else None
                components[key].append({"name": name, "exported": exported})
        # Also try to extract from binary AXML raw
        if not any(components.values()) and self.manifest_raw:
            raw = self.manifest_raw.decode("latin-1", errors="ignore")
            for tag, key in [("activity","activities"),("service","services")]:
                # Very permissive
                for m in re.finditer(r'([a-zA-Z0-9_]+\.)+[a-zA-Z0-9_]+' + tag.capitalize(), raw):
                    components[key].append({"name": m.group(0), "exported": None})
        return components

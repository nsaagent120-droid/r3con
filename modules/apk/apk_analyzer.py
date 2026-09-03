"""
r3con - APK Analyzer
Android APK security analysis: manifest, permissions, smali, strings.
Authorized security research and bug bounty use only.
"""

import re
import zipfile
from pathlib import Path
from typing import List, Dict


DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS":        ("MED",  "Reads user contacts"),
    "android.permission.WRITE_CONTACTS":       ("MED",  "Writes user contacts"),
    "android.permission.READ_SMS":             ("HIGH", "Reads SMS messages"),
    "android.permission.SEND_SMS":             ("HIGH", "Sends SMS (financial fraud risk)"),
    "android.permission.RECEIVE_SMS":          ("HIGH", "Intercepts incoming SMS"),
    "android.permission.READ_CALL_LOG":        ("MED",  "Reads call history"),
    "android.permission.RECORD_AUDIO":         ("HIGH", "Records microphone"),
    "android.permission.CAMERA":               ("MED",  "Accesses camera"),
    "android.permission.ACCESS_FINE_LOCATION": ("MED",  "Precise GPS location"),
    "android.permission.READ_EXTERNAL_STORAGE":("LOW",  "Reads SD card"),
    "android.permission.WRITE_EXTERNAL_STORAGE":("LOW", "Writes SD card"),
    "android.permission.INTERNET":             ("INFO", "Network access"),
    "android.permission.GET_ACCOUNTS":         ("MED",  "Reads device accounts"),
    "android.permission.USE_BIOMETRIC":        ("INFO", "Biometric authentication"),
    "android.permission.INSTALL_PACKAGES":     ("HIGH", "Can install other APKs"),
    "android.permission.REQUEST_INSTALL_PACKAGES":("HIGH","Can request APK install"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":("CRITICAL","Accessibility — keylogger risk"),
    "android.permission.SYSTEM_ALERT_WINDOW":  ("HIGH", "Overlay — tapjacking risk"),
}

SMALI_PATTERNS = [
    (r'Ljava/security/MessageDigest.*MD5',   "HIGH",     "Weak Hash (MD5) in bytecode",
     "MD5 usage detected in Dalvik bytecode — use SHA-256"),
    (r'Ljavax/crypto/Cipher.*DES',           "CRITICAL", "Weak Cipher (DES) in bytecode",
     "DES usage in bytecode — use AES-256-GCM"),
    (r'Ljavax/crypto/Cipher.*ECB',           "HIGH",     "ECB Mode in bytecode",
     "ECB mode in bytecode — use GCM"),
    (r'Ljava/util/Random',                   "HIGH",     "Weak PRNG in bytecode",
     "java.util.Random not crypto-safe — use SecureRandom"),
    (r'exec\s*\(\s*["\']sh["\']|Runtime.*exec', "HIGH",  "Command Execution",
     "Runtime.exec() — verify no user-controlled input reaches here"),
    (r'openFileOutput.*MODE_WORLD_READABLE',  "HIGH",    "World-Readable File",
     "File created with MODE_WORLD_READABLE — any app can read it"),
    (r'openFileOutput.*MODE_WORLD_WRITEABLE', "HIGH",    "World-Writable File",
     "File created with MODE_WORLD_WRITEABLE — any app can overwrite it"),
    (r'getSharedPreferences.*MODE_WORLD',    "HIGH",     "World-Accessible Preferences",
     "SharedPreferences with world access mode"),
    (r'SQLiteDatabase.*rawQuery',            "MED",      "Potential SQL Injection",
     "rawQuery with string concatenation — use parameterized queries"),
    (r'WebView.*loadUrl.*javascript:',       "HIGH",     "JavaScript Injection",
     "WebView loading javascript: URL — XSS / code injection risk"),
    (r'addJavascriptInterface',              "HIGH",     "WebView JS Bridge",
     "addJavascriptInterface exposes Java to JS — RCE in old Android"),
    (r'setWebContentsDebuggingEnabled.*true', "MED",     "WebView Debugging Enabled",
     "WebView debugging enabled in production — remove for release"),
    (r'checkValidity|SSLContext.*TLS|TrustAllCerts', "MED", "SSL/TLS Usage",
     "Verify proper certificate validation — no custom TrustManager"),
    (r'ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier.*ALLOW', "CRITICAL",
     "Hostname Verification Disabled",
     "All hostnames accepted — MitM attack possible"),
    (r'X509TrustManager.*checkServerTrusted.*\{\s*\}', "CRITICAL",
     "Certificate Validation Disabled",
     "Empty checkServerTrusted — accepts any cert — MitM trivial"),
]

MANIFEST_CHECKS = [
    (r'android:debuggable\s*=\s*"true"',     "HIGH",     "Debug Mode Enabled",
     "debuggable=true in production — allows ADB debugging and data extraction"),
    (r'android:allowBackup\s*=\s*"true"',    "MED",      "Backup Enabled",
     "allowBackup=true — ADB can extract app data without root"),
    (r'android:exported\s*=\s*"true"',       "MED",      "Exported Component",
     "Component exported — accessible to other apps, verify intent handling"),
    (r'android:permission\s*=\s*""',         "HIGH",     "Empty Permission",
     "Empty permission on exported component — accessible to all apps"),
    (r'uses-permission.*INSTALL_PACKAGES',   "HIGH",     "APK Install Permission",
     "App can install other APKs — dropper/malware indicator"),
    (r'android:networkSecurityConfig',       "INFO",     "Network Security Config",
     "Custom network security config — verify no cleartext allowed"),
    (r'cleartextTrafficPermitted\s*=\s*"true"', "HIGH",  "Cleartext Traffic Allowed",
     "HTTP plaintext traffic permitted — MitM / data interception risk"),
    (r'minSdkVersion\s*=\s*"[1-9]"',        "LOW",      "Very Low minSdkVersion",
     "Very low minSdkVersion — supports ancient Android with known vulnerabilities"),
]


class APKAnalyzer:
    def __init__(self, apk_path: str):
        self.path     = apk_path
        self.manifest = ""
        self.smali    = []
        self.strings  = []
        self.files    = []
        self._loaded  = False
        self.last_error = None

    def load(self) -> bool:
        """Extract APK contents."""
        try:
            with zipfile.ZipFile(self.path, 'r') as zf:
                self.files = zf.namelist()

                # Read AndroidManifest (binary XML — try text first)
                if "AndroidManifest.xml" in self.files:
                    raw = zf.read("AndroidManifest.xml")
                    try:
                        self.manifest = raw.decode("utf-8", errors="replace")
                    except Exception:
                        self.manifest = raw.decode("latin-1", errors="replace")

                # Read smali files (Dalvik bytecode disassembly if present)
                smali_files = [f for f in self.files if f.endswith(".smali")][:30]
                for sf in smali_files:
                    try:
                        content = zf.read(sf).decode("utf-8", errors="replace")
                        self.smali.append({"file": sf, "content": content})
                    except Exception:
                        pass

                # Extract strings from DEX files
                dex_files = [f for f in self.files if f.endswith(".dex")]
                for df in dex_files[:3]:
                    try:
                        data  = zf.read(df)
                        strs  = self._extract_dex_strings(data)
                        self.strings.extend(strs)
                    except Exception:
                        pass

            self._loaded = True
            self.last_error = None
            return True
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            return False

    def _extract_dex_strings(self, data: bytes) -> List[str]:
        """Extract printable strings from DEX binary."""
        regex   = re.compile(rb'[ -~]{6,}')
        results = []
        for m in regex.finditer(data):
            s = m.group().decode("ascii", errors="ignore")
            results.append(s)
        return results[:500]

    def analyze_manifest(self) -> List[Dict]:
        """Analyze AndroidManifest.xml for security issues."""
        findings = []
        if not self.manifest:
            return [{"severity":"INFO","type":"Manifest","line":None,
                     "description":"Could not parse AndroidManifest.xml (binary XML needs aapt/apktool)",
                     "recommendation":"Run: apktool d app.apk && r3con apk manifest ./app/AndroidManifest.xml"}]

        lines = self.manifest.splitlines()

        # Permission checks
        for i, line in enumerate(lines, 1):
            m = re.search(r'android:name\s*=\s*"(android\.permission\.[^"]+)"', line)
            if m:
                perm = m.group(1)
                if perm in DANGEROUS_PERMISSIONS:
                    sev, desc = DANGEROUS_PERMISSIONS[perm]
                    findings.append({
                        "severity": sev, "type": "Dangerous Permission",
                        "line": i, "description": f"{perm} — {desc}",
                        "recommendation": "Verify this permission is strictly necessary"
                    })

        # Manifest attribute checks
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in MANIFEST_CHECKS:
                if re.search(pat, line, re.I):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": desc.split("—")[-1].strip()
                        if "—" in desc else "Review this setting"
                    })
        return findings

    def analyze_smali(self) -> List[Dict]:
        """Analyze Smali bytecode for vulnerabilities."""
        findings = []
        for smali_file in self.smali:
            content = smali_file["content"]
            lines   = content.splitlines()
            fname   = Path(smali_file["file"]).name

            for i, line in enumerate(lines, 1):
                for pat, sev, vtype, desc in SMALI_PATTERNS:
                    if re.search(pat, line, re.I):
                        findings.append({
                            "severity": sev, "type": vtype,
                            "line": i, "file": fname,
                            "description": desc,
                            "recommendation": desc.split("—")[-1].strip()
                            if "—" in desc else "Review this code"
                        })
        return findings

    def analyze_strings(self) -> List[Dict]:
        """Find security-relevant strings in the APK."""
        findings = []
        STRING_PATS = [
            (r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+',
             "CRITICAL", "Hardcoded Password", "Password found in APK strings"),
            (r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*\S{8,}',
             "CRITICAL", "Hardcoded API Key", "API key found in APK strings"),
            (r'(?i)(secret|private[_-]?key|token)\s*[=:]\s*\S{8,}',
             "HIGH", "Hardcoded Secret", "Secret material found in APK strings"),
            (r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
             "MED", "Hardcoded IP Address", "Server IP hardcoded — avoid for production"),
            (r'(?i)(http://[^\s]{8,})',
             "MED", "Cleartext URL", "HTTP (not HTTPS) URL in strings"),
            (r'(?i)(debug|test|staging|dev)\.(api|server|backend)',
             "LOW", "Debug/Staging Endpoint", "Debug or staging endpoint in strings"),
            (r'(?i)(telnet|ftp://|rsh://)',
             "HIGH", "Insecure Protocol", "Insecure protocol string found"),
        ]

        for s_entry in self.strings:
            s = s_entry["value"] if isinstance(s_entry, dict) else s_entry
            for pat, sev, vtype, desc in STRING_PATS:
                if re.search(pat, s):
                    findings.append({
                        "severity": sev, "type": vtype, "line": None,
                        "description": f"{desc}: '{s[:60]}'",
                        "recommendation": "Remove hardcoded values — use runtime config or secure storage"
                    })

        return findings

    def get_file_summary(self) -> Dict:
        """Summarize APK contents."""
        summary = {
            "total_files":    len(self.files),
            "dex_files":      [f for f in self.files if f.endswith(".dex")],
            "native_libs":    [f for f in self.files if f.endswith(".so")],
            "assets":         [f for f in self.files if f.startswith("assets/")],
            "smali_count":    len([f for f in self.files if f.endswith(".smali")]),
            "has_manifest":   "AndroidManifest.xml" in self.files,
            "has_resources":  "resources.arsc" in self.files,
        }
        return summary

    def get_components(self) -> Dict:
        """Extract Android components from manifest."""
        components = {
            "activities":  [],
            "services":    [],
            "receivers":   [],
            "providers":   [],
        }
        if not self.manifest:
            return components

        for tag, key in [("activity","activities"),("service","services"),
                          ("receiver","receivers"),("provider","providers")]:
            for m in re.finditer(
                    rf'<{tag}[^>]+android:name\s*=\s*"([^"]+)"([^>]*>)',
                    self.manifest, re.I):
                name     = m.group(1)
                attrs    = m.group(2)
                exported = "true" in attrs if "exported" in attrs else None
                components[key].append({
                    "name":     name,
                    "exported": exported,
                })
        return components

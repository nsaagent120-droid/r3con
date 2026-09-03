"""r3con v4.3.0 - Test Suite — Run: python tests/test_all.py"""
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.audit.static_analyzer import StaticAnalyzer
from modules.advanced.heap_analyzer import HeapAnalyzer
from modules.advanced.crypto_checker import CryptoChecker
from modules.advanced.kernel_patterns import KernelPatternScanner
from modules.research.research import CVEMatcher, HypothesisEngine
from modules.apk.apk_analyzer import APKAnalyzer
from modules.firmware.firmware_analyzer import FirmwareAnalyzer

p=0; f=0
def test(n,c):
    global p,f
    if c: print(f"  \033[32m✓\033[0m  {n}"); p+=1
    else: print(f"  \033[31m✗\033[0m  {n}"); f+=1
def sec(t): print(f"\n\033[36m── {t} ──\033[0m")

sec("StaticAnalyzer C")
sa=StaticAnalyzer(lang="c")
test("gets→BOF",       any("Buffer" in x["type"] or "BOF" in x["type"] for x in sa.analyze("void f(){char b[64];gets(b);}")))
test("strcpy→BOF",     any("Buffer" in x["type"] for x in sa.analyze("void f(char*s){char b[64];strcpy(b,s);}")))
test("system→CmdInj",  any("Command" in x["type"] for x in sa.analyze("void f(char*c){system(c);}")))
test("printf→FmtStr",  any("Format" in x["type"] for x in sa.analyze("void f(char*m){printf(m);}")))
test("srand→PRNG",     any("PRNG" in x["type"] or "Crypto" in x["type"] for x in sa.analyze("void f(){srand(time(NULL));}")))
test("hardcoded key",  any("Hardcoded" in x["type"] for x in sa.analyze('void f(){char key[]="secret_key_123";}')))
test("double free",    any("Double" in x["type"] for x in sa.analyze("void f(){\nchar *p=malloc(64);\nfree(p);\nfree(p);\n}")))
test("toctou",         any("TOCTOU" in x["type"] or "Race" in x["type"] for x in sa.analyze("void f(){\nif(access(fn,R_OK)==0){\nint fd=open(fn,O_RDONLY);\n}\n}")))

sec("StaticAnalyzer Python")
sa2=StaticAnalyzer(lang="python")
test("eval→inject",    any("eval" in x["type"].lower() or "Injection" in x["type"] for x in sa2.analyze("r=eval(user_input)")))
test("pickle→deser",   any("Deserialization" in x["type"] for x in sa2.analyze("data=pickle.loads(x)")))
test("shell=True",     any("Command" in x["type"] for x in sa2.analyze("subprocess.run(cmd,shell=True)")))

sec("HeapAnalyzer")
ha=HeapAnalyzer(allocator="glibc")
test("double free",    any("Double" in x["type"] for x in ha.analyze("void f(){\nchar *p=malloc(64);\nfree(p);\nfree(p);\n}")))
test("UAF",            any("Use-After-Free" in x["type"] for x in ha.analyze("void f(){\nobj_t *p=malloc(64);\nfree(p);\np->val=1;\n}")))
test("off-by-one",     any("Off" in x["type"] for x in ha.analyze("char *p=malloc(strlen(s));")))

sec("CryptoChecker")
cc=CryptoChecker()
test("MD5",            any("MD5" in x["type"] for x in cc.analyze("MD5_CTX ctx; MD5_Init(&ctx);")))
test("RC4",            any("RC4" in x["type"] for x in cc.analyze("RC4_KEY key; RC4_set_key(&key,16,data);")))
test("hardcoded key",  any("Hardcoded" in x["type"] for x in cc.analyze('char key[]="super_secret_key_123";')))
test("timing",         any("Timing" in x["type"] for x in cc.analyze("if(memcmp(hmac,expected_hmac,32)==0){}")))
test("zero IV",        any("IV" in x["type"] or "Nonce" in x["type"] for x in cc.analyze("unsigned char iv[16]={0};")))
test("weak PRNG",      any("PRNG" in x["type"] for x in cc.analyze("srand(time(NULL));int t=rand();")))

sec("KernelPatternScanner")
kps=KernelPatternScanner()
test("kmalloc overflow", any("Integer" in x["type"] for x in kps.analyze("buf=kmalloc(count*sizeof(struct item),GFP_KERNEL);")))
test("info leak",        any("Info" in x["type"] for x in kps.analyze("copy_to_user(ubuf,kbuf,size);")))
test("cred modify",      any("Credential" in x["type"] for x in kps.analyze("new_cred=prepare_creds();commit_creds(new_cred);")))
test("kernel ptr leak",  any("Pointer" in x["type"] for x in kps.analyze('printk(KERN_INFO "ptr: %p",kptr);')))

sec("CVEMatcher")
cm=CVEMatcher()
test("gets→CVE",       len(cm.extract_patterns("char buf[128]; gets(buf);"))>0)
test("MD5→CVE",        any("Crypto" in m["finding_class"] or "MD5" in m["finding_class"] for m in cm.extract_patterns("MD5_CTX c; MD5_Init(&c);")))
test("hardcoded→CVE",  any("Hardcoded" in m["finding_class"] for m in cm.extract_patterns('char password[]="admin1234";')))
test("PRNG→CVE",       any("PRNG" in m["finding_class"] for m in cm.extract_patterns("srand(time(NULL));rand();")))

sec("HypothesisEngine")
he=HypothesisEngine()
surf=he.build_attack_surface("void f(){read(fd,buf,1024);memcpy(dst,buf,n);}")
test("entry points",   len(surf["entry_points"])>0)
test("sinks",          len(surf["dangerous_sinks"])>0)

sec("APKAnalyzer")
manifest='''<?xml version="1.0"?>
<manifest package="com.test.app">
  <uses-permission android:name="android.permission.READ_SMS"/>
  <uses-permission android:name="android.permission.RECORD_AUDIO"/>
  <application android:debuggable="true" android:allowBackup="true">
    <activity android:name=".Main" android:exported="true"/>
  </application>
</manifest>'''
apk=APKAnalyzer.__new__(APKAnalyzer); apk.manifest=manifest; apk.smali=[]; apk.strings=[]
findings=apk.analyze_manifest()
test("READ_SMS detected",    any("READ_SMS" in x.get("description","") for x in findings))
test("debuggable detected",  any("Debug" in x["type"] or "debuggable" in x.get("description","").lower() for x in findings))
test("allowBackup detected", any("Backup" in x["type"] for x in findings))
test("exported detected",    any("Exported" in x["type"] for x in findings))
apk.strings=[{"value":'password=supersecret123',"offset":0,"category":"credential"}]
sf=apk.analyze_strings()
test("hardcoded password",   any("Credential" in x.get("type","") or "password" in x.get("description","").lower() for x in sf))

sec("FirmwareAnalyzer")
fw_data=(b"\x1f\x8b\x00\x00"+b"\x00"*0x400+
         b"\x7fELF\x02\x01\x01"+b"\x00"*9+b"\x02\x00\x3e\x00"+b"\x00"*100+
         b"password=admin123\x00"+b"telnetd -l /bin/sh\x00"+
         b"wget http://update.server/fw.bin\x00"+
         b"gdbserver :1234\x00"+b"/etc/passwd\x00"+b"\x00"*0x200)
with tempfile.NamedTemporaryFile(delete=False,suffix=".bin") as tmp:
    tmp.write(fw_data); tmp_path=tmp.name
try:
    fw=FirmwareAnalyzer(tmp_path); fw.load()
    id_info=fw.identify()
    test("gzip magic",      any("gzip" in c["type"] for c in id_info.get("components",[])))
    test("ELF magic",       any("ELF" in c["type"] for c in id_info.get("components",[])))
    test("arch x86_64",     any("x86_64" in h for h in id_info.get("arch_hints",[])))
    strings=fw.extract_strings(min_len=6); vals=[s["value"] for s in strings]
    test("cred string",     any("password" in v.lower() for v in vals))
    test("telnet string",   any("telnet" in v.lower() for v in vals))
    vulns=fw.scan_vulns()
    test("hardcoded cred",  any("Credential" in x["type"] or "Hardcoded" in x["type"] for x in vulns))
    test("telnet vuln",     any("Telnet" in x["type"] for x in vulns))
    test("insecure update", any("Update" in x["type"] or "update" in x.get("description","").lower() for x in vulns))
    test("debug server",    any("Debug" in x["type"] for x in vulns))
    paths=fw.find_interesting_paths()
    test("/etc/passwd",     any("/etc/passwd" in x["match"] for x in paths))
finally:
    os.unlink(tmp_path)

sec("Integration — Multi-module")
VULN="""
void auth(char *inp) {
    char buf[64]; strcpy(buf, inp);
    char *tok = malloc(strlen(inp));
    char key[] = "hardcoded_key_123";
    if (memcmp(tok, key, strlen(key)) == 0) { free(tok); return; }
    free(tok); free(tok);
}
void get_inp() { char b[128]; gets(b); printf(b); srand(time(NULL)); }
"""
all_f = sa.analyze(VULN) + ha.analyze(VULN) + cc.analyze(VULN)
test(">=6 findings",   len(all_f)>=6)
test("CRITICAL/HIGH",  any(x["severity"] in ("CRITICAL","HIGH") for x in all_f))
types=[x["type"] for x in all_f]
test("BOF found",      any("Buffer" in t or "BOF" in t for t in types))
test("crypto found",   any("Hardcoded" in t or "PRNG" in t or "Timing" in t for t in types))
test("heap found",     any("Free" in t or "UAF" in t or "Off" in t for t in types))

print(f"\n\033[36m{'='*44}\033[0m")
print(f"  Results: \033[32m{p} passed\033[0m  \033[31m{f} failed\033[0m  / {p+f} total")
print(f"\033[36m{'='*44}\033[0m")
if f==0: print("  \033[1;32mALL TESTS PASSED ✓\033[0m\n")
else:    print(f"  \033[1;31m{f} TESTS FAILED\033[0m\n"); sys.exit(1)

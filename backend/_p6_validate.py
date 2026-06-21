"""Phase 6 validation harness — run inside the backend container.

Decompiles + analyzes dvba.apk through the real pipeline, then prints the
Phase 6 deltas: findings before/after, attack chains, framework taints
suppressed, certificate findings, and manifest evidence examples.
"""
import sys, json, uuid

sys.path.insert(0, "/app")

from decompiler import decompile_apk
from analyzers.android_analyzer import analyze_apk

APK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/dvba.apk"
scan_id = "p6-" + uuid.uuid4().hex[:8]

print(f"== decompiling {APK} (scan {scan_id}) ==", flush=True)
info = decompile_apk(APK, scan_id)
print("tools_used:", info.get("tools_used"), "errors:", info.get("errors"), flush=True)

print("== analyzing ==", flush=True)
res = analyze_apk(APK, scan_id, "dvba.apk",
                  jadx_dir=info.get("jadx_dir"), apktool_dir=info.get("apktool_dir"))

findings = res.get("findings", [])
qs = res.get("finding_quality_stats", {})
mstats = res.get("manifest_evidence_stats", {})

print("\n================ PHASE 6 VALIDATION ================\n")

print("---- FINDINGS BEFORE / AFTER ----")
print("raw_total (before noise reduction):", qs.get("raw_total"))
print("kept_total (after):                ", qs.get("kept_total"))
print("application_only:                  ", qs.get("application_only_count"))
print("default_view (app + high-conf):    ", qs.get("default_view_count"))
print("suppressed_count:                  ", qs.get("suppressed_count"))
print("collapsed_duplicates:              ", qs.get("collapsed_duplicates"))
print("noise_reduction_pct:               ", qs.get("noise_reduction_pct"))

print("\n---- FRAMEWORK / LIBRARY TAINTS SUPPRESSED (Task 1) ----")
reasons = qs.get("suppressed_reasons", {})
print("suppressed_reasons:", json.dumps(reasons))
print("framework_library_taint:", reasons.get("framework_library_taint", 0))

print("\n---- ATTACK CHAINS DETECTED (Task 2) ----")
chains = [f for f in findings if f.get("is_attack_chain")]
print("attack-chain findings:", len(chains))
for c in chains:
    print(f"  [{c.get('severity','').upper():8}] conf={c.get('confidence_score')} "
          f"id={c.get('attack_chain_id')} :: {c.get('title')}")
    print(f"     members={[m['title'] for m in c.get('attack_chain_members', [])]}")
    print(f"     first_in_list={findings.index(c)==0 or all(findings[i].get('is_attack_chain') for i in range(findings.index(c)+1))}")
print("quick_summary.chain_count:", res.get("quick_summary", {}).get("chain_count"))
# verify members carry the in_attack_chain flag
marked = [f for f in findings if f.get("in_attack_chain")]
print("member findings marked in_attack_chain:", len(marked))

print("\n---- NEW CERTIFICATE FINDINGS (Task 5) ----")
certs = [f for f in findings if str(f.get("category","")).lower() == "certificate"]
# also include suppressed in case
for f in certs:
    print(f"  [{f.get('severity','').upper():8}] own={f.get('ownership_label')} :: {f.get('title')}")
    ev = (f.get('evidence') or '').strip().splitlines()
    print("     evidence:", ev[0] if ev else "(none)", "..." if len(ev) > 1 else "")
    print("     remediation:", (f.get('recommendation') or '')[:90])

print("\n---- MANIFEST EVIDENCE (Task 6) ----")
print("manifest_evidence_stats:", json.dumps({k: v for k, v in mstats.items() if k != 'examples'}))
for ex in mstats.get("examples", []):
    print(f"\n  * {ex['title']}  (AndroidManifest.xml:{ex['line']})")
    for ln in ex["snippet"].splitlines():
        print("    " + ln)
# confirm every manifest finding now has path+line+snippet
manifest_findings = [f for f in findings if f.get("evidence_type") == "manifest"]
print("\nmanifest findings in output:", len(manifest_findings))
for f in manifest_findings:
    ok = bool(f.get("file_path")) and bool(f.get("line")) and bool(f.get("file_evidence"))
    print(f"  {'OK ' if ok else 'BAD'} line={f.get('line')} path={f.get('file_path')} :: {f.get('title')}")

print("\n================ END ================\n")

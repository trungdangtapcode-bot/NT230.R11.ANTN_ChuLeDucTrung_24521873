"""Phan tich bien the co san trong dataset (muc B).
Nhom mau theo dac trung ky thuat, do dong gop tung lop va so sanh detector
5 lop (cu) vs 7 lop (moi). Chi doc du lieu, khong tao payload.
Usage: python3 analyze_variants.py [../Dataset/dataset_75_rule_labeled.csv]
"""
import csv
import os
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "Dataset", "dataset_75_rule_labeled.csv")
THRESHOLD = 50


def layers(r):
    cmd = r["CommandLine"]
    enc = bool(re.search(r"-EncodedCommand|-enc\s", cmd, re.I))
    iex, wr, net = (r[k] == "True" for k in ("HasIEX", "HasWriteAction", "HasNetworkIndicator"))
    return {
        1: 40 if re.search(r"WmiPrvSE\.exe", r["ParentImage"], re.I) else 0,
        2: 30 if enc else 0,
        3: 15 if re.search(r"NT AUTHORITY\\SYSTEM", r["ParentUser"], re.I) and not re.search(r"svchost|TrustedInstaller", cmd, re.I) else 0,
        4: 15 if int(r.get("WmiSubCount") or 0) >= 2 and (re.search(r"WmiPrvSE\.exe", r["ParentImage"], re.I) or r["ParentImage"].strip() in ("-", "")) else 0,
        5: 25 if re.search(r"-WindowStyle\s+Hidden", cmd, re.I) and enc else 0,
        6: 60 if net else 55 if (iex and wr) else 15 if iex else 0,
        7: 20 if (enc or iex) and r["ScriptOnDisk"] != "True" else 0,
    }


def variant(r):
    cmd = r["CommandLine"]
    wmi = bool(re.search(r"WmiPrvSE\.exe", r["ParentImage"], re.I))
    enc = bool(re.search(r"-EncodedCommand|-enc\s", cmd, re.I))
    hid = bool(re.search(r"-WindowStyle\s+Hidden", cmd, re.I))
    iex = r["HasIEX"] == "True"
    if r["Label"] == "benign":
        if iex: return "B1 benign IEX chi doc"
        if re.search(r"-File\s+\S+\.ps1", cmd, re.I): return "B2 benign -File .ps1"
        if enc: return "B3 benign encoded hop le"
        return "B3 benign console/-Command"
    if wmi: return "V1 Fileless qua WMI"
    if enc and hid: return "V2 Encoded + Hidden"
    if enc: return "V3 Encoded, khong an cua so"
    if iex: return "V4 IEX inline"
    return "V? khac"


rows = list(csv.DictReader(open(path, encoding="utf-8-sig")))
buckets = {}
for r in rows:
    v = variant(r)
    L = layers(r)
    full = sum(L.values())
    old = full - L[4] - L[7]  # detector cu = bo lop 4 va 7
    b = buckets.setdefault(v, {"n": 0, "fire": {i: 0 for i in range(1, 8)}, "full": [], "old": [], "det7": 0, "det5": 0})
    b["n"] += 1
    b["full"].append(full)
    b["old"].append(old)
    b["det7"] += full >= THRESHOLD
    b["det5"] += old >= THRESHOLD
    for i in range(1, 8):
        if L[i] > 0: b["fire"][i] += 1

ORDER = ["V1", "V2", "V3", "V4", "B1", "B2", "B3"]
keys = sorted(buckets, key=lambda k: next((i for i, o in enumerate(ORDER) if k.startswith(o)), 99))

print(f"{'Bien the':30} {'n':>3} {'lop fire':20} {'diem7':>6} {'det7':>6} {'diem5':>6} {'det5':>6}")
print("-" * 82)
for k in keys:
    b = buckets[k]
    fired = "+".join(f"L{i}" for i in range(1, 8) if b["fire"][i] == b["n"]) or "-"
    f7 = f"{min(b['full'])}" if min(b['full']) == max(b['full']) else f"{min(b['full'])}-{max(b['full'])}"
    f5 = f"{min(b['old'])}" if min(b['old']) == max(b['old']) else f"{min(b['old'])}-{max(b['old'])}"
    print(f"{k:30} {b['n']:>3} {fired:20} {f7:>6} {b['det7']:>3}/{b['n']:<2} {f5:>6} {b['det5']:>3}/{b['n']:<2}")

print("\nGhi chu: det7 = detector 7 lop (moi), det5 = detector 5 lop (cu, bo L4+L7).")
print("V3 la bien the duy nhat lat tu 'bo sot' (5 lop) sang 'phat hien' (7 lop) nho lop memory.")

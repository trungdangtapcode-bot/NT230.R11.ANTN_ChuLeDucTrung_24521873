"""Ban Python doc lap cua detector.ps1 (cung 7 lop, cung trong so).

Usage:
  python3 verify_metrics.py [dataset.csv] [--disable 4,7] [--by Scenario] [--split 0.5]

  --disable 4,7   tat bot lop (ablation)
  --by COT        thong ke theo nhom (vd Scenario, Source): so mau, so bi bao dong
  --split F       sap theo TimeCreated, F dau = dev (de chinh detector), phan con lai = test
                  (chi bao cao ket qua test trong bao cao de tranh "hoc tu")
"""
import csv
import os
import re
import sys
from collections import defaultdict
from datetime import datetime

args = sys.argv[1:]


def take(flag):
    if flag in args:
        i = args.index(flag)
        v = args[i + 1]
        del args[i:i + 2]
        return v
    return None


disabled = {int(x) for x in (take("--disable") or "").split(",") if x}
by = take("--by")
split = take("--split")
path = args[0] if args else os.path.join(os.path.dirname(__file__), "..", "Dataset", "dataset.csv")
THRESHOLD = 50


def score(r):
    cmd = r["CommandLine"]
    enc = bool(re.search(r"-EncodedCommand|-enc\s", cmd, re.I))
    iex, wr, net = (r[k] == "True" for k in ("HasIEX", "HasWriteAction", "HasNetworkIndicator"))
    layers = {
        1: 40 if re.search(r"WmiPrvSE\.exe", r["ParentImage"], re.I) else 0,
        2: 30 if enc else 0,
        3: 15 if re.search(r"NT AUTHORITY\\SYSTEM", r["ParentUser"], re.I)
              and not re.search(r"svchost|TrustedInstaller", cmd, re.I) else 0,
        4: 15 if int(r.get("WmiSubCount") or 0) >= 2 and (re.search(r"WmiPrvSE\.exe", r["ParentImage"], re.I) or r["ParentImage"].strip() in ("-", "")) else 0,
        5: 25 if re.search(r"-WindowStyle\s+Hidden", cmd, re.I) and re.search(r"-EncodedCommand", cmd, re.I) else 0,
        6: 60 if net else 55 if (iex and wr) else 15 if iex else 0,
        7: 20 if (enc or iex) and r["ScriptOnDisk"] != "True" else 0,
    }
    return sum(v for k, v in layers.items() if k not in disabled)


def metrics(rows, name):
    tp = fp = tn = fn = 0
    for r in rows:
        pred = score(r) >= THRESHOLD
        mal = r["Label"] == "malicious_fileless"
        tp += pred and mal
        fp += pred and not mal
        tn += (not pred) and (not mal)
        fn += (not pred) and mal
    p = tp / (tp + fp) if tp + fp else 0
    rc = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * p * rc / (p + rc) if p + rc else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    print(f"[{name}] Records={len(rows)}  disabled_layers={sorted(disabled) or '-'}")
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"  Precision={p:.2%}  Recall={rc:.2%}  F1={f1:.2%}  FPR={fpr:.2%}")


def parse_time(t):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(t.strip(), fmt)
        except ValueError:
            pass
    return None


rows = list(csv.DictReader(open(path, encoding="utf-8-sig")))
metrics(rows, "ALL")

if split:
    times = [parse_time(r.get("TimeCreated", "")) for r in rows]
    if all(times):
        rows_sorted = [r for _, r in sorted(zip(times, rows), key=lambda x: x[0])]
        k = int(len(rows_sorted) * float(split))
        metrics(rows_sorted[:k], "DEV ")
        metrics(rows_sorted[k:], "TEST")
    else:
        print("Khong doc duoc TimeCreated -> bo qua --split")

if by:
    g = defaultdict(lambda: [0, 0, 0])  # n, alerts, malicious
    for r in rows:
        key = r.get(by, "?")
        g[key][0] += 1
        g[key][1] += score(r) >= THRESHOLD
        g[key][2] += r["Label"] == "malicious_fileless"
    print(f"\nTheo {by}:")
    print(f"  {'nhom':22} {'n':>5} {'canh bao':>9} {'ty le':>7}  nhan")
    for key, (n, a, m) in sorted(g.items(), key=lambda kv: -kv[1][0]):
        lab = "malicious" if m == n else "benign" if m == 0 else "mixed"
        print(f"  {key:22} {n:>5} {a:>9} {a / n:>7.1%}  {lab}")

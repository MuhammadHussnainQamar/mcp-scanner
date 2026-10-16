#!/usr/bin/env python3
"""
rug_pull_check.py - detect silent changes in MCP tools between versions.

A "rug pull" is a server that looks clean when you approve it and changes
behavior after an update. This tool stores a fingerprint (SHA-256) of every
tool when you approve it, then compares later snapshots against it.
Changed tools are also re-scanned with mcp_scan.py's rules.

Usage:
    python rug_pull_check.py save  tools.json baseline.json   # approve now
    python rug_pull_check.py check tools_new.json baseline.json
"""
import difflib
import hashlib
import json
import sys

from mcp_scan import scan_text


def load_tools(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    tools = data["tools"] if isinstance(data, dict) else data
    return {t["name"]: t for t in tools}


def fingerprint(tool):
    # canonical JSON so key order does not change the hash
    blob = json.dumps(tool, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def cmd_save(tools_path, baseline_path):
    tools = load_tools(tools_path)
    baseline = {n: {"hash": fingerprint(t), "tool": t} for n, t in tools.items()}
    with open(baseline_path, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2, ensure_ascii=False)
    print(f"Baseline saved: {len(baseline)} tools -> {baseline_path}")


def cmd_check(tools_path, baseline_path):
    new = load_tools(tools_path)
    with open(baseline_path, encoding="utf-8") as fh:
        base = json.load(fh)

    added = [n for n in new if n not in base]
    removed = [n for n in base if n not in new]
    changed = [n for n in new if n in base and fingerprint(new[n]) != base[n]["hash"]]

    print("=" * 60)
    print("RUG-PULL CHECK")
    print("=" * 60)

    for n in changed:
        old_desc = base[n]["tool"].get("description", "")
        new_desc = new[n].get("description", "")
        print(f"\n[CHANGED] {n}")
        diff = difflib.unified_diff(old_desc.split(), new_desc.split(),
                                    "approved", "now", lineterm="", n=0)
        for line in diff:
            if line.startswith(("+++", "---", "@@")):
                continue
            print("   ", line)
        hits = scan_text(new_desc)
        if hits:
            print("    !! new description trips scanner rules:")
            for h in hits:
                print(f"       - {h['rule']}: \"{h['match']}\"")
    for n in added:
        hits = scan_text(new[n].get("description", ""))
        flag = "  !! scanner hits: " + ", ".join(h["rule"] for h in hits) if hits else ""
        print(f"\n[ADDED]   {n} (not in approved baseline){flag}")
    for n in removed:
        print(f"\n[REMOVED] {n}")

    unchanged = len(new) - len(changed) - len(added)
    print(f"\nSummary: changed={len(changed)}, added={len(added)}, "
          f"removed={len(removed)}, unchanged={unchanged}")
    if changed or added:
        print("Re-approve manually only after reading the diff.")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("save", "check"):
        print(__doc__)
        sys.exit(2)
    {"save": cmd_save, "check": cmd_check}[sys.argv[1]](sys.argv[2], sys.argv[3])

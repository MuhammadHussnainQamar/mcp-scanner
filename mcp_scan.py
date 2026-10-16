#!/usr/bin/env python3
"""
mcp_scan.py - a small defensive scanner for MCP tool descriptions.

It reads a tools list (JSON, same shape as an MCP `tools/list` result) and
flags patterns often linked to tool poisoning, hidden instructions and
preference manipulation. It is a heuristic: it finds suspicious wording,
it does not prove a tool is malicious or safe.

Usage:
    python mcp_scan.py tools.json
    python mcp_scan.py tools.json --json     # machine-readable output
"""
import argparse
import json
import re
import sys
import unicodedata

# (rule id, severity, regex, explanation)
RULES = [
    ("override-instructions", 3,
     r"ignore (all |any )?(previous|prior|above) (instructions|rules)|disregard (the )?(user|system)",
     "Tries to override the AI's existing instructions"),
    ("secrecy", 3,
     r"(do not|don't|never) (tell|inform|mention|show|reveal|notify)( this)?( to)?( the)? user|without (telling|informing|notifying) the user|keep this (secret|hidden)",
     "Asks the AI to hide behavior from the user"),
    ("hidden-block-tag", 2,
     r"<\s*(important|system|instructions?|secret|hidden)\s*>",
     "Special tag often used to smuggle instructions into descriptions"),
    ("sensitive-path", 3,
     r"~/\.ssh|id_rsa|\.env\b|/etc/passwd|credentials?\.json|\.aws/|api[_ -]?key|private key|\btoken\b",
     "References secrets or sensitive files"),
    ("exfiltration", 3,
     r"(send|post|upload|forward|email|exfiltrate)\b[^.]{0,60}\b(to|at)\b[^.]{0,40}(https?://|@|server|address)",
     "Looks like data being sent somewhere else"),
    ("external-url", 1,
     r"https?://[^\s)\"']+",
     "Contains a URL (check if it is expected for this tool)"),
    ("preference-manipulation", 2,
     r"always (use|pick|choose|prefer|call) (this|me)|best tool|only tool you need|(must|should) (be )?(use|used|called) (first|before)|instead of (any )?other tools?",
     "Tries to steer the AI into choosing this tool over others"),
    ("superlative-claim", 2,
     r"\b(best|greatest|top|#1|number one)\b[^.!?]{0,40}\b(tool|option|choice)\b|\bmost (reliable|trusted|accurate|secure|powerful)\b",
     "Boasts that this tool is the best (marketing language, not a description)"),
    ("authority-claim", 1,
     r"trusted by (experts|everyone|millions|professionals)|recommended by (experts|everyone)|always (correct|accurate|right)|never (fails|wrong)",
     "Claims authority or perfection to gain the AI's trust"),
    ("displace-others", 2,
     r"(use this|use me|pick this|choose this)[^.!?]{0,20}(instead of|rather than)[^.!?]{0,15}(other|others|alternatives|competitors)|instead of (any )?(the )?(other|others|alternatives|competitors)\b|don't use (any )?other",
     "Tells the AI to skip other tools in favor of this one"),
    ("cross-tool-instruction", 2,
     r"before (using|calling) (any )?(other )?tool|when (using|calling) (the )?[a-z_]+ tool,? (also|first)|also (call|use|run) [a-z_]+",
     "Gives instructions about OTHER tools (possible tool-chaining attack)"),
    ("shell-exec", 2,
     r"\b(os\.system|subprocess|exec\(|eval\(|rm -rf|curl [^|]*\| ?sh|powershell)\b",
     "Mentions command execution"),
]

INVISIBLE_CATEGORIES = {"Cf", "Cc"}  # format / control characters
MAX_REASONABLE_LEN = 1000


def invisible_chars(text):
    found = []
    for ch in text:
        if ch in "\n\r\t":
            continue
        if unicodedata.category(ch) in INVISIBLE_CATEGORIES:
            found.append(f"U+{ord(ch):04X}")
    return found


def scan_text(text):
    findings = []
    for rule_id, sev, pattern, why in RULES:
        for m in re.finditer(pattern, text, flags=re.IGNORECASE):
            findings.append({
                "rule": rule_id, "severity": sev,
                "match": m.group(0)[:80], "why": why,
            })
    inv = invisible_chars(text)
    if inv:
        findings.append({
            "rule": "invisible-characters", "severity": 3,
            "match": ", ".join(sorted(set(inv))),
            "why": "Hidden/zero-width characters can conceal text from humans",
        })
    if len(text) > MAX_REASONABLE_LEN:
        findings.append({
            "rule": "very-long-description", "severity": 1,
            "match": f"{len(text)} chars",
            "why": "Unusually long descriptions can bury instructions",
        })
    return findings


READ_WORDS = {"read", "get", "list", "fetch", "open", "search", "query",
              "load", "download", "view", "cat"}
ACT_WORDS = {"write", "send", "post", "email", "mail", "upload", "delete",
             "remove", "execute", "exec", "run", "forward", "publish",
             "save", "shell", "command"}


def name_words(name):
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
    return set(re.findall(r"[a-z]+", spaced.lower()))


def chain_check(results):
    """Set-level check: read-type tools + write/send/execute-type tools
    on the same server can be chained into an attack, even when each
    tool looks harmless alone. Judged from tool NAMES only (heuristic)."""
    reads = [r["tool"] for r in results if name_words(r["tool"]) & READ_WORDS]
    acts = [r["tool"] for r in results if name_words(r["tool"]) & ACT_WORDS]
    if reads and acts:
        return reads, acts
    return None


def verdict(score):
    if score == 0:
        return "CLEAN"
    if score < 4:
        return "REVIEW"
    return "SUSPICIOUS"


def scan_tools(data):
    tools = data["tools"] if isinstance(data, dict) else data
    results = []
    for tool in tools:
        name = tool.get("name", "<unnamed>")
        # scan the description and any parameter descriptions too
        texts = [("description", tool.get("description", ""))]
        props = (tool.get("inputSchema") or {}).get("properties", {})
        for pname, pdef in props.items():
            texts.append((f"param:{pname}", pdef.get("description", "")))
        findings = []
        for where, text in texts:
            for f in scan_text(text or ""):
                f["where"] = where
                findings.append(f)
        score = sum(f["severity"] for f in findings)
        results.append({"tool": name, "score": score,
                        "verdict": verdict(score), "findings": findings})
    return results


def print_report(results):
    print("=" * 60)
    print("MCP TOOL DESCRIPTION SCAN")
    print("=" * 60)
    for r in sorted(results, key=lambda x: -x["score"]):
        print(f"\n[{r['verdict']}] {r['tool']}  (score {r['score']})")
        for f in r["findings"]:
            print(f"   - ({f['severity']}) {f['rule']} in {f['where']}: "
                  f"\"{f['match']}\"")
            print(f"       {f['why']}")
    chain = chain_check(results)
    if chain:
        reads, acts = chain
        print("\n" + "-" * 60)
        print("[REVIEW] SET-LEVEL: possible tool chaining")
        print("   read-type tools :", ", ".join(reads))
        print("   write/send/run  :", ", ".join(acts))
        print("   Each tool may look harmless alone, but an AI could chain")
        print("   them (read private data, then write/send it out).")
        print("   Check permissions and keep confirmations ON for these.")
        print("-" * 60)

    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print("\nSummary:", ", ".join(f"{k}={v}" for k, v in counts.items()))
    print("Note: heuristic scanner. REVIEW/SUSPICIOUS means 'a human should look', "
          "CLEAN does not guarantee safety.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="JSON file with MCP tools")
    ap.add_argument("--json", action="store_true", help="print JSON output")
    args = ap.parse_args()
    with open(args.file, encoding="utf-8") as fh:
        data = json.load(fh)
    results = scan_tools(data)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results)
    # non-zero exit if anything suspicious, handy for CI
    sys.exit(1 if any(r["verdict"] == "SUSPICIOUS" for r in results) else 0)


if __name__ == "__main__":
    main()

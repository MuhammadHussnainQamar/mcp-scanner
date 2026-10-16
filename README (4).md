# mcp-scanner

Two small defensive tools for checking MCP (Model Context Protocol) tool descriptions. They were built for a blog post about MCP security risks, based on the research paper *Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions* (Hou et al., 2026).

> **These are learning tools, not a full defence.** A CLEAN verdict never means a tool is safe. It only means none of the simple rules matched. A REVIEW or SUSPICIOUS verdict means a human should take a look.

## What is in this repository

| File | What it does |
|---|---|
| `mcp_scan.py` | Reads each tool's description and parameter descriptions and checks them against pattern rules (hidden tags, "do not tell the user", secret key paths, data being sent to an address, "always use me" wording, and more). Each tool gets a score and a verdict: CLEAN, REVIEW or SUSPICIOUS. It also runs one extra check on the whole tool set, warning when read-type tools and write/run-type tools appear together. |
| `rug_pull_check.py` | Saves a SHA-256 fingerprint of each approved tool. Later, it reports tools that were changed, added or removed, prints the new words and scans them with the same rules. |
| `get_tools.py` | Starts a local MCP server, asks it for its tool list (the MCP `tools/list` request) and saves the result as JSON. It never calls a tool. |

## Requirements

- Python 3.13 (other recent versions may work, but this is what I tested on)
- Windows 10 (tested), the commands below use the Command Prompt
- The MCP package, **version 1.x**:

```
pip install "mcp<2"
```

Version 2.x of the MCP package renamed `FastMCP`, which the paper's demo servers use. If you install the latest version, the demos stop with a "Connection closed" error that does not explain the real cause. Pinning to `mcp<2` (I used 1.30.0) fixes it.

## How to use

**1. Save a server's tool list as JSON**

```
python get_tools.py Examples\tool_poisoning.py poisoning_tools.json
```

The first argument is the MCP server file, the second is the JSON file to write. The demo servers come from the paper's repository (see below).

**2. Scan the tool descriptions**

```
python mcp_scan.py poisoning_tools.json
```

You get one verdict per tool, with the rules that matched and a short reason for each.

**3. Check for rug pulls**

First save a baseline of the tools you have approved (run `python rug_pull_check.py` without arguments to see the usage). Later, check a new version of the tool list against that baseline:

```
python rug_pull_check.py check clean_tools_v2.json baseline.json
```

The checker reports each tool as changed, added, removed or unchanged. Re-approve a tool manually only after reading the difference.

## Scoring

Each rule has a severity from 1 to 3, and a tool's score is the sum of what it finds.

| Score | Verdict |
|---|---|
| 0 | CLEAN |
| 1 to 3 | REVIEW |
| 4 or more | SUSPICIOUS |

## What it catches and what it misses

| Attack | Result |
|---|---|
| Tool poisoning | Caught. Hidden instructions and data-sending wording are in the description. |
| Rug pull | Caught by `rug_pull_check.py`. Any change in a description changes its fingerprint. |
| Preference manipulation | Caught after I made the rules more flexible. My first rules were too exact and missed it. |
| Indirect prompt injection | Missed. The danger is in the data a tool returns, not in its description. |
| Tool chaining | Missed tool by tool. Only the whole-set check gives a warning. |

## Safety

I only asked each demo server for its tool list. I never called a tool, so no attack was carried out. Run the demo servers only on your own machine.

## Demo servers

The deliberately insecure demo servers are **not** included here. They belong to the paper's authors: [github.com/security-pride/MCP_Landscape](https://github.com/security-pride/MCP_Landscape) (see the `Examples` folder).

## Author

Hussnain, Cybersecurity Student, KFUEIT.

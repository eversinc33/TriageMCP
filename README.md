# TriageMCP

MCP server to enable an LLM to do basic static triage of a PE. 

A minimal prompt idea could be:

```
You are a malware analyst tasked to analyse the sample at <PATH> with your MCP tools. Create a markdown report that summarizes your findings. 
```

Of course supplying more info will usually result in a better result.

### Installation

Install dependencies

```powershell
pip install pefile yara-python die-python fastmcp
```

Adjust `triage.py` and change `<TOOL>_EXE_PATH` and `YARA_RULE_PATH` accordingly. Then run:

```powershell
fastmcp install .\triage.py
```

### TODO

* VT/AnyRun/Sandbox integration
* Hash lookup

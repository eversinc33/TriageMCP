# TriageMCP

MCP server to enable an LLM to do basic static triage of a PE. 

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
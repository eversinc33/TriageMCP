# TriageMCP

MCP server to enable an LLM to do basic static triage of a PE. 

A minimal prompt idea could be:

```
You are a malware analyst tasked to analyse the sample at <PATH> with your MCP tools. Create a markdown report that summarizes your findings. 
```

Of course supplying more info will usually yield a better result.

## Installation
Install dependencies:

```shell
pip install pefile yara-python die-python mcp[cli]
```

Then adjust `triage.py` and change `<TOOL>_EXE_PATH` and `YARA_RULE_PATH` accordingly.

### Claude Desktop Integration
You can install this server in Claude Desktop and interact with it right away by running:

```shell
mcp install .\triage.py
```

## Different transport protocol
By default, without using arguments, the server will use `stdio` transport:

```shell
.\triage.py
```

To use `SSE` transport:

```shell
.\triage.py --transport http://127.0.0.1:8744
```

## TODO

* VT/AnyRun/Sandbox integration
* Hash lookup
* Streamable HTTP transport

import os
import die
import pefile
import hashlib
import datetime
import math
import subprocess
import json
import yara
from mcp.server.fastmcp import FastMCP
import argparse
from urllib.parse import urlparse

FLOSS_EXE_PATH="C:\\Tools\\FLOSS\\floss.exe"
UPX_EXE_PATH="C:\\Tools\\upx\\upx-5.1.0-win64\\upx.exe"
CAPA_EXE_PATH="C:\\Tools\\capa\\capa.exe"
YARA_RULE_PATH="C:\\Tools\\yara-forge\\"

mcp = FastMCP("TriageMCP", log_level="ERROR")

# --------------------------------------------
# Utils

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    for f in freq:
        if f:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy

@mcp.tool("list_directory")
def list_directory(path: str = ".") -> dict:
    """
    If the user asks for analysis of multiple files in a directory, this can be used to list the contents of a directory on the local filesystem.
    
    Args:
        path: Path to the directory to list. Defaults to current directory.
              Can include ~ for home directory.
        
    Returns:
        A dictionary with information about the directory contents.
    """
    expanded_path = os.path.expanduser(path)
    
    if not os.path.exists(expanded_path):
        raise FileNotFoundError(f"Directory not found: {expanded_path}")
    
    if not os.path.isdir(expanded_path):
        raise ValueError(f"Not a directory: {expanded_path}")
    
    files = []
    for item in os.listdir(expanded_path):
        item_path = os.path.join(expanded_path, item)
        item_info = {
            "name": item,
            "is_dir": os.path.isdir(item_path),
            "size": os.path.getsize(item_path) if os.path.isfile(item_path) else None,
            "path": item_path
        }
        files.append(item_info)
    
    return {
        "files": files,
        "path": expanded_path,
        "count": len(files)
    }

@mcp.tool("get_hashes") 
def get_hashes(file_path: str) -> dict:
    """
    Calculate file hashes for a PE
    
    Args:
        file_path: Full or relative path to the file to analyze
        
    Returns:
        A dictionary with the md5, sha256 and sha512 hash of the file.
    """
    hashes = {
        "md5": hashlib.md5(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512()
    }

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)

    return {k: v.hexdigest() for k, v in hashes.items()}

# --------------------------------------------
# PE analysis
@mcp.tool("get_IAT")
def get_IAT(file_path: str) -> dict:
    """
    List the Import Address Table (IAT) of a PE
    
    Args:
        file_path: Full or relative path to the file to analyze
        
    Returns:
        A dictionary with information about the IAT.
    """
    pe = pefile.PE(file_path)
    iat = {}
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return iat

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode()
        imports = []
        for imp in entry.imports:
            imp_name = imp.name.decode() if imp.name else f"ordinal_{imp.ordinal}"
            imports.append({
                'address': hex(imp.address),
                'name': imp_name
            })
        iat[dll_name] = imports
    return iat

@mcp.tool("get_EAT")
def get_EAT(file_path: str) -> dict:
    """
    List the Export Address Table (EAT) of a PE
    
    Args:
        file_path: Full or relative path to the file to analyze
        
    Returns:
        A dictionary with information about the EAT.
    """
    pe = pefile.PE(file_path)
    eat = {}
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return eat

    dll_name = pe.get_string_at_rva(pe.DIRECTORY_ENTRY_EXPORT.name).decode()
    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode() if exp.name else f"ordinal_{exp.ordinal}"
        exports.append({
            'address': hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
            'name': name
        })
    eat[dll_name] = exports
    return eat

@mcp.tool("get_sections")
def get_sections(file_path: str) -> dict:
    """
    Get information about the PE's sections, including their names, sizes, properties and entropy.
    
    Args:
        file_path: Full or relative path to the file to analyze
        
    Returns:
        A dictionary with information about the sections.
    """
    pe = pefile.PE(file_path)
    sections_info = {}

    for section in pe.sections:
        name = section.Name.rstrip(b'\x00').decode(errors='ignore')
        data = section.get_data()
        sections_info[name] = {
            'virtual_address': hex(section.VirtualAddress),
            'virtual_size': hex(section.Misc_VirtualSize),
            'raw_size': hex(section.SizeOfRawData),
            'characteristics': hex(section.Characteristics),
            'entropy': round(calculate_entropy(data), 4)
        }

    return sections_info

@mcp.tool("get_pe_metadata")
def get_pe_metadata(file_path: str) -> dict:
    """
    Gets metadata information of the PE, such as timestamps, compilers, original filename or architecture.
    
    Args:
        file_path: Full or relative path to the file to analyze
        
    Returns:
        A dictionary with PE metadata.
    """
    pe = pefile.PE(file_path)
    metadata = {}

    metadata['machine'] = hex(pe.FILE_HEADER.Machine)
    metadata['number_of_sections'] = pe.FILE_HEADER.NumberOfSections
    metadata['timestamp'] = datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat() + 'Z'
    metadata['characteristics'] = hex(pe.FILE_HEADER.Characteristics)

    metadata['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    metadata['image_base'] = hex(pe.OPTIONAL_HEADER.ImageBase)
    metadata['subsystem'] = hex(pe.OPTIONAL_HEADER.Subsystem)
    metadata['dll_characteristics'] = hex(pe.OPTIONAL_HEADER.DllCharacteristics)
    metadata['architecture'] = 'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'

    try:
        rich_header = pe.parse_rich_header()
        metadata['rich_header'] = [
            {
                'tool_id': hex(entry['id']),
                'version': entry['version'],
                'count': entry['count']
            } for entry in rich_header['values']
        ]
    except:
        metadata['rich_header'] = None

    metadata['original_filename'] = None
    metadata['certificate_present'] = False

    if hasattr(pe, 'FileInfo'):
        for fileinfo in pe.FileInfo:
            if fileinfo.Key == b'StringFileInfo':
                for st in fileinfo.StringTable:
                    for k, v in st.entries.items():
                        key = k.decode(errors='ignore')
                        val = v.decode(errors='ignore')
                        metadata[key] = val
                        if key.lower() == 'originalfilename':
                            metadata['original_filename'] = val

    for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if entry.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY' and entry.VirtualAddress != 0:
            metadata['certificate_present'] = True
            break

    return metadata

# --------------------------------------------
# External Tools

@mcp.tool("run_detect-it-easy")
def run_die(file_path: str) -> dict:
    """
    Runs detect it easy to identify the type and characteristics of binary
    
    Args:
        file_path: Full or relative path to the file to analyze
        
    Returns:
        JSON info about the PE.
    """
    return die.scan_file(file_path, die.ScanFlags.VERBOSE_FLAG | die.ScanFlags.DEEP_SCAN | die.ScanFlags.HEURISTIC_SCAN | die.ScanFlags.RECURSIVE_SCAN | die.ScanFlags.RESULT_AS_JSON, str(die.database_path/'db'))

@mcp.tool("run_yara-scan")
def run_yara_scan(file_path: str) -> dict:
    """
    Runs a yara scan with all rules in YARA_RULE_PATH on the PE.
    
    Args:
        file_path: Full or relative path to the file to analyze
        
    Returns:
        A dictionary with YARA matches.
    """
    rules = {}
    for root, _, files in os.walk(YARA_RULE_PATH):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                rule_path = os.path.join(root, file)
                rules[file] = rule_path

    compiled_rules = yara.compile(filepaths=rules)
    matches = compiled_rules.match(file_path)
    result = {}
    for match in matches:
        result[match.rule] = {
            'tags': match.tags,
            'meta': match.meta,
        }

    return result

@mcp.tool("run_capa-scan")
def run_capa_scan(file_path: str) -> dict:
    """
    Runs capa on the binary to get info about its capabilities.
    
    Args:
        file_path: Full or relative path to the file to analyze
        
    Returns:
        A dictionary with information about the PEs capabilities.
    """
    try:
        if os.path.isfile(CAPA_EXE_PATH):
            output = subprocess.check_output(
                [CAPA_EXE_PATH, "-q", file_path],
                stderr=subprocess.DEVNULL,
                encoding='utf-8',
                errors='replace',
                universal_newlines=True
            )
            return output
        else:
            return {"error": "capa.exe not found"}
    except subprocess.CalledProcessError:
        return {"error": "capa execution failed"}
    except json.JSONDecodeError:
        return {"error": "invalid JSON output from capa"}

@mcp.tool("run_floss")
def run_floss(file_path: str) -> dict:
    """
    Runs floss on the binary to get plaintext strings and automatically deobfuscate any obfuscated strings.
    
    Args:
        file_path: Full or relative path to the file to analyze
        
    Returns:
        A list of strings.
    """
    try:
        if os.path.isfile(FLOSS_EXE_PATH):
            output = subprocess.check_output(
                [FLOSS_EXE_PATH, file_path],
                stderr=subprocess.DEVNULL,
                universal_newlines=True
            )
            return output
        else:
            return {"error": "floss.exe not found"}
    except subprocess.CalledProcessError:
        return {"error": "floss execution failed"}
    except json.JSONDecodeError:
        return {"error": "invalid JSON output from floss"}

# --------------------------------------------
# unpacking

@mcp.tool("upx_unpack")
def upx_unpack(file_path: str) -> dict:
    """
    Runs upx.exe to unpack the binary. 
    
    Args:
        file_path: Full or relative path to the file to analyze
        
    Returns:
        A dictionary with the result whether the unpacking was successful and if yes, the filepath of the unpacked PE.
    """
    unpacked_path = file_path + ".unpacked"
    try:
        # Copy original to new path to avoid overwriting
        with open(file_path, "rb") as src, open(unpacked_path, "wb") as dst:
            dst.write(src.read())

        result = subprocess.run(
            [UPX_EXE_PATH, "-d", unpacked_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )

        success = result.returncode == 0
        return {
            "success": success,
            "unpacked_file": unpacked_path if success else None
        }
    except Exception:
        return {
            "success": False,
            "unpacked_file": None
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP server for static PE analysis.")
    parser.add_argument("--transport", type=str, default="stdio", help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)")
    args = parser.parse_args()

    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            mcp.settings.host = url.hostname
            mcp.settings.port = url.port
            print(f"MCP Server availabile at http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.settings.log_level = "INFO"
            mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass

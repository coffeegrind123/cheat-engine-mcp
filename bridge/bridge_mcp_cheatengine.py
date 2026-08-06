# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import requests
import logging
import re
import time
import json
import os
import sys
from typing import Any, Union

from mcp.server.fastmcp import FastMCP
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_CE_SERVER = "http://host.docker.internal:6789"

ENDPOINT_TIMEOUTS = {
    "scan_all": 120,
    "next_scan": 60,
    "aob_scan": 120,
    "aob_scan_unique": 120,
    "aob_scan_module": 120,
    "aob_scan_module_unique": 120,
    "search_string": 120,
    "persistent_scan_first_scan": 120,
    "persistent_scan_next_scan": 120,
    "pointer_rescan": 300,
    "auto_assemble": 300,
    "auto_assemble_check": 60,
    "compile_c_code": 120,
    "compile_cs_code": 120,
    "evaluate_lua": 300,
    "find_references": 60,
    "find_call_references": 60,
    "analyze_function": 60,
    "find_function_boundaries": 60,
    "start_dbvm_watch": 30,
    "poll_dbvm_watch": 30,
    "stop_dbvm_watch": 30,
    "execute_code": 60,
    "execute_code_ex": 60,
    "execute_method": 60,
    "execute_code_local": 60,
    "execute_code_local_ex": 60,
    "inject_dll": 60,
    "inject_dotnet_dll": 120,
    "dissect_structure": 60,
    "get_memory_regions": 60,
    "enum_memory_regions_full": 60,
    "enable_windows_symbols": 60,
    "enable_kernel_symbols": 60,
    "load_new_symbols": 60,
    "reinitialize_symbol_handler": 60,
    "copy_memory": 60,
    "compare_memory": 60,
    "write_region_to_file": 60,
    "read_region_from_file": 60,
    "read_process_memory_cr3": 60,
    "write_process_memory_cr3": 60,
    "debug_process": 60,
    "show_message": 600,
    "input_query": 600,
    "show_selection_list": 600,
    "load_table": 60,
    "save_table": 60,
    "generate_api_hook_script": 30,
    "generate_code_injection_script": 30,
    "run_command": 60,
    "shell_execute": 30,
    "default": 30,
}
MAX_RETRIES = 3
RETRY_BACKOFF_FACTOR = 0.5

session = requests.Session()
retry_strategy = Retry(
    total=MAX_RETRIES,
    backoff_factor=RETRY_BACKOFF_FACTOR,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=20)
session.mount("http://", adapter)
session.mount("https://", adapter)

LOG_LEVEL = os.getenv("CE_MCP_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("ce-mcp-bridge")


ce_server_url = os.getenv("CE_HTTP_URL", DEFAULT_CE_SERVER)

mcp = FastMCP("cheatengine")


def get_timeout_for_endpoint(endpoint: str) -> int:
    name = endpoint.strip("/").split("/")[-1]
    return ENDPOINT_TIMEOUTS.get(name, ENDPOINT_TIMEOUTS["default"])


def safe_post_json(endpoint: str, data: dict = None, retries: int = 3) -> str:
    if data is None:
        data = {}
    url = ce_server_url.rstrip("/") + endpoint
    timeout = get_timeout_for_endpoint(endpoint)

    for attempt in range(retries):
        try:
            start_time = time.time()
            response = session.post(url, json=data, timeout=timeout)
            duration = time.time() - start_time
            logger.info(f"POST {endpoint} took {duration:.2f}s (attempt {attempt + 1})")

            if response.ok:
                return response.text
            elif response.status_code >= 500:
                if attempt < retries - 1:
                    wait_time = 2 ** attempt
                    logger.warning(f"Server error {response.status_code}, retrying in {wait_time}s")
                    time.sleep(wait_time)
                    continue
                return json.dumps({"success": False, "error": f"Server error: {response.status_code}", "error_code": "INTERNAL_ERROR"})
            else:
                return json.dumps({"success": False, "error": response.text.strip()[:500], "error_code": "INTERNAL_ERROR"})

        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                continue
            return json.dumps({"success": False, "error": f"Timeout after {timeout}s", "error_code": "INTERNAL_ERROR"})
        except requests.exceptions.ConnectionError as e:
            # CE may be briefly unreachable (request blip, plugin HTTP thread busy,
            # or CE just (re)starting). Retry with backoff before giving up so a
            # transient drop doesn't surface as a hard failure to the caller.
            if attempt < retries - 1:
                wait_time = min(2 ** attempt, 5)
                logger.warning(f"Connection error on {endpoint} (attempt {attempt + 1}/{retries}), retrying in {wait_time}s: {e}")
                time.sleep(wait_time)
                continue
            return json.dumps({"success": False, "error": f"Cannot reach CE HTTP Bridge at {ce_server_url} after {retries} attempts: {e}", "error_code": "CE_UNREACHABLE"})
        except requests.exceptions.RequestException as e:
            return json.dumps({"success": False, "error": str(e), "error_code": "INTERNAL_ERROR"})

    return json.dumps({"success": False, "error": "Unexpected error", "error_code": "INTERNAL_ERROR"})


def safe_get_json(endpoint: str) -> str:
    url = ce_server_url.rstrip("/") + endpoint
    try:
        response = session.get(url, timeout=10)
        return response.text
    except Exception as e:
        return json.dumps({"success": False, "error": str(e), "error_code": "INTERNAL_ERROR"})


# ============================================================================
# MCP TOOLS
# ============================================================================

@mcp.tool()
def ping() -> str:
    """Ping the CE HTTP bridge to confirm it is reachable and responding. Call this first when other tools time out, to tell a dead bridge from a bad request. Returns the bridge version and uptime."""
    return safe_get_json("/api/ping")


# --- PROCESS & MODULES ---

@mcp.tool()
def get_process_info() -> str:
    """Get current process ID, name, modules count, and architecture."""
    return safe_post_json("/api/get_process_info")


@mcp.tool()
def open_process(process: str) -> str:
    """Attach to a process by name or PID.

    Args:
        process: Process to attach to, given as an executable name or a numeric PID. Example: "game.exe" or "4812"
    """
    return safe_post_json("/api/open_process", {"process": process})


@mcp.tool()
def get_process_list() -> str:
    """List every process currently running on the CE host. Use this to discover a target before open_process. Returns an array of processes with PID and executable name."""
    return safe_post_json("/api/get_process_list")


@mcp.tool()
def get_processid_from_name(name: str) -> str:
    """Resolve a process name to its PID.

    Args:
        name: Executable name of the process, including extension. Example: "game.exe"
    """
    return safe_post_json("/api/get_processid_from_name", {"name": name})


@mcp.tool()
def get_foreground_process() -> str:
    """Get PID and window handle of the active foreground window."""
    return safe_post_json("/api/get_foreground_process")


@mcp.tool()
def create_process(path: str, args: str = "", debug: bool = False, break_on_entry: bool = False) -> str:
    """Launch a new process, optionally under CE debugger control.

    Args:
        path: Absolute path to the executable to launch on the CE host. Example: "C:\\Games\\game.exe"
        args: Command-line arguments passed to the new process, as one string. Example: "-windowed -novid"
        debug: True to launch the process under CE's debugger rather than running it freely. Defaults to False.
        break_on_entry: True to halt at the entry point immediately after launch, before any of the program's code runs. Requires debug=True.
    """
    return safe_post_json("/api/create_process", {
        "path": path, "args": args, "debug": debug, "break_on_entry": break_on_entry,
    })


@mcp.tool()
def get_opened_process_id() -> str:
    """Get the numeric process ID (PID) of the currently attached process. Use get_opened_process_handle for the Windows HANDLE instead. Returns the PID."""
    return safe_post_json("/api/get_opened_process_id")


@mcp.tool()
def get_opened_process_handle() -> str:
    """Get the Windows HANDLE of the currently attached process, for APIs that need the handle rather than the PID. Use get_opened_process_id for the numeric PID instead. Returns the handle."""
    return safe_post_json("/api/get_opened_process_handle")


@mcp.tool()
def enum_modules(offset: int = 0, limit: int = 100) -> str:
    """List loaded modules with base addresses and sizes.

    Args:
        offset: Zero-based index of the first result to return, for paging through large result sets. Example: 100
        limit: Maximum number of results to return in this page. Example: 100
    """
    return safe_post_json("/api/enum_modules", {"offset": offset, "limit": limit})


@mcp.tool()
def get_thread_list(offset: int = 0, limit: int = 100) -> str:
    """Get the thread list of the attached process.

    Args:
        offset: Zero-based index of the first result to return, for paging through large result sets. Example: 100
        limit: Maximum number of results to return in this page. Example: 100
    """
    return safe_post_json("/api/get_thread_list", {"offset": offset, "limit": limit})


# --- MEMORY READING ---

@mcp.tool()
def read_memory(address: str, size: int = 256) -> str:
    """Read raw bytes from memory. Returns hex string.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes to read, returned as a hex string. Example: 256
    """
    return safe_post_json("/api/read_memory", {"address": address, "size": size})


@mcp.tool()
def read_integer(address: str, type: str = "dword") -> str:
    """Read a number. Types: byte, word, dword, qword, float, double.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        type: Width and signedness to decode: byte, word, dword, qword, float, or double. Example: "dword"
    """
    return safe_post_json("/api/read_integer", {"address": address, "type": type})


@mcp.tool()
def read_float(address: str) -> str:
    """Read a 32-bit IEEE-754 float from the attached process. Use read_double for 64-bit values and read_integer for integral types. Returns the decoded float value.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
    """
    return safe_post_json("/api/read_float", {"address": address})


@mcp.tool()
def read_double(address: str) -> str:
    """Read a 64-bit IEEE-754 double from the attached process. Use read_float for 32-bit values. Returns the decoded double value.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
    """
    return safe_post_json("/api/read_double", {"address": address})


@mcp.tool()
def read_string(address: str, max_length: int = 256, wide: bool = False) -> str:
    """Read a null-terminated string from the attached process, in ASCII or UTF-16. Use search_string to locate one first. Returns the decoded text and the byte length consumed.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        max_length: Maximum number of characters to read before giving up on finding a terminator. Example: 256
        wide: True to treat the string as UTF-16 (wide) rather than single-byte ASCII. Defaults to False.
    """
    return safe_post_json("/api/read_string", {"address": address, "max_length": max_length, "wide": wide})


@mcp.tool()
def read_pointer(address: str) -> str:
    """Dereference a pointer at address.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name. The pointer is read from here and its target returned.
    """
    return safe_post_json("/api/read_pointer", {"address": address})


@mcp.tool()
def read_pointer_chain(base: str, offsets: list[int]) -> str:
    """Follow a multi-level pointer chain and return each step.

    Args:
        base: Base address the offsets are applied from. Accepts hex or module-relative form. Example: "hw.dll+1008240"
        offsets: Byte offsets applied in order, dereferencing at each step, as a JSON array of integers. Example: [16, 32, 8]
    """
    return safe_post_json("/api/read_pointer_chain", {"base": base, "offsets": offsets})


@mcp.tool()
def read_many(reads: list[dict]) -> str:
    """Batch-read many typed values in ONE round-trip (much faster than N read_* calls for polling). reads: list of {"address": str, "type": str, "length"?: int}. address may be module-relative (e.g. "hw.dll+1059AE0"). type: byte|word|dword|qword|float|double|pointer|string (default dword); length applies to string reads. Returns per-item {address, resolved, ok, value|error}.

    Args:
        reads: Array of read requests, each {"address": str, "type": str, "length"?: int}. type is byte|word|dword|qword|float|double|pointer|string and defaults to dword; length applies to string reads. Example: [{"address": "hw.dll+1059AE0", "type": "float"}]
    """
    return safe_post_json("/api/read_many", {"reads": reads})


@mcp.tool()
def read_struct(base: str, fields: list[dict]) -> str:
    """Read named typed fields at byte offsets from a base address, in ONE round-trip. base may be module-relative (e.g. "hw.dll+1008240"). fields: list of {"name": str, "offset": int, "type": str, "length"?: int} with type byte|word|dword|qword|float|double|pointer|string (default dword). Returns {"success":true,"base":"0x..","fields":{name:value,...}}.

    Args:
        base: Base address the offsets are applied from. Accepts hex or module-relative form. Example: "hw.dll+1008240"
        fields: Array of field definitions, each {"name": str, "offset": int, "type": str, "length"?: int}, where type is byte|word|dword|qword|float|double|pointer|string and defaults to dword. Example: [{"name": "hp", "offset": 16, "type": "float"}]
    """
    return safe_post_json("/api/read_struct", {"base": base, "fields": fields})


@mcp.tool()
def get_call_stack(frame: str, instruction_pointer: str = "", max_frames: int = 32) -> str:
    """Walk the call stack from a frame pointer (RBP/EBP) and symbolize return addresses. Pass frame (and optionally instruction_pointer) from debug_get_context's registers. Returns symbolized frames; pointer size follows the target's bitness.

    Args:
        frame: Frame-pointer value (RBP on x64, EBP on x86) to start walking from, taken from debug_get_context's registers. Example: "0x14FE30"
        instruction_pointer: Optional current RIP/EIP value, which lets the walker symbolize the innermost frame. Example: "0x7FF6A21C40"
        max_frames: Maximum number of stack frames to walk before stopping. Example: 32
    """
    body = {"frame": frame, "max_frames": max_frames}
    if instruction_pointer:
        body["instruction_pointer"] = instruction_pointer
    return safe_post_json("/api/get_call_stack", body)


@mcp.tool()
def run_to_address(address: str, timeout_s: float = 10.0, poll_interval_s: float = 0.2) -> str:
    """Set a one-shot execute breakpoint at address, let the target run, and return when it is hit (or on timeout). Orchestrates set_breakpoint -> poll get_breakpoint_hits -> remove_breakpoint across separate main-thread calls (a single blocking call would deadlock CE's breakpoint callback). Returns {"success":true,"hit":{...}} or a TIMEOUT error. The breakpoint is removed on exit either way.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        timeout_s: Seconds to wait for the breakpoint to be hit before giving up and returning a TIMEOUT error. Example: 10.0
        poll_interval_s: Seconds to wait between checks for a hit. Lower values react faster but cost more round-trips. Example: 0.2
    """
    setr_text = safe_post_json("/api/set_breakpoint", {"address": address, "trigger": "execute", "size": 1})
    try:
        setr = json.loads(setr_text)
    except Exception:
        return setr_text
    if not setr.get("success"):
        return setr_text
    handle = setr.get("bp_handle")
    deadline = time.time() + float(timeout_s)
    try:
        while time.time() < deadline:
            hr_text = safe_post_json("/api/get_breakpoint_hits", {"handle": handle, "clear": False})
            try:
                hr = json.loads(hr_text)
            except Exception:
                hr = {}
            if hr.get("success") and hr.get("hit_count", 0) > 0:
                return json.dumps({"success": True, "address": address, "hit": hr["hits"][0]})
            time.sleep(float(poll_interval_s))
        return json.dumps({"success": False, "error_code": "TIMEOUT",
                           "error": f"address {address} not hit within {timeout_s}s"})
    finally:
        safe_post_json("/api/remove_breakpoint", {"address": address})


# --- MEMORY WRITING ---

@mcp.tool()
def write_memory(address: str, bytes_hex: str) -> str:
    """Write raw bytes (space-separated hex: '90 90 90').

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        bytes_hex: Bytes to write, as space-separated hex pairs. Example: "90 90 90" to write three NOPs.
    """
    return safe_post_json("/api/write_memory", {"address": address, "bytes": bytes_hex})


@mcp.tool()
def write_integer(address: str, value: int, type: str = "dword") -> str:
    """Write an integral value to the attached process at the given address, using the named width. Use write_float or write_double for floating-point values. Returns success plus the bytes written.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        value: Integer value to write. Example: 100
        type: Width to write: byte, word, dword, or qword. Example: "dword"
    """
    return safe_post_json("/api/write_integer", {"address": address, "value": value, "type": type})


@mcp.tool()
def write_float(address: str, value: float) -> str:
    """Write a 32-bit IEEE-754 float to the attached process. Use write_double for 64-bit values. Returns success and the bytes written.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        value: 32-bit floating-point value to write. Example: 100.0
    """
    return safe_post_json("/api/write_float", {"address": address, "value": value})


@mcp.tool()
def write_double(address: str, value: float) -> str:
    """Write a 64-bit IEEE-754 double to the attached process. Use write_float for 32-bit values. Returns success and the bytes written.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        value: 64-bit floating-point value to write. Example: 100.0
    """
    return safe_post_json("/api/write_double", {"address": address, "value": value})


@mcp.tool()
def write_string(address: str, value: str, wide: bool = False) -> str:
    """Write a string to the attached process, in ASCII or UTF-16. The write is not length-checked, so it can overrun adjacent data. Returns success and the byte count written.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        value: Text to write at the address. Example: "PLAYER1"
        wide: True to treat the string as UTF-16 (wide) rather than single-byte ASCII. Defaults to False.
    """
    return safe_post_json("/api/write_string", {"address": address, "value": value, "wide": wide})


# --- SCANNING ---

@mcp.tool()
def scan_all(value: str, scan_type: str = "exact", value_type: str = "dword",
             start_address: str = "0", stop_address: str = "0x7FFFFFFFFFFFFFFF",
             protection: str = "+W-C",
             offset: int = 0, limit: int = 100) -> str:
    """First scan over memory. scan_type: exact/bigger/smaller/between/unknown/increased/decreased/changed/unchanged.

    Args:
        value: Value to search for, as a string parsed per value_type. Ignored when scan_type is unknown. Example: "100"
        scan_type: Comparison to apply: exact, bigger, smaller, between, unknown, increased, decreased, changed, or unchanged. Example: "exact"
        value_type: How to interpret both the value and memory: byte, word, dword, qword, float, double, or string. Example: "dword"
        start_address: Lowest address to include in the scan, in hex. Example: "0"
        stop_address: Highest address to include in the scan, in hex. Example: "0x7FFFFFFFFFFFFFFF"
        protection: Memory-protection filter restricting which pages are scanned, in CE syntax: "+W-C" means writable and not copy-on-write, "+X" means executable. Example: "+W-C"
        offset: Zero-based index of the first result to return, for paging through large result sets. Example: 100
        limit: Maximum number of results to return in this page. Example: 100
    """
    return safe_post_json("/api/scan_all", {
        "value": value, "scan_type": scan_type, "value_type": value_type,
        "start_address": start_address, "stop_address": stop_address,
        "protection": protection, "offset": offset, "limit": limit,
    })


@mcp.tool()
def next_scan(value: str = "", scan_type: str = "exact") -> str:
    """Refine the results of the previous scan_all, keeping only addresses that still satisfy the comparison. Call scan_all first, then call this repeatedly as the value changes in the target. Returns the surviving result count.

    Args:
        value: Value to compare against on this pass. Leave empty for comparisons that need no operand, such as changed or increased. Example: "90"
        scan_type: Comparison to apply against the previous results: exact, bigger, smaller, between, increased, decreased, changed, or unchanged. Example: "exact"
    """
    return safe_post_json("/api/next_scan", {"value": value, "scan_type": scan_type})


@mcp.tool()
def get_scan_results(offset: int = 0, limit: int = 100) -> str:
    """Fetch results from the most recent scan, paginated.

    Args:
        offset: Zero-based index of the first result to return, for paging through large result sets. Example: 100
        limit: Maximum number of results to return in this page. Example: 100
    """
    return safe_post_json("/api/get_scan_results", {"offset": offset, "limit": limit})


@mcp.tool()
def aob_scan(pattern: str, protection: str = "+X", offset: int = 0, limit: int = 100) -> str:
    """Array of bytes scan with wildcards (e.g. '48 8B ?? 4C 8D').

    Args:
        pattern: Byte pattern in hex, with ?? as a wildcard byte. Example: "48 8B ?? 4C 8D"
        protection: Memory-protection filter limiting which pages are searched, in CE syntax. Example: "+X" to search only executable pages.
        offset: Zero-based index of the first result to return, for paging through large result sets. Example: 100
        limit: Maximum number of results to return in this page. Example: 100
    """
    return safe_post_json("/api/aob_scan", {
        "pattern": pattern, "protection": protection, "offset": offset, "limit": limit,
    })


@mcp.tool()
def aob_scan_unique(pattern: str, protection: str = "+X") -> str:
    """AOB scan that requires exactly one match.

    Args:
        pattern: Byte pattern in hex, with ?? as a wildcard byte. Example: "48 8B ?? 4C 8D"
        protection: Memory-protection filter limiting which pages are searched, in CE syntax. Example: "+X"
    """
    return safe_post_json("/api/aob_scan_unique", {"pattern": pattern, "protection": protection})


@mcp.tool()
def aob_scan_module(pattern: str, module_name: str, protection: str = "+X") -> str:
    """AOB scan constrained to a specific module.

    Args:
        pattern: Byte pattern in hex, with ?? as a wildcard byte. Example: "48 8B ?? 4C 8D"
        module_name: Name of the module to confine the scan to, including extension. Example: "game.exe"
        protection: Memory-protection filter limiting which pages are searched, in CE syntax. Example: "+X"
    """
    return safe_post_json("/api/aob_scan_module", {
        "pattern": pattern, "module_name": module_name, "protection": protection,
    })


@mcp.tool()
def aob_scan_module_unique(pattern: str, module_name: str, protection: str = "+X") -> str:
    """AOB scan within a module requiring exactly one match.

    Args:
        pattern: Byte pattern in hex, with ?? as a wildcard byte. Example: "48 8B ?? 4C 8D"
        module_name: Name of the module to confine the scan to, including extension. Example: "game.exe"
        protection: Memory-protection filter limiting which pages are searched, in CE syntax. Example: "+X"
    """
    return safe_post_json("/api/aob_scan_module_unique", {
        "pattern": pattern, "module_name": module_name, "protection": protection,
    })


@mcp.tool()
def search_string(string: str, wide: bool = False, limit: int = 100) -> str:
    """Quick string search in memory with previews.

    Args:
        string: Literal text to find in the target's memory. Example: "Health"
        wide: True to treat the string as UTF-16 (wide) rather than single-byte ASCII. Defaults to False.
        limit: Maximum number of results to return in this page. Example: 100
    """
    return safe_post_json("/api/search_string", {"string": string, "wide": wide, "limit": limit})


@mcp.tool()
def generate_signature(address: str) -> str:
    """Auto-generate a unique AOB signature that identifies the given address.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name. The generated pattern will uniquely identify this location.
    """
    return safe_post_json("/api/generate_signature", {"address": address})


@mcp.tool()
def pointer_rescan(value: str, previous_results_file: str = "") -> str:
    """Refine a prior pointer scan with a new current value.

    Args:
        value: The value the pointer should now resolve to, after the target has been restarted or the address moved. Example: "100"
        previous_results_file: Path on the CE host to the .PTR file from the earlier pointer scan. Leave empty to use the most recent scan. Example: "C:\\scans\\hp.PTR"
    """
    return safe_post_json("/api/pointer_rescan", {"value": value, "previous_results_file": previous_results_file})


@mcp.tool()
def create_persistent_scan(name: str) -> str:
    """Create a named persistent scan session.

    Args:
        name: Name to give the new scan session, used to address it in later persistent_scan_* calls. Example: "health"
    """
    return safe_post_json("/api/create_persistent_scan", {"name": name})


@mcp.tool()
def persistent_scan_first_scan(name: str, value: str, type: str = "dword", scan_option: str = "exact") -> str:
    """Run the initial scan in a named persistent session, establishing the result set that later refinements narrow. Call create_persistent_scan first, then persistent_scan_next_scan to refine. Returns the match count.

    Args:
        name: Name of the session created by create_persistent_scan. Example: "health"
        value: Value to search for on this first pass. Example: "100"
        type: Value type to interpret the memory as: byte, word, dword, qword, float, double. Example: "dword"
        scan_option: How to compare against the value: exact, bigger, smaller, between, increased, decreased, changed, or unchanged. Example: "exact"
    """
    return safe_post_json("/api/persistent_scan_first_scan", {
        "name": name, "value": value, "type": type, "scan_option": scan_option,
    })


@mcp.tool()
def persistent_scan_next_scan(name: str, value: str = "", scan_option: str = "exact") -> str:
    """Narrow an existing persistent session's results, keeping only addresses still matching. Requires persistent_scan_first_scan to have run in that session. Returns the surviving match count.

    Args:
        name: Name of the session to refine. Example: "health"
        value: Value to compare against on this pass. Leave empty for comparisons that need no operand. Example: "90"
        scan_option: How to compare against the value: exact, bigger, smaller, between, increased, decreased, changed, or unchanged. Example: "exact"
    """
    return safe_post_json("/api/persistent_scan_next_scan", {
        "name": name, "value": value, "scan_option": scan_option,
    })


@mcp.tool()
def persistent_scan_get_results(name: str, offset: int = 0, limit: int = 100) -> str:
    """Fetch results from a persistent scan.

    Args:
        name: Name of the session whose results to fetch. Example: "health"
        offset: Zero-based index of the first result to return, for paging through large result sets. Example: 100
        limit: Maximum number of results to return in this page. Example: 100
    """
    return safe_post_json("/api/persistent_scan_get_results", {
        "name": name, "offset": offset, "limit": limit,
    })


@mcp.tool()
def persistent_scan_destroy(name: str) -> str:
    """Destroy a persistent scan session and free its resources.

    Args:
        name: Name of the session to destroy, freeing its stored result set. Example: "health"
    """
    return safe_post_json("/api/persistent_scan_destroy", {"name": name})


@mcp.tool()
def scan_reset() -> str:
    """Reset/clear the current (non-persistent) scan state."""
    return safe_post_json("/api/scan_reset")


# --- DISASSEMBLY & ANALYSIS ---

@mcp.tool()
def disassemble(address: str, count: int = 10) -> str:
    """Disassemble instructions at address.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        count: Number of instructions to decode. Example: 10
    """
    return safe_post_json("/api/disassemble", {"address": address, "count": count})


@mcp.tool()
def assemble_instruction(address: str, instruction: str, preference: int = 0, skip_range_check: bool = False) -> str:
    """Assemble a single instruction. Returns bytes.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name. Assembly is relative to this address, so relative jumps encode correctly.
        instruction: Single x86/x64 assembly instruction in Intel syntax. Example: "mov eax,[ebx+10]"
        preference: Encoding preference when several encodings exist: 0 lets CE choose the shortest. Example: 0
        skip_range_check: True to assemble even when the target address lies outside a mapped region. Defaults to False.
    """
    return safe_post_json("/api/assemble_instruction", {
        "address": address, "instruction": instruction,
        "preference": preference, "skip_range_check": skip_range_check,
    })


@mcp.tool()
def get_instruction_info(address: str) -> str:
    """Get single instruction details (size, bytes, prev/next addresses).

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
    """
    return safe_post_json("/api/get_instruction_info", {"address": address})


@mcp.tool()
def find_function_boundaries(address: str) -> str:
    """Detect function start/end by scanning for prologue/epilogue.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
    """
    return safe_post_json("/api/find_function_boundaries", {"address": address})


@mcp.tool()
def analyze_function(address: str) -> str:
    """Analyze function: size, calls, boundaries.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
    """
    return safe_post_json("/api/analyze_function", {"address": address})


@mcp.tool()
def find_references(address: str, offset: int = 0, limit: int = 100) -> str:
    """Find code references to an address.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name. Any instruction referring to this address is reported.
        offset: Zero-based index of the first result to return, for paging through large result sets. Example: 100
        limit: Maximum number of results to return in this page. Example: 100
    """
    return safe_post_json("/api/find_references", {"address": address, "offset": offset, "limit": limit})


@mcp.tool()
def find_call_references(address: str, offset: int = 0, limit: int = 100) -> str:
    """Find CALL-specific references to an address.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name. Only CALL instructions targeting this address are reported.
        offset: Zero-based index of the first result to return, for paging through large result sets. Example: 100
        limit: Maximum number of results to return in this page. Example: 100
    """
    return safe_post_json("/api/find_call_references", {"address": address, "offset": offset, "limit": limit})


@mcp.tool()
def get_rtti_classname(address: str) -> str:
    """Identify C++ RTTI class name at an object address.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name. This must point at a polymorphic C++ object, whose vtable is used to find the RTTI record.
    """
    return safe_post_json("/api/get_rtti_classname", {"address": address})


@mcp.tool()
def get_physical_address(address: str) -> str:
    """Translate a virtual address to its physical RAM address (requires DBK).

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
    """
    return safe_post_json("/api/get_physical_address", {"address": address})


@mcp.tool()
def get_memory_regions(offset: int = 0, limit: int = 100) -> str:
    """List virtual memory regions with protection flags.

    Args:
        offset: Zero-based index of the first result to return, for paging through large result sets. Example: 100
        limit: Maximum number of results to return in this page. Example: 100
    """
    return safe_post_json("/api/get_memory_regions", {"offset": offset, "limit": limit})


@mcp.tool()
def enum_memory_regions_full(offset: int = 0, limit: int = 100) -> str:
    """Enhanced memory region enumeration with decoded protection/state flags.

    Args:
        offset: Zero-based index of the first result to return, for paging through large result sets. Example: 100
        limit: Maximum number of results to return in this page. Example: 100
    """
    return safe_post_json("/api/enum_memory_regions_full", {"offset": offset, "limit": limit})


@mcp.tool()
def dissect_structure(address: str, size: int = 256) -> str:
    """Auto-detect fields in a memory structure using CE autoGuess.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes from the base address to analyse for field boundaries. Example: 256
    """
    return safe_post_json("/api/dissect_structure", {"address": address, "size": size})


# --- SYMBOLS ---

@mcp.tool()
def get_symbol_address(symbol: str) -> str:
    """Resolve a symbol name to an address.

    Args:
        symbol: Symbol name to resolve, optionally module-qualified. Example: "kernel32.CreateFileW"
    """
    return safe_post_json("/api/get_symbol_address", {"symbol": symbol})


@mcp.tool()
def get_address_info(address: str, include_modules: bool = True, include_symbols: bool = True, include_sections: bool = False) -> str:
    """Convert an address to a symbolic name (module+offset).

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        include_modules: True to resolve the address into module+offset form. Defaults to True.
        include_symbols: True to include the nearest matching symbol name. Defaults to True.
        include_sections: True to include the containing PE section, such as .text or .data. Defaults to False.
    """
    return safe_post_json("/api/get_address_info", {
        "address": address, "include_modules": include_modules,
        "include_symbols": include_symbols, "include_sections": include_sections,
    })


@mcp.tool()
def register_symbol(name: str, address: str, do_not_save: bool = False) -> str:
    """Create a user-defined symbol that maps a name to an address, so later tools can use the name. Use unregister_symbol to remove one. Returns success.

    Args:
        name: Symbol name to create, which later tools can use in place of the address. Example: "playerBase"
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        do_not_save: True to keep the symbol out of the saved cheat table, so it exists only for this session.
    """
    return safe_post_json("/api/register_symbol", {
        "name": name, "address": address, "do_not_save": do_not_save,
    })


@mcp.tool()
def unregister_symbol(name: str) -> str:
    """Remove one user-defined symbol previously created by register_symbol, leaving all other symbols intact. Returns success.

    Args:
        name: Name of the symbol to remove. Example: "playerBase"
    """
    return safe_post_json("/api/unregister_symbol", {"name": name})


@mcp.tool()
def enum_registered_symbols() -> str:
    """List every user-defined symbol registered through register_symbol, with its address. Returns an array of name/address pairs."""
    return safe_post_json("/api/enum_registered_symbols")


@mcp.tool()
def delete_all_registered_symbols() -> str:
    """Delete all registered symbols."""
    return safe_post_json("/api/delete_all_registered_symbols")


@mcp.tool()
def enable_windows_symbols() -> str:
    """Load Windows debug symbols (PDB)."""
    return safe_post_json("/api/enable_windows_symbols")


@mcp.tool()
def enable_kernel_symbols() -> str:
    """Load Windows kernel debug symbols (requires DBK)."""
    return safe_post_json("/api/enable_kernel_symbols")


@mcp.tool()
def get_symbol_info(name: str) -> str:
    """Get detailed info about a symbol.

    Args:
        name: Symbol name to look up, optionally module-qualified. Example: "kernel32.CreateFileW"
    """
    return safe_post_json("/api/get_symbol_info", {"name": name})


@mcp.tool()
def get_module_size(module_name: str) -> str:
    """Get the size of a loaded module.

    Args:
        module_name: Name of the loaded module, including extension. Example: "game.exe"
    """
    return safe_post_json("/api/get_module_size", {"module_name": module_name})


@mcp.tool()
def load_new_symbols() -> str:
    """Load newly available symbols for loaded modules."""
    return safe_post_json("/api/load_new_symbols")


@mcp.tool()
def reinitialize_symbol_handler() -> str:
    """Reinitialize CE's symbol handler."""
    return safe_post_json("/api/reinitialize_symbol_handler")


# --- DEBUGGING ---

@mcp.tool()
def set_breakpoint(address: str, size: int = 1, trigger: str = "execute") -> str:
    """Set a breakpoint. trigger: execute/write/read/access.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes watched from the address; execute breakpoints use 1. Example: 1
        trigger: What activates the breakpoint: execute, write, read, or access. Example: "execute"
    """
    return safe_post_json("/api/set_breakpoint", {"address": address, "size": size, "trigger": trigger})


@mcp.tool()
def set_data_breakpoint(address: str, size: int = 4, trigger: str = "write") -> str:
    """Set a hardware data watchpoint. trigger: write/read/access.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Width of the watched region in bytes. Hardware watchpoints allow 1, 2, 4, or 8. Example: 4
        trigger: Access that fires the watchpoint: write, read, or access for either. Example: "write"
    """
    return safe_post_json("/api/set_data_breakpoint", {"address": address, "size": size, "trigger": trigger})


@mcp.tool()
def remove_breakpoint(address: str) -> str:
    """Remove the breakpoint at one address, leaving other breakpoints active. Use clear_all_breakpoints to remove every breakpoint at once. Returns success.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
    """
    return safe_post_json("/api/remove_breakpoint", {"address": address})


@mcp.tool()
def list_breakpoints() -> str:
    """List every breakpoint currently set, with its address, trigger type, and handle. Use the returned handle with get_breakpoint_hits. Returns an array of breakpoint descriptors."""
    return safe_post_json("/api/list_breakpoints")


@mcp.tool()
def clear_all_breakpoints() -> str:
    """Remove all breakpoints and clear hit buffers."""
    return safe_post_json("/api/clear_all_breakpoints")


@mcp.tool()
def get_breakpoint_hits(handle: str, clear: bool = False) -> str:
    """Fetch hit log for a breakpoint handle.

    Args:
        handle: Breakpoint handle returned by set_breakpoint or listed by list_breakpoints. Example: "0x1A4"
        clear: True to empty the buffer after reading it, so the next call returns only new entries.
    """
    return safe_post_json("/api/get_breakpoint_hits", {"handle": handle, "clear": clear})


@mcp.tool()
def debug_process(interface: int = 0) -> str:
    """Attach a debugger to the current process. interface: 0=default, 1=windows_native, 2=veh, 3=kernel, 4=dbvm.

    Args:
        interface: Debugger backend to attach with: 0=default, 1=windows_native, 2=veh, 3=kernel, 4=dbvm. Example: 0
    """
    return safe_post_json("/api/debug_process", {"interface": interface})


@mcp.tool()
def debug_is_debugging() -> str:
    """Check if debugger is currently attached."""
    return safe_post_json("/api/debug_is_debugging")


@mcp.tool()
def debug_detach() -> str:
    """Detach CE's debugger from the attached process, leaving the process running and still attached for memory access. Returns success."""
    return safe_post_json("/api/debug_detach")


@mcp.tool()
def debug_continue(method: str = "run") -> str:
    """Continue execution after a breakpoint has been hit, either running freely or stepping one instruction. Returns success.

    Args:
        method: How to resume: run to continue freely, step_into to enter calls, or step_over to run calls to completion. Example: "run"
    """
    return safe_post_json("/api/debug_continue", {"method": method})


@mcp.tool()
def debug_break_thread(thread_id: int) -> str:
    """Break a specific thread into the debugger.

    Args:
        thread_id: ID of the thread to interrupt, as reported by get_thread_list. Example: 4812
    """
    return safe_post_json("/api/debug_break_thread", {"thread_id": thread_id})


@mcp.tool()
def debug_get_context(extra_regs: bool = False) -> str:
    """Read the CPU register values of the debugged thread at the current breakpoint. Use debug_set_context to modify them. Returns the register set.

    Args:
        extra_regs: True to also return the FPU, SSE, and debug registers alongside the general-purpose set. Defaults to False.
    """
    return safe_post_json("/api/debug_get_context", {"extra_regs": extra_regs})


@mcp.tool()
def debug_set_context(registers: dict) -> str:
    """Set CPU register values in the debugged thread's context at the current breakpoint. Read the context first with debug_get_context. Returns the updated register set.

    Args:
        registers: Map of register name to new value, values given as hex strings. Example: {"RAX": "0x1234", "RIP": "0x7FF6A21C40"}
    """
    return safe_post_json("/api/debug_set_context", {"registers": registers})


@mcp.tool()
def debug_get_xmm_pointer(xmm_nr: int = 0) -> str:
    """Get the CE-local address holding the 16 raw bytes of one XMM SIMD register, which you then read with read_memory. Returns that address.

    Args:
        xmm_nr: Index of the XMM register to expose, 0 through 15. Example: 0
    """
    return safe_post_json("/api/debug_get_xmm_pointer", {"xmm_nr": xmm_nr})


@mcp.tool()
def debug_set_last_branch_recording(enable: bool = True) -> str:
    """Enable/disable LBR (Last Branch Recording, requires kernel debugger).

    Args:
        enable: True to start recording branches, False to stop. Requires the kernel debugger.
    """
    return safe_post_json("/api/debug_set_last_branch_recording", {"enable": enable})


@mcp.tool()
def debug_get_last_branch_record(index: int = 0) -> str:
    """Read one entry from the Last Branch Record stack, giving the source and destination address of a recent branch. Enable recording first with debug_set_last_branch_recording. Returns the from/to address pair.

    Args:
        index: Position in the branch stack to read, where 0 is the most recent branch. Example: 0
    """
    return safe_post_json("/api/debug_get_last_branch_record", {"index": index})


@mcp.tool()
def debug_set_breakpoint_for_thread(thread_id: int, address: str, size: int = 1, trigger: str = "execute") -> str:
    """Set a thread-local breakpoint.

    Args:
        thread_id: Numeric thread ID within the attached process, as reported by get_thread_list. Example: 4812
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes watched from the address; execute breakpoints use 1. Example: 1
        trigger: What activates the breakpoint: execute, write, read, or access. Example: "execute"
    """
    return safe_post_json("/api/debug_set_breakpoint_for_thread", {
        "thread_id": thread_id, "address": address, "size": size, "trigger": trigger,
    })


@mcp.tool()
def debug_remove_breakpoint_for_thread(thread_id: int, address: str) -> str:
    """Remove a thread-local breakpoint.

    Args:
        thread_id: Numeric thread ID within the attached process, as reported by get_thread_list. Example: 4812
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
    """
    return safe_post_json("/api/debug_remove_breakpoint_for_thread", {
        "thread_id": thread_id, "address": address,
    })


@mcp.tool()
def pause_process() -> str:
    """Freeze every thread in the attached process so memory stops changing while you inspect it. Use unpause_process to resume. Returns success."""
    return safe_post_json("/api/pause_process")


@mcp.tool()
def unpause_process() -> str:
    """Resume a process previously frozen by pause_process, letting all its threads run again. Returns success."""
    return safe_post_json("/api/unpause_process")


# --- DBVM HYPERVISOR WATCHES (Safe dynamic tracing) ---

@mcp.tool()
def start_dbvm_watch(address: str, mode: str = "w", max_entries: int = 1000) -> str:
    """Start DBVM-level (ring -1) memory watch. mode: w=write, r=read, rw=access, x=execute.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        mode: Access to trap on: w=write, r=read, rw=either, x=execute. Example: "w"
        max_entries: Maximum number of hits to buffer before the oldest are dropped. Example: 1000
    """
    return safe_post_json("/api/start_dbvm_watch", {
        "address": address, "mode": mode, "max_entries": max_entries,
    })


@mcp.tool()
def poll_dbvm_watch(address: str, clear: bool = True, max_results: int = 1000) -> str:
    """Poll DBVM watch log without stopping the watch.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        clear: True to empty the log after reading, so the next poll returns only new hits. Defaults to True.
        max_results: Maximum number of buffered hits to return in this call. Example: 1000
    """
    return safe_post_json("/api/poll_dbvm_watch", {
        "address": address, "clear": clear, "max_results": max_results,
    })


@mcp.tool()
def stop_dbvm_watch(address: str) -> str:
    """Stop a DBVM watch and return the accumulated log.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
    """
    return safe_post_json("/api/stop_dbvm_watch", {"address": address})


# --- CODE INJECTION & ASSEMBLY ---

@mcp.tool()
def auto_assemble(script: str, disable: bool = False) -> str:
    """Execute a CE auto-assembler script. Set disable=true to run [DISABLE] section.

    Args:
        script: Cheat Engine auto-assembler script text, including its [ENABLE] and [DISABLE] sections.
        disable: True to run the script's [DISABLE] section, reverting the change, instead of [ENABLE]. Defaults to False.
    """
    return safe_post_json("/api/auto_assemble", {"script": script, "disable": disable})


@mcp.tool()
def auto_assemble_check(script: str, enable: bool = True, target_self: bool = False) -> str:
    """Check that an auto-assemble script parses and its symbols resolve, without applying any change to the target. Use before auto_assemble to catch errors safely. Returns success or the parse error and its line.

    Args:
        script: Cheat Engine auto-assembler script text, including its [ENABLE] and [DISABLE] sections.
        enable: True to validate the [ENABLE] section, False to validate [DISABLE]. Defaults to True.
        target_self: True to act on Cheat Engine's own process instead of the attached target. Defaults to False.
    """
    return safe_post_json("/api/auto_assemble_check", {
        "script": script, "enable": enable, "target_self": target_self,
    })


@mcp.tool()
def inject_dll(filepath: str, skip_symbol_reload: bool = False) -> str:
    """Inject a native DLL into the target process.

    Args:
        filepath: Absolute path to the native DLL on the CE host to inject. Example: "C:\\payload\\hook.dll"
        skip_symbol_reload: True to skip re-reading symbols after injection, which is faster but leaves the new module's exports unresolved.
    """
    return safe_post_json("/api/inject_dll", {"filepath": filepath, "skip_symbol_reload": skip_symbol_reload})


@mcp.tool()
def inject_dotnet_dll(filepath: str, class_name: str, method_name: str, param: str = "", timeout: int = -1) -> str:
    """Inject a .NET assembly and call a method.

    Args:
        filepath: Absolute path to the .NET assembly on the CE host to inject. Example: "C:\\payload\\mod.dll"
        class_name: Fully-qualified name of the .NET class holding the method to call. Example: "MyMod.Loader"
        method_name: Name of the static method to invoke on that class. Example: "Init"
        param: Single string argument passed to the method. Example: ""
        timeout: Milliseconds to wait for the call to finish; -1 waits forever. Example: 5000
    """
    return safe_post_json("/api/inject_dotnet_dll", {
        "filepath": filepath, "class_name": class_name, "method_name": method_name,
        "param": param, "timeout": timeout,
    })


@mcp.tool()
def allocate_memory(size: int = 4096, base_address: str = "", protection: str = "rwx") -> str:
    """Allocate memory in the target process.

    Args:
        size: Number of bytes to allocate, rounded up to a page boundary by Windows. Example: 4096
        base_address: Preferred address to allocate near, in hex. Leave empty to let Windows choose. Example: "0x7FF6A20000"
        protection: Initial page protection for the new block. Example: "rwx"
    """
    return safe_post_json("/api/allocate_memory", {
        "size": size, "base_address": base_address, "protection": protection,
    })


@mcp.tool()
def free_memory(address: str, size: int = 0) -> str:
    """Release a memory block previously obtained from allocate_memory in the target process. Any code still executing there will crash the target. Returns success.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes to release; 0 frees the whole block allocated at that address. Example: 0
    """
    return safe_post_json("/api/free_memory", {"address": address, "size": size})


@mcp.tool()
def allocate_shared_memory(name: str, size: int) -> str:
    """Allocate a named shared memory region.

    Args:
        name: Name of the shared-memory section, which other processes use to open the same region. Example: "CEShared1"
        size: Number of bytes to allocate in the shared region. Example: 4096
    """
    return safe_post_json("/api/allocate_shared_memory", {"name": name, "size": size})


@mcp.tool()
def allocate_kernel_memory(size: int) -> str:
    """Allocate kernel memory (requires DBK).

    Args:
        size: Number of bytes of non-paged kernel memory to allocate. Example: 4096
    """
    return safe_post_json("/api/allocate_kernel_memory", {"size": size})


@mcp.tool()
def create_section(size: int) -> str:
    """Create a Windows section object of the given size.

    Args:
        size: Size of the section object in bytes. Example: 4096
    """
    return safe_post_json("/api/create_section", {"size": size})


@mcp.tool()
def map_view_of_section(handle: str, address: str = "") -> str:
    """Map a section into the target process's address space.

    Args:
        handle: Handle returned by create_section. Example: "0x1A4"
        address: Preferred address to map at, in hex. Leave empty to let Windows choose. Example: ""
    """
    return safe_post_json("/api/map_view_of_section", {"handle": handle, "address": address})


@mcp.tool()
def execute_code(address: str, param: int = 0, timeout: int = -1) -> str:
    """Execute code at address via CreateRemoteThread.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name. Execution starts here on a new remote thread.
        param: Single integer argument passed to the called code. Example: 0
        timeout: Milliseconds to wait for the call to finish; -1 waits forever. Example: 5000
    """
    return safe_post_json("/api/execute_code", {"address": address, "param": param, "timeout": timeout})


@mcp.tool()
def execute_code_ex(address: str, args: list = None, call_method: int = 0, timeout: int = -1) -> str:
    """Execute code with arbitrary arguments.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name. Execution starts here on a new remote thread.
        args: Arguments passed to the called function, as a JSON array of integers or hex strings. Example: [1, "0x7FF6A21C40"]
        call_method: Calling convention to invoke with: 0=stdcall, 1=cdecl, 2=fastcall. Example: 0
        timeout: Milliseconds to wait for the call to finish; -1 waits forever. Example: 5000
    """
    return safe_post_json("/api/execute_code_ex", {
        "address": address, "args": args or [], "call_method": call_method, "timeout": timeout,
    })


@mcp.tool()
def execute_method(address: str, instance: str, args: list = None, call_method: int = 0, timeout: int = -1) -> str:
    """Call a class method with `instance` as the `this` pointer.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name. This must be the method's code address.
        instance: Address of the object passed as the implicit this pointer, in hex. Example: "0x1F2A3B40"
        args: Arguments passed after this, as a JSON array of integers or hex strings. Example: [1, 2]
        call_method: Calling convention to invoke with: 0=stdcall, 1=cdecl, 2=fastcall. Example: 0
        timeout: Milliseconds to wait for the call to finish; -1 waits forever. Example: 5000
    """
    return safe_post_json("/api/execute_method", {
        "address": address, "instance": instance, "args": args or [],
        "call_method": call_method, "timeout": timeout,
    })


@mcp.tool()
def execute_code_local(address: str, param: int = 0) -> str:
    """Execute code in CE's own process (not the target).

    Args:
        address: Address inside Cheat Engine's own process to execute, in hex. Example: "0x7FF6A21C40"
        param: Single integer argument passed to the called code. Example: 0
    """
    return safe_post_json("/api/execute_code_local", {"address": address, "param": param})


@mcp.tool()
def execute_code_local_ex(address: str, args: list = None, call_method: int = 0) -> str:
    """Execute local code with arguments.

    Args:
        address: Address inside Cheat Engine's own process to execute, in hex. Example: "0x7FF6A21C40"
        args: Arguments passed to the called function, as a JSON array of integers or hex strings. Example: [1, 2]
        call_method: Calling convention to invoke with: 0=stdcall, 1=cdecl, 2=fastcall. Example: 0
    """
    return safe_post_json("/api/execute_code_local_ex", {
        "address": address, "args": args or [], "call_method": call_method,
    })


@mcp.tool()
def compile_c_code(source: str, address: str = "", target_self: bool = False, kernelmode: bool = False) -> str:
    """Compile C source with CE's built-in TCC compiler and inject the result into the target. Use compile_cs_code for C# instead. Returns the resolved symbol addresses.

    Args:
        source: C source text to compile. Example: "int add(int a,int b){return a+b;}"
        address: Address in the target to place the compiled code, in hex. Leave empty to allocate automatically. Example: ""
        target_self: True to act on Cheat Engine's own process instead of the attached target. Defaults to False.
        kernelmode: True to compile for kernel mode, which requires the DBK driver. Defaults to False.
    """
    return safe_post_json("/api/compile_c_code", {
        "source": source, "address": address, "target_self": target_self, "kernelmode": kernelmode,
    })


@mcp.tool()
def compile_cs_code(source: str, references: list = None, core_assembly: str = "") -> str:
    """Compile C# source into a .NET assembly loaded inside CE. Use compile_c_code for native C instead. Returns the assembly handle.

    Args:
        source: C# source text to compile. Example: "public class M { public static void Run(){} }"
        references: Assembly references needed to compile, as a JSON array of names. Example: ["System.dll", "System.Core.dll"]
        core_assembly: Path to the core assembly to compile against. Leave empty for CE's default. Example: ""
    """
    return safe_post_json("/api/compile_cs_code", {
        "source": source, "references": references or [], "core_assembly": core_assembly,
    })


@mcp.tool()
def generate_api_hook_script(address: str, target_address: str, code_to_execute: str = "") -> str:
    """Generate an AA script that hooks a Windows API and calls target_address.

    Args:
        address: Address of the API function to hook, in hex or as a module-qualified symbol. Example: "kernel32.CreateFileW"
        target_address: Address your replacement code lives at, which the hook will jump to. Example: "0x7FF6A21C40"
        code_to_execute: Optional assembly inserted into the generated script's hook body. Example: ""
    """
    return safe_post_json("/api/generate_api_hook_script", {
        "address": address, "target_address": target_address, "code_to_execute": code_to_execute,
    })


@mcp.tool()
def generate_code_injection_script(address: str) -> str:
    """Generate a template AA code-injection script for address.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
    """
    return safe_post_json("/api/generate_code_injection_script", {"address": address})


# --- CHEAT TABLE ---

@mcp.tool()
def load_table(path: str, merge: bool = False) -> str:
    """Load a Cheat Engine cheat table (.CT file).

    Args:
        path: Absolute path to the .CT cheat-table file on the CE host. Example: "C:\\tables\\game.CT"
        merge: True to add the file's records to the current table, False to replace the table entirely.
    """
    return safe_post_json("/api/load_table", {"path": path, "merge": merge})


@mcp.tool()
def save_table(path: str, protect: bool = False) -> str:
    """Write the current cheat table, including all address-list records, to a .CT file on the CE host. Returns success and the path written.

    Args:
        path: Absolute path to write the .CT file to on the CE host. Example: "C:\\tables\\game.CT"
        protect: True to password-protect the saved table against editing. Defaults to False.
    """
    return safe_post_json("/api/save_table", {"path": path, "protect": protect})


@mcp.tool()
def get_address_list(offset: int = 0, limit: int = 100) -> str:
    """Get entries from the address list (cheat table records).

    Args:
        offset: Zero-based index of the first result to return, for paging through large result sets. Example: 100
        limit: Maximum number of results to return in this page. Example: 100
    """
    return safe_post_json("/api/get_address_list", {"offset": offset, "limit": limit})


@mcp.tool()
def get_memory_record(id: int = -1, description: str = "") -> str:
    """Get a single memory record by ID or description.

    Args:
        id: Numeric ID of the record to fetch. Pass -1 to look it up by description instead. Example: 4
        description: Description text to match when id is -1. Example: "Player health"
    """
    data = {}
    if id >= 0:
        data["id"] = id
    if description:
        data["description"] = description
    return safe_post_json("/api/get_memory_record", data)


@mcp.tool()
def create_memory_record(description: str, address: str, type: str = "dword") -> str:
    """Create a new memory record in the cheat table.

    Args:
        description: Human-readable label for the cheat-table record. Example: "Player health"
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        type: Value type for the new record: byte, word, dword, qword, float, double, or string. Example: "dword"
    """
    return safe_post_json("/api/create_memory_record", {
        "description": description, "address": address, "type": type,
    })


@mcp.tool()
def delete_memory_record(id: int) -> str:
    """Delete one record from the cheat table's address list by its numeric ID. This removes the record only, and does not change target memory. Returns success.

    Args:
        id: Numeric ID of the cheat-table memory record. Example: 4
    """
    return safe_post_json("/api/delete_memory_record", {"id": id})


@mcp.tool()
def get_memory_record_value(id: int) -> str:
    """Read the current value through a cheat-table record, resolving whatever address it points at. Use set_memory_record_value to write. Returns the value.

    Args:
        id: Numeric ID of the cheat-table memory record. Example: 4
    """
    return safe_post_json("/api/get_memory_record_value", {"id": id})


@mcp.tool()
def set_memory_record_value(id: int, value: str) -> str:
    """Write a new value through a cheat-table record, which applies it to the address the record points at. Returns success and the value written.

    Args:
        id: Numeric ID of the cheat-table memory record. Example: 4
        value: New value to write, as a string parsed per the record's type. Example: "100"
    """
    return safe_post_json("/api/set_memory_record_value", {"id": id, "value": value})


@mcp.tool()
def freeze_mem(address: str, size: int = 4) -> str:
    """Continuously rewrite an address with its current value so the target cannot change it. Keep the returned freeze_id to pass to unfreeze_mem. Returns the freeze_id.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes to hold constant at the address. Example: 4
    """
    return safe_post_json("/api/freeze_mem", {"address": address, "size": size})


@mcp.tool()
def unfreeze_mem(freeze_id: int) -> str:
    """Stop a freeze started by freeze_mem, letting the target write that address again. Returns success.

    Args:
        freeze_id: ID returned by freeze_mem identifying which freeze to stop. Example: 1
    """
    return safe_post_json("/api/unfreeze_mem", {"freeze_id": freeze_id})


# --- MEMORY OPERATIONS ---

@mcp.tool()
def checksum_memory(address: str, size: int = 256) -> str:
    """Calculate MD5 hash of a memory region (for change detection).

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes to hash from the address. Example: 256
    """
    return safe_post_json("/api/checksum_memory", {"address": address, "size": size})


@mcp.tool()
def md5_memory(address: str, size: int) -> str:
    """Compute the MD5 digest of a memory region in the attached process, for detecting whether its contents changed between two points in time. Returns the hex digest.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes to operate on. Example: 256
    """
    return safe_post_json("/api/md5_memory", {"address": address, "size": size})


@mcp.tool()
def md5_file(filename: str) -> str:
    """Compute the MD5 digest of a file on the CE host, for verifying a dump or payload. Returns the hex digest.

    Args:
        filename: Absolute path to the file on the CE host to hash. Example: "C:\\dumps\\region.bin"
    """
    return safe_post_json("/api/md5_file", {"filename": filename})


@mcp.tool()
def copy_memory(source: str, size: int, dest: str = "", method: int = 0) -> str:
    """Copy a memory region. If dest is empty, allocates a new destination.

    Args:
        source: Address to copy bytes from, in hex or module-relative form. Example: "0x7FF6A21C40"
        size: Number of bytes to copy. Example: 256
        dest: Address to copy bytes to. Leave empty to allocate a new block and return its address. Example: ""
        method: Numeric method selector; 0 selects CE's default. Example: 0
    """
    return safe_post_json("/api/copy_memory", {"source": source, "size": size, "dest": dest, "method": method})


@mcp.tool()
def compare_memory(addr1: str, addr2: str, size: int, method: int = 0) -> str:
    """Compare two memory regions byte by byte.

    Args:
        addr1: First address of the pair to compare, in hex or module-relative form. Example: "0x7FF6A21C40"
        addr2: Second address of the pair to compare, in hex or module-relative form. Example: "0x7FF6A21D40"
        size: Number of bytes to compare from each address. Example: 256
        method: Numeric method selector; 0 selects CE's default. Example: 0
    """
    return safe_post_json("/api/compare_memory", {"addr1": addr1, "addr2": addr2, "size": size, "method": method})


@mcp.tool()
def write_region_to_file(address: str, size: int, filename: str) -> str:
    """Dump a memory region to a file.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes to operate on. Example: 256
        filename: Absolute path on the CE host to write the dump to. Example: "C:\\dumps\\region.bin"
    """
    return safe_post_json("/api/write_region_to_file", {"address": address, "size": size, "filename": filename})


@mcp.tool()
def read_region_from_file(filename: str, destination: str) -> str:
    """Load a file's contents into a memory region.

    Args:
        filename: Absolute path on the CE host to read the bytes from. Example: "C:\\dumps\\region.bin"
        destination: Address in the target to write the file's contents to. Example: "0x7FF6A21C40"
    """
    return safe_post_json("/api/read_region_from_file", {"filename": filename, "destination": destination})


@mcp.tool()
def get_memory_protection(address: str) -> str:
    """Read the current read/write/execute protection flags of the page containing an address. Use set_memory_protection to change them. Returns the decoded flags.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
    """
    return safe_post_json("/api/get_memory_protection", {"address": address})


@mcp.tool()
def set_memory_protection(address: str, size: int, read: bool = True, write: bool = True, execute: bool = True) -> str:
    """Change the read/write/execute protection on a memory region, for example to make read-only code writable before patching. Use get_memory_protection to read the current flags. Returns the previous protection.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes to operate on. Example: 256
        read: True to allow reads from the region. Defaults to True.
        write: True to allow writes to the region. Defaults to True.
        execute: True to allow code execution in the region. Defaults to True.
    """
    return safe_post_json("/api/set_memory_protection", {
        "address": address, "size": size, "read": read, "write": write, "execute": execute,
    })


@mcp.tool()
def full_access(address: str, size: int) -> str:
    """Grant read, write, and execute permission on a memory region, so later writes to read-only pages succeed. Returns the previous protection flags.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes to operate on. Example: 256
    """
    return safe_post_json("/api/full_access", {"address": address, "size": size})


# --- STRUCTURES ---

@mcp.tool()
def create_structure(name: str) -> str:
    """Create a new named CE structure.

    Args:
        name: Name for the new structure definition. Example: "PlayerEntity"
    """
    return safe_post_json("/api/create_structure", {"name": name})


@mcp.tool()
def get_structure_by_name(name: str) -> str:
    """Look up an existing structure by name.

    Args:
        name: Name of the structure to look up. Example: "PlayerEntity"
    """
    return safe_post_json("/api/get_structure_by_name", {"name": name})


@mcp.tool()
def add_element_to_structure(structure_id: int, name: str, offset: int, type: str) -> str:
    """Add a typed field to a structure. type: byte/word/dword/qword/float/double/string/aob/pointer.

    Args:
        structure_id: Numeric ID of a CE structure, as returned by create_structure or get_structure_by_name. Example: 3
        name: Name of the new field. Example: "health"
        offset: Byte offset of the field from the start of the structure. Example: 16
        type: Field type: byte, word, dword, qword, float, double, string, aob, or pointer. Example: "float"
    """
    return safe_post_json("/api/add_element_to_structure", {
        "structure_id": structure_id, "name": name, "offset": offset, "type": type,
    })


@mcp.tool()
def get_structure_elements(structure_id: int) -> str:
    """List every field defined on a CE structure, with each field's name, byte offset, and type. Returns an array of field descriptors.

    Args:
        structure_id: Numeric ID of a CE structure, as returned by create_structure or get_structure_by_name. Example: 3
    """
    return safe_post_json("/api/get_structure_elements", {"structure_id": structure_id})


@mcp.tool()
def export_structure_to_xml(structure_id: int) -> str:
    """Export structure definition as XML.

    Args:
        structure_id: Numeric ID of a CE structure, as returned by create_structure or get_structure_by_name. Example: 3
    """
    return safe_post_json("/api/export_structure_to_xml", {"structure_id": structure_id})


@mcp.tool()
def delete_structure(structure_id: int) -> str:
    """Delete a CE structure definition and free its ID. This removes the definition only, and does not touch target memory. Returns success.

    Args:
        structure_id: Numeric ID of a CE structure, as returned by create_structure or get_structure_by_name. Example: 3
    """
    return safe_post_json("/api/delete_structure", {"structure_id": structure_id})


# --- WINDOW / GUI ---

@mcp.tool()
def find_window(title: str = "", class_name: str = "") -> str:
    """Find a window by title and/or class name.

    Args:
        title: Window title text to match. Leave empty to match on class name alone. Example: "Untitled - Notepad"
        class_name: Window class name to match. Example: "Notepad"
    """
    return safe_post_json("/api/find_window", {"title": title, "class_name": class_name})


@mcp.tool()
def get_window_caption(handle: str) -> str:
    """Get the caption (title bar text) of a window.

    Args:
        handle: Window handle, as returned by find_window. Example: "0x1A4"
    """
    return safe_post_json("/api/get_window_caption", {"handle": handle})


@mcp.tool()
def get_window_class_name(handle: str) -> str:
    """Get the class name of a window.

    Args:
        handle: Window handle, as returned by find_window. Example: "0x1A4"
    """
    return safe_post_json("/api/get_window_class_name", {"handle": handle})


@mcp.tool()
def get_window_process_id(handle: str) -> str:
    """Get the PID that owns a window.

    Args:
        handle: Window handle, as returned by find_window. Example: "0x1A4"
    """
    return safe_post_json("/api/get_window_process_id", {"handle": handle})


@mcp.tool()
def send_window_message(handle: str, msg: int, wparam: int = 0, lparam: int = 0) -> str:
    """Send a Windows message to a window.

    Args:
        handle: Window handle to deliver the message to, as returned by find_window. Example: "0x1A4"
        msg: Windows message code to send. Example: 16 for WM_CLOSE
        wparam: WPARAM value accompanying the message. Example: 0
        lparam: LPARAM value accompanying the message. Example: 0
    """
    return safe_post_json("/api/send_window_message", {
        "handle": handle, "msg": msg, "wparam": wparam, "lparam": lparam,
    })


@mcp.tool()
def show_message(message: str) -> str:
    """Show a modal message box in CE (blocks main thread).

    Args:
        message: Text shown in the message box. The call blocks until the user dismisses it.
    """
    return safe_post_json("/api/show_message", {"message": message})


@mcp.tool()
def input_query(caption: str = "", prompt: str = "", default: str = "") -> str:
    """Show a modal input dialog in CE.

    Args:
        caption: Title-bar text of the dialog window.
        prompt: Prompt text shown above the input field in the dialog.
        default: Text pre-filled into the input field when the dialog opens. Example: ""
    """
    return safe_post_json("/api/input_query", {"caption": caption, "prompt": prompt, "default": default})


@mcp.tool()
def show_selection_list(options: list[str], caption: str = "", prompt: str = "") -> str:
    """Show a modal selection list dialog in CE.

    Args:
        options: Choices to show in the list, as a JSON array of strings. Example: ["Easy", "Normal", "Hard"]
        caption: Title-bar text of the dialog window.
        prompt: Prompt text shown above the input field in the dialog.
    """
    return safe_post_json("/api/show_selection_list", {
        "options": options, "caption": caption, "prompt": prompt,
    })


# --- INPUT AUTOMATION (system-wide) ---

@mcp.tool()
def get_pixel(x: int, y: int) -> str:
    """Read the RGB color at a screen pixel.

    Args:
        x: Horizontal screen coordinate in pixels from the left edge. Example: 640
        y: Vertical screen coordinate in pixels from the top edge. Example: 480
    """
    return safe_post_json("/api/get_pixel", {"x": x, "y": y})


@mcp.tool()
def get_mouse_pos() -> str:
    """Read the current mouse cursor position in absolute screen coordinates. Use set_mouse_pos to move it. Returns x and y."""
    return safe_post_json("/api/get_mouse_pos")


@mcp.tool()
def set_mouse_pos(x: int, y: int) -> str:
    """Move the system mouse cursor to absolute screen coordinates. This affects the whole desktop, not just the target window. Returns success.

    Args:
        x: Horizontal screen coordinate in pixels from the left edge. Example: 640
        y: Vertical screen coordinate in pixels from the top edge. Example: 480
    """
    return safe_post_json("/api/set_mouse_pos", {"x": x, "y": y})


@mcp.tool()
def is_key_pressed(vk: int) -> str:
    """Test whether a key is physically held down right now, system-wide. Returns true while the key is pressed.

    Args:
        vk: Windows virtual-key code of the key to act on. Example: 0x41 for the A key, 0x20 for space.
    """
    return safe_post_json("/api/is_key_pressed", {"vk": vk})


@mcp.tool()
def key_down(vk: int) -> str:
    """Send a key-press event for one virtual-key and hold it down, system-wide. Pair with key_up to release it. Returns success.

    Args:
        vk: Windows virtual-key code of the key to act on. Example: 0x41 for the A key, 0x20 for space.
    """
    return safe_post_json("/api/key_down", {"vk": vk})


@mcp.tool()
def key_up(vk: int) -> str:
    """Send a key-release event for one virtual-key, system-wide. Pair with key_down to complete a held keypress. Returns success.

    Args:
        vk: Windows virtual-key code of the key to act on. Example: 0x41 for the A key, 0x20 for space.
    """
    return safe_post_json("/api/key_up", {"vk": vk})


@mcp.tool()
def do_key_press(vk: int) -> str:
    """Send a complete key press and release for one virtual-key, system-wide. Use key_down and key_up separately to hold a key. Returns success.

    Args:
        vk: Windows virtual-key code of the key to act on. Example: 0x41 for the A key, 0x20 for space.
    """
    return safe_post_json("/api/do_key_press", {"vk": vk})


@mcp.tool()
def get_screen_info() -> str:
    """Get screen width, height, and DPI."""
    return safe_post_json("/api/get_screen_info")


# --- FILE / CLIPBOARD / SHELL ---

@mcp.tool()
def file_exists(filename: str) -> str:
    """Check if a file exists (on the CE host).

    Args:
        filename: Absolute path to test on the CE host. Example: "C:\\tables\\game.CT"
    """
    return safe_post_json("/api/file_exists", {"filename": filename})


@mcp.tool()
def delete_file(filename: str) -> str:
    """Delete a file from the CE host's filesystem. This is permanent and is not sent to the recycle bin. Returns success.

    Args:
        filename: Absolute path of the file to delete on the CE host. Example: "C:\\dumps\\region.bin"
    """
    return safe_post_json("/api/delete_file", {"filename": filename})


@mcp.tool()
def get_file_list(path: str) -> str:
    """List files in a directory on the CE host.

    Args:
        path: Absolute directory path on the CE host to list files from. Example: "C:\\tables"
    """
    return safe_post_json("/api/get_file_list", {"path": path})


@mcp.tool()
def get_directory_list(path: str) -> str:
    """List subdirectories of a path on the CE host.

    Args:
        path: Absolute directory path on the CE host to list subdirectories of. Example: "C:\\"
    """
    return safe_post_json("/api/get_directory_list", {"path": path})


@mcp.tool()
def get_temp_folder() -> str:
    """Get the Windows TEMP folder path."""
    return safe_post_json("/api/get_temp_folder")


@mcp.tool()
def get_file_version(filename: str) -> str:
    """Get version info from an executable or DLL.

    Args:
        filename: Absolute path to an .exe or .dll on the CE host. Example: "C:\\Games\\game.exe"
    """
    return safe_post_json("/api/get_file_version", {"filename": filename})


@mcp.tool()
def read_clipboard() -> str:
    """Read the current text contents of the Windows clipboard on the CE host. Returns the clipboard text."""
    return safe_post_json("/api/read_clipboard")


@mcp.tool()
def write_clipboard(text: str) -> str:
    """Write text to the Windows clipboard.

    Args:
        text: Text to place on the Windows clipboard. Example: "0x7FF6A21C40"
    """
    return safe_post_json("/api/write_clipboard", {"text": text})


@mcp.tool()
def run_command(command: str, args: str = "") -> str:
    """Run a command as a child process on the CE host and capture its stdout and exit code. Gated behind CE_MCP_ALLOW_SHELL=1, and returns an error when that is unset. Returns captured output and the exit code.

    Args:
        command: Executable name or full path to run on the CE host. Example: "cmd.exe"
        args: Arguments passed to the command, as one command-line string. Example: "/c dir C:\\"
    """
    return safe_post_json("/api/run_command", {"command": command, "args": args})


@mcp.tool()
def shell_execute(command: str, args: str = "", working_dir: str = "") -> str:
    """Run a command via Windows ShellExecute (gated by CE_MCP_ALLOW_SHELL=1).

    Args:
        command: Executable name or full path to run on the CE host. Example: "cmd.exe"
        args: Arguments passed to the command, as one command-line string. Example: "/c dir"
        working_dir: Directory to run the command in. Leave empty to inherit CE's own. Example: "C:\\"
    """
    return safe_post_json("/api/shell_execute", {
        "command": command, "args": args, "working_dir": working_dir,
    })


# --- KERNEL / DBK / DBVM ---

@mcp.tool()
def dbk_get_cr0() -> str:
    """Read the CR0 control register, whose bits control protected mode, paging, and write protection. Requires the DBK kernel driver or DBVM. Returns the register value in hex."""
    return safe_post_json("/api/dbk_get_cr0")


@mcp.tool()
def dbk_get_cr3() -> str:
    """Read the CR3 control register, which holds the physical base address of the current page directory and so identifies the address space. Pass it to read_process_memory_cr3. Requires DBK or DBVM. Returns the register value in hex."""
    return safe_post_json("/api/dbk_get_cr3")


@mcp.tool()
def dbk_get_cr4() -> str:
    """Read the CR4 control register, whose bits enable architecture extensions such as PAE, SMEP, and SMAP. Requires the DBK kernel driver or DBVM. Returns the register value in hex."""
    return safe_post_json("/api/dbk_get_cr4")


@mcp.tool()
def read_process_memory_cr3(cr3: str, address: str, size: int) -> str:
    """Read memory from an address space selected by an explicit CR3 value, rather than the attached process. Use this to reach a process CE is not attached to. Requires the DBK driver. Returns the bytes as hex.

    Args:
        cr3: CR3 page-directory-base register value identifying the address space, in hex. Example: "0x1AB000"
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes to read, returned as hex. Example: 256
    """
    return safe_post_json("/api/read_process_memory_cr3", {
        "cr3": cr3, "address": address, "size": size,
    })


@mcp.tool()
def write_process_memory_cr3(cr3: str, address: str, bytes_hex: str) -> str:
    """Write memory into an address space selected by an explicit CR3 value, rather than the attached process. Requires the DBK driver. Returns the number of bytes written.

    Args:
        cr3: CR3 page-directory-base register value identifying the address space, in hex. Example: "0x1AB000"
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        bytes_hex: Bytes to write, as space-separated hex pairs. Example: "90 90 90"
    """
    return safe_post_json("/api/write_process_memory_cr3", {
        "cr3": cr3, "address": address, "bytes": bytes_hex,
    })


@mcp.tool()
def map_memory(address: str, size: int) -> str:
    """Map a region of target memory into CE's own address space through an MDL, giving direct access without per-read syscalls. Use unmap_memory to release it. Requires the DBK driver. Returns the CE-local mapped address.

    Args:
        address: Address in the attached process. Accepts hex ("0x7FF6A21C40"), module-relative ("game.exe+1059AE0"), or a registered symbol name.
        size: Number of bytes to map into CE's address space. Example: 4096
    """
    return safe_post_json("/api/map_memory", {"address": address, "size": size})


@mcp.tool()
def unmap_memory(mapped_address: str) -> str:
    """Release a mapping created by map_memory and invalidate its CE-local address. Requires the DBK driver. Returns success.

    Args:
        mapped_address: CE-local address returned by map_memory. Example: "0x1F2A3B40"
    """
    return safe_post_json("/api/unmap_memory", {"mapped_address": mapped_address})


@mcp.tool()
def dbk_writes_ignore_write_protection(enable: bool) -> str:
    """Toggle write-protection bypass for kernel writes (requires DBK).

    Args:
        enable: True to let kernel writes bypass page write-protection, False to enforce it again.
    """
    return safe_post_json("/api/dbk_writes_ignore_write_protection", {"enable": enable})


@mcp.tool()
def get_physical_address_cr3(cr3: str, virtual_address: str) -> str:
    """Resolve virtual→physical using a specific CR3 (requires DBK).

    Args:
        cr3: CR3 page-directory-base register value identifying the address space, in hex. Example: "0x1AB000"
        virtual_address: Virtual address to translate, in hex. Example: "0x7FF6A21C40"
    """
    return safe_post_json("/api/get_physical_address_cr3", {
        "cr3": cr3, "virtual_address": virtual_address,
    })


# --- THREADING / GLOBALS (CE scripting host) ---

@mcp.tool()
def create_thread(code: str, arg: str = "") -> str:
    """Run arbitrary Lua code in a new thread inside CE (SECURITY: equivalent to evaluate_lua).

    Args:
        code: Lua source to run on the new CE thread. This executes with CE's full privileges.
        arg: Single string argument made available to the Lua code. Example: ""
    """
    return safe_post_json("/api/create_thread", {"code": code, "arg": arg})


@mcp.tool()
def get_global_variable(name: str) -> str:
    """Read the current value of a named global from Cheat Engine's own Lua interpreter. This reads CE state, not target memory. Returns the value.

    Args:
        name: Name of the CE Lua global to read. Example: "myCounter"
    """
    return safe_post_json("/api/get_global_variable", {"name": name})


@mcp.tool()
def set_global_variable(name: str, value: Union[str, int, float, bool]) -> str:
    """Assign a value to a named global in Cheat Engine's own Lua interpreter, so later scripts and tools can read it. This writes CE state, not target memory. Returns success.

    Args:
        name: Name of the CE Lua global to assign. Example: "myCounter"
        value: Value to store, as a string, number, or boolean. Example: 42
    """
    return safe_post_json("/api/set_global_variable", {"name": name, "value": value})


# --- DEBUG OUTPUT / MULTIMEDIA ---

@mcp.tool()
def output_debug_string(message: str) -> str:
    """Emit a Windows OutputDebugString.

    Args:
        message: Text to emit, visible to DebugView and attached debuggers. Example: "hook installed"
    """
    return safe_post_json("/api/output_debug_string", {"message": message})


@mcp.tool()
def speak_text(text: str, english_only: bool = False) -> str:
    """Speak a line of text aloud on the CE host through the Windows SAPI voice engine. Returns success once the utterance is queued.

    Args:
        text: Text content to use.
        english_only: True to force the English voice rather than the system default. Defaults to False.
    """
    return safe_post_json("/api/speak_text", {"text": text, "english_only": english_only})


@mcp.tool()
def play_sound(filename: str) -> str:
    """Play a sound file on the CE host.

    Args:
        filename: Absolute path to a .wav file on the CE host. Example: "C:\\Windows\\Media\\ding.wav"
    """
    return safe_post_json("/api/play_sound", {"filename": filename})


@mcp.tool()
def beep() -> str:
    """Play the standard Windows system beep on the CE host, useful as an audible marker while a long operation runs. Returns success."""
    return safe_post_json("/api/beep")


@mcp.tool()
def speedhack_set_speed(speed: float = 1.0) -> str:
    """Scale the attached target's perceived time (CE speedhack). 1.0 = normal speed, 2.0 = double, 0.5 = half.

    Args:
        speed: Time multiplier applied to the target: 1.0 is normal, 2.0 runs twice as fast, 0.5 runs at half speed. Example: 2.0
    """
    return safe_post_json("/api/speedhack_set_speed", {"speed": speed})


@mcp.tool()
def set_progress_state(state: str) -> str:
    """Set taskbar progress state: none/normal/paused/error/indeterminate.

    Args:
        state: Taskbar progress state: none, normal, paused, error, or indeterminate. Example: "normal"
    """
    return safe_post_json("/api/set_progress_state", {"state": state})


@mcp.tool()
def set_progress_value(current: int, max: int = 100) -> str:
    """Set how full the CE taskbar progress bar appears, as a current value out of a maximum. Call set_progress_state first to make the bar visible. Returns success.

    Args:
        current: Current progress amount, between 0 and max. Example: 50
        max: Value representing a full bar. Example: 100
    """
    return safe_post_json("/api/set_progress_value", {"current": current, "max": max})


# --- LUA EVALUATION (escape hatch) ---

@mcp.tool()
def evaluate_lua(code: str, timeout_ms: int = 300000) -> str:
    """Evaluate arbitrary Lua source inside Cheat Engine's own Lua state, the escape hatch for anything the typed tools do not cover. The code must return a JSON string for structured results. Returns whatever the script returned.

    Args:
        code: Lua source to evaluate. Return a JSON string for structured results. Example: "return getOpenedProcessID()"
        timeout_ms: Milliseconds to allow the script to run before aborting it. Example: 300000
    """
    return safe_post_json("/api/evaluate_lua", {"code": code, "timeout_ms": timeout_ms})


# ============================================================================
# SCHEMA ENRICHMENT
# ============================================================================
#
# FastMCP derives inputSchema from the function signature via pydantic. It uses the
# docstring for the *tool* description but discards the Google-style "Args:" block,
# so every parameter reaches the model with no description even though this file
# documents all of them. These passes copy that text into the schema and emit an
# explicit "required" array. Both touch the private _tool_manager because
# list_tools() is what hands back the live Tool objects; tool.parameters is a plain
# mutable dict, so mutating it in place sticks.

_ARG_HEADING = re.compile(r"^[ \t]*(?:Args|Arguments|Parameters)[ \t]*:[ \t]*$")
_SECTION_HEADING = re.compile(
    r"^[ \t]*(?:Returns?|Yields?|Raises?|Examples?|Notes?|Warnings?|See Also|Attributes)"
    r"[ \t]*:[ \t]*$"
)
_ARG_LINE = re.compile(r"^[ \t]*(\*{0,2}\w+)[ \t]*(?:\([^)]*\))?[ \t]*:[ \t]*(.*)$")


def _parse_docstring_args(doc):
    """Extract {param_name: description} from a Google-style Args: block."""
    if not doc:
        return {}
    lines = doc.expandtabs(4).splitlines()
    start = next((i for i, ln in enumerate(lines) if _ARG_HEADING.match(ln)), None)
    if start is None:
        return {}

    body = []
    for ln in lines[start + 1:]:
        if _SECTION_HEADING.match(ln) or _ARG_HEADING.match(ln):
            break
        body.append(ln)

    entries = {}
    current = None
    base_indent = None
    for ln in body:
        if not ln.strip():
            continue
        indent = len(ln) - len(ln.lstrip())
        match = _ARG_LINE.match(ln)
        # A new entry must sit at the block's own indent level; anything deeper is
        # a continuation of the previous description (which may itself contain ':').
        if match and (base_indent is None or indent <= base_indent):
            base_indent = indent if base_indent is None else base_indent
            current = match.group(1).lstrip("*")
            entries[current] = match.group(2).strip()
        elif current is not None:
            entries[current] = (entries[current] + " " + ln.strip()).strip()
    return {k: v for k, v in entries.items() if v}


def _enrich_tool_schemas(server):
    """Copy docstring Args: text into each parameter's schema description."""
    enriched = 0
    for tool in server._tool_manager.list_tools():
        params = getattr(tool, "parameters", None)
        if not isinstance(params, dict):
            continue
        properties = params.get("properties")
        if not isinstance(properties, dict):
            continue
        documented = _parse_docstring_args(getattr(getattr(tool, "fn", None), "__doc__", None))
        for name, schema in properties.items():
            if not isinstance(schema, dict) or schema.get("description"):
                continue
            text = documented.get(name)
            if text:
                schema["description"] = text
                enriched += 1
    return enriched


def _declare_explicit_required(server):
    """Emit an explicit "required" array on tools where pydantic omitted it.

    pydantic drops "required" entirely when every parameter has a default, which
    reads as an undeclared contract rather than "nothing is mandatory".
    """
    patched = 0
    for tool in server._tool_manager.list_tools():
        params = getattr(tool, "parameters", None)
        if isinstance(params, dict) and params.get("type") == "object" and "required" not in params:
            params["required"] = []
            patched += 1
    return patched


def apply_schema_enrichment():
    """Run both schema passes. Safe to call more than once."""
    try:
        enriched = _enrich_tool_schemas(mcp)
        patched = _declare_explicit_required(mcp)
        logger.debug(
            "Schema enrichment: %d parameter descriptions injected, "
            "%d tools given an explicit required array",
            enriched,
            patched,
        )
    except Exception as exc:  # never let a cosmetic pass stop the server booting
        logger.warning("Schema enrichment skipped: %s", exc)


apply_schema_enrichment()


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    logger.info(f"CE MCP Bridge starting, server: {ce_server_url}")
    mcp.run()

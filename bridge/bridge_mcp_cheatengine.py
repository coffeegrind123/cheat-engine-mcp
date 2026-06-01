# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import requests
import logging
import time
import json
import os
import sys
from typing import Any

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
    """Check connectivity to the CE HTTP Bridge."""
    return safe_get_json("/api/ping")


# --- PROCESS & MODULES ---

@mcp.tool()
def get_process_info() -> str:
    """Get current process ID, name, modules count, and architecture."""
    return safe_post_json("/api/get_process_info")


@mcp.tool()
def open_process(process: str) -> str:
    """Attach to a process by name or PID."""
    return safe_post_json("/api/open_process", {"process": process})


@mcp.tool()
def get_process_list() -> str:
    """List running processes."""
    return safe_post_json("/api/get_process_list")


@mcp.tool()
def get_processid_from_name(name: str) -> str:
    """Resolve a process name to its PID."""
    return safe_post_json("/api/get_processid_from_name", {"name": name})


@mcp.tool()
def get_foreground_process() -> str:
    """Get PID and window handle of the active foreground window."""
    return safe_post_json("/api/get_foreground_process")


@mcp.tool()
def create_process(path: str, args: str = "", debug: bool = False, break_on_entry: bool = False) -> str:
    """Launch a new process, optionally under CE debugger control."""
    return safe_post_json("/api/create_process", {
        "path": path, "args": args, "debug": debug, "break_on_entry": break_on_entry,
    })


@mcp.tool()
def get_opened_process_id() -> str:
    """Get currently attached process ID."""
    return safe_post_json("/api/get_opened_process_id")


@mcp.tool()
def get_opened_process_handle() -> str:
    """Get currently attached process HANDLE."""
    return safe_post_json("/api/get_opened_process_handle")


@mcp.tool()
def enum_modules(offset: int = 0, limit: int = 100) -> str:
    """List loaded modules with base addresses and sizes."""
    return safe_post_json("/api/enum_modules", {"offset": offset, "limit": limit})


@mcp.tool()
def get_thread_list(offset: int = 0, limit: int = 100) -> str:
    """Get the thread list of the attached process."""
    return safe_post_json("/api/get_thread_list", {"offset": offset, "limit": limit})


# --- MEMORY READING ---

@mcp.tool()
def read_memory(address: str, size: int = 256) -> str:
    """Read raw bytes from memory. Returns hex string."""
    return safe_post_json("/api/read_memory", {"address": address, "size": size})


@mcp.tool()
def read_integer(address: str, type: str = "dword") -> str:
    """Read a number. Types: byte, word, dword, qword, float, double."""
    return safe_post_json("/api/read_integer", {"address": address, "type": type})


@mcp.tool()
def read_float(address: str) -> str:
    """Read a 32-bit float."""
    return safe_post_json("/api/read_float", {"address": address})


@mcp.tool()
def read_double(address: str) -> str:
    """Read a 64-bit double."""
    return safe_post_json("/api/read_double", {"address": address})


@mcp.tool()
def read_string(address: str, max_length: int = 256, wide: bool = False) -> str:
    """Read a string from memory."""
    return safe_post_json("/api/read_string", {"address": address, "max_length": max_length, "wide": wide})


@mcp.tool()
def read_pointer(address: str) -> str:
    """Dereference a pointer at address."""
    return safe_post_json("/api/read_pointer", {"address": address})


@mcp.tool()
def read_pointer_chain(base: str, offsets: list[int]) -> str:
    """Follow a multi-level pointer chain and return each step."""
    return safe_post_json("/api/read_pointer_chain", {"base": base, "offsets": offsets})


@mcp.tool()
def read_many(reads: list[dict]) -> str:
    """Batch-read many typed values in ONE round-trip (much faster than N read_* calls for polling).
    reads: list of {"address": str, "type": str, "length"?: int}. address may be module-relative
    (e.g. "hw.dll+1059AE0"). type: byte|word|dword|qword|float|double|pointer|string (default dword);
    length applies to string reads. Returns per-item {address, resolved, ok, value|error}."""
    return safe_post_json("/api/read_many", {"reads": reads})


@mcp.tool()
def read_struct(base: str, fields: list[dict]) -> str:
    """Read named typed fields at byte offsets from a base address, in ONE round-trip.
    base may be module-relative (e.g. "hw.dll+1008240"). fields: list of
    {"name": str, "offset": int, "type": str, "length"?: int} with type
    byte|word|dword|qword|float|double|pointer|string (default dword).
    Returns {"success":true,"base":"0x..","fields":{name:value,...}}."""
    return safe_post_json("/api/read_struct", {"base": base, "fields": fields})


@mcp.tool()
def get_call_stack(frame: str, instruction_pointer: str = "", max_frames: int = 32) -> str:
    """Walk the call stack from a frame pointer (RBP/EBP) and symbolize return addresses.
    Pass frame (and optionally instruction_pointer) from debug_get_context's registers.
    Returns symbolized frames; pointer size follows the target's bitness."""
    body = {"frame": frame, "max_frames": max_frames}
    if instruction_pointer:
        body["instruction_pointer"] = instruction_pointer
    return safe_post_json("/api/get_call_stack", body)


@mcp.tool()
def run_to_address(address: str, timeout_s: float = 10.0, poll_interval_s: float = 0.2) -> str:
    """Set a one-shot execute breakpoint at address, let the target run, and return when it is hit
    (or on timeout). Orchestrates set_breakpoint -> poll get_breakpoint_hits -> remove_breakpoint
    across separate main-thread calls (a single blocking call would deadlock CE's breakpoint
    callback). Returns {"success":true,"hit":{...}} or a TIMEOUT error. The breakpoint is removed
    on exit either way."""
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
    """Write raw bytes (space-separated hex: '90 90 90')."""
    return safe_post_json("/api/write_memory", {"address": address, "bytes": bytes_hex})


@mcp.tool()
def write_integer(address: str, value: int, type: str = "dword") -> str:
    """Write a number."""
    return safe_post_json("/api/write_integer", {"address": address, "value": value, "type": type})


@mcp.tool()
def write_float(address: str, value: float) -> str:
    """Write a 32-bit float."""
    return safe_post_json("/api/write_float", {"address": address, "value": value})


@mcp.tool()
def write_double(address: str, value: float) -> str:
    """Write a 64-bit double."""
    return safe_post_json("/api/write_double", {"address": address, "value": value})


@mcp.tool()
def write_string(address: str, value: str, wide: bool = False) -> str:
    """Write a string."""
    return safe_post_json("/api/write_string", {"address": address, "value": value, "wide": wide})


# --- SCANNING ---

@mcp.tool()
def scan_all(value: str, scan_type: str = "exact", value_type: str = "dword",
             start_address: str = "0", stop_address: str = "0x7FFFFFFFFFFFFFFF",
             protection: str = "+W-C",
             offset: int = 0, limit: int = 100) -> str:
    """First scan over memory. scan_type: exact/bigger/smaller/between/unknown/increased/decreased/changed/unchanged."""
    return safe_post_json("/api/scan_all", {
        "value": value, "scan_type": scan_type, "value_type": value_type,
        "start_address": start_address, "stop_address": stop_address,
        "protection": protection, "offset": offset, "limit": limit,
    })


@mcp.tool()
def next_scan(value: str = "", scan_type: str = "exact") -> str:
    """Refine previous scan results."""
    return safe_post_json("/api/next_scan", {"value": value, "scan_type": scan_type})


@mcp.tool()
def get_scan_results(offset: int = 0, limit: int = 100) -> str:
    """Fetch results from the most recent scan, paginated."""
    return safe_post_json("/api/get_scan_results", {"offset": offset, "limit": limit})


@mcp.tool()
def aob_scan(pattern: str, protection: str = "+X", offset: int = 0, limit: int = 100) -> str:
    """Array of bytes scan with wildcards (e.g. '48 8B ?? 4C 8D')."""
    return safe_post_json("/api/aob_scan", {
        "pattern": pattern, "protection": protection, "offset": offset, "limit": limit,
    })


@mcp.tool()
def aob_scan_unique(pattern: str, protection: str = "+X") -> str:
    """AOB scan that requires exactly one match."""
    return safe_post_json("/api/aob_scan_unique", {"pattern": pattern, "protection": protection})


@mcp.tool()
def aob_scan_module(pattern: str, module_name: str, protection: str = "+X") -> str:
    """AOB scan constrained to a specific module."""
    return safe_post_json("/api/aob_scan_module", {
        "pattern": pattern, "module_name": module_name, "protection": protection,
    })


@mcp.tool()
def aob_scan_module_unique(pattern: str, module_name: str, protection: str = "+X") -> str:
    """AOB scan within a module requiring exactly one match."""
    return safe_post_json("/api/aob_scan_module_unique", {
        "pattern": pattern, "module_name": module_name, "protection": protection,
    })


@mcp.tool()
def search_string(string: str, wide: bool = False, limit: int = 100) -> str:
    """Quick string search in memory with previews."""
    return safe_post_json("/api/search_string", {"string": string, "wide": wide, "limit": limit})


@mcp.tool()
def generate_signature(address: str) -> str:
    """Auto-generate a unique AOB signature that identifies the given address."""
    return safe_post_json("/api/generate_signature", {"address": address})


@mcp.tool()
def pointer_rescan(value: str, previous_results_file: str = "") -> str:
    """Refine a prior pointer scan with a new current value."""
    return safe_post_json("/api/pointer_rescan", {"value": value, "previous_results_file": previous_results_file})


@mcp.tool()
def create_persistent_scan(name: str) -> str:
    """Create a named persistent scan session."""
    return safe_post_json("/api/create_persistent_scan", {"name": name})


@mcp.tool()
def persistent_scan_first_scan(name: str, value: str, type: str = "dword", scan_option: str = "exact") -> str:
    """Run first scan on a persistent scan session."""
    return safe_post_json("/api/persistent_scan_first_scan", {
        "name": name, "value": value, "type": type, "scan_option": scan_option,
    })


@mcp.tool()
def persistent_scan_next_scan(name: str, value: str = "", scan_option: str = "exact") -> str:
    """Run next scan on a persistent scan session."""
    return safe_post_json("/api/persistent_scan_next_scan", {
        "name": name, "value": value, "scan_option": scan_option,
    })


@mcp.tool()
def persistent_scan_get_results(name: str, offset: int = 0, limit: int = 100) -> str:
    """Fetch results from a persistent scan."""
    return safe_post_json("/api/persistent_scan_get_results", {
        "name": name, "offset": offset, "limit": limit,
    })


@mcp.tool()
def persistent_scan_destroy(name: str) -> str:
    """Destroy a persistent scan session and free its resources."""
    return safe_post_json("/api/persistent_scan_destroy", {"name": name})


@mcp.tool()
def scan_reset() -> str:
    """Reset/clear the current (non-persistent) scan state."""
    return safe_post_json("/api/scan_reset")


# --- DISASSEMBLY & ANALYSIS ---

@mcp.tool()
def disassemble(address: str, count: int = 10) -> str:
    """Disassemble instructions at address."""
    return safe_post_json("/api/disassemble", {"address": address, "count": count})


@mcp.tool()
def assemble_instruction(address: str, instruction: str, preference: int = 0, skip_range_check: bool = False) -> str:
    """Assemble a single instruction. Returns bytes."""
    return safe_post_json("/api/assemble_instruction", {
        "address": address, "instruction": instruction,
        "preference": preference, "skip_range_check": skip_range_check,
    })


@mcp.tool()
def get_instruction_info(address: str) -> str:
    """Get single instruction details (size, bytes, prev/next addresses)."""
    return safe_post_json("/api/get_instruction_info", {"address": address})


@mcp.tool()
def find_function_boundaries(address: str) -> str:
    """Detect function start/end by scanning for prologue/epilogue."""
    return safe_post_json("/api/find_function_boundaries", {"address": address})


@mcp.tool()
def analyze_function(address: str) -> str:
    """Analyze function: size, calls, boundaries."""
    return safe_post_json("/api/analyze_function", {"address": address})


@mcp.tool()
def find_references(address: str, offset: int = 0, limit: int = 100) -> str:
    """Find code references to an address."""
    return safe_post_json("/api/find_references", {"address": address, "offset": offset, "limit": limit})


@mcp.tool()
def find_call_references(address: str, offset: int = 0, limit: int = 100) -> str:
    """Find CALL-specific references to an address."""
    return safe_post_json("/api/find_call_references", {"address": address, "offset": offset, "limit": limit})


@mcp.tool()
def get_rtti_classname(address: str) -> str:
    """Identify C++ RTTI class name at an object address."""
    return safe_post_json("/api/get_rtti_classname", {"address": address})


@mcp.tool()
def get_physical_address(address: str) -> str:
    """Translate a virtual address to its physical RAM address (requires DBK)."""
    return safe_post_json("/api/get_physical_address", {"address": address})


@mcp.tool()
def get_memory_regions(offset: int = 0, limit: int = 100) -> str:
    """List virtual memory regions with protection flags."""
    return safe_post_json("/api/get_memory_regions", {"offset": offset, "limit": limit})


@mcp.tool()
def enum_memory_regions_full(offset: int = 0, limit: int = 100) -> str:
    """Enhanced memory region enumeration with decoded protection/state flags."""
    return safe_post_json("/api/enum_memory_regions_full", {"offset": offset, "limit": limit})


@mcp.tool()
def dissect_structure(address: str, size: int = 256) -> str:
    """Auto-detect fields in a memory structure using CE autoGuess."""
    return safe_post_json("/api/dissect_structure", {"address": address, "size": size})


# --- SYMBOLS ---

@mcp.tool()
def get_symbol_address(symbol: str) -> str:
    """Resolve a symbol name to an address."""
    return safe_post_json("/api/get_symbol_address", {"symbol": symbol})


@mcp.tool()
def get_address_info(address: str, include_modules: bool = True, include_symbols: bool = True, include_sections: bool = False) -> str:
    """Convert an address to a symbolic name (module+offset)."""
    return safe_post_json("/api/get_address_info", {
        "address": address, "include_modules": include_modules,
        "include_symbols": include_symbols, "include_sections": include_sections,
    })


@mcp.tool()
def register_symbol(name: str, address: str, do_not_save: bool = False) -> str:
    """Register a user-defined symbol name."""
    return safe_post_json("/api/register_symbol", {
        "name": name, "address": address, "do_not_save": do_not_save,
    })


@mcp.tool()
def unregister_symbol(name: str) -> str:
    """Remove a registered symbol."""
    return safe_post_json("/api/unregister_symbol", {"name": name})


@mcp.tool()
def enum_registered_symbols() -> str:
    """List all registered symbols."""
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
    """Get detailed info about a symbol."""
    return safe_post_json("/api/get_symbol_info", {"name": name})


@mcp.tool()
def get_module_size(module_name: str) -> str:
    """Get the size of a loaded module."""
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
    """Set a breakpoint. trigger: execute/write/read/access."""
    return safe_post_json("/api/set_breakpoint", {"address": address, "size": size, "trigger": trigger})


@mcp.tool()
def set_data_breakpoint(address: str, size: int = 4, trigger: str = "write") -> str:
    """Set a hardware data watchpoint. trigger: write/read/access."""
    return safe_post_json("/api/set_data_breakpoint", {"address": address, "size": size, "trigger": trigger})


@mcp.tool()
def remove_breakpoint(address: str) -> str:
    """Remove a breakpoint."""
    return safe_post_json("/api/remove_breakpoint", {"address": address})


@mcp.tool()
def list_breakpoints() -> str:
    """List all active breakpoints."""
    return safe_post_json("/api/list_breakpoints")


@mcp.tool()
def clear_all_breakpoints() -> str:
    """Remove all breakpoints and clear hit buffers."""
    return safe_post_json("/api/clear_all_breakpoints")


@mcp.tool()
def get_breakpoint_hits(handle: str, clear: bool = False) -> str:
    """Fetch hit log for a breakpoint handle."""
    return safe_post_json("/api/get_breakpoint_hits", {"handle": handle, "clear": clear})


@mcp.tool()
def debug_process(interface: int = 0) -> str:
    """Attach a debugger to the current process. interface: 0=default, 1=windows_native, 2=veh, 3=kernel, 4=dbvm."""
    return safe_post_json("/api/debug_process", {"interface": interface})


@mcp.tool()
def debug_is_debugging() -> str:
    """Check if debugger is currently attached."""
    return safe_post_json("/api/debug_is_debugging")


@mcp.tool()
def debug_detach() -> str:
    """Detach debugger from target."""
    return safe_post_json("/api/debug_detach")


@mcp.tool()
def debug_continue(method: str = "run") -> str:
    """Resume from a breakpoint. method: run, step_into, step_over."""
    return safe_post_json("/api/debug_continue", {"method": method})


@mcp.tool()
def debug_break_thread(thread_id: int) -> str:
    """Break a specific thread into the debugger."""
    return safe_post_json("/api/debug_break_thread", {"thread_id": thread_id})


@mcp.tool()
def debug_get_context(extra_regs: bool = False) -> str:
    """Get CPU register context at the current breakpoint."""
    return safe_post_json("/api/debug_get_context", {"extra_regs": extra_regs})


@mcp.tool()
def debug_set_context(registers: dict) -> str:
    """Set CPU registers (map of name→value, e.g. {'RAX':'0x1234'})."""
    return safe_post_json("/api/debug_set_context", {"registers": registers})


@mcp.tool()
def debug_get_xmm_pointer(xmm_nr: int = 0) -> str:
    """Get the CE-local address for an XMM register (16 raw bytes)."""
    return safe_post_json("/api/debug_get_xmm_pointer", {"xmm_nr": xmm_nr})


@mcp.tool()
def debug_set_last_branch_recording(enable: bool = True) -> str:
    """Enable/disable LBR (Last Branch Recording, requires kernel debugger)."""
    return safe_post_json("/api/debug_set_last_branch_recording", {"enable": enable})


@mcp.tool()
def debug_get_last_branch_record(index: int = 0) -> str:
    """Read an LBR entry (from/to addresses)."""
    return safe_post_json("/api/debug_get_last_branch_record", {"index": index})


@mcp.tool()
def debug_set_breakpoint_for_thread(thread_id: int, address: str, size: int = 1, trigger: str = "execute") -> str:
    """Set a thread-local breakpoint."""
    return safe_post_json("/api/debug_set_breakpoint_for_thread", {
        "thread_id": thread_id, "address": address, "size": size, "trigger": trigger,
    })


@mcp.tool()
def debug_remove_breakpoint_for_thread(thread_id: int, address: str) -> str:
    """Remove a thread-local breakpoint."""
    return safe_post_json("/api/debug_remove_breakpoint_for_thread", {
        "thread_id": thread_id, "address": address,
    })


@mcp.tool()
def pause_process() -> str:
    """Pause/freeze the target process."""
    return safe_post_json("/api/pause_process")


@mcp.tool()
def unpause_process() -> str:
    """Resume the target process."""
    return safe_post_json("/api/unpause_process")


# --- DBVM HYPERVISOR WATCHES (Safe dynamic tracing) ---

@mcp.tool()
def start_dbvm_watch(address: str, mode: str = "w", max_entries: int = 1000) -> str:
    """Start DBVM-level (ring -1) memory watch. mode: w=write, r=read, rw=access, x=execute."""
    return safe_post_json("/api/start_dbvm_watch", {
        "address": address, "mode": mode, "max_entries": max_entries,
    })


@mcp.tool()
def poll_dbvm_watch(address: str, clear: bool = True, max_results: int = 1000) -> str:
    """Poll DBVM watch log without stopping the watch."""
    return safe_post_json("/api/poll_dbvm_watch", {
        "address": address, "clear": clear, "max_results": max_results,
    })


@mcp.tool()
def stop_dbvm_watch(address: str) -> str:
    """Stop a DBVM watch and return the accumulated log."""
    return safe_post_json("/api/stop_dbvm_watch", {"address": address})


# --- CODE INJECTION & ASSEMBLY ---

@mcp.tool()
def auto_assemble(script: str, disable: bool = False) -> str:
    """Execute a CE auto-assembler script. Set disable=true to run [DISABLE] section."""
    return safe_post_json("/api/auto_assemble", {"script": script, "disable": disable})


@mcp.tool()
def auto_assemble_check(script: str, enable: bool = True, target_self: bool = False) -> str:
    """Validate an AA script without executing it."""
    return safe_post_json("/api/auto_assemble_check", {
        "script": script, "enable": enable, "target_self": target_self,
    })


@mcp.tool()
def inject_dll(filepath: str, skip_symbol_reload: bool = False) -> str:
    """Inject a native DLL into the target process."""
    return safe_post_json("/api/inject_dll", {"filepath": filepath, "skip_symbol_reload": skip_symbol_reload})


@mcp.tool()
def inject_dotnet_dll(filepath: str, class_name: str, method_name: str, param: str = "", timeout: int = -1) -> str:
    """Inject a .NET assembly and call a method."""
    return safe_post_json("/api/inject_dotnet_dll", {
        "filepath": filepath, "class_name": class_name, "method_name": method_name,
        "param": param, "timeout": timeout,
    })


@mcp.tool()
def allocate_memory(size: int = 4096, base_address: str = "", protection: str = "rwx") -> str:
    """Allocate memory in the target process."""
    return safe_post_json("/api/allocate_memory", {
        "size": size, "base_address": base_address, "protection": protection,
    })


@mcp.tool()
def free_memory(address: str, size: int = 0) -> str:
    """Free allocated memory."""
    return safe_post_json("/api/free_memory", {"address": address, "size": size})


@mcp.tool()
def allocate_shared_memory(name: str, size: int) -> str:
    """Allocate a named shared memory region."""
    return safe_post_json("/api/allocate_shared_memory", {"name": name, "size": size})


@mcp.tool()
def allocate_kernel_memory(size: int) -> str:
    """Allocate kernel memory (requires DBK)."""
    return safe_post_json("/api/allocate_kernel_memory", {"size": size})


@mcp.tool()
def create_section(size: int) -> str:
    """Create a Windows section object of the given size."""
    return safe_post_json("/api/create_section", {"size": size})


@mcp.tool()
def map_view_of_section(handle: str, address: str = "") -> str:
    """Map a section into the target process's address space."""
    return safe_post_json("/api/map_view_of_section", {"handle": handle, "address": address})


@mcp.tool()
def execute_code(address: str, param: int = 0, timeout: int = -1) -> str:
    """Execute code at address via CreateRemoteThread."""
    return safe_post_json("/api/execute_code", {"address": address, "param": param, "timeout": timeout})


@mcp.tool()
def execute_code_ex(address: str, args: list = None, call_method: int = 0, timeout: int = -1) -> str:
    """Execute code with arbitrary arguments."""
    return safe_post_json("/api/execute_code_ex", {
        "address": address, "args": args or [], "call_method": call_method, "timeout": timeout,
    })


@mcp.tool()
def execute_method(address: str, instance: str, args: list = None, call_method: int = 0, timeout: int = -1) -> str:
    """Call a class method with `instance` as the `this` pointer."""
    return safe_post_json("/api/execute_method", {
        "address": address, "instance": instance, "args": args or [],
        "call_method": call_method, "timeout": timeout,
    })


@mcp.tool()
def execute_code_local(address: str, param: int = 0) -> str:
    """Execute code in CE's own process (not the target)."""
    return safe_post_json("/api/execute_code_local", {"address": address, "param": param})


@mcp.tool()
def execute_code_local_ex(address: str, args: list = None, call_method: int = 0) -> str:
    """Execute local code with arguments."""
    return safe_post_json("/api/execute_code_local_ex", {
        "address": address, "args": args or [], "call_method": call_method,
    })


@mcp.tool()
def compile_c_code(source: str, address: str = "", target_self: bool = False, kernelmode: bool = False) -> str:
    """JIT-compile C source via CE's TCC. Returns symbols."""
    return safe_post_json("/api/compile_c_code", {
        "source": source, "address": address, "target_self": target_self, "kernelmode": kernelmode,
    })


@mcp.tool()
def compile_cs_code(source: str, references: list = None, core_assembly: str = "") -> str:
    """JIT-compile C# source. Returns assembly handle."""
    return safe_post_json("/api/compile_cs_code", {
        "source": source, "references": references or [], "core_assembly": core_assembly,
    })


@mcp.tool()
def generate_api_hook_script(address: str, target_address: str, code_to_execute: str = "") -> str:
    """Generate an AA script that hooks a Windows API and calls target_address."""
    return safe_post_json("/api/generate_api_hook_script", {
        "address": address, "target_address": target_address, "code_to_execute": code_to_execute,
    })


@mcp.tool()
def generate_code_injection_script(address: str) -> str:
    """Generate a template AA code-injection script for address."""
    return safe_post_json("/api/generate_code_injection_script", {"address": address})


# --- CHEAT TABLE ---

@mcp.tool()
def load_table(path: str, merge: bool = False) -> str:
    """Load a Cheat Engine cheat table (.CT file)."""
    return safe_post_json("/api/load_table", {"path": path, "merge": merge})


@mcp.tool()
def save_table(path: str, protect: bool = False) -> str:
    """Save the current cheat table."""
    return safe_post_json("/api/save_table", {"path": path, "protect": protect})


@mcp.tool()
def get_address_list(offset: int = 0, limit: int = 100) -> str:
    """Get entries from the address list (cheat table records)."""
    return safe_post_json("/api/get_address_list", {"offset": offset, "limit": limit})


@mcp.tool()
def get_memory_record(id: int = -1, description: str = "") -> str:
    """Get a single memory record by ID or description."""
    data = {}
    if id >= 0:
        data["id"] = id
    if description:
        data["description"] = description
    return safe_post_json("/api/get_memory_record", data)


@mcp.tool()
def create_memory_record(description: str, address: str, type: str = "dword") -> str:
    """Create a new memory record in the cheat table."""
    return safe_post_json("/api/create_memory_record", {
        "description": description, "address": address, "type": type,
    })


@mcp.tool()
def delete_memory_record(id: int) -> str:
    """Delete a memory record by ID."""
    return safe_post_json("/api/delete_memory_record", {"id": id})


@mcp.tool()
def get_memory_record_value(id: int) -> str:
    """Read the current value of a memory record."""
    return safe_post_json("/api/get_memory_record_value", {"id": id})


@mcp.tool()
def set_memory_record_value(id: int, value: str) -> str:
    """Set a memory record's value."""
    return safe_post_json("/api/set_memory_record_value", {"id": id, "value": value})


@mcp.tool()
def freeze_mem(address: str, size: int = 4) -> str:
    """Freeze a memory value."""
    return safe_post_json("/api/freeze_mem", {"address": address, "size": size})


@mcp.tool()
def unfreeze_mem(freeze_id: int) -> str:
    """Unfreeze a previously frozen memory value."""
    return safe_post_json("/api/unfreeze_mem", {"freeze_id": freeze_id})


# --- MEMORY OPERATIONS ---

@mcp.tool()
def checksum_memory(address: str, size: int = 256) -> str:
    """Calculate MD5 hash of a memory region (for change detection)."""
    return safe_post_json("/api/checksum_memory", {"address": address, "size": size})


@mcp.tool()
def md5_memory(address: str, size: int) -> str:
    """MD5 hash of a memory region."""
    return safe_post_json("/api/md5_memory", {"address": address, "size": size})


@mcp.tool()
def md5_file(filename: str) -> str:
    """MD5 hash of a file."""
    return safe_post_json("/api/md5_file", {"filename": filename})


@mcp.tool()
def copy_memory(source: str, size: int, dest: str = "", method: int = 0) -> str:
    """Copy a memory region. If dest is empty, allocates a new destination."""
    return safe_post_json("/api/copy_memory", {"source": source, "size": size, "dest": dest, "method": method})


@mcp.tool()
def compare_memory(addr1: str, addr2: str, size: int, method: int = 0) -> str:
    """Compare two memory regions byte by byte."""
    return safe_post_json("/api/compare_memory", {"addr1": addr1, "addr2": addr2, "size": size, "method": method})


@mcp.tool()
def write_region_to_file(address: str, size: int, filename: str) -> str:
    """Dump a memory region to a file."""
    return safe_post_json("/api/write_region_to_file", {"address": address, "size": size, "filename": filename})


@mcp.tool()
def read_region_from_file(filename: str, destination: str) -> str:
    """Load a file's contents into a memory region."""
    return safe_post_json("/api/read_region_from_file", {"filename": filename, "destination": destination})


@mcp.tool()
def get_memory_protection(address: str) -> str:
    """Get the memory protection flags (r/w/x) for an address."""
    return safe_post_json("/api/get_memory_protection", {"address": address})


@mcp.tool()
def set_memory_protection(address: str, size: int, read: bool = True, write: bool = True, execute: bool = True) -> str:
    """Set memory protection on a region."""
    return safe_post_json("/api/set_memory_protection", {
        "address": address, "size": size, "read": read, "write": write, "execute": execute,
    })


@mcp.tool()
def full_access(address: str, size: int) -> str:
    """Grant RWX on a memory region."""
    return safe_post_json("/api/full_access", {"address": address, "size": size})


# --- STRUCTURES ---

@mcp.tool()
def create_structure(name: str) -> str:
    """Create a new named CE structure."""
    return safe_post_json("/api/create_structure", {"name": name})


@mcp.tool()
def get_structure_by_name(name: str) -> str:
    """Look up an existing structure by name."""
    return safe_post_json("/api/get_structure_by_name", {"name": name})


@mcp.tool()
def add_element_to_structure(structure_id: int, name: str, offset: int, type: str) -> str:
    """Add a typed field to a structure. type: byte/word/dword/qword/float/double/string/aob/pointer."""
    return safe_post_json("/api/add_element_to_structure", {
        "structure_id": structure_id, "name": name, "offset": offset, "type": type,
    })


@mcp.tool()
def get_structure_elements(structure_id: int) -> str:
    """List fields in a structure."""
    return safe_post_json("/api/get_structure_elements", {"structure_id": structure_id})


@mcp.tool()
def export_structure_to_xml(structure_id: int) -> str:
    """Export structure definition as XML."""
    return safe_post_json("/api/export_structure_to_xml", {"structure_id": structure_id})


@mcp.tool()
def delete_structure(structure_id: int) -> str:
    """Delete a structure."""
    return safe_post_json("/api/delete_structure", {"structure_id": structure_id})


# --- WINDOW / GUI ---

@mcp.tool()
def find_window(title: str = "", class_name: str = "") -> str:
    """Find a window by title and/or class name."""
    return safe_post_json("/api/find_window", {"title": title, "class_name": class_name})


@mcp.tool()
def get_window_caption(handle: str) -> str:
    """Get the caption (title bar text) of a window."""
    return safe_post_json("/api/get_window_caption", {"handle": handle})


@mcp.tool()
def get_window_class_name(handle: str) -> str:
    """Get the class name of a window."""
    return safe_post_json("/api/get_window_class_name", {"handle": handle})


@mcp.tool()
def get_window_process_id(handle: str) -> str:
    """Get the PID that owns a window."""
    return safe_post_json("/api/get_window_process_id", {"handle": handle})


@mcp.tool()
def send_window_message(handle: str, msg: int, wparam: int = 0, lparam: int = 0) -> str:
    """Send a Windows message to a window."""
    return safe_post_json("/api/send_window_message", {
        "handle": handle, "msg": msg, "wparam": wparam, "lparam": lparam,
    })


@mcp.tool()
def show_message(message: str) -> str:
    """Show a modal message box in CE (blocks main thread)."""
    return safe_post_json("/api/show_message", {"message": message})


@mcp.tool()
def input_query(caption: str = "", prompt: str = "", default: str = "") -> str:
    """Show a modal input dialog in CE."""
    return safe_post_json("/api/input_query", {"caption": caption, "prompt": prompt, "default": default})


@mcp.tool()
def show_selection_list(options: list[str], caption: str = "", prompt: str = "") -> str:
    """Show a modal selection list dialog in CE."""
    return safe_post_json("/api/show_selection_list", {
        "options": options, "caption": caption, "prompt": prompt,
    })


# --- INPUT AUTOMATION (system-wide) ---

@mcp.tool()
def get_pixel(x: int, y: int) -> str:
    """Read the RGB color at a screen pixel."""
    return safe_post_json("/api/get_pixel", {"x": x, "y": y})


@mcp.tool()
def get_mouse_pos() -> str:
    """Get the current mouse cursor position."""
    return safe_post_json("/api/get_mouse_pos")


@mcp.tool()
def set_mouse_pos(x: int, y: int) -> str:
    """Move the mouse cursor."""
    return safe_post_json("/api/set_mouse_pos", {"x": x, "y": y})


@mcp.tool()
def is_key_pressed(vk: int) -> str:
    """Check if a virtual-key is currently down."""
    return safe_post_json("/api/is_key_pressed", {"vk": vk})


@mcp.tool()
def key_down(vk: int) -> str:
    """Simulate a key press (without release)."""
    return safe_post_json("/api/key_down", {"vk": vk})


@mcp.tool()
def key_up(vk: int) -> str:
    """Simulate a key release."""
    return safe_post_json("/api/key_up", {"vk": vk})


@mcp.tool()
def do_key_press(vk: int) -> str:
    """Simulate a full key press+release."""
    return safe_post_json("/api/do_key_press", {"vk": vk})


@mcp.tool()
def get_screen_info() -> str:
    """Get screen width, height, and DPI."""
    return safe_post_json("/api/get_screen_info")


# --- FILE / CLIPBOARD / SHELL ---

@mcp.tool()
def file_exists(filename: str) -> str:
    """Check if a file exists (on the CE host)."""
    return safe_post_json("/api/file_exists", {"filename": filename})


@mcp.tool()
def delete_file(filename: str) -> str:
    """Delete a file on the CE host."""
    return safe_post_json("/api/delete_file", {"filename": filename})


@mcp.tool()
def get_file_list(path: str) -> str:
    """List files in a directory on the CE host."""
    return safe_post_json("/api/get_file_list", {"path": path})


@mcp.tool()
def get_directory_list(path: str) -> str:
    """List subdirectories of a path on the CE host."""
    return safe_post_json("/api/get_directory_list", {"path": path})


@mcp.tool()
def get_temp_folder() -> str:
    """Get the Windows TEMP folder path."""
    return safe_post_json("/api/get_temp_folder")


@mcp.tool()
def get_file_version(filename: str) -> str:
    """Get version info from an executable or DLL."""
    return safe_post_json("/api/get_file_version", {"filename": filename})


@mcp.tool()
def read_clipboard() -> str:
    """Read the Windows clipboard."""
    return safe_post_json("/api/read_clipboard")


@mcp.tool()
def write_clipboard(text: str) -> str:
    """Write text to the Windows clipboard."""
    return safe_post_json("/api/write_clipboard", {"text": text})


@mcp.tool()
def run_command(command: str, args: str = "") -> str:
    """Run a process and capture its output (gated by CE_MCP_ALLOW_SHELL=1)."""
    return safe_post_json("/api/run_command", {"command": command, "args": args})


@mcp.tool()
def shell_execute(command: str, args: str = "", working_dir: str = "") -> str:
    """Run a command via Windows ShellExecute (gated by CE_MCP_ALLOW_SHELL=1)."""
    return safe_post_json("/api/shell_execute", {
        "command": command, "args": args, "working_dir": working_dir,
    })


# --- KERNEL / DBK / DBVM ---

@mcp.tool()
def dbk_get_cr0() -> str:
    """Read CR0 (requires DBK/DBVM)."""
    return safe_post_json("/api/dbk_get_cr0")


@mcp.tool()
def dbk_get_cr3() -> str:
    """Read CR3 (requires DBK/DBVM)."""
    return safe_post_json("/api/dbk_get_cr3")


@mcp.tool()
def dbk_get_cr4() -> str:
    """Read CR4 (requires DBK/DBVM)."""
    return safe_post_json("/api/dbk_get_cr4")


@mcp.tool()
def read_process_memory_cr3(cr3: str, address: str, size: int) -> str:
    """Read memory using a specific CR3 (requires DBK)."""
    return safe_post_json("/api/read_process_memory_cr3", {
        "cr3": cr3, "address": address, "size": size,
    })


@mcp.tool()
def write_process_memory_cr3(cr3: str, address: str, bytes_hex: str) -> str:
    """Write memory using a specific CR3 (requires DBK)."""
    return safe_post_json("/api/write_process_memory_cr3", {
        "cr3": cr3, "address": address, "bytes": bytes_hex,
    })


@mcp.tool()
def map_memory(address: str, size: int) -> str:
    """Map target memory into CE's address space via MDL (requires DBK)."""
    return safe_post_json("/api/map_memory", {"address": address, "size": size})


@mcp.tool()
def unmap_memory(mapped_address: str) -> str:
    """Unmap memory previously mapped via map_memory."""
    return safe_post_json("/api/unmap_memory", {"mapped_address": mapped_address})


@mcp.tool()
def dbk_writes_ignore_write_protection(enable: bool) -> str:
    """Toggle write-protection bypass for kernel writes (requires DBK)."""
    return safe_post_json("/api/dbk_writes_ignore_write_protection", {"enable": enable})


@mcp.tool()
def get_physical_address_cr3(cr3: str, virtual_address: str) -> str:
    """Resolve virtual→physical using a specific CR3 (requires DBK)."""
    return safe_post_json("/api/get_physical_address_cr3", {
        "cr3": cr3, "virtual_address": virtual_address,
    })


# --- THREADING / GLOBALS (CE scripting host) ---

@mcp.tool()
def create_thread(code: str, arg: str = "") -> str:
    """Run arbitrary Lua code in a new thread inside CE (SECURITY: equivalent to evaluate_lua)."""
    return safe_post_json("/api/create_thread", {"code": code, "arg": arg})


@mcp.tool()
def get_global_variable(name: str) -> str:
    """Read a CE Lua global variable."""
    return safe_post_json("/api/get_global_variable", {"name": name})


@mcp.tool()
def set_global_variable(name: str, value: Any) -> str:
    """Set a CE Lua global variable."""
    return safe_post_json("/api/set_global_variable", {"name": name, "value": value})


# --- DEBUG OUTPUT / MULTIMEDIA ---

@mcp.tool()
def output_debug_string(message: str) -> str:
    """Emit a Windows OutputDebugString."""
    return safe_post_json("/api/output_debug_string", {"message": message})


@mcp.tool()
def speak_text(text: str, english_only: bool = False) -> str:
    """Speak text via Windows SAPI."""
    return safe_post_json("/api/speak_text", {"text": text, "english_only": english_only})


@mcp.tool()
def play_sound(filename: str) -> str:
    """Play a sound file on the CE host."""
    return safe_post_json("/api/play_sound", {"filename": filename})


@mcp.tool()
def beep() -> str:
    """Play a system beep."""
    return safe_post_json("/api/beep")


@mcp.tool()
def speedhack_set_speed(speed: float = 1.0) -> str:
    """Scale the attached target's perceived time (CE speedhack). 1.0 = normal speed, 2.0 = double, 0.5 = half."""
    return safe_post_json("/api/speedhack_set_speed", {"speed": speed})


@mcp.tool()
def set_progress_state(state: str) -> str:
    """Set taskbar progress state: none/normal/paused/error/indeterminate."""
    return safe_post_json("/api/set_progress_state", {"state": state})


@mcp.tool()
def set_progress_value(current: int, max: int = 100) -> str:
    """Set taskbar progress value."""
    return safe_post_json("/api/set_progress_value", {"current": current, "max": max})


# --- LUA EVALUATION (escape hatch) ---

@mcp.tool()
def evaluate_lua(code: str, timeout_ms: int = 300000) -> str:
    """Execute arbitrary Lua in CE's Lua state. The code must return a JSON string for structured results."""
    return safe_post_json("/api/evaluate_lua", {"code": code, "timeout_ms": timeout_ms})


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    logger.info(f"CE MCP Bridge starting, server: {ce_server_url}")
    mcp.run()

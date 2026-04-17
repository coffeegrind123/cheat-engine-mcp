# CE HTTP Bridge

An HTTP/MCP bridge for [Cheat Engine](https://www.cheatengine.org/) that lets Claude Code (or any MCP client) drive CE's memory inspection, scanning, debugging, and code-injection features from a Linux container targeting Windows.

The plugin DLL embeds an HTTP server inside Cheat Engine; a Python MCP bridge in the container translates MCP stdio calls into HTTP requests against the plugin. Same dual-process pattern as the Ghidra MCP bridge.

```
Claude Code (container)
  └─ stdio ─► bridge_mcp_cheatengine.py   (Python, container)
                └─ HTTP/JSON ─► ce_http_bridge.dll   (C++ plugin in CE on Windows)
                                  ├─ CE SDK direct calls (thread-safe)
                                  └─ Lua command queue → 10ms main-thread timer
                                        └─► Target process
```

## Feature Surface

- 175 HTTP endpoints / 176 MCP tools covering the full CE Lua API
- Process attach, memory read/write (typed), AOB/value/module scanning with persistent sessions
- Disassembly, assembly, function analysis, xref discovery, RTTI identification
- Software + hardware breakpoints, per-thread breakpoints, CPU context get/set, XMM/LBR
- DBVM (ring -1) invisible watchpoints with poll/stop lifecycle
- Code injection: auto-assembler, DLL injection (.NET too), TCC/C# JIT, executeCode variants
- Cheat table load/save, memory record CRUD
- CE structures, window/GUI automation, input simulation, kernel-mode (DBK) operations
- Clipboard, file I/O, shell execution (gated), taskbar progress, TTS

See `bridge/bridge_mcp_cheatengine.py` for the complete tool inventory with docstrings.

## Requirements

**Host (Windows, where Cheat Engine runs):**
- Cheat Engine 7.x (provides `lua53-64.dll`, which the plugin imports)

**MCP client host (Linux, typically a container):**
- Python 3.10+
- `mingw-w64` package for cross-compilation (if building the DLL from source)

## Build

Cross-compiled from Linux using MinGW.

```bash
sudo apt-get install mingw-w64        # once
git clone <repo> && cd cheatengine-http-bridge
make fetch-lua-headers                # downloads Lua 5.3.6 headers into vendor/ (once)
make                                  # produces build/ce_http_bridge.dll
make clean && make                    # full rebuild
```

Override paths or the toolchain if needed:
```bash
make MINGW_PREFIX=x86_64-w64-mingw32         # default toolchain prefix
make LUA_SRC=/path/to/lua-5.3.x/src          # use a different Lua header tree
```

**Runtime dependencies of the output DLL:** `KERNEL32.dll`, `msvcrt.dll`, `WS2_32.dll` (Windows system libraries) and `lua53-64.dll` (shipped with Cheat Engine). `libstdc++`, `libgcc`, and `libwinpthread` are statically linked.

**Why dynamic-link Lua?** The plugin must share CE's Lua state. Statically linking a separate Lua runtime would corrupt that state (two allocators, two function tables) and crash with an access violation. The `plugin/lua53-64.def` file declares CE's Lua exports; `plugin/lua53-64.a` is the import library regenerated from it via:

```bash
cd plugin && x86_64-w64-mingw32-dlltool \
    --input-def lua53-64.def --dllname lua53-64.dll \
    --output-lib lua53-64.a --kill-at
```

Vendor single-header libraries (`httplib.h`, `nlohmann/json.hpp`) are committed under `plugin/vendor/`.

### Building with Visual Studio

`plugin/plugin.vcxproj` builds the same DLL with MSVC on Windows. Generate `lua53-64.lib` from the `.def` file first:

```cmd
lib /def:plugin\lua53-64.def /out:plugin\lua53-64.lib /machine:x64
```

Then open the vcxproj and build `Release|x64`.

## Installation

1. Copy `build/ce_http_bridge.dll` to Cheat Engine's `autorun\` or `Plugins\` directory
2. Start Cheat Engine — a console window appears and the plugin logs:
   ```
   [CE HTTP Bridge] HTTP server listening on 0.0.0.0:6789
   ```
3. Install Python deps on the MCP host:
   ```bash
   pip install -r bridge/requirements.txt
   ```
4. Register the MCP server with your client. For Claude Code in `~/.claude/settings.json`:
   ```json
   {
     "mcpServers": {
       "cheatengine": {
         "command": "/bin/bash",
         "args": ["/absolute/path/to/cheatengine-http-bridge/bridge/run-mcp.sh"]
       }
     }
   }
   ```

The bridge connects to `http://host.docker.internal:6789` by default (the common hostname when Claude Code runs inside Docker and CE runs on the Docker host). Override with `CE_HTTP_URL` if CE runs on a different machine or port:

```bash
export CE_HTTP_URL=http://192.168.1.10:6789
```

Change the plugin's listen port with `CE_HTTP_PORT` (set in Cheat Engine's environment before launch).

## Project Layout

```
plugin/                      # C++ DLL source (Windows target)
├── main.cpp                 # CE plugin lifecycle, starts HTTP server on port 6789
├── ce_api.{h,cpp}           # Wrapper around CE SDK ExportedFunctions
├── lua_bridge.{h,cpp}       # Thread-safe Lua execution: queue + 10ms timer
├── http_server.{h,cpp}      # cpp-httplib server, JSON/hex helpers
├── handlers/                # One file per endpoint category
│   ├── handler_helpers.h    # Shared Lua-escape / JSON→Lua helpers
│   ├── handlers.h           # Registration function declarations
│   └── *_handlers.cpp       # 15 categories: process, memory, scan, analysis,
│                            # debug, symbol, injection, table, structure,
│                            # window, input, file, kernel, threading, misc
├── CheatEngine/             # CE Plugin SDK headers (cepluginsdk.h, lua*.h)
├── vendor/                  # httplib.h, nlohmann/json.hpp
├── lua53-64.def             # CE's Lua DLL export declaration
├── lua53-64.a               # Import library (regenerated from .def)
├── plugin.def               # DLL exports (CEPlugin_* functions)
└── plugin.vcxproj           # Visual Studio project (alternative build)

bridge/                      # Python MCP bridge
├── bridge_mcp_cheatengine.py   # FastMCP server, 176 @mcp.tool() functions
├── run-mcp.sh                  # Startup wrapper
└── requirements.txt

Makefile                     # MinGW cross-compile
vendor/                      # Downloaded Lua 5.3.6 headers (after make fetch-lua-headers)
build/                       # Build artifacts — ce_http_bridge.dll is the output
```

## Architecture Notes

### Two execution paths in the plugin

**SDK-direct** (runs on HTTP worker thread, safe from any thread):
`ReadProcessMemory`, `WriteProcessMemory`, disassembly, assembly, AutoAssemble, breakpoint SDK calls, pause/unpause, InjectDLL, FreezeMem, symbol resolution.

**Lua-marshaled** (queued onto CE main thread via 10ms timer): everything that touches CE's Lua API — scans, module enumeration, structures, DBVM, cheat tables, register context, etc. CE's Lua state is not thread-safe; commands are executed sequentially on the main thread.

### HTTP API convention

- All calls POST with JSON (except `GET /api/ping`)
- Success: `{"success": true, ...}`
- Error: `{"success": false, "error": "...", "error_code": "..."}`
- Error codes: `NO_PROCESS`, `INVALID_ADDRESS`, `INVALID_PARAMS`, `NOT_FOUND`, `OUT_OF_RESOURCES`, `INTERNAL_ERROR`, `DBVM_NOT_LOADED`, `DBK_NOT_LOADED`, `PERMISSION_DENIED`, `CE_API_UNAVAILABLE`
- Addresses: hex strings in and out (`"0x140001000"`)
- Pagination: `offset`/`limit` → `{total, offset, limit, returned, items[]}`

### Persistent state

A Lua-side `serverState` table (initialized by `lua_bridge.cpp`) holds:
- `scan_memscan` / `scan_foundlist` — most-recent scan session
- `persistent_scans[name]` — named long-lived scan sessions
- `active_watches[addr]` — DBVM watch registry
- `breakpoints[handle]` / `breakpoint_hits[handle]` — BP registry + hit buffers
- `structures[id]` / `structure_next_id` — CE structure registry
- `sections[handle]` — Win32 section objects
- `mappedMDL[addr]` — kernel MDL handles for unmap

## Security

### Shell execution

`run_command` and `shell_execute` are gated behind `CE_MCP_ALLOW_SHELL=1`. Without this environment variable set on the plugin side, both return `PERMISSION_DENIED`.

### Path traversal

File-I/O endpoints (`file_exists`, `delete_file`, `get_file_list`, `get_directory_list`, `get_file_version`, `play_sound`, `write_region_to_file`, `read_region_from_file`) reject paths containing `..`.

### Arbitrary code execution

These tools are functionally equivalent to arbitrary code execution on the Windows host and target process and have the same blast radius:
- `evaluate_lua`, `create_thread` — arbitrary Lua in CE's scripting host
- `auto_assemble`, `inject_dll`, `inject_dotnet_dll`, `execute_code*` — arbitrary code in the target
- `compile_c_code`, `compile_cs_code` — JIT compile + run

Exposing the MCP server to untrusted networks is equivalent to giving shell access. The HTTP server binds to `0.0.0.0:6789` by default — firewall accordingly.

## Reference Implementations

- **CE Plugin SDK**: [Metick/CheatEngine-DMA](https://github.com/Metick/CheatEngine-DMA) — SDK headers copied from here
- **Feature source of truth**: [lauralex/cheatengine-mcp-bridge](https://github.com/lauralex/cheatengine-mcp-bridge) — the Named Pipe bridge whose ~180-tool surface this project replicates
- **Architecture template**: [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) — dual-process HTTP bridge pattern

## Troubleshooting

**Plugin console shows "Lua bridge init failed"**
CE's Lua state wasn't available at `GetLuaState()`. Lua-based endpoints will return errors; SDK-direct endpoints still work. Restart CE.

**`{"error_code":"DBVM_NOT_LOADED"}` on DBVM watches**
Enable DBVM in Cheat Engine: `Settings → Debugger → Use DBVM`. Requires Intel VT-x / AMD-V.

**`{"error_code":"DBK_NOT_LOADED"}` on kernel endpoints**
Enable kernel debugger: `Settings → Debugger → Kernelmode debugger`. Requires disabling Windows Driver Signature Enforcement or signing the DBK driver.

**`Cannot reach CE HTTP Bridge at http://host.docker.internal:6789`**
- Verify the DLL loaded (plugin console visible)
- From the container: `curl http://host.docker.internal:6789/api/ping`
- On Windows, open port 6789 in the firewall or bind the plugin to a specific interface via `CE_HTTP_PORT`

**Builds fail with `lua.h: No such file or directory`**
Run `make fetch-lua-headers` to download Lua 5.3.6 into `vendor/`, or point to an existing copy with `make LUA_SRC=/path/to/lua-5.3.x/src`.

**Plugin loads but the process crashes with an access violation on init**
You built the DLL with Lua statically linked. The plugin must import CE's `lua53-64.dll` at runtime — rebuild with the import library (`plugin/lua53-64.a` generated from `plugin/lua53-64.def`) and verify with `objdump -p build/ce_http_bridge.dll | grep 'DLL Name'` that `lua53-64.dll` appears.

**`The plugin dll could not be loaded: 126`**
Missing DLL dependency. Run `objdump -p build/ce_http_bridge.dll | grep 'DLL Name'`; every entry must be either a Windows system DLL or `lua53-64.dll`. If `libstdc++-6.dll` or `libwinpthread-1.dll` appear, the `-static-libstdc++` / `-Wl,-Bstatic -lpthread` flags in the Makefile aren't applying.

**Builds fail with `windows.h: No such file or directory`**
The toolchain isn't MinGW. Install `mingw-w64` or override with `make MINGW_PREFIX=<your-prefix>`.

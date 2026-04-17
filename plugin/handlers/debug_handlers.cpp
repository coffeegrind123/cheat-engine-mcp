#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

void RegisterDebugHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/set_breakpoint", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int size = body.value("size", 1);
            std::string trigger = body.value("trigger", "execute");

            std::string triggerLua;
            if (trigger == "write") triggerLua = "bptWrite";
            else if (trigger == "read" || trigger == "access") triggerLua = "bptAccess";
            else triggerLua = "bptExecute";

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr or addr == 0 then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local bpHandle = "bp_" .. string.format("%X", addr)
                serverState.breakpoint_hits = serverState.breakpoint_hits or {}
                serverState.breakpoint_hits[bpHandle] = {}
                local ok, err = pcall(debug_setBreakpoint, addr, )LUA" + std::to_string(size) + R"LUA(, )LUA" + triggerLua + R"LUA(, function()
                    table.insert(serverState.breakpoint_hits[bpHandle], {
                        address = string.format("0x%X", addr),
                        timestamp = os.time()
                    })
                    debug_continueFromBreakpoint(co_run)
                    return 1
                end)
                if not ok then
                    serverState.breakpoint_hits[bpHandle] = nil
                    return '{"success":false,"error":"debug_setBreakpoint failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"CE_API_UNAVAILABLE"}'
                end
                serverState.breakpoints = serverState.breakpoints or {}
                serverState.breakpoints[bpHandle] = { address = addr, trigger = ")LUA" + trigger + R"LUA(", size = )LUA" + std::to_string(size) + R"LUA( }
                return '{"success":true,"bp_handle":"' .. bpHandle .. '","address":"' .. string.format("0x%X", addr) .. '","trigger":")LUA" + trigger + R"LUA("}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/set_data_breakpoint", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int size = body.value("size", 4);
            std::string trigger = body.value("trigger", "write");

            std::string triggerLua;
            if (trigger == "write") triggerLua = "bptWrite";
            else if (trigger == "read") triggerLua = "bptAccess";
            else triggerLua = "bptAccess";

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr or addr == 0 then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local bpHandle = "data_" .. string.format("%X", addr)
                serverState.breakpoint_hits = serverState.breakpoint_hits or {}
                serverState.breakpoint_hits[bpHandle] = {}
                local ok, err = pcall(debug_setBreakpoint, addr, )LUA" + std::to_string(size) + R"LUA(, )LUA" + triggerLua + R"LUA(, function()
                    table.insert(serverState.breakpoint_hits[bpHandle], {
                        address = string.format("0x%X", addr),
                        rip = RIP or EIP or 0,
                        timestamp = os.time()
                    })
                    debug_continueFromBreakpoint(co_run)
                    return 1
                end)
                if not ok then
                    serverState.breakpoint_hits[bpHandle] = nil
                    return '{"success":false,"error":"debug_setBreakpoint failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"CE_API_UNAVAILABLE"}'
                end
                serverState.breakpoints = serverState.breakpoints or {}
                serverState.breakpoints[bpHandle] = { address = addr, trigger = ")LUA" + trigger + R"LUA(", size = )LUA" + std::to_string(size) + R"LUA( }
                return '{"success":true,"bp_handle":"' .. bpHandle .. '","address":"' .. string.format("0x%X", addr) .. '","trigger":")LUA" + trigger + R"LUA("}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/remove_breakpoint", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr or addr == 0 then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ok, err = pcall(debug_removeBreakpoint, addr)
                if not ok then return '{"success":false,"error":"debug_removeBreakpoint failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"INTERNAL_ERROR"}' end
                serverState.breakpoints = serverState.breakpoints or {}
                serverState.breakpoint_hits = serverState.breakpoint_hits or {}
                for k, v in pairs(serverState.breakpoints) do
                    if v.address == addr then
                        serverState.breakpoints[k] = nil
                        serverState.breakpoint_hits[k] = nil
                    end
                end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/list_breakpoints", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            serverState.breakpoints = serverState.breakpoints or {}
            local items = {}
            for k, v in pairs(serverState.breakpoints) do
                items[#items+1] = '{"handle":"' .. k .. '","address":"' .. string.format("0x%X", v.address or 0) ..
                    '","trigger":"' .. tostring(v.trigger or "") ..
                    '","size":' .. tostring(v.size or 1) .. '}'
            end
            return '{"success":true,"count":' .. #items .. ',"breakpoints":[' .. table.concat(items, ',') .. ']}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/clear_all_breakpoints", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            serverState.breakpoints = serverState.breakpoints or {}
            serverState.breakpoint_hits = serverState.breakpoint_hits or {}
            local cnt = 0
            for _, v in pairs(serverState.breakpoints) do
                pcall(debug_removeBreakpoint, v.address)
                cnt = cnt + 1
            end
            serverState.breakpoints = {}
            serverState.breakpoint_hits = {}
            return '{"success":true,"cleared_count":' .. cnt .. '}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/get_breakpoint_hits", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string handle = body.value("handle", "");
            bool clear = body.value("clear", false);

            std::string luaCode = R"LUA(
                serverState.breakpoint_hits = serverState.breakpoint_hits or {}
                local h = ")LUA" + hh::luaEscape(handle) + R"LUA("
                local hits = serverState.breakpoint_hits[h]
                if not hits then return '{"success":false,"error":"Breakpoint handle not found","error_code":"NOT_FOUND"}' end
                local items = {}
                for i, hit in ipairs(hits) do
                    items[#items+1] = '{"address":"' .. tostring(hit.address or "") ..
                        '","rip":"' .. tostring(hit.rip or "") ..
                        '","timestamp":' .. tostring(hit.timestamp or 0) .. '}'
                end
                if )LUA" + hh::boolLua(clear) + R"LUA( then serverState.breakpoint_hits[h] = {} end
                return '{"success":true,"handle":"' .. h .. '","hit_count":' .. #items .. ',"hits":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/debug_process", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int iface = body.value("interface", 0);
            std::string luaCode = R"LUA(
                local pid = getOpenedProcessID()
                if not pid or pid == 0 then return '{"success":false,"error":"No process attached","error_code":"NO_PROCESS"}' end
                local ok, err = pcall(debugProcess, )LUA" + std::to_string(iface) + R"LUA()
                if not ok then return '{"success":false,"error":"debugProcess failed: ' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true,"interface_used":)LUA" + std::to_string(iface) + R"LUA(}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/debug_is_debugging", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok, r = pcall(debug_isDebugging)
            if not ok then return '{"success":false,"error":"' .. tostring(r):gsub('"','\\"') .. '"}' end
            return '{"success":true,"is_debugging":' .. tostring(r == true) .. '}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/debug_detach", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok, r = pcall(detachIfPossible)
            if not ok then return '{"success":false,"error":"' .. tostring(r):gsub('"','\\"') .. '"}' end
            return '{"success":true,"detached":' .. tostring(r == true) .. '}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/debug_continue", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string method = body.value("method", "run");
            std::string ceMethod;
            if (method == "step_into") ceMethod = "co_stepinto";
            else if (method == "step_over") ceMethod = "co_stepover";
            else ceMethod = "co_run";
            std::string luaCode = R"LUA(
                local ok, err = pcall(debug_continueFromBreakpoint, )LUA" + ceMethod + R"LUA()
                if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/debug_break_thread", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            long long tid = body.value("thread_id", (long long)0);
            std::string luaCode = R"LUA(
                local ok, err = pcall(debug_breakThread, )LUA" + std::to_string(tid) + R"LUA()
                if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/debug_get_context", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            bool extra = body.value("extra_regs", false);

            std::string luaCode = R"LUA(
                local pid = getOpenedProcessID()
                if not pid or pid == 0 then return '{"success":false,"error":"No process attached","error_code":"NO_PROCESS"}' end
                local ok = pcall(debug_getContext, )LUA" + hh::boolLua(extra) + R"LUA()
                if not ok then return '{"success":false,"error":"debug_getContext failed","error_code":"CE_API_UNAVAILABLE"}' end

                local is64 = targetIs64Bit and targetIs64Bit() or false
                local arch = is64 and "x64" or "x86"
                local regs = {}
                local names64 = {"RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","RIP","R8","R9","R10","R11","R12","R13","R14","R15","EFLAGS"}
                local names32 = {"EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP","EFLAGS"}
                local set = is64 and names64 or names32
                local parts = {}
                for _, n in ipairs(set) do
                    local v = _G[n]
                    if v ~= nil then
                        parts[#parts+1] = '"' .. n .. '":"' .. string.format("0x%X", v) .. '"'
                    end
                end
                local extraStr = ""
                if )LUA" + hh::boolLua(extra) + R"LUA( then
                    local eparts = {}
                    local maxXmm = is64 and 15 or 7
                    for i = 0, maxXmm do
                        local pok, xptr = pcall(debug_getXMMPointer, i)
                        if pok and xptr then
                            local bts = readBytes(xptr, 16, true)
                            if bts then
                                local hx = {}
                                for _, b in ipairs(bts) do hx[#hx+1] = string.format("%02X", b) end
                                eparts[#eparts+1] = '"xmm' .. i .. '":"' .. table.concat(hx) .. '"'
                            end
                        end
                    end
                    extraStr = ',"extra":{' .. table.concat(eparts, ',') .. '}'
                end
                return '{"success":true,"arch":"' .. arch ..
                       '","registers":{' .. table.concat(parts, ',') .. '}' .. extraStr .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/debug_set_context", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            if (!body.contains("registers") || !body["registers"].is_object()) {
                res.set_content(HttpServer::ErrorJson("registers must be an object", "INVALID_PARAMS"), "application/json");
                return;
            }
            std::string setLua;
            for (auto it = body["registers"].begin(); it != body["registers"].end(); ++it) {
                std::string name = it.key();
                std::string val;
                if (it.value().is_string()) {
                    std::string s = it.value().get<std::string>();
                    val = "tonumber(\"" + hh::luaEscape(s) + "\", 16) or tonumber(\"" + hh::luaEscape(s) + "\")";
                } else if (it.value().is_number()) {
                    val = std::to_string(it.value().get<long long>());
                }
                setLua += "local v = " + val + "\nif v then _G[\"" + hh::luaEscape(name) + "\"] = v end\n";
            }
            std::string luaCode = R"LUA(
                local pid = getOpenedProcessID()
                if not pid or pid == 0 then return '{"success":false,"error":"No process attached","error_code":"NO_PROCESS"}' end
                )LUA" + setLua + R"LUA(
                local ok, err = pcall(debug_setContext)
                if not ok then return '{"success":false,"error":"debug_setContext failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"CE_API_UNAVAILABLE"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/debug_get_xmm_pointer", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int xmm = body.value("xmm_nr", 0);
            std::string luaCode = R"LUA(
                local ok, ptr = pcall(debug_getXMMPointer, )LUA" + std::to_string(xmm) + R"LUA()
                if not ok then return '{"success":false,"error":"debug_getXMMPointer failed","error_code":"CE_API_UNAVAILABLE"}' end
                return '{"success":true,"xmm_nr":)LUA" + std::to_string(xmm) + R"LUA(,"pointer":"' .. string.format("0x%X", ptr or 0) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/debug_set_last_branch_recording", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            bool enable = body.value("enable", false);
            std::string luaCode = R"LUA(
                local iface = debug_getCurrentDebuggerInterface and debug_getCurrentDebuggerInterface() or nil
                if iface ~= 3 then return '{"success":false,"error":"LBR requires kernel debugger","error_code":"CE_API_UNAVAILABLE"}' end
                local ok, err = pcall(debug_setLastBranchRecording, )LUA" + hh::boolLua(enable) + R"LUA()
                if not ok then return '{"success":false,"error":"debug_setLastBranchRecording failed"}' end
                return '{"success":true,"enabled":)LUA" + hh::boolLua(enable) + R"LUA(}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/debug_get_last_branch_record", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int index = body.value("index", 0);
            std::string luaCode = R"LUA(
                local ok, rec = pcall(debug_getLastBranchRecord, )LUA" + std::to_string(index) + R"LUA()
                if not ok or type(rec) ~= "table" then return '{"success":false,"error":"LBR failed","error_code":"CE_API_UNAVAILABLE"}' end
                return '{"success":true,"index":)LUA" + std::to_string(index) + R"LUA(,"from":"' .. string.format("0x%X", rec.from or 0) .. '","to":"' .. string.format("0x%X", rec.to or 0) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/debug_set_breakpoint_for_thread", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            long long tid = body.value("thread_id", (long long)0);
            std::string addrStr = body.value("address", "0");
            int size = body.value("size", 1);
            std::string trigger = body.value("trigger", "execute");
            std::string triggerLua;
            if (trigger == "write") triggerLua = "bptWrite";
            else if (trigger == "read" || trigger == "access") triggerLua = "bptAccess";
            else triggerLua = "bptExecute";

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_PARAMS"}' end
                local tid = )LUA" + std::to_string(tid) + R"LUA(
                local bpHandle = "thread_" .. tid .. "_" .. string.format("%X", addr)
                serverState.breakpoint_hits = serverState.breakpoint_hits or {}
                serverState.breakpoint_hits[bpHandle] = {}
                local ok, err = pcall(debug_setBreakpointForThread, tid, addr, )LUA" + std::to_string(size) + R"LUA(, )LUA" + triggerLua + R"LUA(, bpmDebugRegister, function()
                    table.insert(serverState.breakpoint_hits[bpHandle], { handle = bpHandle, thread_id = tid, address = string.format("0x%X", addr), timestamp = os.time() })
                    debug_continueFromBreakpoint(co_run)
                    return 1
                end)
                if not ok then
                    serverState.breakpoint_hits[bpHandle] = nil
                    return '{"success":false,"error":"debug_setBreakpointForThread failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"CE_API_UNAVAILABLE"}'
                end
                serverState.breakpoints = serverState.breakpoints or {}
                serverState.breakpoints[bpHandle] = { address = addr, thread_id = tid, trigger = ")LUA" + trigger + R"LUA(", size = )LUA" + std::to_string(size) + R"LUA( }
                return '{"success":true,"bp_handle":"' .. bpHandle .. '","thread_id":' .. tid .. ',"address":"' .. string.format("0x%X", addr) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/debug_remove_breakpoint_for_thread", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            long long tid = body.value("thread_id", (long long)0);
            std::string addrStr = body.value("address", "0");
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_PARAMS"}' end
                local ok, err = pcall(debug_removeBreakpoint, addr)
                if not ok then return '{"success":false,"error":"removeBreakpoint failed"}' end
                local bpHandle = "thread_)LUA" + std::to_string(tid) + R"LUA(_" .. string.format("%X", addr)
                serverState.breakpoints[bpHandle] = nil
                serverState.breakpoint_hits[bpHandle] = nil
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/pause_process", [api](const httplib::Request&, httplib::Response& res) {
        api->Pause();
        res.set_content(R"({"success":true})", "application/json");
    });

    svr.Post("/api/unpause_process", [api](const httplib::Request&, httplib::Response& res) {
        api->Unpause();
        res.set_content(R"({"success":true})", "application/json");
    });

    // DBVM watch lifecycle

    svr.Post("/api/start_dbvm_watch", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string mode = body.value("mode", "w");
            if (body.contains("type")) mode = body.value("type", mode);
            int maxEntries = body.value("max_entries", 1000);

            std::string watchFn;
            if (mode == "x") watchFn = "dbvm_watch_executes";
            else if (mode == "r" || mode == "rw") watchFn = "dbvm_watch_reads";
            else watchFn = "dbvm_watch_writes";

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                if not dbk_initialized or not dbk_initialized() then return '{"success":false,"error":"DBK not loaded","error_code":"DBK_NOT_LOADED"}' end
                if dbvm_initialized and not dbvm_initialized() then pcall(dbvm_initialize) end
                if not (dbvm_initialized and dbvm_initialized()) then return '{"success":false,"error":"DBVM not running","error_code":"DBVM_NOT_LOADED"}' end
                local ok, phys = pcall(dbk_getPhysicalAddress, addr)
                if not ok or not phys or phys == 0 then return '{"success":false,"error":"Could not resolve physical address","error_code":"NOT_FOUND"}' end
                local watchKey = string.format("0x%X", addr)
                serverState.active_watches = serverState.active_watches or {}
                if serverState.active_watches[watchKey] then return '{"success":false,"error":"Already watching","error_code":"INVALID_PARAMS"}' end
                local options = 1 + 2 + 8
                local okW, wid = pcall()LUA" + watchFn + R"LUA(, phys, 1, options, )LUA" + std::to_string(maxEntries) + R"LUA()
                if not okW or not wid then return '{"success":false,"error":"DBVM watch failed","error_code":"INTERNAL_ERROR"}' end
                serverState.active_watches[watchKey] = { id = wid, physical = phys, mode = ")LUA" + mode + R"LUA(", start_time = os.time() }
                return '{"success":true,"status":"monitoring","virtual_address":"' .. string.format("0x%X", addr) ..
                       '","physical_address":"' .. string.format("0x%X", phys) ..
                       '","watch_id":' .. tostring(wid) ..
                       ',"mode":")LUA" + mode + R"LUA("}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 30000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/poll_dbvm_watch", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            bool clear = body.value("clear", true);
            int maxResults = body.value("max_results", 1000);

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                local watchKey = string.format("0x%X", addr)
                serverState.active_watches = serverState.active_watches or {}
                local w = serverState.active_watches[watchKey]
                if not w then return '{"success":false,"error":"No active watch","error_code":"NOT_FOUND"}' end
                local okL, log = pcall(dbvm_watch_retrievelog, w.id)
                local items = {}
                if okL and log then
                    local count = math.min(#log, )LUA" + std::to_string(maxResults) + R"LUA()
                    for i = 1, count do
                        local e = log[i]
                        items[#items+1] = '{"hit_number":' .. i ..
                            ',"RIP":"' .. string.format("0x%X", e.RIP or 0) ..
                            '","RSP":"' .. string.format("0x%X", e.RSP or 0) ..
                            '","RAX":"' .. string.format("0x%X", e.RAX or 0) ..
                            '","RBX":"' .. string.format("0x%X", e.RBX or 0) ..
                            '","RCX":"' .. string.format("0x%X", e.RCX or 0) ..
                            '","RDX":"' .. string.format("0x%X", e.RDX or 0) ..
                            '","RSI":"' .. string.format("0x%X", e.RSI or 0) ..
                            '","RDI":"' .. string.format("0x%X", e.RDI or 0) .. '"}'
                    end
                end
                if )LUA" + hh::boolLua(clear) + R"LUA( then pcall(dbvm_watch_clearlog, w.id) end
                return '{"success":true,"status":"active","virtual_address":"' .. string.format("0x%X", addr) ..
                       '","physical_address":"' .. string.format("0x%X", w.physical) ..
                       '","mode":"' .. w.mode ..
                       '","uptime_seconds":' .. (os.time() - w.start_time) ..
                       ',"hit_count":' .. #items ..
                       ',"hits":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 30000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/stop_dbvm_watch", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                local watchKey = string.format("0x%X", addr)
                serverState.active_watches = serverState.active_watches or {}
                local w = serverState.active_watches[watchKey]
                if not w then return '{"success":false,"error":"No active watch","error_code":"NOT_FOUND"}' end
                local okL, log = pcall(dbvm_watch_retrievelog, w.id)
                local items = {}
                if okL and log then
                    for i, e in ipairs(log) do
                        local desc = "???"
                        if e.RIP then
                            local okD, d = pcall(disassemble, e.RIP)
                            if okD and d then desc = d end
                        end
                        local dEsc = desc:gsub('\\', '\\\\'):gsub('"', '\\"')
                        items[#items+1] = '{"hit_number":' .. i ..
                            ',"instruction_address":"' .. string.format("0x%X", e.RIP or 0) ..
                            '","instruction":"' .. dEsc ..
                            '","registers":{' ..
                                '"RAX":"' .. string.format("0x%X", e.RAX or 0) .. '",' ..
                                '"RBX":"' .. string.format("0x%X", e.RBX or 0) .. '",' ..
                                '"RCX":"' .. string.format("0x%X", e.RCX or 0) .. '",' ..
                                '"RDX":"' .. string.format("0x%X", e.RDX or 0) .. '",' ..
                                '"RSI":"' .. string.format("0x%X", e.RSI or 0) .. '",' ..
                                '"RDI":"' .. string.format("0x%X", e.RDI or 0) .. '",' ..
                                '"RBP":"' .. string.format("0x%X", e.RBP or 0) .. '",' ..
                                '"RSP":"' .. string.format("0x%X", e.RSP or 0) .. '",' ..
                                '"RIP":"' .. string.format("0x%X", e.RIP or 0) .. '"' ..
                            '}}'
                    end
                end
                pcall(dbvm_watch_disable, w.id)
                local dur = os.time() - w.start_time
                serverState.active_watches[watchKey] = nil
                return '{"success":true,"virtual_address":"' .. string.format("0x%X", addr) ..
                       '","physical_address":"' .. string.format("0x%X", w.physical) ..
                       '","mode":"' .. w.mode ..
                       '","hit_count":' .. #items ..
                       ',"duration_seconds":' .. dur ..
                       ',"hits":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 30000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/evaluate_lua", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string code = body.value("code", "");
            if (code.empty()) {
                res.set_content(HttpServer::ErrorJson("Missing 'code' parameter", "INVALID_PARAMS"), "application/json");
                return;
            }
            int timeout = body.value("timeout_ms", 300000);
            res.set_content(lua->ExecuteOnMainThread(code, timeout), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });
}

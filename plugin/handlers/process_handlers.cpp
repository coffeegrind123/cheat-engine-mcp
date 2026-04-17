#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

void RegisterProcessHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/open_process", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string process = body.value("process", "");
            if (process.empty()) process = body.value("process_id_or_name", "");
            if (process.empty()) {
                res.set_content(HttpServer::ErrorJson("Missing 'process' parameter", "INVALID_PARAMS"), "application/json");
                return;
            }

            std::string luaCode = R"LUA(
                local arg = ")LUA" + hh::luaEscape(process) + R"LUA("
                local pid = tonumber(arg)
                if not pid then
                    local list = createStringlist()
                    local ok = pcall(getProcessList, list, true)
                    if ok then
                        local needle = arg:lower()
                        for i = 0, list.Count - 1 do
                            local entry = list[i]
                            local pid_str, name = entry:match("^(%x+)%-(.+)$")
                            if name and name:lower() == needle then
                                pid = tonumber(pid_str, 16)
                                break
                            end
                        end
                    end
                    list.destroy()
                end
                if not pid or pid == 0 then
                    return '{"success":false,"error":"Process not found: ' .. arg:gsub('"','\\"') .. '","error_code":"NOT_FOUND"}'
                end
                local ok, err = pcall(openProcess, pid)
                if not ok then
                    return '{"success":false,"error":"openProcess failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"INTERNAL_ERROR"}'
                end
                local opened = getOpenedProcessID() or 0
                local pname = process or ""
                return '{"success":true,"process_id":' .. tostring(opened) .. ',"requested":"' .. arg:gsub('"','\\"') .. '","process_name":"' .. tostring(pname):gsub('"','\\"') .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INTERNAL_ERROR"), "application/json");
        }
    });

    svr.Post("/api/get_process_info", [api, lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local pid = getOpenedProcessID()
            local result = '{"success":true,"pid":' .. tostring(pid or 0)
            if pid and pid > 0 then
                local pname = process or "unknown"
                local is64 = targetIs64Bit()
                result = result .. ',"process_name":"' .. tostring(pname) .. '"'
                result = result .. ',"is64bit":' .. (is64 and 'true' or 'false')
                local mods = enumModules()
                result = result .. ',"module_count":' .. tostring(mods and #mods or 0)
            end
            result = result .. '}'
            return result
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/get_process_list", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local list = createStringlist()
            local ok, err = pcall(getProcessList, list, true)
            if not ok then
                list.destroy()
                return '{"success":false,"error":"getProcessList failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"INTERNAL_ERROR"}'
            end
            local items = {}
            for i = 0, list.Count - 1 do
                local entry = list[i]
                local pid_str, name = entry:match("^(%x+)%-(.+)$")
                if pid_str and name then
                    local nameEsc = name:gsub('\\', '\\\\'):gsub('"', '\\"')
                    items[#items+1] = '{"pid":' .. tonumber(pid_str, 16) .. ',"name":"' .. nameEsc .. '"}'
                end
            end
            list.destroy()
            return '{"success":true,"count":' .. #items .. ',"processes":[' .. table.concat(items, ',') .. ']}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/get_processid_from_name", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            if (name.empty()) {
                res.set_content(HttpServer::ErrorJson("Missing 'name' parameter", "INVALID_PARAMS"), "application/json");
                return;
            }
            std::string luaCode = R"LUA(
                local needle = ")LUA" + hh::luaEscape(name) + R"LUA("
                local list = createStringlist()
                local ok, err = pcall(getProcessList, list, true)
                if not ok then
                    list.destroy()
                    return '{"success":false,"error":"getProcessList failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"INTERNAL_ERROR"}'
                end
                local lower = needle:lower()
                local pid = nil
                local matched = nil
                for i = 0, list.Count - 1 do
                    local entry = list[i]
                    local pid_str, pname = entry:match("^(%x+)%-(.+)$")
                    if pname and pname:lower() == lower then
                        pid = tonumber(pid_str, 16)
                        matched = pname
                        break
                    end
                end
                list.destroy()
                if not pid then
                    return '{"success":false,"error":"Process not found","error_code":"NOT_FOUND"}'
                end
                return '{"success":true,"process_id":' .. tostring(pid) .. ',"process_name":"' .. matched:gsub('\\','\\\\'):gsub('"','\\"') .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_foreground_process", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok, pid = pcall(getForegroundProcess)
            if not ok then return '{"success":false,"error":"getForegroundProcess failed"}' end
            local hwnd = 0
            local ok2, wh = pcall(getForegroundWindow)
            if ok2 and wh then hwnd = wh end
            return '{"success":true,"process_id":' .. tostring(pid or 0) .. ',"window_handle":"' .. string.format("0x%X", hwnd or 0) .. '"}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/create_process", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string path = body.value("path", "");
            std::string args = body.value("args", "");
            bool debug = body.value("debug", false);
            bool breakOnEntry = body.value("break_on_entry", false);
            std::string luaCode = R"LUA(
                local ok, err = pcall(createProcess, ")LUA" + hh::luaEscape(path) + R"LUA(", ")LUA" + hh::luaEscape(args) + R"LUA(", )LUA" + hh::boolLua(debug) + R"LUA(, )LUA" + hh::boolLua(breakOnEntry) + R"LUA()
                if not ok then return '{"success":false,"error":"createProcess failed: ' .. tostring(err):gsub('"','\\"') .. '"}' end
                local ok2, pid = pcall(getOpenedProcessID)
                return '{"success":true,"process_id":' .. tostring((ok2 and pid) or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_opened_process_id", [api](const httplib::Request&, httplib::Response& res) {
        PULONG p = api->GetOpenedProcessID();
        uint32_t pid = p ? *p : 0;
        if (pid == 0) { res.set_content(HttpServer::ErrorJson("No process attached", "NO_PROCESS"), "application/json"); return; }
        json r; r["success"] = true; r["process_id"] = pid;
        res.set_content(r.dump(), "application/json");
    });

    svr.Post("/api/get_opened_process_handle", [api](const httplib::Request&, httplib::Response& res) {
        PHANDLE h = api->GetOpenedProcessHandle();
        json r; r["success"] = true;
        r["handle"] = HttpServer::FormatHex(h ? (uint64_t)(uintptr_t)*h : 0);
        res.set_content(r.dump(), "application/json");
    });

    svr.Post("/api/enum_modules", [lua](const httplib::Request& req, httplib::Response& res) {
        int offset = 0, limit = 100;
        try {
            auto body = json::parse(req.body);
            offset = body.value("offset", 0);
            limit = body.value("limit", 100);
        } catch (...) {}

        std::string luaCode = R"LUA(
            local mods = enumModules()
            if not mods then
                return '{"success":false,"error":"No process attached","error_code":"NO_PROCESS"}'
            end
            local total = #mods
            local offset = )LUA" + std::to_string(offset) + R"LUA(
            local limit = )LUA" + std::to_string(limit) + R"LUA(
            local items = {}
            for i = offset + 1, math.min(offset + limit, total) do
                local m = mods[i]
                local base = string.format("0x%X", m.Address)
                local size = m.Size or 0
                local nameEsc = m.Name:gsub('\\', '\\\\'):gsub('"', '\\"')
                items[#items+1] = '{"name":"' .. nameEsc .. '","address":"' .. base .. '","size":' .. size .. '}'
            end
            return '{"success":true,"total":' .. total .. ',"offset":' .. offset ..
                   ',"limit":' .. limit .. ',"returned":' .. #items ..
                   ',"modules":[' .. table.concat(items, ',') .. ']}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/get_thread_list", [lua](const httplib::Request& req, httplib::Response& res) {
        int offset = 0, limit = 100;
        try {
            auto body = json::parse(req.body);
            offset = body.value("offset", 0);
            limit = body.value("limit", 100);
        } catch (...) {}

        std::string luaCode = R"LUA(
            local pid = getOpenedProcessID()
            if not pid or pid == 0 then
                return '{"success":false,"error":"No process attached","error_code":"NO_PROCESS"}'
            end
            local list_ok, list = pcall(createStringlist)
            if not list_ok or not list then
                return '{"success":false,"error":"createStringlist failed","error_code":"CE_API_UNAVAILABLE"}'
            end
            local ok, err = pcall(getThreadlist, list)
            if not ok then
                pcall(function() list.destroy() end)
                return '{"success":false,"error":"getThreadlist failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"CE_API_UNAVAILABLE"}'
            end
            local all = {}
            for i = 0, (list.Count or 0) - 1 do
                local idHex = list[i]
                all[#all+1] = { id_hex = idHex, id_int = tonumber(idHex, 16) }
            end
            pcall(function() list.destroy() end)
            local total = #all
            local offset = )LUA" + std::to_string(offset) + R"LUA(
            local limit = )LUA" + std::to_string(limit) + R"LUA(
            local items = {}
            for i = offset + 1, math.min(offset + limit, total) do
                local t = all[i]
                items[#items+1] = '{"id_hex":"' .. t.id_hex .. '","id_int":' .. tostring(t.id_int) .. '}'
            end
            return '{"success":true,"total":' .. total .. ',"offset":' .. offset ..
                   ',"limit":' .. limit .. ',"returned":' .. #items ..
                   ',"threads":[' .. table.concat(items, ',') .. ']}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });
}

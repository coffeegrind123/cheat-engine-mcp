#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

void RegisterAnalysisHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/disassemble", [api, lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int count = body.value("count", 10);
            count = std::min(count, 500);

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local count = )LUA" + std::to_string(count) + R"LUA(
                local items = {}
                local current = addr
                for i = 1, count do
                    local desc, info = disassemble(current)
                    if desc == nil then break end
                    local bytes = ""
                    local extra = getInstructionSize(current)
                    if extra and extra > 0 then
                        local bts = readBytes(current, extra, true)
                        if bts then
                            local parts = {}
                            for _, b in ipairs(bts) do
                                parts[#parts+1] = string.format("%02X", b)
                            end
                            bytes = table.concat(parts, " ")
                        end
                    end
                    desc = desc:gsub('\\', '\\\\'):gsub('"', '\\"')
                    items[#items+1] = '{"address":"' .. string.format("0x%X", current) ..
                                      '","instruction":"' .. desc ..
                                      '","bytes":"' .. bytes ..
                                      '","size":' .. (extra or 0) .. '}'
                    current = current + (extra or 1)
                end
                return '{"success":true,"address":"' .. string.format("0x%X", addr) ..
                       '","count":' .. #items ..
                       ',"instructions":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/assemble_instruction", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string line = body.value("instruction", "");
            if (line.empty()) line = body.value("line", "");
            int preference = body.value("preference", 0);
            bool skipRangeCheck = body.value("skip_range_check", false);

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                local line = ")LUA" + hh::luaEscape(line) + R"LUA("
                local ok, result = pcall(assemble, line, addr, )LUA" + std::to_string(preference) + R"LUA(, )LUA" + hh::boolLua(skipRangeCheck) + R"LUA()
                if not ok then return '{"success":false,"error":"assemble() raised: ' .. tostring(result):gsub('"','\\"') .. '","error_code":"CE_API_UNAVAILABLE"}' end
                if not result then return '{"success":false,"error":"Invalid instruction","error_code":"INVALID_PARAMS"}' end
                local parts = {}
                for i = 1, #result do parts[i] = string.format("%02X", result[i]) end
                return '{"success":true,"address":"' .. string.format("0x%X", addr) ..
                       '","bytes":"' .. table.concat(parts, " ") ..
                       '","size":' .. #result .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_instruction_info", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local desc, info = disassemble(addr)
                if not desc then return '{"success":false,"error":"disassemble failed","error_code":"INVALID_ADDRESS"}' end
                local sz = getInstructionSize(addr) or 0
                local bts = readBytes(addr, sz, true) or {}
                local parts = {}
                for _, b in ipairs(bts) do parts[#parts+1] = string.format("%02X", b) end
                desc = desc:gsub('\\', '\\\\'):gsub('"', '\\"')
                local prev = previousOpcode and previousOpcode(addr) or 0
                local nxt = addr + sz
                return '{"success":true,"address":"' .. string.format("0x%X", addr) ..
                       '","instruction":"' .. desc ..
                       '","size":' .. sz ..
                       ',"bytes":"' .. table.concat(parts, " ") ..
                       '","previous":"' .. string.format("0x%X", prev) ..
                       '","next":"' .. string.format("0x%X", nxt) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/find_function_boundaries", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                -- scan back for prologue (push ebp/rbp, sub esp, etc.) or ret above
                local start = addr
                local maxBack = 2048
                local cur = addr
                for i = 1, maxBack do
                    local prev = previousOpcode(cur)
                    if not prev or prev == 0 or prev >= cur then break end
                    local desc = disassemble(prev)
                    if desc then
                        local d = desc:lower()
                        if d:find("^ret") or d:find("^int3") then
                            start = cur
                            break
                        end
                        start = prev
                    end
                    cur = prev
                end
                local stop = addr
                local cur2 = addr
                for i = 1, 4096 do
                    local desc = disassemble(cur2)
                    if not desc then break end
                    local sz = getInstructionSize(cur2) or 1
                    local d = desc:lower()
                    if d:find("^ret") or d:find("^int3") then
                        stop = cur2 + sz
                        break
                    end
                    cur2 = cur2 + sz
                end
                return '{"success":true,"start":"' .. string.format("0x%X", start) ..
                       '","end":"' .. string.format("0x%X", stop) ..
                       '","size":' .. (stop - start) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/analyze_function", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local current = addr
                local calls = {}
                local maxInstr = 1000
                for i = 1, maxInstr do
                    local desc, info = disassemble(current)
                    if desc == nil then break end
                    local size = getInstructionSize(current) or 1
                    local dl = desc:lower()
                    if dl:find("^ret") or dl:find("^int3") then
                        current = current + size
                        break
                    end
                    if dl:find("call ") then
                        local target = desc:match("call%s+(.+)")
                        if target then
                            target = target:gsub('\\', '\\\\'):gsub('"', '\\"')
                            calls[#calls+1] = '{"address":"' .. string.format("0x%X", current) .. '","target":"' .. target .. '"}'
                        end
                    end
                    current = current + size
                end
                local funcSize = current - addr
                return '{"success":true,"address":"' .. string.format("0x%X", addr) ..
                       '","end_address":"' .. string.format("0x%X", current) ..
                       '","size":' .. funcSize ..
                       ',"call_count":' .. #calls ..
                       ',"calls":[' .. table.concat(calls, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/find_references", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int offset = body.value("offset", 0);
            int limit = body.value("limit", 100);

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local refs = findReferences(addr)
                if refs == nil then
                    return '{"success":true,"total":0,"references":[]}'
                end
                local total = #refs
                local offset = )LUA" + std::to_string(offset) + R"LUA(
                local limit = )LUA" + std::to_string(limit) + R"LUA(
                local items = {}
                for i = offset + 1, math.min(offset + limit, total) do
                    items[#items+1] = '{"address":"' .. string.format("0x%X", refs[i]) .. '"}'
                end
                return '{"success":true,"total":' .. total ..
                       ',"offset":' .. offset .. ',"limit":' .. limit ..
                       ',"returned":' .. #items ..
                       ',"references":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/find_call_references", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int offset = body.value("offset", 0);
            int limit = body.value("limit", 100);

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local refs = findReferences(addr)
                if refs == nil then return '{"success":true,"total":0,"references":[]}' end
                local items = {}
                for i = 1, #refs do
                    local ra = refs[i]
                    local desc = disassemble(ra)
                    if desc and desc:lower():find("call ") then
                        items[#items+1] = ra
                    end
                end
                local total = #items
                local offset = )LUA" + std::to_string(offset) + R"LUA(
                local limit = )LUA" + std::to_string(limit) + R"LUA(
                local out = {}
                for i = offset + 1, math.min(offset + limit, total) do
                    out[#out+1] = '{"address":"' .. string.format("0x%X", items[i]) .. '"}'
                end
                return '{"success":true,"total":' .. total ..
                       ',"offset":' .. offset .. ',"limit":' .. limit ..
                       ',"returned":' .. #out ..
                       ',"references":[' .. table.concat(out, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_rtti_classname", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ok, cls = pcall(getRTTIClassName, addr)
                if ok and cls then
                    local e = tostring(cls):gsub('\\', '\\\\'):gsub('"', '\\"')
                    return '{"success":true,"address":"' .. string.format("0x%X", addr) .. '","class_name":"' .. e .. '","found":true}'
                end
                return '{"success":true,"address":"' .. string.format("0x%X", addr) .. '","found":false}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_physical_address", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ok, phys = pcall(dbk_getPhysicalAddress, addr)
                if not ok then return '{"success":false,"error":"DBK not loaded","error_code":"DBK_NOT_LOADED"}' end
                if not phys or phys == 0 then
                    return '{"success":false,"error":"Page not present","error_code":"NOT_FOUND"}'
                end
                return '{"success":true,"virtual_address":"' .. string.format("0x%X", addr) ..
                       '","physical_address":"' .. string.format("0x%X", phys) ..
                       '","physical_int":' .. tostring(phys) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_memory_regions", [lua](const httplib::Request& req, httplib::Response& res) {
        int offset = 0, limit = 100;
        try {
            auto body = json::parse(req.body);
            offset = body.value("offset", 0);
            limit = body.value("limit", 100);
        } catch (...) {}

        std::string luaCode = R"LUA(
            local regions = enumMemoryRegions()
            if regions == nil then
                return '{"success":false,"error":"No process attached","error_code":"NO_PROCESS"}'
            end
            local total = #regions
            local offset = )LUA" + std::to_string(offset) + R"LUA(
            local limit = )LUA" + std::to_string(limit) + R"LUA(
            local items = {}
            for i = offset + 1, math.min(offset + limit, total) do
                local r = regions[i]
                items[#items+1] = '{"base_address":"' .. string.format("0x%X", r.BaseAddress or 0) ..
                    '","size":' .. (r.RegionSize or 0) ..
                    ',"protect":' .. (r.Protect or 0) ..
                    ',"state":' .. (r.State or 0) ..
                    ',"type":' .. (r.Type or 0) .. '}'
            end
            return '{"success":true,"total":' .. total ..
                   ',"offset":' .. offset .. ',"limit":' .. limit ..
                   ',"returned":' .. #items ..
                   ',"regions":[' .. table.concat(items, ',') .. ']}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/dissect_structure", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int size = body.value("size", 256);

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local size = )LUA" + std::to_string(size) + R"LUA(
                local ok, struct = pcall(createStructure, "MCP_TempStruct")
                if not ok or not struct then return '{"success":false,"error":"createStructure failed","error_code":"CE_API_UNAVAILABLE"}' end
                pcall(function() struct:autoGuess(addr, 0, size) end)
                local elements = {}
                local count = struct.Count or 0
                for i = 0, count - 1 do
                    local el = struct.Element[i]
                    if el then
                        local val = nil
                        pcall(function() val = el:getValue(addr) end)
                        local valEsc = tostring(val or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                        local nameEsc = (el.Name or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                        elements[#elements+1] = '{"offset":' .. (el.Offset or 0) ..
                            ',"hex_offset":"+0x' .. string.format("%X", el.Offset or 0) ..
                            '","name":"' .. nameEsc ..
                            '","vartype":' .. tostring(el.Vartype or 0) ..
                            ',"bytesize":' .. (el.Bytesize or 0) ..
                            ',"current_value":"' .. valEsc .. '"}'
                    end
                end
                pcall(function() struct:removeFromGlobalStructureList() end)
                pcall(function() struct:destroy() end)
                return '{"success":true,"base_address":"' .. string.format("0x%X", addr) ..
                       '","size_analyzed":' .. size .. ',"element_count":' .. #elements ..
                       ',"elements":[' .. table.concat(elements, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });
}

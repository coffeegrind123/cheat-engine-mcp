#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

void RegisterStructureHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/create_structure", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            if (name.empty()) { res.set_content(HttpServer::ErrorJson("name required", "INVALID_PARAMS"), "application/json"); return; }
            std::string luaCode = R"LUA(
                local ok, s = pcall(createStructure, ")LUA" + hh::luaEscape(name) + R"LUA(")
                if not ok or not s then return '{"success":false,"error":"createStructure failed","error_code":"CE_API_UNAVAILABLE"}' end
                pcall(function() s.addToGlobalStructureList() end)
                serverState.structures = serverState.structures or {}
                serverState.structure_next_id = serverState.structure_next_id or 1
                local id = serverState.structure_next_id
                serverState.structure_next_id = id + 1
                serverState.structures[id] = s
                return '{"success":true,"structure_id":' .. id .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_structure_by_name", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            std::string luaCode = R"LUA(
                local ok, count = pcall(getStructureCount)
                if not ok then return '{"success":false,"error":"getStructureCount failed","error_code":"CE_API_UNAVAILABLE"}' end
                serverState.structures = serverState.structures or {}
                serverState.structure_next_id = serverState.structure_next_id or 1
                for i = 0, count - 1 do
                    local ok2, s = pcall(getStructure, i)
                    if ok2 and s then
                        local ok3, sn = pcall(function() return s.Name end)
                        if ok3 and sn == ")LUA" + hh::luaEscape(name) + R"LUA(" then
                            local sid
                            for k, stored in pairs(serverState.structures) do
                                local okS, sn2 = pcall(function() return stored.Name end)
                                if okS and sn2 == sn then sid = k; break end
                            end
                            if not sid then
                                sid = serverState.structure_next_id
                                serverState.structure_next_id = sid + 1
                                serverState.structures[sid] = s
                            end
                            local okSz, sz = pcall(function() return s.Size end)
                            local okCnt, c = pcall(function() return s.Count end)
                            return '{"success":true,"structure_id":' .. sid .. ',"name":"' .. sn:gsub('"','\\"') .. '","element_count":' .. tostring((okCnt and c) or 0) .. ',"size":' .. tostring((okSz and sz) or 0) .. '}'
                        end
                    end
                end
                return '{"success":false,"error":"Structure not found","error_code":"NOT_FOUND"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/add_element_to_structure", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            long long sid = body.value("structure_id", (long long)0);
            std::string ename = body.value("name", "");
            int offset = body.value("offset", 0);
            std::string etype = body.value("type", "dword");

            std::string luaCode = R"LUA(
                local vtMap = { byte=vtByte, word=vtWord, dword=vtDword, qword=vtQword, float=vtSingle, single=vtSingle, double=vtDouble, string=vtString, aob=vtByteArray, bytearray=vtByteArray, pointer=vtPointer }
                local vt = vtMap[")LUA" + hh::luaEscape(etype) + R"LUA("] or vtDword
                local s = serverState.structures and serverState.structures[)LUA" + std::to_string(sid) + R"LUA(]
                if not s then return '{"success":false,"error":"Unknown structure_id","error_code":"NOT_FOUND"}' end
                local okE, el = pcall(function() return s.addElement() end)
                if not okE or not el then return '{"success":false,"error":"addElement failed"}' end
                pcall(function()
                    el.Name = ")LUA" + hh::luaEscape(ename) + R"LUA("
                    el.Offset = )LUA" + std::to_string(offset) + R"LUA(
                    el.Vartype = vt
                end)
                local okC, cnt = pcall(function() return s.Count end)
                return '{"success":true,"element_index":' .. tostring((okC and cnt and cnt - 1) or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_structure_elements", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            long long sid = body.value("structure_id", (long long)0);

            std::string luaCode = R"LUA(
                local s = serverState.structures and serverState.structures[)LUA" + std::to_string(sid) + R"LUA(]
                if not s then return '{"success":false,"error":"Unknown structure_id","error_code":"NOT_FOUND"}' end
                local ok, cnt = pcall(function() return s.Count end)
                if not ok then return '{"success":false,"error":"read count failed"}' end
                local vtypeNames = { [vtByte]="byte", [vtWord]="word", [vtDword]="dword", [vtQword]="qword", [vtSingle]="float", [vtDouble]="double", [vtString]="string", [vtByteArray]="aob", [vtPointer]="pointer" }
                local items = {}
                for i = 0, cnt - 1 do
                    local ok2, el = pcall(function() return s.getElement(i) end)
                    if ok2 and el then
                        local n, o, v, sz
                        pcall(function() n = el.Name end)
                        pcall(function() o = el.Offset end)
                        pcall(function() v = el.Vartype end)
                        pcall(function() sz = el.Bytesize end)
                        local nameEsc = tostring(n or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                        items[#items+1] = '{"name":"' .. nameEsc .. '","offset":' .. tostring(o or 0) ..
                            ',"type":"' .. tostring(vtypeNames[v] or v or "") ..
                            '","size":' .. tostring(sz or 0) .. '}'
                    end
                end
                return '{"success":true,"structure_id":)LUA" + std::to_string(sid) + R"LUA(,"elements":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/export_structure_to_xml", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            long long sid = body.value("structure_id", (long long)0);

            std::string luaCode = R"LUA(
                local s = serverState.structures and serverState.structures[)LUA" + std::to_string(sid) + R"LUA(]
                if not s then return '{"success":false,"error":"Unknown structure_id","error_code":"NOT_FOUND"}' end
                local function xmlEsc(v)
                    v = tostring(v)
                    v = v:gsub("&","&amp;"):gsub("<","&lt;"):gsub(">","&gt;"):gsub('"',"&quot;"):gsub("'","&apos;")
                    return v
                end
                local vtypeNames = { [vtByte]="byte", [vtWord]="word", [vtDword]="dword", [vtQword]="qword", [vtSingle]="float", [vtDouble]="double", [vtString]="string", [vtByteArray]="aob", [vtPointer]="pointer" }
                local okN, sn = pcall(function() return s.Name end)
                local okSz, sz = pcall(function() return s.Size end)
                local okC, c = pcall(function() return s.Count end)
                local lines = {}
                lines[#lines+1] = '<?xml version="1.0" encoding="utf-8"?>'
                lines[#lines+1] = '<Structure Name="' .. xmlEsc(sn or "") .. '" Size="' .. tostring((okSz and sz) or 0) .. '">'
                for i = 0, ((okC and c) or 0) - 1 do
                    local okE, el = pcall(function() return s.getElement(i) end)
                    if okE and el then
                        local n, o, v, zs
                        pcall(function() n = el.Name end)
                        pcall(function() o = el.Offset end)
                        pcall(function() v = el.Vartype end)
                        pcall(function() zs = el.Bytesize end)
                        lines[#lines+1] = '  <Element Name="' .. xmlEsc(n or "") .. '" Offset="' .. tostring(o or 0) ..
                            '" Type="' .. xmlEsc(vtypeNames[v] or v or "") .. '" Size="' .. tostring(zs or 0) .. '"/>'
                    end
                end
                lines[#lines+1] = '</Structure>'
                local xml = table.concat(lines, "\n"):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r')
                return '{"success":true,"xml":"' .. xml .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/delete_structure", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            long long sid = body.value("structure_id", (long long)0);
            std::string luaCode = R"LUA(
                local s = serverState.structures and serverState.structures[)LUA" + std::to_string(sid) + R"LUA(]
                if not s then return '{"success":false,"error":"Unknown structure_id","error_code":"NOT_FOUND"}' end
                pcall(function() s.removeFromGlobalStructureList() end)
                pcall(function() s.destroy() end)
                serverState.structures[)LUA" + std::to_string(sid) + R"LUA(] = nil
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });
}

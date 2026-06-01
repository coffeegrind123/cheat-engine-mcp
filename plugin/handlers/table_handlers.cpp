#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

void RegisterTableHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/load_table", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string path = body.value("path", "");
            if (path.empty()) path = body.value("filename", "");
            bool merge = body.value("merge", false);
            std::string escPath = path;
            for (auto& c : escPath) { if (c == '\\') c = '/'; }

            std::string luaCode = R"LUA(
                local ok, err = pcall(loadTable, ")LUA" + hh::luaEscape(escPath) + R"LUA(", )LUA" + hh::boolLua(merge) + R"LUA()
                if not ok then return '{"success":false,"error":"loadTable failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"INTERNAL_ERROR"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/save_table", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string path = body.value("path", "");
            if (path.empty()) path = body.value("filename", "");
            bool protect = body.value("protect", false);
            std::string escPath = path;
            for (auto& c : escPath) { if (c == '\\') c = '/'; }

            std::string luaCode = R"LUA(
                local ok, err = pcall(saveTable, ")LUA" + hh::luaEscape(escPath) + R"LUA(", )LUA" + hh::boolLua(protect) + R"LUA()
                if not ok then return '{"success":false,"error":"saveTable failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"INTERNAL_ERROR"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_address_list", [lua](const httplib::Request& req, httplib::Response& res) {
        int offset = 0, limit = 100;
        try {
            auto body = json::parse(req.body);
            offset = body.value("offset", 0);
            limit = body.value("limit", 100);
        } catch (...) {}

        std::string luaCode = R"LUA(
            local ok, al = pcall(getAddressList)
            if not ok or not al then return '{"success":false,"error":"getAddressList failed","error_code":"CE_API_UNAVAILABLE"}' end
            local total = al.Count
            local offset = )LUA" + std::to_string(offset) + R"LUA(
            local limit = )LUA" + std::to_string(limit) + R"LUA(
            local items = {}
            for i = offset, math.min(offset + limit - 1, total - 1) do
                local mr = al[i]
                if mr then
                    local desc = (mr.Description or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                    local addr = (mr.Address or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                    local val = tostring(mr.Value or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                    local active = mr.Active and 'true' or 'false'
                    local offsetCount = mr.OffsetCount or 0
                    local offs = {}
                    for j = 0, offsetCount - 1 do offs[#offs+1] = tostring(mr.Offset[j]) end
                    items[#items+1] = '{"id":' .. (mr.ID or 0) ..
                        ',"description":"' .. desc ..
                        '","address":"' .. addr ..
                        '","value":"' .. val ..
                        '","type":' .. tostring(mr.VarType or 0) ..
                        ',"offsets":[' .. table.concat(offs, ',') .. ']' ..
                        ',"active":' .. active .. '}'
                end
            end
            return '{"success":true,"total":' .. total ..
                   ',"offset":' .. offset .. ',"limit":' .. limit ..
                   ',"returned":' .. #items ..
                   ',"entries":[' .. table.concat(items, ',') .. '}}':sub(1,-3) .. ']}'
        )LUA";
        // fix typo in return string by rewriting
        luaCode = R"LUA(
            local ok, al = pcall(getAddressList)
            if not ok or not al then return '{"success":false,"error":"getAddressList failed","error_code":"CE_API_UNAVAILABLE"}' end
            local total = al.Count
            local offset = )LUA" + std::to_string(offset) + R"LUA(
            local limit = )LUA" + std::to_string(limit) + R"LUA(
            local items = {}
            for i = offset, math.min(offset + limit - 1, total - 1) do
                local mr = al[i]
                if mr then
                    local desc = (mr.Description or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                    local addr = (mr.Address or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                    local val = tostring(mr.Value or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                    local active = mr.Active and 'true' or 'false'
                    local offsetCount = mr.OffsetCount or 0
                    local offs = {}
                    for j = 0, offsetCount - 1 do offs[#offs+1] = tostring(mr.Offset[j]) end
                    items[#items+1] = '{"id":' .. (mr.ID or 0) ..
                        ',"description":"' .. desc ..
                        '","address":"' .. addr ..
                        '","value":"' .. val ..
                        '","type":' .. tostring(mr.VarType or 0) ..
                        ',"offsets":[' .. table.concat(offs, ',') .. '],"active":' .. active .. '}'
                end
            end
            return '{"success":true,"total":' .. total ..
                   ',"offset":' .. offset .. ',"limit":' .. limit ..
                   ',"returned":' .. #items ..
                   ',"entries":[' .. table.concat(items, ',') .. ']}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/get_memory_record", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            bool hasId = body.contains("id");
            long long id = body.value("id", (long long)-1);
            std::string desc = body.value("description", "");

            std::string lookup;
            if (hasId) {
                lookup = "pcall(function() return al:getMemoryRecordByID(" + std::to_string(id) + ") end)";
            } else {
                lookup = "pcall(function() return al:getMemoryRecordByDescription(\"" + hh::luaEscape(desc) + "\") end)";
            }
            std::string luaCode = R"LUA(
                local ok, al = pcall(getAddressList)
                if not ok or not al then return '{"success":false,"error":"getAddressList failed","error_code":"CE_API_UNAVAILABLE"}' end
                local ok2, rec = )LUA" + lookup + R"LUA(
                if not ok2 or not rec then return '{"success":false,"error":"Memory record not found","error_code":"NOT_FOUND"}' end
                local d = (rec.Description or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                local a = (rec.Address or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                local v = tostring(rec.Value or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                return '{"success":true,"record":{"id":' .. (rec.ID or 0) ..
                    ',"description":"' .. d ..
                    '","address":"' .. a ..
                    '","value":"' .. v ..
                    '","type":' .. tostring(rec.VarType or 0) ..
                    ',"active":' .. tostring(rec.Active == true) .. '}}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/create_memory_record", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string desc = body.value("description", "");
            std::string addr = body.value("address", "");
            std::string type = body.value("type", "dword");

            std::string luaCode = R"LUA(
                local TYPE_MAP = { byte="vtByte", word="vtWord", dword="vtDword", qword="vtQword", float="vtSingle", single="vtSingle", double="vtDouble", string="vtString", bytearray="vtByteArray", aob="vtByteArray" }
                local vtName = TYPE_MAP["')LUA" + hh::luaEscape(type) + R"LUA('"] or "vtDword"
                local ok, al = pcall(getAddressList)
                if not ok or not al then return '{"success":false,"error":"getAddressList failed","error_code":"CE_API_UNAVAILABLE"}' end
                local okR, rec = pcall(function() return al:createMemoryRecord() end)
                if not okR or not rec then return '{"success":false,"error":"createMemoryRecord failed","error_code":"INTERNAL_ERROR"}' end
                pcall(function() rec.Description = ")LUA" + hh::luaEscape(desc) + R"LUA(" end)
                pcall(function() rec.Address = ")LUA" + hh::luaEscape(addr) + R"LUA(" end)
                if not pcall(function() rec.VarType = vtName end) then
                    pcall(function() rec.VarType = _G[vtName] end)
                end
                local okId, rid = pcall(function() return rec.ID end)
                return '{"success":true,"id":' .. tostring((okId and rid) or 0) .. '}'
            )LUA";
            // Fix the quoted string issue
            std::string fixedLua = R"LUA(
                local TYPE_MAP = { byte="vtByte", word="vtWord", dword="vtDword", qword="vtQword", float="vtSingle", single="vtSingle", double="vtDouble", string="vtString", bytearray="vtByteArray", aob="vtByteArray" }
                local vtName = TYPE_MAP[")LUA" + hh::luaEscape(type) + R"LUA("] or "vtDword"
                local ok, al = pcall(getAddressList)
                if not ok or not al then return '{"success":false,"error":"getAddressList failed","error_code":"CE_API_UNAVAILABLE"}' end
                local okR, rec = pcall(function() return al:createMemoryRecord() end)
                if not okR or not rec then return '{"success":false,"error":"createMemoryRecord failed","error_code":"INTERNAL_ERROR"}' end
                pcall(function() rec.Description = ")LUA" + hh::luaEscape(desc) + R"LUA(" end)
                pcall(function() rec.Address = ")LUA" + hh::luaEscape(addr) + R"LUA(" end)
                if not pcall(function() rec.VarType = vtName end) then
                    pcall(function() rec.VarType = _G[vtName] end)
                end
                local okId, rid = pcall(function() return rec.ID end)
                return '{"success":true,"id":' .. tostring((okId and rid) or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(fixedLua), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/delete_memory_record", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            long long id = body.value("id", (long long)-1);
            std::string luaCode = R"LUA(
                local ok, al = pcall(getAddressList)
                if not ok or not al then return '{"success":false,"error":"getAddressList failed","error_code":"CE_API_UNAVAILABLE"}' end
                local okR, rec = pcall(function() return al:getMemoryRecordByID()LUA" + std::to_string(id) + R"LUA() end)
                if not okR or not rec then return '{"success":false,"error":"Record not found","error_code":"NOT_FOUND"}' end
                local okD, err = pcall(function() rec:delete() end)
                if not okD then return '{"success":false,"error":"delete failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"INTERNAL_ERROR"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_memory_record_value", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            long long id = body.value("id", (long long)-1);
            std::string luaCode = R"LUA(
                local ok, al = pcall(getAddressList)
                if not ok or not al then return '{"success":false,"error":"getAddressList failed","error_code":"CE_API_UNAVAILABLE"}' end
                local okR, rec = pcall(function() return al:getMemoryRecordByID()LUA" + std::to_string(id) + R"LUA() end)
                if not okR or not rec then return '{"success":false,"error":"Record not found","error_code":"NOT_FOUND"}' end
                local okV, v = pcall(function() return rec.Value end)
                if not okV then return '{"success":false,"error":"value read failed","error_code":"INTERNAL_ERROR"}' end
                local vEsc = tostring(v or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                return '{"success":true,"value":"' .. vEsc .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/set_memory_record_value", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            long long id = body.value("id", (long long)-1);
            std::string value;
            if (body.contains("value")) {
                if (body["value"].is_string()) value = body["value"].get<std::string>();
                else value = body["value"].dump();
            }
            std::string luaCode = R"LUA(
                local ok, al = pcall(getAddressList)
                if not ok or not al then return '{"success":false,"error":"getAddressList failed","error_code":"CE_API_UNAVAILABLE"}' end
                local okR, rec = pcall(function() return al:getMemoryRecordByID()LUA" + std::to_string(id) + R"LUA() end)
                if not okR or not rec then return '{"success":false,"error":"Record not found","error_code":"NOT_FOUND"}' end
                local okS, err = pcall(function() rec.Value = ")LUA" + hh::luaEscape(value) + R"LUA(" end)
                if not okS then return '{"success":false,"error":"set value failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"INTERNAL_ERROR"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    // Freezing mutates CE's freeze/timer state — must run on the main thread.
    // Implemented via CE's address-list memory records (createMemoryRecord +
    // Active=true freezes the value). Returns the record ID as freeze_id.
    svr.Post("/api/freeze_mem", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int size = body.value("size", 4);
            // map byte-size -> CE valueType: vtByte=0 vtWord=1 vtDword=2 vtQword=3
            int vt = (size == 1) ? 0 : (size == 2) ? 1 : (size == 8) ? 3 : 2;

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local al = getAddressList()
                local mr = al.createMemoryRecord()
                if not mr then return '{"success":false,"error":"createMemoryRecord failed","error_code":"INTERNAL_ERROR"}' end
                mr.Address = string.format("0x%X", addr)
                mr.Type = )LUA" + std::to_string(vt) + R"LUA(
                mr.Active = true
                return '{"success":true,"freeze_id":' .. tostring(mr.ID) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/unfreeze_mem", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int freezeId = body.value("freeze_id", -1);

            std::string luaCode = R"LUA(
                local id = )LUA" + std::to_string(freezeId) + R"LUA(
                local al = getAddressList()
                local mr = al.getMemoryRecordByID(id)
                if not mr then return '{"success":false,"error":"Freeze record not found","error_code":"NOT_FOUND"}' end
                mr.destroy()
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });
}

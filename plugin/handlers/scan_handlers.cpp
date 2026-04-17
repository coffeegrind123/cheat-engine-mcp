#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

void RegisterScanHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/scan_all", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string value = body.value("value", "");
            std::string scanType = body.value("scan_type", "exact");
            std::string valueType = body.value("value_type", "dword");
            std::string startAddr = body.value("start_address", "0");
            std::string stopAddr = body.value("stop_address", "0x7FFFFFFFFFFFFFFF");
            std::string protection = body.value("protection", "+W-C");
            int offset = body.value("offset", 0);
            int limit = body.value("limit", 100);

            std::string luaCode = R"LUA(
                local valueTypeMap = {
                    byte = vtByte, ["2byte"] = vtWord, word = vtWord,
                    ["4byte"] = vtDword, dword = vtDword,
                    ["8byte"] = vtQword, qword = vtQword,
                    float = vtSingle, single = vtSingle, double = vtDouble,
                    string = vtString, aob = vtByteArray, bytearray = vtByteArray
                }
                local scanTypeMap = {
                    exact = soExactValue, bigger = soBiggerThan,
                    smaller = soSmallerThan, between = soValueBetween,
                    unknown = soUnknownValue, increased = soIncreasedValue,
                    decreased = soDecreasedValue, changed = soChanged,
                    unchanged = soUnchanged
                }
                local st = scanTypeMap[")LUA" + hh::luaEscape(scanType) + R"LUA("] or soExactValue
                local vt = valueTypeMap[")LUA" + hh::luaEscape(valueType) + R"LUA("] or vtDword

                if serverState.scan_memscan then pcall(function() serverState.scan_memscan.destroy() end) end
                if serverState.scan_foundlist then pcall(function() serverState.scan_foundlist.destroy() end) end

                local ms = createMemScan()
                serverState.scan_memscan = ms
                local ok, err = pcall(function()
                    ms.firstScan(st, vt, rtRounded, ")LUA" + hh::luaEscape(value) + R"LUA(", nil,
                        )LUA" + startAddr + "," + stopAddr + R"LUA(, ")LUA" + hh::luaEscape(protection) + R"LUA(", fsmNotAligned, "1", false, false, false, false)
                    ms.waitTillDone()
                end)
                if not ok then
                    return '{"success":false,"error":"firstScan failed: ' .. tostring(err):gsub('"','\\"'):gsub('\\','\\\\') .. '","error_code":"INTERNAL_ERROR"}'
                end

                local fl = createFoundList(ms)
                fl.initialize()
                serverState.scan_foundlist = fl

                local total = fl.getCount()
                local offset = )LUA" + std::to_string(offset) + R"LUA(
                local limit = )LUA" + std::to_string(limit) + R"LUA(
                local items = {}
                for i = offset, math.min(offset + limit - 1, total - 1) do
                    local addr = fl.getAddress(i)
                    if addr and not addr:match("^0[xX]") then addr = "0x" .. addr end
                    local val = fl.getValue(i) or ""
                    val = tostring(val):gsub('\\', '\\\\'):gsub('"', '\\"')
                    items[#items+1] = '{"address":"' .. addr .. '","value":"' .. val .. '"}'
                end
                return '{"success":true,"total":' .. total .. ',"offset":' .. offset ..
                       ',"limit":' .. limit .. ',"returned":' .. #items ..
                       ',"results":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 120000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/next_scan", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string value = body.value("value", "");
            std::string scanType = body.value("scan_type", "exact");

            std::string luaCode = R"LUA(
                if not serverState.scan_memscan then
                    return '{"success":false,"error":"No previous scan","error_code":"NOT_FOUND"}'
                end
                local scanTypeMap = {
                    exact = soExactValue, bigger = soBiggerThan,
                    smaller = soSmallerThan, between = soValueBetween,
                    increased = soIncreasedValue, decreased = soDecreasedValue,
                    changed = soChanged, unchanged = soUnchanged
                }
                local st = scanTypeMap[")LUA" + hh::luaEscape(scanType) + R"LUA("] or soExactValue
                local ms = serverState.scan_memscan
                local ok, err = pcall(function()
                    if st == soExactValue or st == soBiggerThan or st == soSmallerThan or st == soValueBetween then
                        ms.nextScan(st, rtRounded, ")LUA" + hh::luaEscape(value) + R"LUA(", nil, false, false, false, false, false)
                    else
                        ms.nextScan(st, rtRounded, nil, nil, false, false, false, false, false)
                    end
                    ms.waitTillDone()
                end)
                if not ok then
                    return '{"success":false,"error":"nextScan failed: ' .. tostring(err):gsub('"','\\"'):gsub('\\','\\\\') .. '","error_code":"INTERNAL_ERROR"}'
                end
                if serverState.scan_foundlist then pcall(function() serverState.scan_foundlist.destroy() end) end
                local fl = createFoundList(ms)
                fl.initialize()
                serverState.scan_foundlist = fl
                return '{"success":true,"count":' .. fl.getCount() .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_scan_results", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int offset = body.value("offset", 0);
            int limit = body.value("limit", 100);

            std::string luaCode = R"LUA(
                if not serverState.scan_foundlist then
                    return '{"success":false,"error":"No scan results","error_code":"NOT_FOUND"}'
                end
                local fl = serverState.scan_foundlist
                local total = fl.getCount()
                local offset = )LUA" + std::to_string(offset) + R"LUA(
                local limit = )LUA" + std::to_string(limit) + R"LUA(
                local items = {}
                for i = offset, math.min(offset + limit - 1, total - 1) do
                    local addr = fl.getAddress(i)
                    if addr and not addr:match("^0[xX]") then addr = "0x" .. addr end
                    local val = fl.getValue(i) or ""
                    val = tostring(val):gsub('\\', '\\\\'):gsub('"', '\\"')
                    items[#items+1] = '{"address":"' .. addr .. '","value":"' .. val .. '"}'
                end
                return '{"success":true,"total":' .. total .. ',"offset":' .. offset ..
                       ',"limit":' .. limit .. ',"returned":' .. #items ..
                       ',"results":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/aob_scan", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string pattern = body.value("pattern", "");
            std::string protection = body.value("protection", "+X");
            int offset = body.value("offset", 0);
            int limit = body.value("limit", 100);

            if (pattern.empty()) {
                res.set_content(HttpServer::ErrorJson("Missing 'pattern' parameter", "INVALID_PARAMS"), "application/json");
                return;
            }

            std::string luaCode = R"LUA(
                local results = AOBScan(")LUA" + hh::luaEscape(pattern) + R"LUA(", ")LUA" + hh::luaEscape(protection) + R"LUA(")
                if results == nil then
                    return '{"success":true,"total":0,"offset":0,"limit":)LUA" + std::to_string(limit) + R"LUA(,"returned":0,"results":[]}'
                end
                local total = results.Count
                local offset = )LUA" + std::to_string(offset) + R"LUA(
                local limit = )LUA" + std::to_string(limit) + R"LUA(
                local items = {}
                for i = offset, math.min(offset + limit - 1, total - 1) do
                    items[#items+1] = '{"address":"0x' .. results.getString(i) .. '"}'
                end
                results.destroy()
                return '{"success":true,"total":' .. total .. ',"offset":' .. offset ..
                       ',"limit":' .. limit .. ',"returned":' .. #items ..
                       ',"results":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 120000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/aob_scan_unique", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string pattern = body.value("pattern", "");
            std::string protection = body.value("protection", "+X");

            std::string luaCode = R"LUA(
                local results = AOBScan(")LUA" + hh::luaEscape(pattern) + R"LUA(", ")LUA" + hh::luaEscape(protection) + R"LUA(")
                local count = results and results.Count or 0
                if count ~= 1 then
                    if results then pcall(function() results.destroy() end) end
                    return '{"success":false,"error":"Pattern matched ' .. count .. ' times (expected 1)","error_code":"INVALID_PARAMS","count":' .. count .. '}'
                end
                local addrStr = results.getString(0)
                pcall(function() results.destroy() end)
                return '{"success":true,"address":"0x' .. addrStr .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 120000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/aob_scan_module", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string pattern = body.value("pattern", "");
            std::string moduleName = body.value("module_name", "");
            std::string protection = body.value("protection", "+X");

            std::string luaCode = R"LUA(
                local modBase, modSize
                local ok1 = pcall(function() modBase = getAddress(")LUA" + hh::luaEscape(moduleName) + R"LUA(") end)
                if not ok1 or not modBase or modBase == 0 then
                    return '{"success":false,"error":"Module not found","error_code":"INVALID_PARAMS"}'
                end
                local ok2 = pcall(function() modSize = getModuleSize(")LUA" + hh::luaEscape(moduleName) + R"LUA(") end)
                if not ok2 or not modSize or modSize == 0 then
                    return '{"success":false,"error":"Cannot get module size","error_code":"INVALID_PARAMS"}'
                end
                local modEnd = modBase + modSize
                local results = AOBScan(")LUA" + hh::luaEscape(pattern) + R"LUA(", ")LUA" + hh::luaEscape(protection) + R"LUA(")
                local items = {}
                if results and results.Count > 0 then
                    for i = 0, results.Count - 1 do
                        local a = tonumber(results.getString(i), 16)
                        if a and a >= modBase and a < modEnd then
                            items[#items+1] = '"0x' .. results.getString(i) .. '"'
                        end
                    end
                end
                if results then pcall(function() results.destroy() end) end
                return '{"success":true,"count":' .. #items .. ',"module_name":")LUA" + hh::luaEscape(moduleName) + R"LUA(","addresses":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 120000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/aob_scan_module_unique", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string pattern = body.value("pattern", "");
            std::string moduleName = body.value("module_name", "");
            std::string protection = body.value("protection", "+X");

            std::string luaCode = R"LUA(
                local modBase, modSize
                local ok1 = pcall(function() modBase = getAddress(")LUA" + hh::luaEscape(moduleName) + R"LUA(") end)
                if not ok1 or not modBase or modBase == 0 then
                    return '{"success":false,"error":"Module not found","error_code":"INVALID_PARAMS"}'
                end
                local ok2 = pcall(function() modSize = getModuleSize(")LUA" + hh::luaEscape(moduleName) + R"LUA(") end)
                if not ok2 or not modSize or modSize == 0 then
                    return '{"success":false,"error":"Cannot get module size","error_code":"INVALID_PARAMS"}'
                end
                local modEnd = modBase + modSize
                local results = AOBScan(")LUA" + hh::luaEscape(pattern) + R"LUA(", ")LUA" + hh::luaEscape(protection) + R"LUA(")
                local matches = {}
                if results and results.Count > 0 then
                    for i = 0, results.Count - 1 do
                        local a = tonumber(results.getString(i), 16)
                        if a and a >= modBase and a < modEnd then
                            matches[#matches+1] = "0x" .. results.getString(i)
                        end
                    end
                end
                if results then pcall(function() results.destroy() end) end
                if #matches ~= 1 then
                    return '{"success":false,"error":"Pattern matched ' .. #matches .. ' times in module (expected 1)","error_code":"INVALID_PARAMS","count":' .. #matches .. '}'
                end
                return '{"success":true,"address":"' .. matches[1] .. '","module_name":")LUA" + hh::luaEscape(moduleName) + R"LUA("}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 120000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/search_string", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string searchStr = body.value("string", "");
            if (searchStr.empty()) searchStr = body.value("pattern", "");
            bool wide = body.value("wide", false);
            int limit = body.value("limit", 100);

            if (searchStr.empty()) {
                res.set_content(HttpServer::ErrorJson("Missing 'string'", "INVALID_PARAMS"), "application/json");
                return;
            }

            std::string pattern;
            for (size_t i = 0; i < searchStr.size(); i++) {
                if (i > 0) pattern += " ";
                char buf[8];
                snprintf(buf, sizeof(buf), "%02X", (unsigned char)searchStr[i]);
                pattern += buf;
                if (wide) pattern += " 00";
            }

            std::string luaCode = R"LUA(
                local results = AOBScan(")LUA" + pattern + R"LUA(")
                if not results then return '{"success":true,"count":0,"addresses":[]}' end
                local items = {}
                local limit = )LUA" + std::to_string(limit) + R"LUA(
                local stop = math.min(results.Count - 1, limit - 1)
                for i = 0, stop do
                    local addr = tonumber(results.getString(i), 16)
                    local preview = readString(addr, 50, )LUA" + hh::boolLua(wide) + R"LUA() or ""
                    preview = preview:gsub('\\', '\\\\'):gsub('"', '\\"')
                    items[#items+1] = '{"address":"0x' .. results.getString(i) .. '","preview":"' .. preview .. '"}'
                end
                pcall(function() results.destroy() end)
                return '{"success":true,"count":' .. #items .. ',"addresses":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 120000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/generate_signature", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then
                    return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}'
                end
                local ok, sig, off = pcall(getUniqueAOB, addr)
                if not ok then
                    return '{"success":false,"error":"getUniqueAOB failed: ' .. tostring(sig):gsub('"','\\"'):gsub('\\','\\\\') .. '","error_code":"CE_API_UNAVAILABLE"}'
                end
                if not sig or sig == "" then
                    return '{"success":false,"error":"Could not generate unique signature","error_code":"NOT_FOUND"}'
                end
                local byteCount = 0
                for _ in sig:gmatch("%S+") do byteCount = byteCount + 1 end
                local sigEsc = sig:gsub('\\', '\\\\'):gsub('"', '\\"')
                return '{"success":true,"address":"' .. string.format("0x%X", addr) ..
                       '","signature":"' .. sigEsc ..
                       '","offset_from_start":' .. (off or 0) ..
                       ',"byte_count":' .. byteCount .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/pointer_rescan", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string value = body.value("value", "");
            std::string prevFile = body.value("previous_results_file", "");

            std::string luaCode;
            if (prevFile.empty()) {
                luaCode = R"LUA(
                    local ok, err = pcall(pointerRescan, )LUA" + value + R"LUA()
                    if not ok then
                        return '{"success":false,"error":"pointerRescan failed: ' .. tostring(err):gsub('"','\\"'):gsub('\\','\\\\') .. '","error_code":"INTERNAL_ERROR"}'
                    end
                    return '{"success":true}'
                )LUA";
            } else {
                luaCode = R"LUA(
                    local ok, err = pcall(pointerRescan, )LUA" + value + R"LUA(, ")LUA" + hh::luaEscape(prevFile) + R"LUA(")
                    if not ok then
                        return '{"success":false,"error":"pointerRescan failed: ' .. tostring(err):gsub('"','\\"'):gsub('\\','\\\\') .. '","error_code":"INTERNAL_ERROR"}'
                    end
                    return '{"success":true}'
                )LUA";
            }
            res.set_content(lua->ExecuteOnMainThread(luaCode, 120000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/create_persistent_scan", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            if (name.empty()) { res.set_content(HttpServer::ErrorJson("Missing name", "INVALID_PARAMS"), "application/json"); return; }

            std::string luaCode = R"LUA(
                serverState.persistent_scans = serverState.persistent_scans or {}
                local name = ")LUA" + hh::luaEscape(name) + R"LUA("
                local existing = serverState.persistent_scans[name]
                if existing then
                    if existing.fl then pcall(function() existing.fl.destroy() end) end
                    pcall(function() existing.ms.destroy() end)
                end
                local ms = createMemScan()
                serverState.persistent_scans[name] = { ms = ms, fl = nil, has_scan = false }
                return '{"success":true,"scan_name":"' .. name .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/persistent_scan_first_scan", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            std::string value = body.value("value", "");
            std::string vtype = body.value("type", "dword");
            std::string scanOpt = body.value("scan_option", "exact");

            std::string luaCode = R"LUA(
                serverState.persistent_scans = serverState.persistent_scans or {}
                local entry = serverState.persistent_scans[")LUA" + hh::luaEscape(name) + R"LUA("]
                if not entry then
                    return '{"success":false,"error":"Scan not found","error_code":"INVALID_PARAMS"}'
                end
                local vtMap = { byte=vtByte, word=vtWord, dword=vtDword, qword=vtQword, float=vtSingle, single=vtSingle, double=vtDouble, string=vtString }
                local soMap = { exact=soExactValue, unknown=soUnknownValue, between=soValueBetween, bigger=soBiggerThan, smaller=soSmallerThan, increased=soIncreasedValue, decreased=soDecreasedValue, changed=soChanged, unchanged=soUnchanged }
                local vt = vtMap[")LUA" + hh::luaEscape(vtype) + R"LUA("] or vtDword
                local so = soMap[")LUA" + hh::luaEscape(scanOpt) + R"LUA("] or soExactValue
                local ms = entry.ms
                local ok, err = pcall(function()
                    ms.firstScan(so, vt, rtRounded, ")LUA" + hh::luaEscape(value) + R"LUA(", nil, 0, 0x7FFFFFFFFFFFFFFF, "+W-C", fsmNotAligned, "1", false, false, false, false)
                    ms.waitTillDone()
                end)
                if not ok then return '{"success":false,"error":"firstScan failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"INTERNAL_ERROR"}' end
                if entry.fl then pcall(function() entry.fl.destroy() end) end
                local fl = createFoundList(ms)
                fl.initialize()
                entry.fl = fl
                entry.has_scan = true
                return '{"success":true,"scan_name":")LUA" + hh::luaEscape(name) + R"LUA(","count":' .. fl.getCount() .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 120000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/persistent_scan_next_scan", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            std::string value = body.value("value", "");
            std::string scanOpt = body.value("scan_option", "exact");

            std::string luaCode = R"LUA(
                serverState.persistent_scans = serverState.persistent_scans or {}
                local entry = serverState.persistent_scans[")LUA" + hh::luaEscape(name) + R"LUA("]
                if not entry then return '{"success":false,"error":"Scan not found","error_code":"INVALID_PARAMS"}' end
                if not entry.has_scan then return '{"success":false,"error":"No first scan","error_code":"INVALID_PARAMS"}' end
                local soMap = { exact=soExactValue, between=soValueBetween, bigger=soBiggerThan, smaller=soSmallerThan, increased=soIncreasedValue, decreased=soDecreasedValue, changed=soChanged, unchanged=soUnchanged }
                local so = soMap[")LUA" + hh::luaEscape(scanOpt) + R"LUA("] or soExactValue
                local ms = entry.ms
                local ok, err = pcall(function()
                    if so == soExactValue or so == soValueBetween or so == soBiggerThan or so == soSmallerThan then
                        ms.nextScan(so, rtRounded, ")LUA" + hh::luaEscape(value) + R"LUA(", nil, false, false, false, false, false)
                    else
                        ms.nextScan(so, rtRounded, nil, nil, false, false, false, false, false)
                    end
                    ms.waitTillDone()
                end)
                if not ok then return '{"success":false,"error":"nextScan failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"INTERNAL_ERROR"}' end
                if entry.fl then pcall(function() entry.fl.destroy() end) end
                local fl = createFoundList(ms)
                fl.initialize()
                entry.fl = fl
                return '{"success":true,"scan_name":")LUA" + hh::luaEscape(name) + R"LUA(","count":' .. fl.getCount() .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 120000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/persistent_scan_get_results", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            int offset = body.value("offset", 0);
            int limit = body.value("limit", 100);

            std::string luaCode = R"LUA(
                serverState.persistent_scans = serverState.persistent_scans or {}
                local entry = serverState.persistent_scans[")LUA" + hh::luaEscape(name) + R"LUA("]
                if not entry then return '{"success":false,"error":"Scan not found","error_code":"INVALID_PARAMS"}' end
                if not entry.fl then return '{"success":false,"error":"No results","error_code":"INVALID_PARAMS"}' end
                local fl = entry.fl
                local total = fl.getCount()
                local offset = )LUA" + std::to_string(offset) + R"LUA(
                local limit = )LUA" + std::to_string(limit) + R"LUA(
                local items = {}
                for i = offset, math.min(offset + limit - 1, total - 1) do
                    local addr = fl.getAddress(i)
                    if addr and not addr:match("^0[xX]") then addr = "0x" .. addr end
                    local val = tostring(fl.getValue(i) or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                    items[#items+1] = '{"address":"' .. addr .. '","value":"' .. val .. '"}'
                end
                return '{"success":true,"scan_name":")LUA" + hh::luaEscape(name) + R"LUA(","total":' .. total .. ',"offset":' .. offset .. ',"limit":' .. limit .. ',"returned":' .. #items .. ',"results":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/persistent_scan_destroy", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");

            std::string luaCode = R"LUA(
                serverState.persistent_scans = serverState.persistent_scans or {}
                local entry = serverState.persistent_scans[")LUA" + hh::luaEscape(name) + R"LUA("]
                if not entry then return '{"success":false,"error":"Scan not found","error_code":"INVALID_PARAMS"}' end
                if entry.fl then pcall(function() entry.fl.destroy() end) end
                pcall(function() entry.ms.destroy() end)
                serverState.persistent_scans[")LUA" + hh::luaEscape(name) + R"LUA("] = nil
                return '{"success":true,"scan_name":")LUA" + hh::luaEscape(name) + R"LUA(","destroyed":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/scan_reset", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            if serverState.scan_foundlist then pcall(function() serverState.scan_foundlist.destroy() end); serverState.scan_foundlist = nil end
            if serverState.scan_memscan then pcall(function() serverState.scan_memscan.destroy() end); serverState.scan_memscan = nil end
            return '{"success":true}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });
}

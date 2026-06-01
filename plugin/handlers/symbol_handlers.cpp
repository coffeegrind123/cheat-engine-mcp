#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

void RegisterSymbolHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    // CE's symbol handler (NameToAddress) is not thread-safe — resolve on the main thread.
    svr.Post("/api/get_symbol_address", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string symbol = body.value("symbol", "");

            std::string luaCode = R"LUA(
                local sym = ")LUA" + hh::luaEscape(symbol) + R"LUA("
                local addr = getAddressSafe(sym)
                if addr == nil or addr == 0 then
                    return '{"success":false,"error":"Symbol not found: ' .. sym:gsub('"','\\"') .. '","error_code":"NOT_FOUND"}'
                end
                return '{"success":true,"symbol":"' .. sym:gsub('"','\\"') .. '","address":"' .. string.format("0x%X", addr) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_address_info", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            bool includeModules = body.value("include_modules", true);
            bool includeSymbols = body.value("include_symbols", true);
            bool includeSections = body.value("include_sections", false);

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local sym = getNameFromAddress(addr, )LUA" + hh::boolLua(includeModules) + R"LUA(, )LUA" + hh::boolLua(includeSymbols) + R"LUA(, )LUA" + hh::boolLua(includeSections) + R"LUA()
                local isInMod = false
                local ok, r = pcall(inModule, addr)
                if ok and r then isInMod = true
                elseif sym and sym:match("%+") then isInMod = true
                end
                if sym and sym:match("^%x+$") then sym = "0x" .. sym end
                local symEsc = sym and sym:gsub('\\', '\\\\'):gsub('"', '\\"') or ""
                return '{"success":true,"address":"' .. string.format("0x%X", addr) ..
                       '","symbolic_name":"' .. symEsc ..
                       '","is_in_module":' .. tostring(isInMod) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/register_symbol", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            std::string addrStr = body.value("address", "0");
            bool doNotSave = body.value("do_not_save", false);

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr or addr == 0 then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ok, err = pcall(registerSymbol, ")LUA" + hh::luaEscape(name) + R"LUA(", addr, )LUA" + hh::boolLua(doNotSave) + R"LUA()
                if not ok then return '{"success":false,"error":"registerSymbol failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"INTERNAL_ERROR"}' end
                return '{"success":true,"name":")LUA" + hh::luaEscape(name) + R"LUA(","address":"' .. string.format("0x%X", addr) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/unregister_symbol", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            std::string luaCode = R"LUA(
                local ok, err = pcall(unregisterSymbol, ")LUA" + hh::luaEscape(name) + R"LUA(")
                if not ok then return '{"success":false,"error":"unregisterSymbol failed","error_code":"INTERNAL_ERROR"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/enum_registered_symbols", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok, result = pcall(enumRegisteredSymbols)
            if not ok then return '{"success":false,"error":"enumRegisteredSymbols failed","error_code":"INTERNAL_ERROR"}' end
            local items = {}
            if result and type(result) == "table" then
                for i = 1, #result do
                    local s = result[i]
                    if s then
                        local a = s.address or 0
                        local m = s.module or s.modulename or ""
                        local n = s.symbolname or s.name or ""
                        m = tostring(m):gsub('\\', '\\\\'):gsub('"', '\\"')
                        n = n:gsub('\\', '\\\\'):gsub('"', '\\"')
                        items[#items+1] = '{"name":"' .. n .. '","address":"' .. string.format("0x%X", a) .. '","module":"' .. m .. '"}'
                    end
                end
            end
            return '{"success":true,"count":' .. #items .. ',"symbols":[' .. table.concat(items, ',') .. ']}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/delete_all_registered_symbols", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok1, r = pcall(enumRegisteredSymbols)
            local cnt = 0
            if ok1 and r and type(r) == "table" then cnt = #r end
            local ok, err = pcall(deleteAllRegisteredSymbols)
            if not ok then return '{"success":false,"error":"deleteAllRegisteredSymbols failed","error_code":"INTERNAL_ERROR"}' end
            return '{"success":true,"deleted_count":' .. cnt .. '}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/enable_windows_symbols", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok, err = pcall(enableWindowsSymbols)
            if not ok then return '{"success":false,"error":"enableWindowsSymbols failed"}' end
            return '{"success":true}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
    });

    svr.Post("/api/enable_kernel_symbols", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok, err = pcall(enableKernelSymbols)
            if not ok then
                local em = tostring(err):lower()
                if em:find("dbk") or em:find("kernel") or em:find("driver") then
                    return '{"success":false,"error":"Kernel driver not loaded","error_code":"DBK_NOT_LOADED"}'
                end
                return '{"success":false,"error":"enableKernelSymbols failed","error_code":"INTERNAL_ERROR"}'
            end
            return '{"success":true}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
    });

    svr.Post("/api/get_symbol_info", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            std::string luaCode = R"LUA(
                local ok, info = pcall(getSymbolInfo, ")LUA" + hh::luaEscape(name) + R"LUA(")
                if not ok then return '{"success":false,"error":"getSymbolInfo failed","error_code":"INTERNAL_ERROR"}' end
                if not info then return '{"success":false,"error":"Symbol not found","error_code":"NOT_FOUND"}' end
                local a = info.address or 0
                local m = tostring(info.modulename or info.module or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                local n = (info.searchkey or info.name or ")LUA" + hh::luaEscape(name) + R"LUA("):gsub('\\', '\\\\'):gsub('"', '\\"')
                return '{"success":true,"name":"' .. n .. '","address":"' .. string.format("0x%X", a) .. '","module":"' .. m .. '","size":' .. (info.size or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_module_size", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("module_name", "");
            std::string luaCode = R"LUA(
                local ok, sz = pcall(getModuleSize, ")LUA" + hh::luaEscape(name) + R"LUA(")
                if not ok then return '{"success":false,"error":"getModuleSize failed","error_code":"INTERNAL_ERROR"}' end
                if not sz then return '{"success":false,"error":"Module not found","error_code":"NOT_FOUND"}' end
                return '{"success":true,"size":' .. sz .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/load_new_symbols", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok, err = pcall(loadNewSymbols)
            if not ok then return '{"success":false,"error":"loadNewSymbols failed"}' end
            return '{"success":true}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
    });

    svr.Post("/api/reinitialize_symbol_handler", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok, err = pcall(reinitializeSymbolhandler)
            if not ok then return '{"success":false,"error":"reinitializeSymbolhandler failed"}' end
            return '{"success":true}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
    });
}

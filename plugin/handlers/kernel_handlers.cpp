#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

void RegisterKernelHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    auto makeCR = [&svr, lua](const std::string& endpoint, const std::string& fn, const std::string& outKey) {
        svr.Post(endpoint, [lua, fn, outKey](const httplib::Request&, httplib::Response& res) {
            std::string luaCode = R"LUA(
                local ok, r = pcall()LUA" + fn + R"LUA()
                if not ok then return '{"success":false,"error":"DBK/DBVM not loaded","error_code":"DBK_NOT_LOADED"}' end
                return '{"success":true,")LUA" + outKey + R"LUA(":"' .. string.format("0x%X", r or 0) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        });
    };
    makeCR("/api/dbk_get_cr0", "dbk_getCR0", "cr0");
    makeCR("/api/dbk_get_cr3", "dbk_getCR3", "cr3");
    makeCR("/api/dbk_get_cr4", "dbk_getCR4", "cr4");

    svr.Post("/api/read_process_memory_cr3", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string cr3 = body.value("cr3", "0");
            std::string addr = body.value("address", "0");
            int size = body.value("size", 0);
            std::string luaCode = R"LUA(
                local cr3 = getAddress(")LUA" + hh::luaEscape(cr3) + R"LUA(")
                local addr = getAddress(")LUA" + hh::luaEscape(addr) + R"LUA(")
                local size = )LUA" + std::to_string(size) + R"LUA(
                if not cr3 or not addr or size <= 0 then return '{"success":false,"error":"Invalid params"}' end
                local ok, bts = pcall(readProcessMemoryCR3, cr3, addr, size)
                if not ok then return '{"success":false,"error":"DBK not loaded","error_code":"DBK_NOT_LOADED"}' end
                if not bts then return '{"success":false,"error":"Read failed"}' end
                local parts = {}
                for _, b in ipairs(bts) do parts[#parts+1] = string.format("%02X", b) end
                return '{"success":true,"bytes":"' .. table.concat(parts, " ") .. '","size":' .. #bts .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/write_process_memory_cr3", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string cr3 = body.value("cr3", "0");
            std::string addr = body.value("address", "0");
            std::string bytesHex = body.value("bytes", "");

            std::string bytesLua = "{";
            std::istringstream iss(bytesHex);
            std::string tok;
            bool first = true;
            while (iss >> tok) {
                if (!first) bytesLua += ",";
                bytesLua += std::to_string((int)std::stoul(tok, nullptr, 16));
                first = false;
            }
            bytesLua += "}";

            std::string luaCode = R"LUA(
                local cr3 = getAddress(")LUA" + hh::luaEscape(cr3) + R"LUA(")
                local addr = getAddress(")LUA" + hh::luaEscape(addr) + R"LUA(")
                local bts = )LUA" + bytesLua + R"LUA(
                if not cr3 or not addr then return '{"success":false,"error":"Invalid params"}' end
                local ok = pcall(writeProcessMemoryCR3, cr3, addr, bts)
                if not ok then return '{"success":false,"error":"DBK not loaded","error_code":"DBK_NOT_LOADED"}' end
                return '{"success":true,"bytes_written":' .. #bts .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/map_memory", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addr = body.value("address", "0");
            int size = body.value("size", 0);
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addr) + R"LUA(")
                if not addr or )LUA" + std::to_string(size) + R"LUA( <= 0 then return '{"success":false,"error":"Invalid params"}' end
                local ok, mapped, mdl = pcall(mapMemory, addr, )LUA" + std::to_string(size) + R"LUA()
                if not ok then return '{"success":false,"error":"DBK not loaded","error_code":"DBK_NOT_LOADED"}' end
                if not mapped then return '{"success":false,"error":"mapMemory failed"}' end
                serverState.mappedMDL = serverState.mappedMDL or {}
                local key = string.format("0x%X", mapped)
                serverState.mappedMDL[key] = mdl
                return '{"success":true,"mapped_address":"' .. key .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/unmap_memory", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addr = body.value("mapped_address", "0");
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address"}' end
                local key = string.format("0x%X", addr)
                serverState.mappedMDL = serverState.mappedMDL or {}
                local ok = pcall(unmapMemory, addr, serverState.mappedMDL[key])
                if not ok then return '{"success":false,"error":"DBK not loaded","error_code":"DBK_NOT_LOADED"}' end
                serverState.mappedMDL[key] = nil
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/dbk_writes_ignore_write_protection", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            bool enable = body.value("enable", false);
            std::string luaCode = R"LUA(
                local ok = pcall(dbk_writesIgnoreWriteProtection, )LUA" + hh::boolLua(enable) + R"LUA()
                if not ok then return '{"success":false,"error":"DBK not loaded","error_code":"DBK_NOT_LOADED"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_physical_address_cr3", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string cr3 = body.value("cr3", "0");
            std::string va = body.value("virtual_address", "0");
            std::string luaCode = R"LUA(
                local cr3 = getAddress(")LUA" + hh::luaEscape(cr3) + R"LUA(")
                local va = getAddress(")LUA" + hh::luaEscape(va) + R"LUA(")
                if not cr3 or not va then return '{"success":false,"error":"Invalid params"}' end
                local ok, phys = pcall(getPhysicalAddressCR3, cr3, va)
                if not ok then return '{"success":false,"error":"DBK not loaded","error_code":"DBK_NOT_LOADED"}' end
                if not phys then return '{"success":false,"error":"Address not paged"}' end
                return '{"success":true,"physical_address":"' .. string.format("0x%X", phys) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });
}

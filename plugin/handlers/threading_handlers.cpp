#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

void RegisterThreadingHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/create_thread", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string code = body.value("code", "");
            std::string arg = body.value("arg", "");
            std::string luaCode = R"LUA(
                local code = [==[)LUA" + hh::luaLongEscape(code) + R"LUA(]==]
                local arg = ")LUA" + hh::luaEscape(arg) + R"LUA("
                local ok, err = pcall(function()
                    createThread(function(thread, a)
                        local f, ferr = load(code)
                        if not f then error("compile error: " .. tostring(ferr)) end
                        return f(thread, a)
                    end, arg)
                end)
                if not ok then return '{"success":false,"error":"createThread failed: ' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_global_variable", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            std::string luaCode = R"LUA(
                local ok, v = pcall(getGlobalVariable, ")LUA" + hh::luaEscape(name) + R"LUA(")
                if not ok then return '{"success":false,"error":"' .. tostring(v):gsub('"','\\"') .. '"}' end
                local vEsc = tostring(v):gsub('\\', '\\\\'):gsub('"', '\\"')
                return '{"success":true,"value":"' .. vEsc .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/set_global_variable", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            std::string valueLua;
            if (body.contains("value")) {
                if (body["value"].is_string()) valueLua = "\"" + hh::luaEscape(body["value"].get<std::string>()) + "\"";
                else if (body["value"].is_number_integer()) valueLua = std::to_string(body["value"].get<long long>());
                else if (body["value"].is_number()) valueLua = std::to_string(body["value"].get<double>());
                else if (body["value"].is_boolean()) valueLua = hh::boolLua(body["value"].get<bool>());
                else valueLua = "nil";
            }
            std::string luaCode = R"LUA(
                local ok, err = pcall(setGlobalVariable, ")LUA" + hh::luaEscape(name) + R"LUA(", )LUA" + valueLua + R"LUA()
                if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });
}

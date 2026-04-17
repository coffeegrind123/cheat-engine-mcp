#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

void RegisterMiscHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/output_debug_string", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string m = body.value("message", "");
            std::string luaCode = R"LUA(
                local ok, err = pcall(outputDebugString, ")LUA" + hh::luaEscape(m) + R"LUA(")
                if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/speak_text", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string t = body.value("text", "");
            bool eng = body.value("english_only", false);
            std::string fn = eng ? "speakEnglish" : "speak";
            std::string luaCode = R"LUA(
                local ok, err = pcall()LUA" + fn + R"LUA(, ")LUA" + hh::luaEscape(t) + R"LUA(")
                if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/play_sound", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string f = body.value("filename", "");
            if (f.find("..") != std::string::npos) { res.set_content(HttpServer::ErrorJson("Invalid filename", "INVALID_PARAMS"), "application/json"); return; }
            std::string luaCode = R"LUA(
                local ok, err = pcall(playSound, ")LUA" + hh::luaEscape(f) + R"LUA(")
                if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/beep", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok, err = pcall(beep)
            if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
            return '{"success":true}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/set_progress_state", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string state = body.value("state", "none");
            std::string luaCode = R"LUA(
                local m = { none=tbpsNone, normal=tbpsNormal, paused=tbpsPaused, error=tbpsError, indeterminate=tbpsIndeterminate }
                local st = m[")LUA" + hh::luaEscape(state) + R"LUA("]
                if not st then return '{"success":false,"error":"Invalid state","error_code":"INVALID_PARAMS"}' end
                local ok, err = pcall(setProgressState, st)
                if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/set_progress_value", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int current = body.value("current", 0);
            int max = body.value("max", 100);
            std::string luaCode = R"LUA(
                local ok, err = pcall(setProgressValue, )LUA" + std::to_string(current) + ", " + std::to_string(max) + R"LUA()
                if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });
}

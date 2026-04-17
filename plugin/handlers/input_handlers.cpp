#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

void RegisterInputHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/get_pixel", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int x = body.value("x", 0);
            int y = body.value("y", 0);
            std::string luaCode = R"LUA(
                local ok, rgb = pcall(getPixel, )LUA" + std::to_string(x) + ", " + std::to_string(y) + R"LUA()
                if not ok then return '{"success":false,"error":"' .. tostring(rgb):gsub('"','\\"') .. '"}' end
                local r = rgb % 256
                local g = math.floor(rgb / 256) % 256
                local b = math.floor(rgb / 65536) % 256
                return '{"success":true,"r":' .. r .. ',"g":' .. g .. ',"b":' .. b .. ',"rgb":' .. rgb .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_mouse_pos", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok, x, y = pcall(getMousePos)
            if not ok then return '{"success":false,"error":"' .. tostring(x):gsub('"','\\"') .. '"}' end
            return '{"success":true,"x":' .. tostring(x) .. ',"y":' .. tostring(y) .. '}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/set_mouse_pos", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int x = body.value("x", 0);
            int y = body.value("y", 0);
            std::string luaCode = R"LUA(
                local ok, err = pcall(setMousePos, )LUA" + std::to_string(x) + ", " + std::to_string(y) + R"LUA()
                if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/is_key_pressed", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int vk = body.value("vk", 0);
            std::string luaCode = R"LUA(
                local ok, p = pcall(isKeyPressed, )LUA" + std::to_string(vk) + R"LUA()
                if not ok then return '{"success":false,"error":"' .. tostring(p):gsub('"','\\"') .. '"}' end
                return '{"success":true,"pressed":' .. tostring(p == true) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    auto makeKeyAction = [&svr, lua](const std::string& endpoint, const std::string& fn) {
        svr.Post(endpoint, [lua, fn](const httplib::Request& req, httplib::Response& res) {
            try {
                auto body = json::parse(req.body);
                int vk = body.value("vk", 0);
                std::string luaCode = R"LUA(
                    local ok, err = pcall()LUA" + fn + R"LUA(, )LUA" + std::to_string(vk) + R"LUA()
                    if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                    return '{"success":true}'
                )LUA";
                res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
            } catch (const std::exception& e) {
                res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
            }
        });
    };
    makeKeyAction("/api/key_down", "keyDown");
    makeKeyAction("/api/key_up", "keyUp");
    makeKeyAction("/api/do_key_press", "doKeyPress");

    svr.Post("/api/get_screen_info", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local okW, w = pcall(getScreenWidth)
            local okH, h = pcall(getScreenHeight)
            local okD, d = pcall(getScreenDPI)
            if not okW or not okH or not okD then return '{"success":false,"error":"screen info failed"}' end
            return '{"success":true,"width":' .. tostring(w) .. ',"height":' .. tostring(h) .. ',"dpi":' .. tostring(d) .. '}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });
}

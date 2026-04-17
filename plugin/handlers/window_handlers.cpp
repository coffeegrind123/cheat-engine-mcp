#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

void RegisterWindowHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/find_window", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string title = body.value("title", "");
            std::string cls = body.value("class_name", "");

            std::string titleArg = title.empty() ? "nil" : ("\"" + hh::luaEscape(title) + "\"");
            std::string clsArg = cls.empty() ? "nil" : ("\"" + hh::luaEscape(cls) + "\"");

            std::string luaCode = R"LUA(
                local ok, h = pcall(function() return findWindow()LUA" + clsArg + ", " + titleArg + R"LUA() end)
                if not ok then return '{"success":false,"error":"findWindow failed"}' end
                if not h or h == 0 then return '{"success":false,"error":"Window not found","error_code":"NOT_FOUND"}' end
                return '{"success":true,"handle":"' .. string.format("0x%X", h) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    auto makeWindowProp = [&svr, lua](const std::string& endpoint, const std::string& fn, const std::string& outKey) {
        svr.Post(endpoint, [lua, fn, outKey](const httplib::Request& req, httplib::Response& res) {
            try {
                auto body = json::parse(req.body);
                std::string handleStr = body.value("handle", "");
                std::string luaCode = R"LUA(
                    local hClean = (")LUA" + hh::luaEscape(handleStr) + R"LUA("):gsub("^0[xX]","")
                    local handle = tonumber(hClean, 16)
                    if not handle then return '{"success":false,"error":"Invalid handle"}' end
                    local ok, r = pcall()LUA" + fn + R"LUA(, handle)
                    if not ok then return '{"success":false,"error":"' .. tostring(r):gsub('"','\\"') .. '"}' end
                    local rEsc = tostring(r or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                    return '{"success":true,")LUA" + outKey + R"LUA(":"' .. rEsc .. '"}'
                )LUA";
                res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
            } catch (const std::exception& e) {
                res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
            }
        });
    };
    makeWindowProp("/api/get_window_caption", "getWindowCaption", "caption");
    makeWindowProp("/api/get_window_class_name", "getWindowClassName", "class_name");

    svr.Post("/api/get_window_process_id", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string handleStr = body.value("handle", "");
            std::string luaCode = R"LUA(
                local hClean = (")LUA" + hh::luaEscape(handleStr) + R"LUA("):gsub("^0[xX]","")
                local handle = tonumber(hClean, 16)
                if not handle then return '{"success":false,"error":"Invalid handle"}' end
                local ok, pid = pcall(getWindowProcessID, handle)
                if not ok then return '{"success":false,"error":"' .. tostring(pid):gsub('"','\\"') .. '"}' end
                return '{"success":true,"process_id":' .. tostring(pid or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/send_window_message", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string handleStr = body.value("handle", "");
            long long msg = body.value("msg", (long long)0);
            long long wp = body.value("wparam", (long long)0);
            long long lp = body.value("lparam", (long long)0);
            std::string luaCode = R"LUA(
                local hClean = (")LUA" + hh::luaEscape(handleStr) + R"LUA("):gsub("^0[xX]","")
                local handle = tonumber(hClean, 16)
                if not handle then return '{"success":false,"error":"Invalid handle"}' end
                local ok, r = pcall(sendMessage, handle, )LUA" + std::to_string(msg) + ", " + std::to_string(wp) + ", " + std::to_string(lp) + R"LUA()
                if not ok then return '{"success":false,"error":"' .. tostring(r):gsub('"','\\"') .. '"}' end
                return '{"success":true,"result":' .. tostring(r or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/show_message", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string message = body.value("message", "");
            std::string luaCode = R"LUA(
                local ok, err = pcall(showMessage, ")LUA" + hh::luaEscape(message) + R"LUA(")
                if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 600000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/input_query", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string caption = body.value("caption", "");
            std::string prompt = body.value("prompt", "");
            std::string def = body.value("default", "");
            std::string luaCode = R"LUA(
                local ok, v = pcall(inputQuery, ")LUA" + hh::luaEscape(caption) + R"LUA(", ")LUA" + hh::luaEscape(prompt) + R"LUA(", ")LUA" + hh::luaEscape(def) + R"LUA(")
                if not ok then return '{"success":false,"error":"' .. tostring(v):gsub('"','\\"') .. '"}' end
                if v == nil then return '{"success":true,"value":"","cancelled":true}' end
                local vEsc = tostring(v):gsub('\\', '\\\\'):gsub('"', '\\"')
                return '{"success":true,"value":"' .. vEsc .. '","cancelled":false}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 600000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/show_selection_list", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string caption = body.value("caption", "");
            std::string prompt = body.value("prompt", "");
            std::string optsLua = hh::stringArrayFromJson(body, "options");

            std::string luaCode = R"LUA(
                local sl = createStringlist()
                for _, v in ipairs()LUA" + optsLua + R"LUA() do sl.add(v) end
                local ok, idx, selected = pcall(showSelectionList, ")LUA" + hh::luaEscape(caption) + R"LUA(", ")LUA" + hh::luaEscape(prompt) + R"LUA(", sl)
                sl.destroy()
                if not ok then return '{"success":false,"error":"' .. tostring(idx):gsub('"','\\"') .. '"}' end
                if idx == nil or idx < 0 then return '{"success":true,"selected_index":-1,"selected_value":"","cancelled":true}' end
                local vEsc = tostring(selected or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                return '{"success":true,"selected_index":' .. idx .. ',"selected_value":"' .. vEsc .. '","cancelled":false}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 600000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });
}

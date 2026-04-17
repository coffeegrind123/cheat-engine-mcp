#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"
#include <cstdlib>

using json = nlohmann::json;

static bool isShellAllowed() {
    const char* v = std::getenv("CE_MCP_ALLOW_SHELL");
    return v && (std::string(v) == "1" || std::string(v) == "true");
}

void RegisterFileHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/file_exists", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string f = body.value("filename", "");
            if (f.find("..") != std::string::npos) { res.set_content(HttpServer::ErrorJson("Path traversal not allowed", "INVALID_PARAMS"), "application/json"); return; }
            std::string luaCode = R"LUA(
                local ok, r = pcall(fileExists, ")LUA" + hh::luaEscape(f) + R"LUA(")
                if not ok then return '{"success":false,"error":"' .. tostring(r):gsub('"','\\"') .. '"}' end
                return '{"success":true,"exists":' .. tostring(r == true) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/delete_file", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string f = body.value("filename", "");
            if (f.find("..") != std::string::npos) { res.set_content(HttpServer::ErrorJson("Path traversal not allowed", "INVALID_PARAMS"), "application/json"); return; }
            std::string luaCode = R"LUA(
                local ok, r = pcall(deleteFile, ")LUA" + hh::luaEscape(f) + R"LUA(")
                if not ok then return '{"success":false,"error":"' .. tostring(r):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    auto makeList = [&svr, lua](const std::string& endpoint, const std::string& fn, const std::string& outKey) {
        svr.Post(endpoint, [lua, fn, outKey](const httplib::Request& req, httplib::Response& res) {
            try {
                auto body = json::parse(req.body);
                std::string p = body.value("path", "");
                if (p.find("..") != std::string::npos) { res.set_content(HttpServer::ErrorJson("Path traversal not allowed", "INVALID_PARAMS"), "application/json"); return; }
                std::string luaCode = R"LUA(
                    local ok, r = pcall()LUA" + fn + R"LUA(, ")LUA" + hh::luaEscape(p) + R"LUA(")
                    if not ok then return '{"success":false,"error":"' .. tostring(r):gsub('"','\\"') .. '"}' end
                    local items = {}
                    if type(r) == "table" then
                        for _, v in ipairs(r) do
                            local e = tostring(v):gsub('\\', '\\\\'):gsub('"', '\\"')
                            items[#items+1] = '"' .. e .. '"'
                        end
                    end
                    return '{"success":true,"count":' .. #items .. ',")LUA" + outKey + R"LUA(":[' .. table.concat(items, ',') .. ']}'
                )LUA";
                res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
            } catch (const std::exception& e) {
                res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
            }
        });
    };
    makeList("/api/get_file_list", "getFileList", "files");
    makeList("/api/get_directory_list", "getDirectoryList", "directories");

    svr.Post("/api/get_temp_folder", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok, r = pcall(getTempFolder)
            if not ok then return '{"success":false,"error":"' .. tostring(r):gsub('"','\\"') .. '"}' end
            local rEsc = tostring(r or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
            return '{"success":true,"path":"' .. rEsc .. '"}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/get_file_version", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string f = body.value("filename", "");
            if (f.find("..") != std::string::npos) { res.set_content(HttpServer::ErrorJson("Path traversal not allowed", "INVALID_PARAMS"), "application/json"); return; }
            std::string luaCode = R"LUA(
                local ok, raw, ver = pcall(function() return getFileVersion(")LUA" + hh::luaEscape(f) + R"LUA(") end)
                if not ok then return '{"success":false,"error":"' .. tostring(raw):gsub('"','\\"') .. '"}' end
                if type(ver) ~= "table" then return '{"success":false,"error":"No version table"}' end
                local ma, mi, re, bu = ver.major or 0, ver.minor or 0, ver.release or 0, ver.build or 0
                return '{"success":true,"major":' .. ma .. ',"minor":' .. mi .. ',"release":' .. re .. ',"build":' .. bu ..
                       ',"version_string":"' .. ma .. '.' .. mi .. '.' .. re .. '.' .. bu .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/read_clipboard", [lua](const httplib::Request&, httplib::Response& res) {
        std::string luaCode = R"LUA(
            local ok, r = pcall(readFromClipboard)
            if not ok then return '{"success":false,"error":"' .. tostring(r):gsub('"','\\"') .. '"}' end
            local rEsc = tostring(r or ""):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r')
            return '{"success":true,"text":"' .. rEsc .. '"}'
        )LUA";
        res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
    });

    svr.Post("/api/write_clipboard", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string text = body.value("text", "");
            std::string luaCode = R"LUA(
                local ok, err = pcall(writeToClipboard, ")LUA" + hh::luaEscape(text) + R"LUA(")
                if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/run_command", [lua](const httplib::Request& req, httplib::Response& res) {
        if (!isShellAllowed()) {
            res.set_content(HttpServer::ErrorJson("Shell execution disabled. Set CE_MCP_ALLOW_SHELL=1", "PERMISSION_DENIED"), "application/json");
            return;
        }
        try {
            auto body = json::parse(req.body);
            std::string cmd = body.value("command", "");
            std::string args = body.value("args", "");
            std::string luaCode = R"LUA(
                local ok, output, code = pcall(runCommand, ")LUA" + hh::luaEscape(cmd) + R"LUA(", ")LUA" + hh::luaEscape(args) + R"LUA(")
                if not ok then return '{"success":false,"error":"' .. tostring(output):gsub('"','\\"') .. '"}' end
                local o = tostring(output or ""):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r')
                return '{"success":true,"output":"' .. o .. '","exit_code":' .. tostring(code or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/shell_execute", [lua](const httplib::Request& req, httplib::Response& res) {
        if (!isShellAllowed()) {
            res.set_content(HttpServer::ErrorJson("Shell execution disabled. Set CE_MCP_ALLOW_SHELL=1", "PERMISSION_DENIED"), "application/json");
            return;
        }
        try {
            auto body = json::parse(req.body);
            std::string cmd = body.value("command", "");
            std::string args = body.value("args", "");
            std::string wd = body.value("working_dir", "");
            std::string wdLua = wd.empty() ? "nil" : ("\"" + hh::luaEscape(wd) + "\"");
            std::string luaCode = R"LUA(
                local ok, err = pcall(shellExecute, ")LUA" + hh::luaEscape(cmd) + R"LUA(", ")LUA" + hh::luaEscape(args) + R"LUA(", )LUA" + wdLua + R"LUA()
                if not ok then return '{"success":false,"error":"' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 30000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });
}

#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

using json = nlohmann::json;

static std::string argsJsonToLua(const nlohmann::json& j) {
    std::string out = "{";
    if (j.is_array()) {
        for (size_t i = 0; i < j.size(); i++) {
            if (i > 0) out += ",";
            if (j[i].is_string()) out += "\"" + hh::luaEscape(j[i].get<std::string>()) + "\"";
            else if (j[i].is_number_integer()) out += std::to_string(j[i].get<long long>());
            else if (j[i].is_number()) out += std::to_string(j[i].get<double>());
            else if (j[i].is_boolean()) out += hh::boolLua(j[i].get<bool>());
            else out += "nil";
        }
    }
    out += "}";
    return out;
}

void RegisterInjectionHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/auto_assemble", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string script = body.value("script", "");
            if (script.empty()) script = body.value("code", "");
            bool disable = body.value("disable", false);

            std::string luaCode = R"LUA(
                local script = [==[)LUA" + hh::luaLongEscape(script) + R"LUA(]==]
                local ok, success, dinfo
                if )LUA" + hh::boolLua(disable) + R"LUA( then
                    ok, success, dinfo = pcall(autoAssemble, script, {})
                else
                    ok, success, dinfo = pcall(autoAssemble, script)
                end
                if not ok then return '{"success":false,"error":"autoAssemble threw: ' .. tostring(success):gsub('"','\\"') .. '"}' end
                if success then return '{"success":true,"executed":true,"section":")LUA" + (disable ? "disable" : "enable") + R"LUA("}' end
                return '{"success":false,"error":"autoAssemble failed: ' .. tostring(dinfo):gsub('"','\\"') .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 300000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/auto_assemble_check", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string script = body.value("script", "");
            bool enable = body.value("enable", true);
            bool targetSelf = body.value("target_self", false);

            std::string luaCode = R"LUA(
                local script = [==[)LUA" + hh::luaLongEscape(script) + R"LUA(]==]
                local ok, valid, errMsg = pcall(autoAssembleCheck, script, )LUA" + hh::boolLua(enable) + R"LUA(, )LUA" + hh::boolLua(targetSelf) + R"LUA()
                if not ok then return '{"success":false,"valid":false,"errors":["' .. tostring(valid):gsub('"','\\"') .. '"]}' end
                if valid then return '{"success":true,"valid":true,"errors":[]}' end
                local e = tostring(errMsg or ""):gsub('\\', '\\\\'):gsub('"', '\\"')
                return '{"success":true,"valid":false,"errors":["' .. e .. '"]}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/inject_dll", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string filepath = body.value("filepath", "");
            if (filepath.empty()) filepath = body.value("dll_path", "");
            bool skip = body.value("skip_symbol_reload", false);

            std::string luaCode = R"LUA(
                local ok, r = pcall(injectDLL, ")LUA" + hh::luaEscape(filepath) + R"LUA(", )LUA" + hh::boolLua(skip) + R"LUA()
                if not ok then return '{"success":false,"error":"injectDLL failed: ' .. tostring(r):gsub('"','\\"') .. '"}' end
                return '{"success":' .. tostring(r == true) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/inject_dotnet_dll", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string filepath = body.value("filepath", "");
            std::string cls = body.value("class_name", "");
            std::string method = body.value("method_name", "");
            std::string param = body.value("param", "");
            int timeout = body.value("timeout", -1);
            std::string luaCode = R"LUA(
                local ok, r = pcall(injectDotNetDLL, ")LUA" + hh::luaEscape(filepath) + R"LUA(", ")LUA" + hh::luaEscape(cls) + R"LUA(", ")LUA" + hh::luaEscape(method) + R"LUA(", ")LUA" + hh::luaEscape(param) + R"LUA(", )LUA" + std::to_string(timeout) + R"LUA()
                if not ok then return '{"success":false,"error":"injectDotNetDLL failed: ' .. tostring(r):gsub('"','\\"') .. '"}' end
                return '{"success":true,"result":' .. tostring(r) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 120000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/allocate_memory", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int size = body.value("size", 4096);
            std::string baseAddr = body.value("base_address", "");
            if (baseAddr.empty()) baseAddr = body.value("near_address", "");
            std::string prot = body.value("protection", "rwx");

            std::string baseLua = baseAddr.empty() ? "nil" : ("getAddress(\"" + hh::luaEscape(baseAddr) + "\")");

            std::string luaCode = R"LUA(
                local protMap = { r = 0x02, rw = 0x04, rx = 0x20, rwx = 0x40 }
                local protConst = protMap[")LUA" + hh::luaEscape(prot) + R"LUA("] or 0x40
                local size = )LUA" + std::to_string(size) + R"LUA(
                local ok, addr = pcall(allocateMemory, size, )LUA" + baseLua + R"LUA(, protConst)
                if not ok or not addr or addr == 0 then
                    return '{"success":false,"error":"allocateMemory failed","error_code":"OUT_OF_RESOURCES"}'
                end
                return '{"success":true,"address":"' .. string.format("0x%X", addr) .. '","size":' .. size .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/free_memory", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int size = body.value("size", 0);
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ok, err = pcall(deAlloc, addr, )LUA" + std::to_string(size) + R"LUA()
                if not ok then return '{"success":false,"error":"deAlloc failed"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/execute_code", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            long long param = body.value("param", (long long)0);
            if (body.contains("parameter")) param = body.value("parameter", (long long)0);
            int timeout = body.value("timeout", -1);
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ok, r = pcall(executeCode, addr, )LUA" + std::to_string(param) + R"LUA(, )LUA" + std::to_string(timeout) + R"LUA()
                if not ok then return '{"success":false,"error":"executeCode failed: ' .. tostring(r):gsub('"','\\"') .. '"}' end
                return '{"success":true,"return_value":' .. tostring(r or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/execute_code_ex", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int callMethod = body.value("call_method", 0);
            int timeout = body.value("timeout", -1);
            std::string argsLua = body.contains("args") ? argsJsonToLua(body["args"]) : "{}";
            std::string luaCode = R"LUA(
                local unpack = table.unpack or unpack
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local args = )LUA" + argsLua + R"LUA(
                local ok, r = pcall(executeCodeEx, )LUA" + std::to_string(callMethod) + R"LUA(, )LUA" + std::to_string(timeout) + R"LUA(, addr, unpack(args))
                if not ok then return '{"success":false,"error":"executeCodeEx failed: ' .. tostring(r):gsub('"','\\"') .. '"}' end
                return '{"success":true,"return_value":' .. tostring(r or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/execute_method", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string instStr = body.value("instance", "0");
            int callMethod = body.value("call_method", 0);
            int timeout = body.value("timeout", -1);
            std::string argsLua = body.contains("args") ? argsJsonToLua(body["args"]) : "{}";
            std::string luaCode = R"LUA(
                local unpack = table.unpack or unpack
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                local inst = getAddress(")LUA" + hh::luaEscape(instStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local args = )LUA" + argsLua + R"LUA(
                local ok, r = pcall(executeMethod, )LUA" + std::to_string(callMethod) + R"LUA(, )LUA" + std::to_string(timeout) + R"LUA(, addr, inst, unpack(args))
                if not ok then return '{"success":false,"error":"executeMethod failed: ' .. tostring(r):gsub('"','\\"') .. '"}' end
                return '{"success":true,"return_value":' .. tostring(r or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/execute_code_local", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            long long param = body.value("param", (long long)0);
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ok, r = pcall(executeCodeLocal, addr, )LUA" + std::to_string(param) + R"LUA()
                if not ok then return '{"success":false,"error":"executeCodeLocal failed: ' .. tostring(r):gsub('"','\\"') .. '"}' end
                return '{"success":true,"return_value":' .. tostring(r or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/execute_code_local_ex", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int callMethod = body.value("call_method", 0);
            std::string argsLua = body.contains("args") ? argsJsonToLua(body["args"]) : "{}";
            std::string luaCode = R"LUA(
                local unpack = table.unpack or unpack
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local args = )LUA" + argsLua + R"LUA(
                local ok, r = pcall(executeCodeLocalEx, )LUA" + std::to_string(callMethod) + R"LUA(, addr, unpack(args))
                if not ok then return '{"success":false,"error":"executeCodeLocalEx failed: ' .. tostring(r):gsub('"','\\"') .. '"}' end
                return '{"success":true,"return_value":' .. tostring(r or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/compile_c_code", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string source = body.value("source", "");
            std::string addrStr = body.value("address", "");
            bool targetSelf = body.value("target_self", false);
            bool kernelMode = body.value("kernelmode", false);

            std::string addrLua = addrStr.empty() ? "nil" : ("getAddress(\"" + hh::luaEscape(addrStr) + "\")");

            std::string luaCode = R"LUA(
                if type(compile) ~= "function" then return '{"success":false,"error":"TCC not available","error_code":"CE_API_UNAVAILABLE"}' end
                local src = [==[)LUA" + hh::luaLongEscape(source) + R"LUA(]==]
                local ok, syms, errMsg = pcall(compile, src, )LUA" + addrLua + R"LUA(, )LUA" + hh::boolLua(targetSelf) + R"LUA(, )LUA" + hh::boolLua(kernelMode) + R"LUA(, false)
                if not ok then return '{"success":false,"symbols":{},"errors":["' .. tostring(syms):gsub('"','\\"') .. '"]}' end
                if not syms then
                    local e = tostring(errMsg or ""):gsub('"','\\"')
                    return '{"success":false,"symbols":{},"errors":["' .. e .. '"]}'
                end
                local parts = {}
                for name, a in pairs(syms) do
                    parts[#parts+1] = '"' .. tostring(name):gsub('"','\\"') .. '":"' .. string.format("0x%X", a) .. '"'
                end
                return '{"success":true,"symbols":{' .. table.concat(parts, ',') .. '},"errors":[]}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 120000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/compile_cs_code", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string source = body.value("source", "");
            std::string refsLua = body.contains("references") ? argsJsonToLua(body["references"]) : "{}";
            std::string core = body.value("core_assembly", "");
            std::string coreLua = core.empty() ? "nil" : ("\"" + hh::luaEscape(core) + "\"");

            std::string luaCode = R"LUA(
                if type(compileCS) ~= "function" then return '{"success":false,"error":".NET/compileCS not available","error_code":"CE_API_UNAVAILABLE"}' end
                local src = [==[)LUA" + hh::luaLongEscape(source) + R"LUA(]==]
                local ok, result = pcall(compileCS, src, )LUA" + refsLua + R"LUA(, )LUA" + coreLua + R"LUA()
                if not ok or not result then
                    return '{"success":false,"assembly_handle":null,"error":"' .. tostring(result or ""):gsub('"','\\"') .. '"}'
                end
                return '{"success":true,"assembly_handle":"' .. tostring(result) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 120000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/generate_api_hook_script", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string targetStr = body.value("target_address", "0");
            std::string code = body.value("code_to_execute", "");
            std::string extLua = code.empty() ? "nil" : ("[==[" + hh::luaLongEscape(code) + "]==]");
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                local tgt = getAddress(")LUA" + hh::luaEscape(targetStr) + R"LUA(")
                if not addr or not tgt then return '{"success":false,"error":"Invalid address"}' end
                local ok, r = pcall(generateAPIHookScript, addr, tgt, nil, )LUA" + extLua + R"LUA()
                if not ok or not r then return '{"success":false,"error":"generateAPIHookScript failed: ' .. tostring(r or ""):gsub('"','\\"') .. '"}' end
                local e = tostring(r):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r')
                return '{"success":true,"script":"' .. e .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 30000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/generate_code_injection_script", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address"}' end
                local sl = createStringlist()
                local ok, err = pcall(generateCodeInjectionScript, sl, addr)
                if not ok then sl.destroy(); return '{"success":false,"error":"generateCodeInjectionScript failed: ' .. tostring(err):gsub('"','\\"') .. '"}' end
                local script = sl.Text
                sl.destroy()
                if not script or script == "" then return '{"success":false,"error":"empty script"}' end
                local e = script:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r')
                return '{"success":true,"script":"' .. e .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 30000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });
}

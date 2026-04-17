#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "handlers.h"
#include "handler_helpers.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"
#include <algorithm>

using json = nlohmann::json;

void RegisterMemoryHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua) {

    svr.Post("/api/read_memory", [api](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int size = body.value("size", 256);
            size = std::min(size, 1048576);

            uint64_t address = HttpServer::ParseAddress(addrStr);
            std::vector<uint8_t> buffer(size, 0);
            size_t bytesRead = 0;

            if (api->ReadProcessMemory(address, buffer.data(), size, &bytesRead)) {
                json r;
                r["success"] = true;
                r["address"] = HttpServer::FormatHex(address);
                r["size"] = (int)bytesRead;
                r["bytes"] = HttpServer::BytesToHexString(buffer.data(), bytesRead);
                res.set_content(r.dump(), "application/json");
            } else {
                res.set_content(HttpServer::ErrorJson("ReadProcessMemory failed at " + HttpServer::FormatHex(address), "INVALID_ADDRESS"), "application/json");
            }
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/write_memory", [api](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string bytesHex = body.value("bytes", "");

            uint64_t address = HttpServer::ParseAddress(addrStr);
            auto bytes = HttpServer::HexStringToBytes(bytesHex);

            if (bytes.empty()) {
                res.set_content(HttpServer::ErrorJson("No bytes to write", "INVALID_PARAMS"), "application/json");
                return;
            }

            if (api->WriteProcessMemory(address, bytes.data(), bytes.size())) {
                json r;
                r["success"] = true;
                r["address"] = HttpServer::FormatHex(address);
                r["written"] = (int)bytes.size();
                res.set_content(r.dump(), "application/json");
            } else {
                res.set_content(HttpServer::ErrorJson("WriteProcessMemory failed", "INVALID_ADDRESS"), "application/json");
            }
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/read_integer", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string type = body.value("type", "dword");

            std::string readFunc;
            if (type == "byte") readFunc = "readBytes(addr, 1, false)";
            else if (type == "word") readFunc = "readSmallInteger(addr)";
            else if (type == "dword") readFunc = "readInteger(addr)";
            else if (type == "qword") readFunc = "readQword(addr)";
            else if (type == "float") readFunc = "readFloat(addr)";
            else if (type == "double") readFunc = "readDouble(addr)";
            else readFunc = "readInteger(addr)";

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local val = )LUA" + readFunc + R"LUA(
                if val == nil then
                    return '{"success":false,"error":"Read failed","error_code":"INVALID_ADDRESS"}'
                end
                return '{"success":true,"address":"' .. string.format("0x%X", addr) .. '","value":' .. tostring(val) .. ',"type":")LUA" + hh::luaEscape(type) + R"LUA("}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/write_integer", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string type = body.value("type", "dword");
            double value = body.value("value", 0.0);

            std::string writeFunc;
            if (type == "byte") writeFunc = "writeBytes(addr, {" + std::to_string((int)value) + "})";
            else if (type == "word") writeFunc = "writeSmallInteger(addr, " + std::to_string((int)value) + ")";
            else if (type == "dword") writeFunc = "writeInteger(addr, " + std::to_string((int)value) + ")";
            else if (type == "qword") writeFunc = "writeQword(addr, " + std::to_string((long long)value) + ")";
            else if (type == "float") writeFunc = "writeFloat(addr, " + std::to_string(value) + ")";
            else if (type == "double") writeFunc = "writeDouble(addr, " + std::to_string(value) + ")";
            else writeFunc = "writeInteger(addr, " + std::to_string((int)value) + ")";

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ok, err = pcall(function() )LUA" + writeFunc + R"LUA( end)
                if not ok then return '{"success":false,"error":"Write failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"PERMISSION_DENIED"}' end
                return '{"success":true,"address":"' .. string.format("0x%X", addr) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    auto makeReadTyped = [&svr, lua](const std::string& endpoint, const std::string& luaFn) {
        svr.Post(endpoint, [lua, luaFn](const httplib::Request& req, httplib::Response& res) {
            try {
                auto body = json::parse(req.body);
                std::string addrStr = body.value("address", "0");
                std::string luaCode = R"LUA(
                    local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                    if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                    local val = )LUA" + luaFn + R"LUA((addr)
                    if val == nil then return '{"success":false,"error":"Read failed","error_code":"INVALID_ADDRESS"}' end
                    return '{"success":true,"address":"' .. string.format("0x%X", addr) .. '","value":' .. tostring(val) .. '}'
                )LUA";
                res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
            } catch (const std::exception& e) {
                res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
            }
        });
    };
    makeReadTyped("/api/read_float", "readFloat");
    makeReadTyped("/api/read_double", "readDouble");

    auto makeWriteTyped = [&svr, lua](const std::string& endpoint, const std::string& luaFn) {
        svr.Post(endpoint, [lua, luaFn](const httplib::Request& req, httplib::Response& res) {
            try {
                auto body = json::parse(req.body);
                std::string addrStr = body.value("address", "0");
                double value = body.value("value", 0.0);
                std::string luaCode = R"LUA(
                    local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                    if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                    local ok, err = pcall()LUA" + luaFn + R"LUA(, addr, )LUA" + std::to_string(value) + R"LUA()
                    if not ok then return '{"success":false,"error":"Write failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"PERMISSION_DENIED"}' end
                    return '{"success":true,"address":"' .. string.format("0x%X", addr) .. '"}'
                )LUA";
                res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
            } catch (const std::exception& e) {
                res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
            }
        });
    };
    makeWriteTyped("/api/write_float", "writeFloat");
    makeWriteTyped("/api/write_double", "writeDouble");

    svr.Post("/api/read_string", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int maxLen = body.value("max_length", 256);
            bool wide = body.value("wide", false);

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local val = readString(addr, )LUA" + std::to_string(maxLen) + ", " + hh::boolLua(wide) + R"LUA()
                if val == nil then val = "" end
                val = val:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r'):gsub('\t', '\\t')
                return '{"success":true,"address":"' .. string.format("0x%X", addr) .. '","value":"' .. val .. '","wide":)LUA" + hh::boolLua(wide) + R"LUA(}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/write_string", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string value = body.value("value", "");
            bool wide = body.value("wide", false);

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ok, err = pcall(writeString, addr, ")LUA" + hh::luaEscape(value) + R"LUA(", )LUA" + hh::boolLua(wide) + R"LUA()
                if not ok then return '{"success":false,"error":"Write failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"PERMISSION_DENIED"}' end
                return '{"success":true,"address":"' .. string.format("0x%X", addr) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/read_pointer", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ptr = readPointer(addr)
                if ptr == nil then return '{"success":false,"error":"Null pointer","error_code":"INVALID_ADDRESS"}' end
                return '{"success":true,"address":"' .. string.format("0x%X", addr) .. '","pointer":"' .. string.format("0x%X", ptr) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/read_pointer_chain", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string base = body.value("base", "0");
            std::string offsetsLua = hh::intArrayFromJson(body, "offsets");

            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(base) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid base","error_code":"INVALID_ADDRESS"}' end
                local offsets = )LUA" + offsetsLua + R"LUA(
                local steps = {}
                local current = addr
                for i, off in ipairs(offsets) do
                    local ptr = readPointer(current)
                    if ptr == nil or ptr == 0 then
                        return '{"success":false,"error":"Null pointer at step ' .. i .. '","error_code":"INVALID_ADDRESS"}'
                    end
                    steps[#steps+1] = '{"from":"' .. string.format("0x%X", current) .. '","pointer":"' .. string.format("0x%X", ptr) .. '","offset":' .. off .. '}'
                    current = ptr + off
                end
                local finalValue = nil
                pcall(function() finalValue = readPointer(current) end)
                return '{"success":true,"base":"' .. string.format("0x%X", addr) ..
                       '","final_address":"' .. string.format("0x%X", current) ..
                       '","final_value":' .. (finalValue and ('"' .. string.format("0x%X", finalValue) .. '"') or 'null') ..
                       ',"steps":[' .. table.concat(steps, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    // Checksum / MD5

    auto makeMd5 = [&svr, lua](const std::string& endpoint) {
        svr.Post(endpoint, [lua](const httplib::Request& req, httplib::Response& res) {
            try {
                auto body = json::parse(req.body);
                std::string addrStr = body.value("address", "0");
                int size = body.value("size", 256);
                std::string luaCode = R"LUA(
                    local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                    if not addr then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                    local ok, hash = pcall(md5memory, addr, )LUA" + std::to_string(size) + R"LUA()
                    if not ok or not hash then
                        return '{"success":false,"error":"md5memory failed","error_code":"NOT_FOUND"}'
                    end
                    return '{"success":true,"address":"' .. string.format("0x%X", addr) .. '","size":)LUA" + std::to_string(size) + R"LUA(,"md5_hash":"' .. tostring(hash) .. '"}'
                )LUA";
                res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
            } catch (const std::exception& e) {
                res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
            }
        });
    };
    makeMd5("/api/checksum_memory");
    makeMd5("/api/md5_memory");

    svr.Post("/api/md5_file", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string filename = body.value("filename", "");
            std::string luaCode = R"LUA(
                local ok, hash = pcall(md5file, ")LUA" + hh::luaEscape(filename) + R"LUA(")
                if not ok or not hash then return '{"success":false,"error":"md5file failed"}' end
                return '{"success":true,"md5_hash":"' .. tostring(hash) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/copy_memory", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string src = body.value("source", "0");
            int size = body.value("size", 0);
            std::string dest = body.value("dest", "");
            int method = body.value("method", 0);

            std::string destArg = dest.empty() ? "nil" : ("getAddress(\"" + hh::luaEscape(dest) + "\")");

            std::string luaCode = R"LUA(
                local src = getAddress(")LUA" + hh::luaEscape(src) + R"LUA(")
                if not src then return '{"success":false,"error":"Invalid source"}' end
                local ok, result = pcall(copyMemory, src, )LUA" + std::to_string(size) + R"LUA(, )LUA" + destArg + R"LUA(, )LUA" + std::to_string(method) + R"LUA()
                if not ok or not result then return '{"success":false,"error":"copyMemory failed: ' .. tostring(result):gsub('"','\\"') .. '"}' end
                return '{"success":true,"dest_address":"' .. string.format("0x%X", result) .. '","size":)LUA" + std::to_string(size) + R"LUA(}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/compare_memory", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string a1 = body.value("addr1", "0");
            std::string a2 = body.value("addr2", "0");
            int size = body.value("size", 0);
            int method = body.value("method", 0);

            std::string luaCode = R"LUA(
                local a1 = getAddress(")LUA" + hh::luaEscape(a1) + R"LUA(")
                local a2 = getAddress(")LUA" + hh::luaEscape(a2) + R"LUA(")
                if not a1 or not a2 then return '{"success":false,"error":"Invalid address"}' end
                local ok, r1, r2 = pcall(compareMemory, a1, a2, )LUA" + std::to_string(size) + R"LUA(, )LUA" + std::to_string(method) + R"LUA()
                if not ok then return '{"success":false,"error":"compareMemory failed: ' .. tostring(r1):gsub('"','\\"') .. '"}' end
                if r1 == true then
                    return '{"success":true,"equal":true,"first_diff":-1}'
                else
                    return '{"success":true,"equal":false,"first_diff":' .. tostring(r2 or -1) .. '}'
                end
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/write_region_to_file", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int size = body.value("size", 0);
            std::string filename = body.value("filename", "");
            if (filename.find("..") != std::string::npos) {
                res.set_content(HttpServer::ErrorJson("Path traversal not allowed", "INVALID_PARAMS"), "application/json");
                return;
            }
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr then return '{"success":false,"error":"Invalid address"}' end
                local ok, bw = pcall(writeRegionToFile, ")LUA" + hh::luaEscape(filename) + R"LUA(", addr, )LUA" + std::to_string(size) + R"LUA()
                if not ok then return '{"success":false,"error":"writeRegionToFile failed: ' .. tostring(bw):gsub('"','\\"') .. '"}' end
                return '{"success":true,"bytes_written":' .. (bw or 0) .. ',"filename":")LUA" + hh::luaEscape(filename) + R"LUA("}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/read_region_from_file", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string filename = body.value("filename", "");
            std::string dest = body.value("destination", "0");
            if (filename.find("..") != std::string::npos) {
                res.set_content(HttpServer::ErrorJson("Path traversal not allowed", "INVALID_PARAMS"), "application/json");
                return;
            }
            std::string luaCode = R"LUA(
                local dest = getAddress(")LUA" + hh::luaEscape(dest) + R"LUA(")
                if not dest then return '{"success":false,"error":"Invalid destination"}' end
                local ok, br = pcall(readRegionFromFile, ")LUA" + hh::luaEscape(filename) + R"LUA(", dest)
                if not ok then return '{"success":false,"error":"readRegionFromFile failed: ' .. tostring(br):gsub('"','\\"') .. '"}' end
                return '{"success":true,"bytes_read":' .. (br or 0) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/get_memory_protection", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr or addr == 0 then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ok, prot = pcall(getMemoryProtection, addr)
                if not ok or not prot then return '{"success":false,"error":"getMemoryProtection failed","error_code":"INTERNAL_ERROR"}' end
                local r = prot.r == true
                local w = prot.w == true
                local x = prot.x == true
                return '{"success":true,"read":' .. tostring(r) .. ',"write":' .. tostring(w) .. ',"execute":' .. tostring(x) .. '}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/set_memory_protection", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int size = body.value("size", 0);
            bool r = body.value("read", true);
            bool w = body.value("write", true);
            bool x = body.value("execute", true);
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr or addr == 0 then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ok, err = pcall(setMemoryProtection, addr, )LUA" + std::to_string(size) + R"LUA(, { r=)LUA" + hh::boolLua(r) + R"LUA(, w=)LUA" + hh::boolLua(w) + R"LUA(, x=)LUA" + hh::boolLua(x) + R"LUA( })
                if not ok then return '{"success":false,"error":"setMemoryProtection failed: ' .. tostring(err):gsub('"','\\"') .. '","error_code":"INTERNAL_ERROR"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/full_access", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string addrStr = body.value("address", "0");
            int size = body.value("size", 0);
            std::string luaCode = R"LUA(
                local addr = getAddress(")LUA" + hh::luaEscape(addrStr) + R"LUA(")
                if not addr or addr == 0 then return '{"success":false,"error":"Invalid address","error_code":"INVALID_ADDRESS"}' end
                local ok, err = pcall(fullAccess, addr, )LUA" + std::to_string(size) + R"LUA()
                if not ok then return '{"success":false,"error":"fullAccess failed: ' .. tostring(err):gsub('"','\\"') .. '"}' end
                return '{"success":true}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/allocate_shared_memory", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string name = body.value("name", "");
            int size = body.value("size", 0);
            std::string luaCode = R"LUA(
                local ok, result = pcall(allocateSharedMemory, ")LUA" + hh::luaEscape(name) + R"LUA(", )LUA" + std::to_string(size) + R"LUA()
                if not ok or not result or result == 0 then return '{"success":false,"error":"Shared mem alloc failed","error_code":"OUT_OF_RESOURCES"}' end
                return '{"success":true,"address":"' .. string.format("0x%X", result) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/allocate_kernel_memory", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int size = body.value("size", 0);
            std::string luaCode = R"LUA(
                if not dbk_initialized or not dbk_initialized() then
                    return '{"success":false,"error":"DBK not loaded","error_code":"DBK_NOT_LOADED"}'
                end
                local ok, result = pcall(allocateKernelMemory, )LUA" + std::to_string(size) + R"LUA()
                if not ok or not result or result == 0 then return '{"success":false,"error":"Kernel alloc failed","error_code":"OUT_OF_RESOURCES"}' end
                return '{"success":true,"address":"' .. string.format("0x%X", result) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/create_section", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int size = body.value("size", 0);
            std::string luaCode = R"LUA(
                local ok, handle = pcall(createSection, )LUA" + std::to_string(size) + R"LUA()
                if not ok or not handle then return '{"success":false,"error":"createSection failed","error_code":"CE_API_UNAVAILABLE"}' end
                serverState.sections = serverState.sections or {}
                serverState.sections[string.format("0x%X", handle)] = handle
                return '{"success":true,"handle":"' .. string.format("0x%X", handle) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/map_view_of_section", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string handleStr = body.value("handle", "");
            std::string addrStr = body.value("address", "");
            std::string luaCode = R"LUA(
                local hClean = (")LUA" + hh::luaEscape(handleStr) + R"LUA("):gsub("^0[xX]", "")
                local handle = tonumber(hClean, 16)
                if not handle then return '{"success":false,"error":"Invalid handle","error_code":"INVALID_PARAMS"}' end
                local mapped
                )LUA" + (addrStr.empty()
                    ? std::string("local ok\n ok, mapped = pcall(mapViewOfSection, handle)\n")
                    : ("local prefAddr = getAddress(\"" + hh::luaEscape(addrStr) + "\")\nlocal ok\n ok, mapped = pcall(mapViewOfSection, handle, prefAddr)\n"))
                + R"LUA(
                if not ok or not mapped then return '{"success":false,"error":"mapViewOfSection failed"}' end
                return '{"success":true,"mapped_address":"' .. string.format("0x%X", mapped) .. '"}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });

    svr.Post("/api/enum_memory_regions_full", [lua](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            int offset = body.value("offset", 0);
            int limit = body.value("limit", 100);

            std::string luaCode = R"LUA(
                local regions = enumMemoryRegions()
                if not regions then return '{"success":false,"error":"No process attached","error_code":"NO_PROCESS"}' end
                local total = #regions
                local offset = )LUA" + std::to_string(offset) + R"LUA(
                local limit = )LUA" + std::to_string(limit) + R"LUA(
                local items = {}
                local function protStr(p)
                    if p == 0x10 then return "X"
                    elseif p == 0x20 then return "RX"
                    elseif p == 0x40 then return "RWX"
                    elseif p == 0x80 then return "WX"
                    elseif p == 0x02 then return "R"
                    elseif p == 0x04 then return "RW"
                    elseif p == 0x08 then return "W"
                    else return string.format("0x%X", p) end
                end
                for i = offset + 1, math.min(offset + limit, total) do
                    local r = regions[i]
                    local p = r.Protect or 0
                    local s = r.State or 0
                    items[#items+1] = '{"base":"' .. string.format("0x%X", r.BaseAddress or 0) ..
                        '","allocation_base":"' .. string.format("0x%X", r.AllocationBase or 0) ..
                        '","size":' .. (r.RegionSize or 0) ..
                        ',"state":' .. s ..
                        ',"protect":' .. p ..
                        ',"protect_string":"' .. protStr(p) ..
                        '","type":' .. (r.Type or 0) ..
                        ',"is_committed":' .. tostring(s == 0x1000) ..
                        ',"is_reserved":' .. tostring(s == 0x2000) ..
                        ',"is_free":' .. tostring(s == 0x10000) .. '}'
                end
                return '{"success":true,"total":' .. total .. ',"offset":' .. offset .. ',"limit":' .. limit .. ',"returned":' .. #items .. ',"regions":[' .. table.concat(items, ',') .. ']}'
            )LUA";
            res.set_content(lua->ExecuteOnMainThread(luaCode, 60000), "application/json");
        } catch (const std::exception& e) {
            res.set_content(HttpServer::ErrorJson(e.what(), "INVALID_PARAMS"), "application/json");
        }
    });
}

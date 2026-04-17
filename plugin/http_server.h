#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <thread>
#include <atomic>
#include "ce_api.h"
#include "lua_bridge.h"

namespace httplib { class Server; }

class HttpServer {
public:
    HttpServer(CEApi* api, LuaBridge* lua, int port = 6789);
    ~HttpServer();

    void Start();
    void Stop();
    int GetPort() const { return port_; }

    static std::string SuccessJson(const std::string& extraFields = "");
    static std::string ErrorJson(const std::string& error, const std::string& errorCode);

    static uint64_t ParseAddress(const std::string& addr);
    static std::string FormatHex(uint64_t addr);
    static std::string BytesToHexString(const uint8_t* data, size_t len);
    static std::vector<uint8_t> HexStringToBytes(const std::string& hex);

private:
    void RegisterHandlers();
    void ServerThread();

    httplib::Server* server_ = nullptr;
    CEApi* api_;
    LuaBridge* lua_;
    std::thread serverThread_;
    int port_;
    std::atomic<bool> running_{false};
};

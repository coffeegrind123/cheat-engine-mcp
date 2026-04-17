#define CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND 30
#include "vendor/httplib.h"
#include "vendor/nlohmann/json.hpp"
#include "http_server.h"
#include "handlers/handlers.h"
#include <cstdio>
#include <sstream>
#include <iomanip>

using json = nlohmann::json;

HttpServer::HttpServer(CEApi* api, LuaBridge* lua, int port)
    : api_(api), lua_(lua), port_(port) {
    server_ = new httplib::Server();
}

HttpServer::~HttpServer() {
    Stop();
    delete server_;
}

void HttpServer::Start() {
    if (running_) return;
    running_ = true;
    RegisterHandlers();
    serverThread_ = std::thread(&HttpServer::ServerThread, this);
}

void HttpServer::Stop() {
    if (!running_) return;
    running_ = false;
    if (server_) server_->stop();
    if (serverThread_.joinable()) serverThread_.join();
}

void HttpServer::RegisterHandlers() {
    server_->Get("/api/ping", [](const httplib::Request&, httplib::Response& res) {
        json r;
        r["success"] = true;
        r["version"] = "1.0.0";
        r["message"] = "CE HTTP Bridge Active";
        res.set_content(r.dump(), "application/json");
    });

    RegisterProcessHandlers(*server_, api_, lua_);
    RegisterMemoryHandlers(*server_, api_, lua_);
    RegisterScanHandlers(*server_, api_, lua_);
    RegisterAnalysisHandlers(*server_, api_, lua_);
    RegisterDebugHandlers(*server_, api_, lua_);
    RegisterSymbolHandlers(*server_, api_, lua_);
    RegisterInjectionHandlers(*server_, api_, lua_);
    RegisterTableHandlers(*server_, api_, lua_);
    RegisterStructureHandlers(*server_, api_, lua_);
    RegisterWindowHandlers(*server_, api_, lua_);
    RegisterInputHandlers(*server_, api_, lua_);
    RegisterFileHandlers(*server_, api_, lua_);
    RegisterKernelHandlers(*server_, api_, lua_);
    RegisterThreadingHandlers(*server_, api_, lua_);
    RegisterMiscHandlers(*server_, api_, lua_);
}

void HttpServer::ServerThread() {
    printf("[CE HTTP Bridge] Starting HTTP server on 0.0.0.0:%d\n", port_);
    if (!server_->listen("0.0.0.0", port_)) {
        printf("[CE HTTP Bridge] ERROR: Failed to start HTTP server on port %d\n", port_);
    }
    printf("[CE HTTP Bridge] HTTP server stopped\n");
}

std::string HttpServer::SuccessJson(const std::string& extraFields) {
    if (extraFields.empty())
        return R"({"success":true})";
    return R"({"success":true,)" + extraFields + "}";
}

std::string HttpServer::ErrorJson(const std::string& error, const std::string& errorCode) {
    json r;
    r["success"] = false;
    r["error"] = error;
    r["error_code"] = errorCode;
    return r.dump();
}

uint64_t HttpServer::ParseAddress(const std::string& addr) {
    if (addr.empty()) return 0;
    try {
        if (addr.substr(0, 2) == "0x" || addr.substr(0, 2) == "0X")
            return std::stoull(addr, nullptr, 16);
        return std::stoull(addr, nullptr, 16);
    } catch (...) {
        return 0;
    }
}

std::string HttpServer::FormatHex(uint64_t addr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << addr;
    return oss.str();
}

std::string HttpServer::BytesToHexString(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        if (i > 0) oss << " ";
        oss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)data[i];
    }
    return oss.str();
}

std::vector<uint8_t> HttpServer::HexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    std::istringstream iss(hex);
    std::string token;
    while (iss >> token) {
        bytes.push_back((uint8_t)std::stoul(token, nullptr, 16));
    }
    return bytes;
}

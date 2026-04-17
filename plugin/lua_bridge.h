#pragma once
#include <string>
#include <deque>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <windows.h>
#include "ce_api.h"

struct LuaCommand {
    uint64_t id;
    std::string code;
    std::string result;
    bool success;
    bool completed;
    HANDLE completionEvent;
};

class LuaBridge {
public:
    LuaBridge();
    ~LuaBridge();

    bool Initialize(CEApi* api);
    void Shutdown();

    std::string ExecuteOnMainThread(const std::string& luaCode, uint32_t timeoutMs = 300000);

    LuaCommand* Dequeue();
    void Complete(uint64_t id, bool success, const std::string& result);

private:
    CEApi* api_ = nullptr;
    std::mutex queueMutex_;
    std::deque<LuaCommand*> pendingQueue_;
    std::mutex activeMutex_;
    std::deque<LuaCommand*> activeCommands_;
    std::atomic<uint64_t> nextId_{1};
    bool initialized_ = false;

    static int LuaDequeue(lua_State* L);
    static int LuaComplete(lua_State* L);
};

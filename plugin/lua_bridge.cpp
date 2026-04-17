#include "lua_bridge.h"
#include <cstdio>

static LuaBridge* g_luaBridgeInstance = nullptr;

LuaBridge::LuaBridge() {}

LuaBridge::~LuaBridge() {
    Shutdown();
}

bool LuaBridge::Initialize(CEApi* api) {
    api_ = api;
    g_luaBridgeInstance = this;

    lua_State* L = api_->GetLuaState();
    if (!L) {
        printf("[CE HTTP Bridge] ERROR: GetLuaState() returned NULL\n");
        return false;
    }

    lua_register(L, "ce_http_dequeue", LuaDequeue);
    lua_register(L, "ce_http_complete", LuaComplete);

    const char* timerScript = R"LUA(
        -- Shared state for persistent scan sessions, DBVM watches, breakpoint hits,
        -- structure registry, section handles, etc. Initialized once at load time.
        if not serverState then
            serverState = {
                scan_memscan = nil,
                scan_foundlist = nil,
                persistent_scans = {},
                active_watches = {},
                breakpoints = {},
                breakpoint_hits = {},
                structures = {},
                structure_next_id = 1,
                sections = {},
                mappedMDL = {},
            }
        end

        local __ce_http_timer = createTimer(getMainForm())
        __ce_http_timer.Interval = 10
        __ce_http_timer.OnTimer = function(t)
            local cmd_code, cmd_id = ce_http_dequeue()
            if cmd_code then
                local fn, err = load(cmd_code)
                if fn then
                    local ok, result = pcall(fn)
                    if ok then
                        ce_http_complete(cmd_id, true, tostring(result or ""))
                    else
                        ce_http_complete(cmd_id, false, tostring(result or "pcall error"))
                    end
                else
                    ce_http_complete(cmd_id, false, "Lua compile error: " .. tostring(err))
                end
            end
        end
        __ce_http_timer.Enabled = true
    )LUA";

    int err = luaL_dostring(L, timerScript);
    if (err != 0) {
        const char* errMsg = lua_tostring(L, -1);
        printf("[CE HTTP Bridge] Lua timer init error: %s\n", errMsg ? errMsg : "unknown");
        lua_pop(L, 1);
        return false;
    }

    initialized_ = true;
    printf("[CE HTTP Bridge] Lua bridge initialized (timer polling at 10ms)\n");
    return true;
}

void LuaBridge::Shutdown() {
    if (!initialized_) return;

    lua_State* L = api_ ? api_->GetLuaState() : nullptr;
    if (L) {
        luaL_dostring(L, R"LUA(
            if __ce_http_timer then
                __ce_http_timer.Enabled = false
                __ce_http_timer.destroy()
                __ce_http_timer = nil
            end
        )LUA");
    }

    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        for (auto* cmd : pendingQueue_) {
            cmd->success = false;
            cmd->result = "Bridge shutting down";
            cmd->completed = true;
            SetEvent(cmd->completionEvent);
        }
        pendingQueue_.clear();
    }

    {
        std::lock_guard<std::mutex> lock(activeMutex_);
        for (auto* cmd : activeCommands_) {
            cmd->success = false;
            cmd->result = "Bridge shutting down";
            cmd->completed = true;
            SetEvent(cmd->completionEvent);
        }
        activeCommands_.clear();
    }

    g_luaBridgeInstance = nullptr;
    initialized_ = false;
    printf("[CE HTTP Bridge] Lua bridge shut down\n");
}

std::string LuaBridge::ExecuteOnMainThread(const std::string& luaCode, uint32_t timeoutMs) {
    if (!initialized_) {
        return R"({"success":false,"error":"Lua bridge not initialized","error_code":"INTERNAL_ERROR"})";
    }

    auto* cmd = new LuaCommand();
    cmd->id = nextId_.fetch_add(1);
    cmd->code = luaCode;
    cmd->success = false;
    cmd->completed = false;
    cmd->completionEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        pendingQueue_.push_back(cmd);
    }

    DWORD waitResult = WaitForSingleObject(cmd->completionEvent, timeoutMs);
    CloseHandle(cmd->completionEvent);

    std::string result;
    if (waitResult == WAIT_TIMEOUT) {
        result = R"({"success":false,"error":"Lua execution timeout","error_code":"INTERNAL_ERROR"})";
    } else if (!cmd->success) {
        result = R"({"success":false,"error":")" + cmd->result + R"(","error_code":"INTERNAL_ERROR"})";
    } else {
        result = cmd->result;
    }

    delete cmd;
    return result;
}

LuaCommand* LuaBridge::Dequeue() {
    std::lock_guard<std::mutex> lock(queueMutex_);
    if (pendingQueue_.empty()) return nullptr;

    auto* cmd = pendingQueue_.front();
    pendingQueue_.pop_front();

    {
        std::lock_guard<std::mutex> alock(activeMutex_);
        activeCommands_.push_back(cmd);
    }

    return cmd;
}

void LuaBridge::Complete(uint64_t id, bool success, const std::string& result) {
    std::lock_guard<std::mutex> lock(activeMutex_);
    for (auto it = activeCommands_.begin(); it != activeCommands_.end(); ++it) {
        if ((*it)->id == id) {
            (*it)->success = success;
            (*it)->result = result;
            (*it)->completed = true;
            SetEvent((*it)->completionEvent);
            activeCommands_.erase(it);
            return;
        }
    }
}

int LuaBridge::LuaDequeue(lua_State* L) {
    if (!g_luaBridgeInstance) {
        lua_pushnil(L);
        return 1;
    }

    auto* cmd = g_luaBridgeInstance->Dequeue();
    if (!cmd) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushstring(L, cmd->code.c_str());
    lua_pushinteger(L, (lua_Integer)cmd->id);
    return 2;
}

int LuaBridge::LuaComplete(lua_State* L) {
    if (!g_luaBridgeInstance) return 0;

    uint64_t id = (uint64_t)luaL_checkinteger(L, 1);
    bool success = lua_toboolean(L, 2);
    const char* result = luaL_checkstring(L, 3);

    g_luaBridgeInstance->Complete(id, success, result ? result : "");
    return 0;
}

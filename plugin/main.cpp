#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include "CheatEngine/cepluginsdk.h"
#include "ce_api.h"
#include "lua_bridge.h"
#include "http_server.h"

static CEApi g_ceApi;
static LuaBridge g_luaBridge;
static HttpServer* g_httpServer = nullptr;

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}

extern "C" {

BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int sizeofpluginversion) {
    pv->version = CESDK_VERSION;
    pv->pluginname = (char*)"CE HTTP Bridge";
    return TRUE;
}

static void __stdcall MenuCallback(void) {
    char msg[256];
    snprintf(msg, sizeof(msg), "CE HTTP Bridge v1.0.0\nHTTP server on port %d\nStatus: %s",
             g_httpServer ? g_httpServer->GetPort() : 0,
             g_httpServer ? "Running" : "Stopped");
    g_ceApi.ShowMessage(msg);
}

BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef, int pluginid) {
    AllocConsole();
    freopen("conin$", "r", stdin);
    freopen("conout$", "w", stdout);
    freopen("conout$", "w", stderr);

    printf("[CE HTTP Bridge] Initializing...\n");

    g_ceApi.Initialize(ef, pluginid);

    if (!g_luaBridge.Initialize(&g_ceApi)) {
        printf("[CE HTTP Bridge] WARNING: Lua bridge init failed, Lua-based commands will be unavailable\n");
    }

    int port = 6789;
    const char* portEnv = getenv("CE_HTTP_PORT");
    if (portEnv) port = atoi(portEnv);

    g_httpServer = new HttpServer(&g_ceApi, &g_luaBridge, port);
    g_httpServer->Start();

    printf("[CE HTTP Bridge] HTTP server listening on 0.0.0.0:%d\n", port);

    MAINMENUPLUGIN_INIT menuInit;
    menuInit.name = (char*)"CE HTTP Bridge Status";
    menuInit.callbackroutine = MenuCallback;
    ef->RegisterFunction(pluginid, ptMainMenu, &menuInit);

    printf("[CE HTTP Bridge] Plugin initialized successfully\n");
    return TRUE;
}

BOOL __stdcall CEPlugin_DisablePlugin(void) {
    printf("[CE HTTP Bridge] Shutting down...\n");

    if (g_httpServer) {
        g_httpServer->Stop();
        delete g_httpServer;
        g_httpServer = nullptr;
    }

    g_luaBridge.Shutdown();

    printf("[CE HTTP Bridge] Plugin disabled\n");
    return TRUE;
}

} // extern "C"

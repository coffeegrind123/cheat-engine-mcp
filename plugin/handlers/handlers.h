#pragma once

namespace httplib { class Server; }
class CEApi;
class LuaBridge;

void RegisterProcessHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterMemoryHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterScanHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterAnalysisHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterDebugHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterSymbolHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterInjectionHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterTableHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterStructureHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterWindowHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterInputHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterFileHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterKernelHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterThreadingHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);
void RegisterMiscHandlers(httplib::Server& svr, CEApi* api, LuaBridge* lua);

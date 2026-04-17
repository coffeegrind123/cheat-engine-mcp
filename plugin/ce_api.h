#pragma once
#include <cstdint>
#include <windows.h>
#include "CheatEngine/cepluginsdk.h"

class CEApi {
public:
    void Initialize(PExportedFunctions ef, int pluginId);

    bool ReadProcessMemory(uint64_t address, void* buffer, size_t size, size_t* bytesRead);
    bool WriteProcessMemory(uint64_t address, const void* buffer, size_t size);

    bool Disassemble(uint64_t address, char* output, int maxSize);
    bool Assembler(uint64_t address, const char* instruction, uint8_t* output, int maxLen, int* returnedSize);
    bool AutoAssemble(const char* script);

    bool NameToAddress(const char* name, uint64_t* address);
    bool AddressToName(uint64_t address, char* name, int maxSize);
    uint64_t GetAddressFromPointer(uint64_t base, int offsetCount, int* offsets);
    uint32_t PreviousOpcode(uint64_t address);
    uint32_t NextOpcode(uint64_t address);

    bool SetBreakpoint(uint64_t address, int size, int trigger);
    bool RemoveBreakpoint(uint64_t address);
    bool ContinueFromBreakpoint(int option);

    uint32_t GetProcessIDFromName(const char* name);
    uint32_t OpenProcess(uint32_t pid);
    void Pause();
    void Unpause();

    bool InjectDLL(const char* dllName, const char* funcToCall);
    int FreezeMem(uint64_t address, int size);
    bool UnfreezeMem(int freezeId);

    void ShowMessage(const char* message);

    PULONG GetOpenedProcessID();
    PHANDLE GetOpenedProcessHandle();
    lua_State* GetLuaState();
    HANDLE GetMainWindowHandle();

    PExportedFunctions GetEF() { return ef_; }

private:
    PExportedFunctions ef_ = nullptr;
    int pluginId_ = -1;
};

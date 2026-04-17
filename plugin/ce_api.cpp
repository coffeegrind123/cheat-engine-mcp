#include "ce_api.h"
#include <cstdio>

void CEApi::Initialize(PExportedFunctions ef, int pluginId) {
    ef_ = ef;
    pluginId_ = pluginId;
}

bool CEApi::ReadProcessMemory(uint64_t address, void* buffer, size_t size, size_t* bytesRead) {
    if (!ef_ || !ef_->ReadProcessMemory) return false;
    auto fn = *ef_->ReadProcessMemory;
    if (!fn) return false;
    return fn(*ef_->OpenedProcessHandle, (LPCVOID)address, (LPVOID)buffer, size, bytesRead);
}

bool CEApi::WriteProcessMemory(uint64_t address, const void* buffer, size_t size) {
    if (!ef_ || !ef_->WriteProcessMemory) return false;
    auto fn = *(BOOL(__stdcall**)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*))ef_->WriteProcessMemory;
    if (!fn) return false;
    return fn(*ef_->OpenedProcessHandle, (LPCVOID)address, (LPVOID)buffer, size, nullptr);
}

bool CEApi::Disassemble(uint64_t address, char* output, int maxSize) {
    if (!ef_ || !ef_->disassembleEx) return false;
    return ef_->disassembleEx((UINT_PTR)address, output, maxSize);
}

bool CEApi::Assembler(uint64_t address, const char* instruction, uint8_t* output, int maxLen, int* returnedSize) {
    if (!ef_ || !ef_->Assembler) return false;
    return ef_->Assembler((UINT_PTR)address, (char*)instruction, (BYTE*)output, maxLen, returnedSize);
}

bool CEApi::AutoAssemble(const char* script) {
    if (!ef_ || !ef_->AutoAssemble) return false;
    return ef_->AutoAssemble((char*)script);
}

bool CEApi::NameToAddress(const char* name, uint64_t* address) {
    if (!ef_ || !ef_->sym_nameToAddress) return false;
    UINT_PTR addr = 0;
    bool result = ef_->sym_nameToAddress((char*)name, &addr);
    *address = addr;
    return result;
}

bool CEApi::AddressToName(uint64_t address, char* name, int maxSize) {
    if (!ef_ || !ef_->sym_addressToName) return false;
    return ef_->sym_addressToName((UINT_PTR)address, name, maxSize);
}

uint64_t CEApi::GetAddressFromPointer(uint64_t base, int offsetCount, int* offsets) {
    if (!ef_ || !ef_->GetAddressFromPointer) return 0;
    return ef_->GetAddressFromPointer((UINT_PTR)base, offsetCount, offsets);
}

uint32_t CEApi::PreviousOpcode(uint64_t address) {
    if (!ef_ || !ef_->previousOpcode) return 0;
    return ef_->previousOpcode((UINT_PTR)address);
}

uint32_t CEApi::NextOpcode(uint64_t address) {
    if (!ef_ || !ef_->nextOpcode) return 0;
    return ef_->nextOpcode((UINT_PTR)address);
}

bool CEApi::SetBreakpoint(uint64_t address, int size, int trigger) {
    if (!ef_ || !ef_->debug_setBreakpoint) return false;
    return ef_->debug_setBreakpoint((UINT_PTR)address, size, trigger);
}

bool CEApi::RemoveBreakpoint(uint64_t address) {
    if (!ef_ || !ef_->debug_removeBreakpoint) return false;
    return ef_->debug_removeBreakpoint((UINT_PTR)address);
}

bool CEApi::ContinueFromBreakpoint(int option) {
    if (!ef_ || !ef_->debug_continueFromBreakpoint) return false;
    return ef_->debug_continueFromBreakpoint(option);
}

uint32_t CEApi::GetProcessIDFromName(const char* name) {
    if (!ef_ || !ef_->getProcessIDFromProcessName) return 0;
    return ef_->getProcessIDFromProcessName((char*)name);
}

uint32_t CEApi::OpenProcess(uint32_t pid) {
    if (!ef_ || !ef_->openProcessEx) return 0;
    return ef_->openProcessEx(pid);
}

void CEApi::Pause() {
    if (ef_ && ef_->pause) ef_->pause();
}

void CEApi::Unpause() {
    if (ef_ && ef_->unpause) ef_->unpause();
}

bool CEApi::InjectDLL(const char* dllName, const char* funcToCall) {
    if (!ef_ || !ef_->InjectDLL) return false;
    return ef_->InjectDLL((char*)dllName, (char*)funcToCall);
}

int CEApi::FreezeMem(uint64_t address, int size) {
    if (!ef_ || !ef_->FreezeMem) return -1;
    return ef_->FreezeMem((UINT_PTR)address, size);
}

bool CEApi::UnfreezeMem(int freezeId) {
    if (!ef_ || !ef_->UnfreezeMem) return false;
    return ef_->UnfreezeMem(freezeId);
}

void CEApi::ShowMessage(const char* message) {
    if (ef_ && ef_->ShowMessage) ef_->ShowMessage((char*)message);
}

PULONG CEApi::GetOpenedProcessID() {
    return ef_ ? ef_->OpenedProcessID : nullptr;
}

PHANDLE CEApi::GetOpenedProcessHandle() {
    return ef_ ? ef_->OpenedProcessHandle : nullptr;
}

lua_State* CEApi::GetLuaState() {
    if (!ef_ || !ef_->GetLuaState) return nullptr;
    return ef_->GetLuaState();
}

HANDLE CEApi::GetMainWindowHandle() {
    if (!ef_ || !ef_->GetMainWindowHandle) return (HANDLE)nullptr;
    return (HANDLE)ef_->GetMainWindowHandle();
}

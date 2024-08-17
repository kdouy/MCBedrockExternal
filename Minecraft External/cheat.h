#pragma once

std::pair<LPVOID, LPVOID> inject_fly_update(HANDLE hProcess, uintptr_t injectAddress, const unsigned char* assemblyCode, size_t codeSize) {
    std::pair<LPVOID, LPVOID> store_buffer = {};

    LPVOID hook_offset = (LPVOID)(injectAddress - 0x60000000);
    LPVOID hooked_buffer = VirtualAllocEx(hProcess, hook_offset, codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (hooked_buffer == nullptr) {
        std::cerr << "First buffer. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, hooked_buffer, 0, MEM_RELEASE);
        return store_buffer;
    }

    LPVOID answer_offset = (LPVOID)(injectAddress - 0x70000000);
    LPVOID answer_buffer = VirtualAllocEx(hProcess, answer_offset, codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (answer_buffer == nullptr) {
        std::cerr << "Second buffer. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, hooked_buffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, answer_buffer, 0, MEM_RELEASE);
        return store_buffer;
    }

    unsigned char* modifiedCode = new unsigned char[codeSize];
    memcpy(modifiedCode, assemblyCode, codeSize);

    uintptr_t answer_address = (uintptr_t)answer_buffer;
    memcpy(&modifiedCode[6], &answer_address, sizeof(answer_address));

    uintptr_t original_address = (injectAddress - 1 + 8) - ((uintptr_t)hooked_buffer + 26);
    memcpy(&modifiedCode[23], &original_address, sizeof(original_address));

    if (!WriteProcessMemory(hProcess, hooked_buffer, modifiedCode, codeSize, nullptr)) {
        std::cerr << "Failed to write memory in target process. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, hooked_buffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, answer_buffer, 0, MEM_RELEASE);
        delete[] modifiedCode;
        return store_buffer;
    }

    uintptr_t relativeAddress = (uintptr_t)hooked_buffer - (injectAddress + 5);
    unsigned char jmpInstruction[5] = { 0xE9 };
    memcpy(&jmpInstruction[1], &relativeAddress, sizeof(relativeAddress));

    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, (LPVOID)injectAddress, sizeof(jmpInstruction), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "Failed to change memory protection. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, hooked_buffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, answer_buffer, 0, MEM_RELEASE);
        return store_buffer;
    }

    if (!WriteProcessMemory(hProcess, (LPVOID)injectAddress, jmpInstruction, sizeof(jmpInstruction), nullptr)) {
        std::cerr << "Failed to write JMP instruction to target process. Error code: " << GetLastError() << std::endl;
        VirtualProtectEx(hProcess, (LPVOID)injectAddress, sizeof(jmpInstruction), oldProtect, &oldProtect);
        VirtualFreeEx(hProcess, hooked_buffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, answer_buffer, 0, MEM_RELEASE);
        return store_buffer;
    }

    VirtualProtectEx(hProcess, (LPVOID)injectAddress, sizeof(jmpInstruction), oldProtect, &oldProtect);

    BYTE new_bytes[] = { 0x0F, 0x1F, 0x00 };

    if (!ReplaceBytes(hProcess, injectAddress + 5, new_bytes, sizeof(new_bytes)))
    {
        std::cerr << "Failed to replace last bytes. Error code: " << GetLastError() << std::endl;
        VirtualProtectEx(hProcess, (LPVOID)injectAddress, sizeof(jmpInstruction), oldProtect, &oldProtect);
        VirtualFreeEx(hProcess, hooked_buffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, answer_buffer, 0, MEM_RELEASE);
        return store_buffer;
    };

    return std::make_pair(answer_buffer, hooked_buffer);
}

std::pair<LPVOID, LPVOID> inject_speed_update(HANDLE hProcess, uintptr_t injectAddress, const unsigned char* assemblyCode, size_t codeSize) {
    std::pair<LPVOID, LPVOID> store_buffer = {};

    LPVOID hook_offset = (LPVOID)(injectAddress - 0x62000000);
    LPVOID hooked_buffer = VirtualAllocEx(hProcess, hook_offset, codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (hooked_buffer == nullptr) {
        std::cerr << "First buffer. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, hooked_buffer, 0, MEM_RELEASE);
        return store_buffer;
    }

    LPVOID answer_offset = (LPVOID)(injectAddress - 0x72000000);
    LPVOID answer_buffer = VirtualAllocEx(hProcess, answer_offset, codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (answer_buffer == nullptr) {
        std::cerr << "Second buffer. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, hooked_buffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, answer_buffer, 0, MEM_RELEASE);
        return store_buffer;
    }

    unsigned char* modifiedCode = new unsigned char[codeSize];
    memcpy(modifiedCode, assemblyCode, codeSize);

    uintptr_t answer_address = (uintptr_t)answer_buffer;
    memcpy(&modifiedCode[9], &answer_address, sizeof(answer_address));

    uintptr_t original_address = (injectAddress + 5) - ((uintptr_t)hooked_buffer + 31);
    memcpy(&modifiedCode[27], &original_address, sizeof(original_address));

    if (!WriteProcessMemory(hProcess, hooked_buffer, modifiedCode, codeSize, nullptr)) {
        std::cerr << "Failed to write memory in target process. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, hooked_buffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, answer_buffer, 0, MEM_RELEASE);
        delete[] modifiedCode;
        return store_buffer;
    }

    uintptr_t relativeAddress = (uintptr_t)hooked_buffer - (injectAddress + 5);
    unsigned char jmpInstruction[5] = { 0xE9 };
    memcpy(&jmpInstruction[1], &relativeAddress, sizeof(relativeAddress));

    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, (LPVOID)injectAddress, sizeof(jmpInstruction), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "Failed to change memory protection. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, hooked_buffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, answer_buffer, 0, MEM_RELEASE);
        return store_buffer;
    }

    if (!WriteProcessMemory(hProcess, (LPVOID)injectAddress, jmpInstruction, sizeof(jmpInstruction), nullptr)) {
        std::cerr << "Failed to write JMP instruction to target process. Error code: " << GetLastError() << std::endl;
        VirtualProtectEx(hProcess, (LPVOID)injectAddress, sizeof(jmpInstruction), oldProtect, &oldProtect);
        VirtualFreeEx(hProcess, hooked_buffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, answer_buffer, 0, MEM_RELEASE);
        return store_buffer;
    }

    VirtualProtectEx(hProcess, (LPVOID)injectAddress, sizeof(jmpInstruction), oldProtect, &oldProtect);

    BYTE new_bytes[] = { 0x0F, 0x1F, 0x40, 0x00 };

    if (!ReplaceBytes(hProcess, injectAddress + 5, new_bytes, sizeof(new_bytes)))
    {
        std::cerr << "Failed to replace last bytes. Error code: " << GetLastError() << std::endl;
        VirtualProtectEx(hProcess, (LPVOID)injectAddress, sizeof(jmpInstruction), oldProtect, &oldProtect);
        VirtualFreeEx(hProcess, hooked_buffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, answer_buffer, 0, MEM_RELEASE);
        return store_buffer;
    };

    return std::make_pair(answer_buffer, hooked_buffer);
}

bool set_value(HANDLE proc_handle, uintptr_t offset, DWORD new_value)
{
    BOOL result = WriteProcessMemory(proc_handle, (LPVOID)(offset), &new_value, sizeof(new_value), 0);

    if (result)
        return true;

    return false;
}

bool set_value_float(HANDLE proc_handle, uintptr_t offset, float new_value)
{
    BOOL result = WriteProcessMemory(proc_handle, (LPVOID)(offset), &new_value, sizeof(new_value), 0);

    if (result)
        return true;

    return false;
}

uintptr_t get_ptr_addr(HANDLE phandle, uintptr_t address, std::vector<DWORD> offsets)
{
    uintptr_t offset_null = NULL;
    ReadProcessMemory(phandle, (LPVOID*)(address), &offset_null, sizeof(offset_null), 0);
    uintptr_t pointeraddress = offset_null;

    for (int i = 0; i < offsets.size() - 1; i++)
    {
        ReadProcessMemory(phandle, (LPVOID*)(pointeraddress + offsets.at(i)), &pointeraddress, sizeof(pointeraddress), 0);
    }

    return pointeraddress += offsets.at(offsets.size() - 1);
}
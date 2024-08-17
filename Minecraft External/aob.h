#pragma once

uintptr_t startAddress = 0x00000000000;
uintptr_t endAddress = 0x50000000000;

std::string wchar_to_string(const wchar_t* wideString) {
    if (wideString == nullptr)
        return "";

    int wideStringLength = static_cast<int>(wcslen(wideString));
    int requiredSize = WideCharToMultiByte(CP_UTF8, 0, wideString, wideStringLength, NULL, 0, NULL, NULL);
    if (requiredSize == 0) {
        return "";
    }

    std::string result(requiredSize, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wideString, wideStringLength, &result[0], requiredSize, NULL, NULL);
    return result;
}

std::vector<std::string> get_modules(const DWORD pid) {
    std::vector<std::string> modules;

    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap_shot == INVALID_HANDLE_VALUE)
        return modules;

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(decltype(entry));

    if (Module32FirstW(snap_shot, &entry) == TRUE) {
        do {
            modules.emplace_back(wchar_to_string(entry.szModule));
        } while (Module32NextW(snap_shot, &entry));
    }

    CloseHandle(snap_shot);

    return modules;
}

uintptr_t get_module(const DWORD pid, std::string module_name) {
    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap_shot == INVALID_HANDLE_VALUE)
        return 0;

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(decltype(entry));

    if (Module32FirstW(snap_shot, &entry) == TRUE) {
        do {
            if (strcmp("Minecraft.Windows.exe", wchar_to_string(entry.szModule).c_str()) == 0) {
                return (uintptr_t)entry.modBaseAddr;
            }
        } while (Module32NextW(snap_shot, &entry));
    }

    CloseHandle(snap_shot);

    return 0;
}

DWORD get_minecraft_process() {
    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snap_shot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(decltype(entry));

    if (Process32FirstW(snap_shot, &entry) == TRUE) {
        while (Process32NextW(snap_shot, &entry) == TRUE) {
            if (strcmp("Minecraft.Windows.exe", wchar_to_string(entry.szExeFile).c_str()) == 0) {
                return (DWORD)entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snap_shot);

    return 0;
}

bool ReadMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
    SIZE_T bytesRead;
    return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &bytesRead);
}

bool DataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask) {
        if (*szMask == 'x' && *pData != *bMask) {
            return false;
        }
    }
    return (*szMask) == 0;
}

uintptr_t AOBScan(HANDLE hProcess, uintptr_t start, uintptr_t end, const BYTE* bMask, const char* szMask) {
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t current = start;

    while (current < end && VirtualQueryEx(hProcess, (LPCVOID)current, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            std::vector<BYTE> buffer(mbi.RegionSize);
            if (ReadMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize)) {
                for (size_t i = 0; i < buffer.size(); ++i) {
                    if (DataCompare(buffer.data() + i, bMask, szMask)) {
                        return current + i;
                    }
                }
            }
        }
        current += mbi.RegionSize;
    }
    return 0;
}

uintptr_t game_scan(HANDLE hProcess, const BYTE* bMask, const char* szMask) {
    return AOBScan(hProcess, startAddress, endAddress, bMask, szMask);
}

bool ChangeProtection(HANDLE ProcessHandle, ULONG Address, size_t size, DWORD NewProtect, DWORD& OldProtect)
{
    return VirtualProtectEx(ProcessHandle, (LPVOID)Address, size, NewProtect, &OldProtect);;
}

bool WriteBytes(HANDLE ProcessHandle, ULONG WriteAddress, BYTE* RepByte, bool ForceWrite = false) {

    DWORD OldProtect;
    int RepByteSize = _msize(RepByte);
    if (RepByteSize <= 0) return false;
    if (ForceWrite)
    {
        ChangeProtection(ProcessHandle, WriteAddress, RepByteSize, PAGE_EXECUTE_READWRITE, OldProtect);
    }
    bool status = WriteProcessMemory(ProcessHandle, (LPVOID)WriteAddress, RepByte, RepByteSize, 0);
    if (ForceWrite && OldProtect != 0)
    {
        ChangeProtection(ProcessHandle, WriteAddress, RepByteSize, PAGE_EXECUTE_READ, OldProtect);
    }
    delete[] RepByte;
    return status;
}

bool ReplaceBytes(HANDLE hProcess, uintptr_t address, const BYTE* newValues, size_t size) {
    SIZE_T bytesWritten;
    return WriteProcessMemory(hProcess, (LPVOID)address, newValues, size, &bytesWritten) && bytesWritten == size;
}

bool NopBytes(HANDLE hProcess, uintptr_t address, size_t size) {
    BYTE nopInstruction = 0x90;
    std::vector<BYTE> nopBuffer(size, nopInstruction);

    SIZE_T bytesWritten;
    return WriteProcessMemory(hProcess, (LPVOID)address, nopBuffer.data(), nopBuffer.size(), &bytesWritten) && bytesWritten == nopBuffer.size();
}
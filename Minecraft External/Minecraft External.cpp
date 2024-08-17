#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <sstream>
#include <string>
#include <iomanip>
#include <random>
#include <fstream>
#include <psapi.h>

#include "aob.h"
#include "cheat.h"
#include "offsets.h"

int main()
{
    DWORD game_pid = get_minecraft_process();

    if (!game_pid)
        return 0;

    std::cout << game_pid << std::endl;

    HANDLE game_handle = OpenProcess(PROCESS_ALL_ACCESS, false, game_pid);

    if (!game_handle)
        return 0;

    std::cout << game_handle << std::endl;

    uintptr_t minecraft_module = get_module(game_pid, "Minecraft.Windows.exe");

    if (!minecraft_module)
        return 0;

    std::pair<PVOID, PVOID> fly_buffers = inject_fly_update(game_handle, minecraft_module + kesh::r_fly_offset , kesh::fly_injection_bytecode, sizeof(kesh::fly_injection_bytecode));
    std::pair<PVOID, PVOID> speed_buffers = inject_speed_update(game_handle, minecraft_module + kesh::r_speed_offset, kesh::speed_injection_bytecode, sizeof(kesh::speed_injection_bytecode));

    if (!fly_buffers.first)
        return 0;

    if (!speed_buffers.first)
        return 0;

    std::cout << std::endl;
    std::cout << "Minecraft Module: 0x" << std::hex << minecraft_module << std::endl;
    std::cout << std::endl;
    std::cout << "R-Fly Offset: 0x" << std::hex << minecraft_module + kesh::r_fly_offset << std::endl;
    std::cout << "Fly Hooked Offset: " << std::hex << fly_buffers.first << std::endl;
    std::cout << std::endl;
    std::cout << "R-Speed Offset: 0x" << std::hex << minecraft_module + kesh::r_speed_offset << std::endl;
    std::cout << "Speed Hooked Offset: " << std::hex << speed_buffers.first << std::endl;

    while (true)
    {
        uintptr_t fly_addy = get_ptr_addr(game_handle, (uintptr_t)fly_buffers.first, { 0x0 });
        uintptr_t speed_addy = get_ptr_addr(game_handle, (uintptr_t)speed_buffers.first, { 0x0 });

        if (speed_addy)
        {
            set_value_float(game_handle, (uintptr_t)speed_addy, 0.6f);
            // set_value(game_handle, (uintptr_t)fly_addy, 0x1);
        }
        Sleep(100);
    }

    // fly_loop
    /*
    while (true)
    {
        // uintptr_t fly_addy = get_ptr_addr(game_handle, (uintptr_t)fly_buffers.first, { 0x0 });
        // uintptr_t speed_addy = get_ptr_addr(game_handle, (uintptr_t)speed_buffers.first, { 0x0 });

        if (true)
        {
            float value = 0.3;
            // set_value(game_handle, (uintptr_t)speed_addy, value);
            // set_value(game_handle, (uintptr_t)fly_addy, 0x1);
        }
        Sleep(100);
    }
    */
}
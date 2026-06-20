// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <thread>

#define REBASE(x) x + (uintptr_t)GetModuleHandle(nullptr)

void start()
{
    const uintptr_t printoffs = REBASE(0x1EDBA40);

    typedef enum { print, info, warn, error } printtype;
    using rprint = void(__fastcall*)(printtype type, const char* fmt, ...);
    auto rblxprint = (rprint)printoffs;

    int timer = 1;

    while (true)
    {
        rblxprint(print, "injected for %d seconds", timer);
        timer++;
        Sleep(1000);
    }
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        MessageBoxA(NULL, "LAMSDOQDASFASFGD", "LAMSDOQWEFDA", NULL);
        //std::thread(start).detach();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


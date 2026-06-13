#include <iostream>
#include <vector>
#include <filesystem>
#include "Memory/Memory.hpp"
#include "Mapper/Mapper.hpp"
#include "Defs.hpp"


// NOTE: THIS CODE IS NOT MINE, THIS IS X4V'S HEARTBEAT INJECTOR, IT USED OFFSETS (taskschedulerptr, jobs) and i just made it offsetless + driverless

// creds to x4v for the heartbeat src i heavily modified it to be driverless and offsetless

// my discord: atreluted, x4v's discord: nuvq

// THX, PLEASE STAR THE GITHUB AND SHARE IT

uintptr_t Hook(uintptr_t a1, uintptr_t a2, uintptr_t a3) {
    auto s = (Shared*)0x100000000;
    if (s->Status == State::Load) {
        s->Status = State::Wait;
        char m[] = { 'm', 's', 'h', 't', 'm', 'l', '.', 'd', 'l', 'l', '\0' };
        s->LdrEx(m, NULL, DONT_RESOLVE_DLL_REFERENCES);
    }
    if (s->Status == State::Inject) {
        auto d = s->dllSt;
        auto n = (PIMAGE_NT_HEADERS)((BYTE*)d + ((PIMAGE_DOS_HEADER)d)->e_lfanew);
        auto& e = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (e.Size)
            s->AddTab((PRUNTIME_FUNCTION)((BYTE*)d + e.VirtualAddress), e.Size / sizeof(RUNTIME_FUNCTION), (DWORD64)d);

        auto i = (PIMAGE_IMPORT_DESCRIPTOR)(d + s->ImpVA);
        auto ie = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)i + s->ImpSz);
        while (i < ie && i->Name) {
            HMODULE l = s->Ldr((char*)(d + i->Name));
            if (!l) {
                ++i;
                continue;
            }
            uintptr_t* t = (uintptr_t*)(d + (i->OriginalFirstThunk ? i->OriginalFirstThunk : i->FirstThunk));
            FARPROC* f = (FARPROC*)(d + i->FirstThunk);
            for (; *t; ++t, ++f) {
                if (IMAGE_SNAP_BY_ORDINAL(*t))
                    *f = s->Proc(l, MAKEINTRESOURCEA(IMAGE_ORDINAL(*t)));
                else
                    *f = s->Proc(l, ((IMAGE_IMPORT_BY_NAME*)(d + *t))->Name);
            }
            ++i;
        }

        if (s->TlsVA && s->TlsSz) {
            auto t = (IMAGE_TLS_DIRECTORY64*)(d + s->TlsVA);
            ULONGLONG rv = t->AddressOfCallBacks;
            if (rv) {
                uintptr_t c = (uintptr_t)rv;
                if (c < d || c >= s->dllEd)
                    c = d + (uintptr_t)rv;
                PIMAGE_TLS_CALLBACK* cl = (PIMAGE_TLS_CALLBACK*)c;
                for (size_t i = 0;; ++i) {
                    if (!cl[i]) break;
                    cl[i]((PVOID)d, DLL_PROCESS_ATTACH, nullptr);
                }
            }
        }
        ((BOOL(__stdcall*)(HMODULE, DWORD, LPVOID))(s->dllEp))((HMODULE)d, DLL_PROCESS_ATTACH, nullptr);
        s->Status = State::Done;
    }
    return s->OrgHbk(a1, a2, a3);
}
uintptr_t FindHeartbeatJob(HANDLE process_handle) {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    uintptr_t start_address = (uintptr_t)sys_info.lpMinimumApplicationAddress;
    uintptr_t end_address = (uintptr_t)sys_info.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;

    while (start_address < end_address) {
        if (VirtualQueryEx(process_handle, (LPCVOID)start_address, &mbi, sizeof(mbi))) {
            if ((mbi.State == MEM_COMMIT) && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) && !(mbi.Protect & PAGE_GUARD)) {
                size_t region_size = mbi.RegionSize;
                std::vector<BYTE> buffer(region_size);

                if (g_Syscall.SyscallRead(process_handle, start_address, buffer.data(), region_size)) {
                    for (size_t i = 0; i < region_size - 0x80; i += 8) {
                        uintptr_t potential_ptr = *reinterpret_cast<uintptr_t*>(&buffer[i]);

                        if (potential_ptr >= 0x10000 && potential_ptr < 0x7FFFFFFFFFFF) {
                            char possible_name[32]{ 0 };
                            if (g_Syscall.SyscallRead(process_handle, potential_ptr + 0x18, possible_name, sizeof(possible_name))) {
                                if (strcmp(possible_name, "Heartbeat") == 0) {
                                    return potential_ptr; // Returns the address of the Heartbeat job object
                                }
                            }
                        }
                    }
                }
            }
            start_address += mbi.RegionSize;
        }
        else {
            start_address += 0x1000;
        }
    }
    return 0;
}
unsigned long g_pid = 0;
unsigned long g_old = 0;
void* g_process = nullptr;
int main() {
    g_DllPath = (std::filesystem::current_path() / "module.dll").string();
    if (!std::filesystem::exists(g_DllPath)) return 0;
    g_pid = GetPid("RobloxPlayerBeta.exe");
    if (!g_pid) return 0;

    if (!ensure_proc_handle())
    {
        printf("no valid process handle, exiting");
        return 1;
    }

    std::vector<MODULEENTRY32> mods;
    GetMods(g_pid, { "devenum.dll", "RobloxPlayerBeta.exe", "KERNELBASE.dll", "KERNEL32.dll", "ntdll.dll" }, mods);

    if (mods.size() < 5 || !mods[0].modBaseAddr || !mods[1].modBaseAddr) return 0;

    uintptr_t deBase = (uintptr_t)mods[0].modBaseAddr;
    uintptr_t rbBase = (uintptr_t)mods[1].modBaseAddr;
    uintptr_t kbBase = (uintptr_t)mods[2].modBaseAddr;
    uintptr_t k3Base = (uintptr_t)mods[3].modBaseAddr;
    uintptr_t ntBase = (uintptr_t)mods[4].modBaseAddr;

    printf("[+] Scanning memory for Heartbeat job...\n");
    uintptr_t hbkJ = FindHeartbeatJob(g_process);

    if (!hbkJ) {
        printf("[-] Could not find Heartbeat job address.\n");
        system("pause");
        return 0;
    }

    printf("[+] Heartbeat job address found: 0x%p\n", (void*)hbkJ);

    uintptr_t oVab = Read<uintptr_t>(hbkJ);

    printf("[+] Heartbeat VTable address: 0x%p\n", (void*)oVab);

    uintptr_t oHbk = Read<uintptr_t>(oVab + 8);

    uintptr_t nVab = Alloc(0x300, PAGE_READWRITE);

    if (!nVab) return 0;

    for (uintptr_t i = 0; i < 0x300; i += 8) {

        Write<uintptr_t>(nVab + i, Read<uintptr_t>(oVab + i));

    }

    g_Shared = Alloc(sizeof(Shared), PAGE_READWRITE);
    if (!g_Shared) return 0;
    Prot(deBase, 0x1000, PAGE_EXECUTE_READWRITE);
    std::vector<BYTE> z(0x1000, 0);
    Write(deBase, z.data(), z.size());

    std::vector<BYTE> sc = ExtSc((uintptr_t)Hook);
    RepSc(sc, 0x100000000ULL, g_Shared);
    Write(deBase, sc.data(), sc.size());

    Write<uintptr_t>(nVab + 8, deBase);
    Shared loc = {};
    loc.OrgHbk = (fHbk)oHbk;
    loc.LdrEx = (fLdrEx)GetProc(kbBase, "LoadLibraryExA");
    loc.Ldr = (fLdr)GetProc(k3Base, "LoadLibraryA");
    loc.Proc = (fProc)GetProc(k3Base, "GetProcAddress");
    loc.AddTab = (fTab)GetProc(ntBase, "RtlAddFunctionTable");
    loc.Status = State::Load;
    Write(g_Shared, &loc, sizeof(Shared));
    Write<uintptr_t>(hbkJ, nVab);

    MODULEENTRY32 msme = {};
    while (!msme.modBaseAddr) {
        msme = GetMod(g_pid, "mshtml.dll");
        Sleep(250);
    }
    uintptr_t msBase = (uintptr_t)msme.modBaseAddr;
    Prot(msBase, msme.modBaseSize, PAGE_EXECUTE_READWRITE);
    z = std::vector<BYTE>(msme.modBaseSize, 0);
    Write(msBase, z.data(), z.size());

    g_DllBase = msBase;
    g_DllSz = DllSz(g_DllPath);
    SH(dllSt, g_DllBase);
    SH(dllEd, g_DllBase + g_DllSz);
    mapr::Map(g_DllPath);
    mapr::Inj();
    Write<uintptr_t>(hbkJ, oVab);

    return 0;
}
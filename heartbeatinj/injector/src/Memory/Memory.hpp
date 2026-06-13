#pragma once
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

class SyscallEngine {
private:
    using SyscallFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

    SyscallFn _read = nullptr;
    SyscallFn _write = nullptr;

    SyscallFn BuildTrampoline(const char* system_call_name) {
        HMODULE ntdll_handle = GetModuleHandleA("ntdll.dll");
        if (!ntdll_handle) return nullptr;

        BYTE* function_address = reinterpret_cast<BYTE*>(GetProcAddress(ntdll_handle, system_call_name));
        if (!function_address) return nullptr;

        DWORD syscall_id = 0;
        for (int i = 0; i < 32; i++) {
            if (function_address[i] == 0xB8) {
                syscall_id = *reinterpret_cast<DWORD*>(function_address + i + 1);
                break;
            }
        }
        if (!syscall_id) return nullptr;

        BYTE assembly_stub[] = {
            0x4C, 0x8B, 0xD1,             // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, syscall_id
            0x0F, 0x05,                   // syscall
            0xC3                          // ret
        };
        *reinterpret_cast<DWORD*>(assembly_stub + 4) = syscall_id;

        LPVOID executable_memory = VirtualAlloc(nullptr, sizeof(assembly_stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!executable_memory) return nullptr;

        memcpy(executable_memory, assembly_stub, sizeof(assembly_stub));
        return reinterpret_cast<SyscallFn>(executable_memory);
    }

public:
    bool Initialize() {
        if (!_read) _read = BuildTrampoline("NtReadVirtualMemory");
        if (!_write) _write = BuildTrampoline("NtWriteVirtualMemory");
        return (_read && _write);
    }

    bool SyscallRead(HANDLE process_handle, uintptr_t target_address, void* destination_buffer, size_t total_bytes) {
        if (!_read) return false;
        SIZE_T bytes_read_count = 0;
        NTSTATUS status = _read(process_handle, reinterpret_cast<PVOID>(target_address), destination_buffer, total_bytes, &bytes_read_count);
        return (status == 0);
    }

    bool SyscallWrite(HANDLE process_handle, uintptr_t target_address, const void* source_buffer, size_t total_bytes) {
        if (!_write) return false;
        SIZE_T bytes_written_count = 0;
        NTSTATUS status = _write(process_handle, reinterpret_cast<PVOID>(target_address), const_cast<PVOID>(source_buffer), total_bytes, &bytes_written_count);
        return (status == 0);
    }
};

inline SyscallEngine g_Syscall;

extern HANDLE g_process;
extern DWORD g_pid;
extern DWORD g_old;

inline bool ensure_proc_handle() {
    if (!g_process && g_pid != 0) {
        g_process = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, g_pid);
    }
    if (g_process != NULL) {
        g_Syscall.Initialize();
    }
    return (g_process != NULL);
}

template<typename T>
T Read(uintptr_t target_address) {
    T output_value{};
    if (!ensure_proc_handle()) return output_value;

    g_Syscall.SyscallRead(g_process, target_address, &output_value, sizeof(T));
    return output_value;
}

bool Read(uintptr_t target_address, void* destination_buffer, size_t total_bytes) {
    if (!ensure_proc_handle()) return false;

    return g_Syscall.SyscallRead(g_process, target_address, destination_buffer, total_bytes);
}

template<typename T>
bool Write(uintptr_t target_address, const T& source_value) {
    if (!ensure_proc_handle()) return false;

    return g_Syscall.SyscallWrite(g_process, target_address, &source_value, sizeof(T));
}

bool Write(uintptr_t target_address, const void* source_buffer, size_t total_bytes) {
    if (!ensure_proc_handle()) return false;

    return g_Syscall.SyscallWrite(g_process, target_address, source_buffer, total_bytes);
}

bool Prot(uintptr_t target_address, SIZE_T region_size, DWORD new_protection_flags) {
    if (!ensure_proc_handle()) return false;

    DWORD previous_protection = 0;
    bool status = VirtualProtectEx(g_process, (LPVOID)target_address, region_size, new_protection_flags, &previous_protection);
    if (status) {
        g_old = previous_protection;
    }
    return status;
}

uintptr_t Alloc(SIZE_T allocation_size, DWORD protection_flags) {
    if (!ensure_proc_handle()) return 0;

    LPVOID allocation_base = VirtualAllocEx(g_process, nullptr, allocation_size, MEM_COMMIT | MEM_RESERVE, protection_flags);
    return (uintptr_t)allocation_base;
}

DWORD GetPid(const char* process_name) {
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot_handle == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 process_entry = { 0 };
    process_entry.dwSize = sizeof(process_entry);

    for (BOOL loop_status = Process32First(snapshot_handle, &process_entry); loop_status; loop_status = Process32Next(snapshot_handle, &process_entry)) {
        if (_stricmp(process_entry.szExeFile, process_name) == 0) {
            CloseHandle(snapshot_handle);
            return process_entry.th32ProcessID;
        }
    }
    CloseHandle(snapshot_handle);
    return 0;
}

MODULEENTRY32 GetMod(DWORD target_pid, const char* module_name) {
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid);
    if (snapshot_handle == INVALID_HANDLE_VALUE) return {};

    MODULEENTRY32 module_entry = { 0 };
    module_entry.dwSize = sizeof(module_entry);

    for (BOOL loop_status = Module32First(snapshot_handle, &module_entry); loop_status; loop_status = Module32Next(snapshot_handle, &module_entry)) {
        if (_stricmp(module_entry.szModule, module_name) == 0) {
            CloseHandle(snapshot_handle);
            return module_entry;
        }
    }
    CloseHandle(snapshot_handle);
    return {};
}

void GetMods(DWORD target_pid, std::vector<const char*> search_names, std::vector<MODULEENTRY32>& tracking_results) {
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid);
    if (snapshot_handle == INVALID_HANDLE_VALUE) return;

    tracking_results.resize(search_names.size(), {});
    MODULEENTRY32 module_entry = { 0 };
    module_entry.dwSize = sizeof(module_entry);

    for (BOOL loop_status = Module32First(snapshot_handle, &module_entry); loop_status; loop_status = Module32Next(snapshot_handle, &module_entry)) {
        for (size_t current_index = 0; current_index < search_names.size(); ++current_index) {
            if (_stricmp(module_entry.szModule, search_names[current_index]) == 0) {
                tracking_results[current_index] = module_entry;
                break;
            }
        }
    }
    CloseHandle(snapshot_handle);
}

uintptr_t GetProc(uintptr_t base_address, const char* export_name) {
    auto dos_header = Read<IMAGE_DOS_HEADER>(base_address);
    auto nt_headers = Read<IMAGE_NT_HEADERS>(base_address + dos_header.e_lfanew);

    auto export_directory_entry = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!export_directory_entry.VirtualAddress || !export_directory_entry.Size) return 0;

    auto export_dir = Read<IMAGE_EXPORT_DIRECTORY>(base_address + export_directory_entry.VirtualAddress);

    std::vector<DWORD> names_table(export_dir.NumberOfNames);
    std::vector<WORD> ordinals_table(export_dir.NumberOfNames);
    std::vector<DWORD> functions_table(export_dir.NumberOfFunctions);

    bool verify_read = Read(base_address + export_dir.AddressOfNames, names_table.data(), 4 * names_table.size()) &&
        Read(base_address + export_dir.AddressOfNameOrdinals, ordinals_table.data(), 2 * ordinals_table.size()) &&
        Read(base_address + export_dir.AddressOfFunctions, functions_table.data(), 4 * functions_table.size());

    if (!verify_read) return 0;

    for (size_t current_index = 0; current_index < names_table.size(); ++current_index) {
        char local_string_buffer[128]{ 0 };
        if (!Read(base_address + names_table[current_index], local_string_buffer, sizeof(local_string_buffer))) continue;

        if (strcmp(local_string_buffer, export_name) == 0) {
            WORD actual_ordinal = ordinals_table[current_index];
            if (actual_ordinal >= functions_table.size()) return 0;
            return base_address + functions_table[actual_ordinal];
        }
    }
    return 0;
}

uintptr_t GetHbk(uintptr_t job_manager_pointer) {
    std::vector<uintptr_t> pointers_array(0x80);
    if (!Read(job_manager_pointer, pointers_array.data(), pointers_array.size() * sizeof(uintptr_t))) return 0;

    for (uintptr_t current_block : pointers_array) {
        if (!current_block) continue;

        char block_name[32]{};
        if (Read(current_block + 0x18, block_name, sizeof(block_name))) {
            if (strcmp(block_name, "Heartbeat") == 0) {
                return current_block;
            }
        }
    }
    return 0;
}

std::vector<BYTE> ExtSc(uintptr_t starting_function) {
    MEMORY_BASIC_INFORMATION memory_info;
    VirtualQuery((void*)starting_function, &memory_info, sizeof(memory_info));

    size_t scan_limit = memory_info.RegionSize;
    std::vector<BYTE> final_shellcode;

    for (size_t memory_offset = 0; memory_offset < scan_limit; ++memory_offset) {
        BYTE current_byte = *(BYTE*)(starting_function + memory_offset);
        final_shellcode.push_back(current_byte);

        if (current_byte == 0xCC &&
            *(BYTE*)(starting_function + memory_offset + 1) == 0xCC &&
            *(BYTE*)(starting_function + memory_offset + 2) == 0xCC) {
            break;
        }
    }
    return final_shellcode;
}

void RepSc(std::vector<BYTE>& shellcode_vector, uint64_t signature_value, uint64_t replace_value) {
    for (size_t scan_index = 0; scan_index <= shellcode_vector.size() - 10; ++scan_index) {
        if ((shellcode_vector[scan_index] == 0x48 || shellcode_vector[scan_index] == 0x49) &&
            shellcode_vector[scan_index + 1] >= 0xB8 && shellcode_vector[scan_index + 1] <= 0xBF) {

            uint64_t working_qword = *(uint64_t*)(&shellcode_vector[scan_index + 2]);
            uint32_t working_dword = *(uint32_t*)(&shellcode_vector[scan_index + 2]);

            if (working_qword - working_dword == signature_value) {
                uintptr_t adjusted_ptr = (uintptr_t)(replace_value + working_dword);
                memcpy(&shellcode_vector[scan_index + 2], &adjusted_ptr, 8);
            }
        }

        uint64_t direct_qword = *(uint64_t*)(&shellcode_vector[scan_index + 1]);
        uint32_t direct_dword = *(uint32_t*)(&shellcode_vector[scan_index + 1]);

        if ((shellcode_vector[scan_index] == 0xA1 || shellcode_vector[scan_index] == 0xA2 || shellcode_vector[scan_index] == 0xA3) &&
            direct_qword - direct_dword == signature_value) {

            uintptr_t adjusted_ptr2 = (uintptr_t)(replace_value + direct_dword);
            memcpy(&shellcode_vector[scan_index + 1], &adjusted_ptr2, 8);
        }
    }
}
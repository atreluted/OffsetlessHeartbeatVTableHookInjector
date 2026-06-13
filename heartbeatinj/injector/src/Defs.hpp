#pragma once
#include <Windows.h>
using fHbk = uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t);
using fLdrEx = HMODULE(__stdcall*)(LPCSTR, HANDLE, DWORD);
using fLdr = HMODULE(__stdcall*)(LPCSTR);
using fProc = FARPROC(__stdcall*)(HMODULE, LPCSTR);
using fTab = BOOLEAN(__cdecl*)(PRUNTIME_FUNCTION, DWORD, DWORD64);

#define SH(f, v) Write<decltype(Shared::f)>(g_Shared + offsetof(Shared, f), v)

enum class State { Load, Wait, Inject, Done };

struct Shared {
    fHbk OrgHbk;
    fLdrEx LdrEx;
    fLdr Ldr;
    fProc Proc;
    fTab AddTab;
    uintptr_t dllSt, dllEd, dllEp, ExcVA, ExcSz, ImpVA, ImpSz, TlsVA, TlsSz;
    State Status;
};

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned long;
using u64 = unsigned long long;
using i32 = long;
using i64 = long long;
using uptr = uintptr_t;

#define NT_SUCCESS(s) ((i32)(s) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((i32)0xC0000004L)

struct ustr {
    u16 len;
    u16 max;
    wchar_t* buf;
};

struct obj_attr {
    u32 len;
    HANDLE root;
    ustr* name;
    u32 attribs;
    void* sd;
    void* sqos;
};

struct cid {
    HANDLE pid;
    HANDLE tid;
};

struct io_sb {
    union {
        i32 status;
        void* ptr;
    };
    uptr info;
};

struct pbi {
    i32 exit_status;
    void* peb_addr;
    uptr affinity;
    i32 priority;
    uptr pid;
    uptr ppid;
};

struct ldr_entry {
    LIST_ENTRY link;
    LIST_ENTRY mem_link;
    LIST_ENTRY init_link;
    void* base;
    void* entry;
    u32 img_size;
    ustr full_name;
    ustr base_name;
};

struct peb_ldr {
    u32 len;
    u8 init;
    void* ss;
    LIST_ENTRY mem_order;
    LIST_ENTRY mem_init;
    LIST_ENTRY init_order;
};

struct peb {
    u8 reserved1[2];
    u8 being_debugged;
    u8 reserved2[1];
    void* reserved3[2];
    peb_ldr* ldr;
};

struct sys_handle_entry {
    u16 pid;
    u16 creator_bt_idx;
    u8 obj_type_idx;
    u8 flags;
    u16 handle;
    void* obj;
    u32 access;
};

struct sys_handle_info {
    u32 count;
    sys_handle_entry handles[1];
};

struct sys_handle_entry_ex {
    void* obj;
    uptr pid;
    uptr handle;
    u32 access;
    u16 creator_bt_idx;
    u16 obj_type_idx;
    u32 flags;
    u32 reserved;
};

struct sys_handle_info_ex {
    uptr count;
    uptr reserved;
    sys_handle_entry_ex handles[1];
};

struct tp_task_callbacks {
    void* execute_callback;
    void* unposted;
};

struct tp_task {
    tp_task_callbacks* callbacks;
    u32 numa_node;
    u8 ideal_proc;
    u8 pad[3];
    LIST_ENTRY list_entry;
};

struct tp_direct {
    tp_task task;
    u64 lock;
    LIST_ENTRY io_completion_info_list;
    void* callback;
    u32 numa_node;
    u8 ideal_proc;
    u8 pad[3];
};

struct pub_info {
    u32 obj_type_idx;
    u32 reserved;
    HANDLE handle;
};

constexpr u32 SYS_HANDLE_INFO = 16;
constexpr u32 SYS_HANDLE_INFO_EX = 64;
constexpr u32 PROC_BASIC_INFO = 0;
constexpr u32 OBJ_TYPE_INFO = 2;
constexpr u32 WORKER_FACTORY_BASIC_INFO = 7;

struct obj_type_info {
    ustr type_name;
    u32 total_obj;
    u32 total_handles;
    u32 total_paged_pool;
    u32 total_non_paged;
    u32 total_name_pool;
    u32 total_handle_table;
    u32 peak_obj;
    u32 peak_handles;
    u32 peak_paged;
    u32 peak_non_paged;
    u32 peak_name;
    u32 peak_handle_table;
    u32 invalid_attribs;
    GENERIC_MAPPING generic_map;
    u32 valid_access;
    u8 security_required;
    u8 maintain_handle_count;
    u8 type_idx;
    u8 reserved_byte;
    u32 pool_type;
    u32 default_paged;
    u32 default_non_paged;
};

struct worker_factory_info {
    LARGE_INTEGER timeout;
    LARGE_INTEGER retry_timeout;
    LARGE_INTEGER idle_timeout;
    u8 paused;
    u8 timer_set;
    u8 queued_to_ex_worker;
    u8 may_create;
    u8 create_in_progress;
    u8 inserted_into_queue;
    u8 shutdown;
    u8 pad;
    u32 binding_count;
    u32 thread_minimum;
    u32 thread_maximum;
    u32 pending_worker_count;
    u32 waiting_worker_count;
    u32 total_worker_count;
    u32 release_count;
    i64 infinite_wait_goal;
    void* start_routine;
    void* start_parameter;
    HANDLE process_id;
    SIZE_T stack_reserve;
    SIZE_T stack_commit;
    i32 create_thread_status;
    HANDLE completion_port;
};
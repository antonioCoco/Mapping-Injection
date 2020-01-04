# Mapping-Injection
Mapping injection is a process injection technique that avoids the usage of common monitored syscall VirtualAllocEx and WriteProcessMemory. 


This can be achieved by using the Syscall [MapViewOfFile2()](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile2) and some preliminary steps in order to “prepare” the memory with the required shellcode.


Once the memory is allocated in the remote process a remote thread is spawned . For the PoC purpose a straight CreateRemoteThread() is used. Some stealthier variations could be used with [QueueUserApc()](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc) or through Thread Hijacking but this won’t be covered in this PoC.


With this technique you will have a different syscall pattern from the classic process injection that is:<br>
**VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread**.<br>
In this technique you will have the following syscall pattern:<br>
**CreateFileMapping -> MapViewOfFile -> memcpy -> MapViewOfFile2 -> CreateRemoteThread**

## Requirements
Supported OS: **Windows 10 / Windows Server 2016, version 1703 (build 10.0.15063)** and above versions

## Usage
The PoC will inject just a MessageBox shellcode in the target process PID specified as first argument:

` mapping_injection.exe [TargetProcessPID] `


![demo](https://drive.google.com/uc?id=12HhgrwU56DLnUsLGpOiRgUCME4ZVRhwj)


## Technical Description

With the function MapViewOfFile2() is possible to map a view of a file in a remote process. For the creation of the view it is needed to create a file mapping object for a file through a call to the function [CreateFileMapping](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga). 

The problem in this scenario is that you need to drop the shellcode to the disk. In an ideal scenario you want your unpacked payload resides just in memory and never touches the disk (most of times means getting caught by AVs).

Luckily enough is possible to create a file mapping object, through CreateFileMapping(), that is backed by the system paging file instead of by a file in the file system. This can be achieved by using the costant **INVALID_HANDLE_VALUE** as 1st parameter to the function CreateFileMapping().

Once the global file mapping object is created a local view of file is created with write permission in order to copy the shellcode into the file mapping object. Then a **memcpy()** is called to place the shellcode in the file mapping object. 
After that a call to **MapViewOfFile2()** is issued and this will map in the remote process the shared memory we have just wrote with the last memcpy call. The result of MapViewOfFile2 is just the starting address of shared memory in the target process. Using that address in a call to **CreateRemoteThread()** will trigger a remote thread in the target process with the starting address pointing at the shared memory where the shellcode was placed.

Done. Enjoy your injected payload :)

#### Some additional consideration must be taken:

Looking at the definition of **MapViewOfFile2()** in **memoryapi.h** i just noticed that it's just a wrapper for the function **MapViewOfFileNuma2()**.<br>
The function **MapViewOfFileNuma2()** is imported from **Kernelbase.dll**.<br>
Reversing MapViewOfFileNuma2() from Kernelbase.dll is possible to see that it will call internally **ntdll!NtMapViewOfSection** in order to allocate remote memory in the target process.<br>

Process injection through the syscall NtMapViewOfSection() or ZwMapViewOfSection() are already known. So those syscalls are already monitored by most sandboxes. In any case pattern matching algorithm could be fooled if some variation is applied (like in this case). Monitoring CreateFileMapping with RWX permission and MapViewOfFile2 should be considered.

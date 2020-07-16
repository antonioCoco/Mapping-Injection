# Mapping-Injection
Mapping injection is a process injection technique that avoids the usage of common monitored syscall VirtualAllocEx, WriteProcessMemory and CreateRemoteThread. 

With this technique you will have a different syscall pattern from the classic process injection that is:<br>
**VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread**.<br>
In this technique you will have the following syscall pattern:<br>
**OpenProcess() -> (CreateFileMapping() -> MapViewOfFile3() [current process] -> MapViewOfFile3() [target process]) x 2 times -> NtSetInformationProcess()**

## Requirements
Supported OS: **Windows 10 / Windows Server 2016, version 1703 (build 10.0.15063)** and above versions

## Technical Description

https://splintercod3.blogspot.com/p/weaponizing-mapping-injection-with.html

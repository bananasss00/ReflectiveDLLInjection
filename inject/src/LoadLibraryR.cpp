//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "LoadLibraryR.h"
#include <stdio.h>
#include <TlHelp32.h>
#include <assert.h>
#include <string>
#include <vector>
#include <atlbase.h>

using namespace std;
using namespace ATL;

vector<DWORD> getProcessThreads(DWORD pid)
{
    auto snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (INVALID_HANDLE_VALUE == snapshot)
    {
        return {};
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);

    if (!::Thread32First(snapshot, &te32))
    {
        ::CloseHandle(snapshot);
        return {};
    }

    vector<DWORD> tids;

    do 
    {
        if (te32.th32OwnerProcessID == pid)
        {
            tids.push_back(te32.th32ThreadID);
        }
    } while (::Thread32Next(snapshot, &te32));

    ::CloseHandle(snapshot);
    return tids;
}

//===============================================================================================//
DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
{    
	WORD wIndex                          = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders         = NULL;
	
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if( dwRva < pSectionHeader[0].PointerToRawData )
        return dwRva;

    for( wIndex=0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections ; wIndex++ )
    {   
        if( dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData) )           
           return ( dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData );
    }
    
    return 0;
}
//===============================================================================================//
DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer )
{
	UINT_PTR uiBaseAddress   = 0;
	UINT_PTR uiExportDir     = 0;
	UINT_PTR uiNameArray     = 0;
	UINT_PTR uiAddressArray  = 0;
	UINT_PTR uiNameOrdinals  = 0;
	DWORD dwCounter          = 0;
#if _M_X64
	DWORD dwCompiledArch = 2;
#else
	// This will catch Win32 and WinRT.
	DWORD dwCompiledArch = 1;
#endif

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has  
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B ) // PE32
	{
		if( dwCompiledArch != 1 )
			return 0;
	}
	else if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B ) // PE64
	{
		if( dwCompiledArch != 2 )
			return 0;
	}
	else
	{
		return 0;
	}

	// uiNameArray = the address of the modules export directory entry
	uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress );

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, uiBaseAddress );

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, uiBaseAddress );	

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while( dwCounter-- )
	{
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset( DEREF_32( uiNameArray ), uiBaseAddress ));

		if( strstr( cpExportedFunctionName, "ReflectiveLoader" ) != NULL )
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );	
	
			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset( DEREF_32( uiAddressArray ), uiBaseAddress );
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}
//===============================================================================================//
// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader function
// Note: You must compile whatever you are injecting with REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR 
//       defined in order to use the correct RDI prototypes.
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
// Note: This function currently cant inject accross architectures, but only to architectures which are the 
//       same as the arch this function is compiled as, e.g. x86->x86 and x64->x64 but not x64->x86 or x86->x64.

bool InjectUsingCreateRemoteThread(HANDLE process, LPTHREAD_START_ROUTINE startRoutine, LPVOID parameter)
{
    HANDLE thread = ::CreateRemoteThread(process, NULL, 1024 * 1024, startRoutine, parameter, 0, NULL);

    if (thread)
    {
        ::CloseHandle(thread);
    }

    return !!thread;
}

#if _M_X64
const unsigned char shell[] =
{
    0x90,
    0x50,                                           // push        rax
    0x50,                                           // push        rax
    0x53,                                           // push        rbx
    0x51,                                           // push        rcx
    0x52,                                           // push        rdx
    0x55,                                           // push        rbp
    0x56,                                           // push        rsi
    0x57,                                           // push        rdi
    0x54,                                           // push        rsp
    0x41, 0x50,                                     // push        r8
    0x41, 0x51,                                     // push        r9
    0x41, 0x52,                                     // push        r10
    0x41, 0x53,                                     // push        r11
    0x41, 0x54,                                     // push        r12
    0x41, 0x55,                                     // push        r13
    0x41, 0x56,                                     // push        r14
    0x41, 0x57,                                     // push        r15
    0x90,//0x9C,                                    // pushfq
    0x48, 0xB8, 0,0,0,0,0,0,0,0,                    // mov         rax,1122334455667788h RIP
    0x48, 0x89, 0x84, 0x24, 0x80 /*0x88*/, 0x00, 0x00, 0x00, // mov         qword ptr[rsp + 88h],rax
    0x48, 0xB8, 0,0,0,0,0,0,0,0,                    // mov         rax,1122334455667788h ARG
    0x48, 0x8B, 0xC8,                               // mov         rcx,rax
    0x48, 0xB8, 0,0,0,0,0,0,0,0,                    // mov         rax,1122334455667788h FUNC

    0x41, 0x57,                                     // push        r15
    0x41, 0x57,                                     // push        r15
    0x41, 0x57,                                     // push        r15
    0x41, 0x57,                                     // push        r15

    0xFF, 0xD0,                                     // call        rax

    0x41, 0x5F,                                     // pop         r15
    0x41, 0x5F,                                     // pop         r15
    0x41, 0x5F,                                     // pop         r15
    0x41, 0x5F,                                     // pop         r15

    0x41, 0x5F,                                     // pop         r15
    0x41, 0x5E,                                     // pop         r14
    0x41, 0x5D,                                     // pop         r13
    0x41, 0x5C,                                     // pop         r12
    0x41, 0x5B,                                     // pop         r11
    0x41, 0x5A,                                     // pop         r10
    0x41, 0x59,                                     // pop         r9
    0x41, 0x58,                                     // pop         r8
    0x5C,                                           // pop         rsp
    0x5F,                                           // pop         rdi
    0x5E,                                           // pop         rsi
    0x5D,                                           // pop         rbp
    0x5A,                                           // pop         rdx
    0x59,                                           // pop         rcx
    0x5B,                                           // pop         rbx
    0x58,                                           // pop         rax
    0x90,//0x9D,                                    // popfq
    0xC3,                                           // ret
};
#elif _M_IX86
const unsigned char shell[] =
{
    0x90,
    0x50,                   //push        eax
    0x60,                   //pushad
    0x9C,                   //pushfd
    0xB8, 0, 0, 0, 0,       //mov         eax,11223344h
    0x89, 0x44, 0x24, 0x24, //mov         dword ptr[esp + 24h],eax
    0xB8, 0, 0, 0, 0,       //mov         eax,11223344h
    0x50,                   //push        eax
    0xB8, 0, 0, 0, 0,       //mov         eax,11223344h
    0xFF, 0xD0,             //call        eax
    0x9D,                   //popfd
    0x61,                   //popad
    0xC3,                   //ret
    0xcc
};
#endif

DWORD WINAPI DummyThreadFn(LPVOID lpThreadParamete)
{
    for (;;)
        SleepEx(10, TRUE);
}

BOOL InjectUsingSetThreadContext(HANDLE hProcess, LPTHREAD_START_ROUTINE lpReflectiveLoader, PVOID lpParameter)
{
    PDWORD_PTR pdwptr = NULL;
    THREADENTRY32 te32;
    CONTEXT ctx;
    LPBYTE ptr = 0;
    PVOID mem = 0;
    int found = 0;
    HANDLE hSnap = NULL;
    DWORD processId = GetProcessId(hProcess);
    DWORD currentThreadId = GetCurrentThreadId();
    DWORD targetThreadId = 0;
    HANDLE targetThread = NULL;
    
    if (processId == GetCurrentProcessId())
    {
        CreateThread(NULL, 0, DummyThreadFn, 0, 0, NULL);
        YieldProcessor();
    }

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);;

    te32.dwSize = sizeof(te32);
    ctx.ContextFlags = CONTEXT_FULL;

    Thread32First(hSnap, &te32);
    printf("\nFinding a thread to hijack.\n");

    while (Thread32Next(hSnap, &te32))
    {
        if (te32.th32OwnerProcessID == processId)
        {
            if (currentThreadId == te32.th32ThreadID)
            {
                continue;
            }

            targetThreadId = te32.th32ThreadID;

            printf("\nTarget thread found. Thread ID: %d", targetThreadId);

            printf("\nAllocating memory in target process.");

            mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (!mem)
            {
                printf("\nError: Unable to allocate memory in target process (%d)", GetLastError());
                continue;
            }

            printf("\nMemory allocated at %p", mem);
            printf("\nOpening target thread handle %d.", targetThreadId);

            targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadId);

            if (!targetThread)
            {
                printf("\nError: Unable to open target thread handle (%d)\n", GetLastError());
                continue;
            }

            printf("\nSuspending target thread.");

            SuspendThread(targetThread);
            if (!GetThreadContext(targetThread, &ctx))
            {
                printf("\n Error: GetThreadContext failed %d\n", GetLastError());
                ResumeThread(targetThread);
                continue;
            }

            // shellcode
            ptr = (LPBYTE)VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!ptr)
            {
                ResumeThread(targetThread);
                printf("\nError: no memory\n");
                continue;
            }

            memcpy(ptr, shell, sizeof(shell));

#if _M_IX86
            pdwptr = (PDWORD)(((char*)ptr) + 5);
            *pdwptr = ctx.Eip;

            pdwptr = (PDWORD)(((char*)ptr) + 14);
            *pdwptr = (DWORD_PTR)lpParameter;

            pdwptr = (PDWORD)(((char*)ptr) + 20);
            *pdwptr = (DWORD_PTR)lpReflectiveLoader;
#elif _M_X64
            pdwptr = (PDWORD64)(((char*)ptr) + 29);
            *pdwptr = ctx.Rip;

            pdwptr = (PDWORD64)(((char*)ptr) + 47);
            *pdwptr = (DWORD_PTR)lpParameter;

            pdwptr = (PDWORD64)(((char*)ptr) + 60);
            *pdwptr = (DWORD_PTR)lpReflectiveLoader;
#endif

            printf("\nWriting shellcode into target process.");

            if (!WriteProcessMemory(hProcess, mem, ptr, sizeof(shell) + 10, NULL))
            {
                ResumeThread(targetThread);
                continue;
            }

#if _M_X64
            ctx.Rip = (DWORD64)mem;
#elif _M_IX86
            ctx.Eip = (DWORD)mem;
#endif

            printf("\nHijacking target thread.");

            if (!SetThreadContext(targetThread, &ctx))
            {
                printf("\nError: Unable to hijack target thread (%d)\n", GetLastError());
                ResumeThread(targetThread);
                continue;
            }

            printf("\nResuming target thread.");

            ResumeThread(targetThread);
            CloseHandle(targetThread);
        }
    }
    
    return TRUE;
}

#pragma runtime_checks("", off)
VOID CALLBACK APCProc(ULONG_PTR dwParam)
{
    // Check activation context stack
#if _M_IX86
    if (0 == __readfsdword(0x1a8)) 
#elif _M_X64
    if (0 == __readgsqword(0x2c8))
#endif
    {
        return;
    }

    LPTHREAD_START_ROUTINE lpReflectiveLoader = (LPTHREAD_START_ROUTINE)dwParam;
    lpReflectiveLoader(NULL);
}

void APCProcEnd()
{
}
#pragma runtime_checks("", restore)

bool InjectUsingQueueUserAPC(HANDLE hProcess, LPTHREAD_START_ROUTINE startRoutine, PVOID lpParameter)
{
    const DWORD processId = ::GetProcessId(hProcess);
    const DWORD currentThreadId = ::GetCurrentThreadId();

    if (processId == ::GetCurrentProcessId())
    {
        ::CreateThread(NULL, 0, DummyThreadFn, 0, 0, NULL);
        ::YieldProcessor();
    }

    auto mem = ::VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem)
    {
        printf("\nError: Unable to allocate memory in target process (%d)", GetLastError());
        return false;
    }

    if (!::WriteProcessMemory(hProcess, mem, &APCProc, (DWORD_PTR)&APCProcEnd - (DWORD_PTR)&APCProc, NULL))
    {
        return false;
    }

    for (auto tid : getProcessThreads(processId))
    {
        if (tid == currentThreadId)
        {
            continue;
        }

        CHandle targetThread(::OpenThread(THREAD_ALL_ACCESS, FALSE, tid));
        if (!targetThread)
        {
            printf("\nError: Unable to open target thread handle (%d)\n", GetLastError());
            continue;
        }

        printf("\nHijacking target thread.");

        if (!::QueueUserAPC(reinterpret_cast<PAPCFUNC>(mem), targetThread, reinterpret_cast<DWORD_PTR>(startRoutine)))
        {
            printf("\nError: Unable to hijack target thread (%d)\n", GetLastError());
            continue;
        }        
    }

    return TRUE;
}

BOOL WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPCSTR dllName, InjectType injectType, LPVOID lpParameter)
{
    if (!hProcess)
    {
        return FALSE;
    }

    HANDLE hFile = ::CreateFileA(dllName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        GOTO_CLEANUP_WITH_ERROR("Failed to open the DLL file");
    }

    auto dwLength = ::GetFileSize(hFile, NULL);
    if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
    {
        GOTO_CLEANUP_WITH_ERROR("Failed to get the DLL file size");
    }

    auto lpBuffer = ::HeapAlloc(::GetProcessHeap(), 0, dwLength);
    if (!lpBuffer)
    {
        GOTO_CLEANUP_WITH_ERROR("Failed to get the DLL file size");
    }

    DWORD dwBytesRead = 0;
    if (::ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE)
    {
        GOTO_CLEANUP_WITH_ERROR("Failed to alloc a buffer!");
    }

	// check if the library has a ReflectiveLoader...
    DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
    if (!dwReflectiveLoaderOffset)
    {
        return FALSE;
    }

	// alloc memory (RWX) in the host process for the image...
    LPVOID remoteLibraryBuffer = ::VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteLibraryBuffer)
    {
        return FALSE;
    }

	// write the image into the host process...
    if (!::WriteProcessMemory(hProcess, remoteLibraryBuffer, lpBuffer, dwLength, NULL))
    {
        return FALSE;
    }
			
	// add the offset to ReflectiveLoader() to the remote library address...
    auto reflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)remoteLibraryBuffer + dwReflectiveLoaderOffset);

    switch (injectType)
    {
    case kCreateRemoteThread:
        return InjectUsingCreateRemoteThread(hProcess, reflectiveLoader, lpParameter);

    case kSetThreadContext:
        return InjectUsingSetThreadContext(hProcess, reflectiveLoader, lpParameter);

    case kQueueUserAPC:
        return InjectUsingQueueUserAPC(hProcess, reflectiveLoader, lpParameter);
    }

cleanup:
    return FALSE;
}

template<class CharT>
bool LoadRemoteLibrary(HANDLE hProcess, const basic_string<CharT>& dllName, InjectType injectType)
{
    const LPCSTR kLoadLibraryProcName = sizeof(CharT) == sizeof(char) ? "LoadLibraryA" : "LoadLibraryW";
    auto loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(::GetProcAddress(::GetModuleHandle("kernel32"), kLoadLibraryProcName));

    // alloc memory (RW) in the host process for the image...
    LPVOID remoteDllName = ::VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remoteDllName)
    {
        return FALSE;
    }

    // write the image into the host process...
    if (!::WriteProcessMemory(hProcess, remoteDllName, dllName.c_str(), (dllName.size() + 1) * sizeof(CharT), nullptr))
    {
        return FALSE;
    }

    switch (injectType)
    {
    case kCreateRemoteThread:
        return InjectUsingCreateRemoteThread(hProcess, loadLibrary, remoteDllName);

    default:
        GOTO_CLEANUP_WITH_ERROR("Not supported");
    }

cleanup:
    return FALSE;
}

bool LoadRemoteLibrary(HANDLE hProcess, LPCWSTR dllName, InjectType injectType)
{
    return LoadRemoteLibrary(hProcess, wstring(dllName), injectType);
}

bool LoadRemoteLibrary(HANDLE hProcess, LPCSTR dllName, InjectType injectType)
{
    return LoadRemoteLibrary(hProcess, string(dllName), injectType);
}
//===============================================================================================//

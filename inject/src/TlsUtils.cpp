//////////////////////////////////////////////////////////////////////////////////////////
//										TLS UTILS										//
//////////////////////////////////////////////////////////////////////////////////////////
#include "TlsUtils.h"

size_t FindPattern(const std::string& sig, void* scanStart, size_t scanSize, std::vector<size_t>& out)
{
	out.clear();

	uint8_t *pBuffer = (uint8_t*)VirtualAlloc(NULL, scanSize, MEM_COMMIT, PAGE_READWRITE);

	SIZE_T dwRead = 0;
	ReadProcessMemory(GetCurrentProcess(), scanStart, pBuffer, scanSize, &dwRead);

	if (pBuffer)
	{
		size_t bad_char_skip[UCHAR_MAX + 1];

		const uint8_t* haystack = (const uint8_t*)pBuffer;
		const uint8_t* needle = (const uint8_t*)&sig[0];
		intptr_t       nlen = sig.length();
		intptr_t       scan = 0;
		intptr_t       last = nlen - 1;

		for (scan = 0; scan <= UCHAR_MAX; ++scan)
			bad_char_skip[scan] = nlen;

		for (scan = 0; scan < last; ++scan)
			bad_char_skip[needle[scan]] = last - scan;

		while (scanSize >= (size_t)nlen)
		{
			for (scan = last; haystack[scan] == needle[scan]; --scan)
				if (scan == 0)
					out.emplace_back(haystack - pBuffer + (size_t)scanStart);

			scanSize -= bad_char_skip[haystack[last]];
			haystack += bad_char_skip[haystack[last]];
		}
	}

	if (pBuffer)
		VirtualFree(pBuffer, 0, MEM_DECOMMIT);

	return out.size();
}

bool GetNtdllTextSection(void* &pStart, size_t &scanSize)
{
	void* pFileBase = GetModuleHandleA("ntdll.dll");

	const IMAGE_DOS_HEADER        *pDosHdr = nullptr;
	const IMAGE_SECTION_HEADER    *pSection = nullptr;

	if (!pFileBase)
	{
		return false;
	}

	pDosHdr = (const IMAGE_DOS_HEADER*)(pFileBase);

	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}

	const IMAGE_NT_HEADERS *pImageHdr = (const IMAGE_NT_HEADERS*)((uint8_t*)pDosHdr + pDosHdr->e_lfanew);

	if (pImageHdr->Signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}

	pSection = (const IMAGE_SECTION_HEADER*)((uint8_t*)pImageHdr + sizeof(IMAGE_NT_HEADERS));

	for (int i = 0; i < pImageHdr->FileHeader.NumberOfSections; ++i, pSection++)
	{
		if (_stricmp((LPCSTR)pSection->Name, ".text") == 0)
		{
			pStart = (void*)((size_t)GetModuleHandleA("ntdll.dll") + pSection->VirtualAddress);
			scanSize = pSection->Misc.VirtualSize;
			
			return true;
		}
	}
	
	return false;
}

ULONG_PTR GetLdrpHandleTlsDataOffset()
{
	static bool initOnce = false;
	if (!initOnce)
	{
		InitVersion();
		initOnce = true;
	}

	void* pStart = nullptr;
	size_t scanSize = 0;

	if (!GetNtdllTextSection(pStart, scanSize))
		return 0;
	
	std::vector<size_t> foundData; 
	ULONG_PTR m_LdrpHandleTlsData = 0;
	
	if (IsWindows10FallCreatorsOrGreater())
	{
		FindPattern("\x8b\xc1\x8d\x4d\xbc\x51", pStart, scanSize, foundData);

		if (!foundData.empty())
			m_LdrpHandleTlsData = (ULONG_PTR)(foundData.front() - 0x18);
	}
	if (IsWindows10CreatorsOrGreater())
	{
		FindPattern("\x8b\xc1\x8d\x4d\xbc\x51", pStart, scanSize, foundData);

		if (!foundData.empty())
			m_LdrpHandleTlsData = (ULONG_PTR)(foundData.front() - 0x18);
	}
	else if (IsWindows8Point1OrGreater())
	{
		FindPattern("\x50\x6a\x09\x6a\x01\x8b\xc1", pStart, scanSize, foundData);

		if (!foundData.empty())
			m_LdrpHandleTlsData = (ULONG_PTR)(foundData.front() - 0x1B);
	}
	else if (IsWindows8OrGreater())
	{
		FindPattern("\x8b\x45\x08\x89\x45\xa0", pStart, scanSize, foundData);

		if (!foundData.empty())
			m_LdrpHandleTlsData = (ULONG_PTR)(foundData.front() - 0x0C);
	}
	else if (IsWindows7OrGreater())
	{
		FindPattern("\x74\x20\x8d\x45\xd4\x50\x6a\x09", pStart, scanSize, foundData);

		if (!foundData.empty())
			m_LdrpHandleTlsData = (ULONG_PTR)(foundData.front() - 0x14);
	}
	else
	{
		printf("Unsupported OS!\n");
	}

	return m_LdrpHandleTlsData;
}

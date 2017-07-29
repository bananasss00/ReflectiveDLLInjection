//////////////////////////////////////////////////////////////////////////////////////////
//										TLS UTILS										//
//////////////////////////////////////////////////////////////////////////////////////////
#pragma once

#include <vector>
#include "VersionHelper.h"

typedef struct
{
	ULONG_PTR pLdrpHandleTlsData;
	bool win81orGreater;
} TLS_DATA, *PTLS_DATA;

size_t 		FindPattern(const std::string& sig, void* scanStart, size_t scanSize, std::vector<size_t>& out);
bool 		GetNtdllTextSection(const void* pFileBase, void* &pStart, size_t &scanSize);
ULONG_PTR 	GetLdrpHandleTlsDataOffset();
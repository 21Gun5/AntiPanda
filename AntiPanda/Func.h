#pragma once
#include <windows.h>

BOOL FindTargetProcess(char *pszProcessName, DWORD *dwPid);
BOOL EnableDebugPrivilege(char *pszPrivilege);
DWORD CRC32(BYTE* ptr, DWORD Size);
DWORD WINAPI FindFiles(LPVOID lpszPath);
extern CString csTxt;
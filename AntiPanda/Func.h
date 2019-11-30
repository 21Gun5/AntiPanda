#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstring>
#include <queue>
using namespace std;

#define MAX_PATH 500

extern CString csTxt;

BOOL FindVirusProcess(char *pszProcessName, DWORD *dwPid);
BOOL EnableDebugPrivilege(char *pszPrivilege);
DWORD GenerateCRC32(BYTE* ptr, DWORD Size);
DWORD WINAPI DeleteIniFile(LPVOID lpszPath);
BOOL IsInfected(char* buff, int size, const char* str, int len);
std::shared_ptr<std::vector<std::string> > fileList(const std::string& folder_path);
std::shared_ptr<std::vector<std::string> >  QueryFileCounts(LPCTSTR Path);

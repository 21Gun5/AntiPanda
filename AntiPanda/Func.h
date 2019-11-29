#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstring>
#include <queue>


BOOL FindTargetProcess(char *pszProcessName, DWORD *dwPid);
BOOL EnableDebugPrivilege(char *pszPrivilege);
DWORD CRC32(BYTE* ptr, DWORD Size);
DWORD WINAPI FindFiles(LPVOID lpszPath);
DWORD WINAPI FindFiles2(LPVOID lpszPath);
int findsub(char *str1, char *str2, long sizes);
BOOL MyStrPos(char* buff, int size, const char* str, int len);
std::shared_ptr<std::vector<std::string> > fileList(const std::string& folder_path);
void GetFile(CString lpszPath);
std::shared_ptr<std::vector<std::string> >  QueryFileCounts(LPCTSTR Path);
extern CString csTxt;
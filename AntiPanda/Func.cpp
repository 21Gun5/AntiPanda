#include "stdafx.h"
#include "Func.h"
#include <TlHelp32.h>

CString csTxt= NULL;

BOOL FindTargetProcess(char *pszProcessName, DWORD *dwPid)
{
	BOOL bFind = FALSE;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return bFind;
	}

	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);

	BOOL bRet = Process32First(hProcessSnap, &pe);
	while (bRet)
	{
		if (lstrcmp(pe.szExeFile, pszProcessName) == 0)
		{
			*dwPid = pe.th32ProcessID;
			bFind = TRUE;
			break;
		}
		bRet = Process32Next(hProcessSnap, &pe);
	}

	CloseHandle(hProcessSnap);

	return bFind;
}

BOOL EnableDebugPrivilege(char *pszPrivilege)
{
	HANDLE hToken = INVALID_HANDLE_VALUE;
	LUID luid;
	TOKEN_PRIVILEGES tp;

	BOOL bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	if (bRet == FALSE)
	{
		return bRet;
	}

	bRet = LookupPrivilegeValue(NULL, pszPrivilege, &luid);
	if (bRet == FALSE)
	{
		return bRet;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	bRet = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

	return bRet;
}

DWORD CRC32(BYTE* ptr, DWORD Size)
{
	DWORD crcTable[256], crcTmp1;
	//动态生成CRC-32表
	for (int i = 0; i < 256; i++)
	{
		crcTmp1 = i;
		for (int j = 8; j > 0; j--)
		{
			if (crcTmp1 & 1) crcTmp1 = (crcTmp1 >> 1) ^ 0xEDB88320L;
			else crcTmp1 >>= 1;
		}

		crcTable[i] = crcTmp1;
	}
	//计算CRC32值
	DWORD crcTmp2 = 0xFFFFFFFF;
	while (Size--)
	{
		crcTmp2 = ((crcTmp2 >> 8) & 0x00FFFFFF) ^ crcTable[(crcTmp2 ^ (*ptr)) & 0xFF];
		ptr++;
	}
	return (crcTmp2 ^ 0xFFFFFFFF);
}

#define MAX_PATH 500
DWORD WINAPI FindFiles(LPVOID lpszPath)
{
	WIN32_FIND_DATA stFindFile;
	HANDLE hFindFile;
	// 扫描路径
	char szPath[MAX_PATH];
	char szFindFile[MAX_PATH];
	char szSearch[MAX_PATH];
	char *szFilter;
	int len;
	int ret = 0;

	szFilter = "*.*";
	lstrcpy(szPath, (char *)lpszPath);

	len = lstrlen(szPath);
	if (szPath[len - 1] != '\\')
	{
		szPath[len] = '\\';
		szPath[len + 1] = '\0';
	}

	lstrcpy(szSearch, szPath);
	lstrcat(szSearch, szFilter);

	hFindFile = FindFirstFile(szSearch, &stFindFile);
	if (hFindFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			lstrcpy(szFindFile, szPath);
			lstrcat(szFindFile, stFindFile.cFileName);

			if (stFindFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (stFindFile.cFileName[0] != '.')
				{
					FindFiles(szFindFile);
				}
			}
			else
			{
				if (!lstrcmp(stFindFile.cFileName, "Desktop_.ini"))
				{
					// 去除文件的隐藏、系统以及只读属性
					DWORD dwFileAttributes = GetFileAttributes(szFindFile);
					dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
					dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
					dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
					SetFileAttributes(szFindFile, dwFileAttributes);
					// 删除Desktop_.ini
					BOOL bRet = DeleteFile(szFindFile);
					csTxt += szFindFile;
					if (bRet)
					{
						csTxt += _T("被删除！\r\n");
					}
					else
					{
						csTxt += _T("无法删除\r\n");
					}
				}
			}
			ret = FindNextFile(hFindFile, &stFindFile);
		} while (ret != 0);
	}

	FindClose(hFindFile);

	return 0;
}




#include "stdafx.h"
#include "Func.h"
#include <TlHelp32.h>
#include <iostream>
#include <memory>
#include <windows.h>

CString csTxt = NULL;// 编辑框控件的显示

// 发现病毒进程
BOOL FindVirusProcess(char *pszProcessName, DWORD *dwPid)
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
// 提升权限，完成一些受限的操作
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
// 计算文件哈希值，判断是否未病毒文件
DWORD GenerateCRC32(BYTE* ptr, DWORD Size)
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
// 遍历全盘，删除ini文件（递归遍历，速度慢待改进
DWORD WINAPI DeleteIniFile(LPVOID lpszPath)
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
					DeleteIniFile(szFindFile);
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
						csTxt += _T("删除成功\r\n");
					}
					else
					{
						csTxt += _T("删除失败\r\n");
					}
				}
			}
			ret = FindNextFile(hFindFile, &stFindFile);
		} while (ret != 0);
	}

	FindClose(hFindFile);

	return 0;
}
// 检查文件是否被感染（文件内容中是否能搜到感染标记
BOOL IsInfected(char* buff, int size, const char* str, int len)
{
	bool flag = true;
	for (int i = size - 1; i > 0; --i)
	{
		if (buff[i] == str[len - 1])
		{
			flag = true;
			for (int j = len - 2; j >= 0; --j)
			{
				if (buff[i + j - len + 1] != str[j])
				{
					flag = false;
				}
			}
			if (flag)
			{
				return true;
			}
		}
	}
	return false;
}
// 递归遍历文件（速度慢，待改进）
std::shared_ptr<std::vector<std::string> > fileList(const std::string& folder_path)
{
	static std::shared_ptr<std::vector<std::string> >
		folder_files(new std::vector<std::string>); //返回指针, 需要迭代使用

	WIN32_FIND_DATA FindData;
	HANDLE hError;

	int file_count(0);
	std::string file_path(folder_path); //路径名
	std::string full_file_path; //全路径名 

	file_path.append("/*.*");
	hError = FindFirstFile(file_path.c_str(), &FindData);
	if (hError == INVALID_HANDLE_VALUE) {
		//std::cout << "failed to search files." << std::endl;
		return nullptr;
	}
	while (FindNextFile(hError, &FindData))
	{
		//过虑".", "..", "-q"
		if (0 == strcmp(FindData.cFileName, ".") ||
			0 == strcmp(FindData.cFileName, "..") ||
			0 == strcmp(FindData.cFileName, "-q"))
		{
			continue;
		}
		//完整路径
		full_file_path.append(folder_path);
		full_file_path.append("\\");
		full_file_path.append(FindData.cFileName);
		++file_count;

		if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			fileList(full_file_path);
		}
		else
		{
			folder_files->push_back(full_file_path);
		}
		full_file_path.clear(); //清空目录
	}
	return folder_files;
}
// 非递归遍历文件（仅思路，暂未使用
std::shared_ptr<std::vector<std::string> >  QueryFileCounts(LPCTSTR Path)
{
	static std::shared_ptr<std::vector<std::string> >
		folder_files(new std::vector<std::string>); //返回指针, 需要迭代使用

	queue<std::string> qFolders;
	qFolders.push(Path);

	int fileCounts = 0;
	WIN32_FIND_DATA findResult;
	HANDLE handle = NULL;





	while (qFolders.size() > 0)
	{
		std::string tempFolder = qFolders.front();
		tempFolder.append("\\*.*");
		handle = FindFirstFile(tempFolder.c_str(), &findResult);


		do
		{


			if (findResult.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{



				if (lstrcmp(".", findResult.cFileName) == 0 || lstrcmp("..", findResult.cFileName) == 0)
				{
					continue;
				}
				tempFolder = qFolders.front();
				tempFolder.append("\\").append(findResult.cFileName);
				qFolders.push(tempFolder);
			}
			else 
			{

				fileCounts++;
			}

		} while (FindNextFile(handle, &findResult));
		qFolders.pop();
	}
	if (handle)
	{
		FindClose(handle);
		handle = NULL;
	}
	//return fileCounts;
	return folder_files;
}


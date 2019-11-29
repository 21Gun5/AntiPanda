#include "stdafx.h"
#include "Func.h"
#include <TlHelp32.h>
#include <iostream>

#include <memory>
#include <windows.h>

CString csTxt = NULL;

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

DWORD WINAPI FindFiles2(LPVOID lpszPath)
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
				DWORD dwNum = 0;
				//char szTargetPath[MAX_PATH] = "C:\\Users\\ry1yn\\Desktop\\AutoRuns.ex";
				HANDLE hFile = CreateFile(szFindFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				DWORD dwTotalSize = GetFileSize(hFile, NULL);
				char *pFile = (char*)malloc(dwTotalSize);
				ReadFile(hFile, pFile, dwTotalSize, &dwNum, NULL);

				//若找到 WhBoy且位置大于病毒大小，则是感染标志，则文件被感染
				if (MyStrPos(pFile, dwNum, "WhBoy", 5))
				{
					// 将原文件读取到内存
					DWORD dwRead = 0;
					// 标记信息长度: strlen(szTargetPath)求的是绝对路径的长度，而非文件名,程序后面一堆0，少几个没事
					WORD dwSignLen = 5 + strlen(szFindFile) + 12;// whboy + 程序名 + .exe.xxxxxx
					DWORD dwNormalSize = dwTotalSize - 0x7531 - dwSignLen;// 总大小-病毒大小
					BYTE *pFileBuff = (BYTE*)malloc(dwNormalSize);
					SetFilePointer(hFile, 0x7531, NULL, FILE_BEGIN);//将文件指针指向病毒结尾，即原文件开头
					ReadFile(hFile, pFileBuff, dwNormalSize, &dwRead, NULL);
					CloseHandle(hFile);

					// 恢复文件
					DeleteFile(szFindFile);//先删除被感染的，再创建新的，来存放原文件内容
					HANDLE hsFile = CreateFile(szFindFile,
						GENERIC_WRITE, FILE_SHARE_READ, NULL,
						CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					if (hsFile != INVALID_HANDLE_VALUE) // 如果创建成功
					{
						// 将内容写入到原文件（暂没去掉尾部特征，其不影响程序运行
						BOOL bRet = WriteFile(hsFile, pFileBuff, dwNormalSize, &dwRead, NULL);//here
						if (bRet == 0)
						{
							csTxt += szFindFile;
							csTxt += _T(": 修复失败 \r\n");
						}
						else
						{
							csTxt += szFindFile;
							csTxt += _T(": 修复成功 \r\n");
						}
					}
					CloseHandle(hsFile);
				}

			}
			ret = FindNextFile(hFindFile, &stFindFile);
		} while (ret != 0);
	}

	FindClose(hFindFile);

	return 0;
}





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


int findsub(char *str1, char *str2, long sizes)
{
	int i = 0, j = 0;
	while (sizes - i) //多少个字符长度就执行多少次
	{
		for (; str1[i] != str2[0]; i++);//后面每个字符比较都不相等就i++

		if (str1[i] == str2[0])//判断首次相等
		{
			for (j = 0; str1[i + j] == str2[j]; j++);//后面每个字符比较都相等就j++

			if (str2[j] == '\0')//直到把字符串2都比较完都相等
			{
				if (i > 0x7531)// WhBoy可能也出现在病毒数据区，大于病毒大小位置才是真正的标记所在处
					return i;
			}
			// 返回字符串2中出现字符串1的第一个位置
		}
		i++; //不相等就继续往后走
	}
	return -1;//如果没有找到合适的返回-1.
}


BOOL MyStrPos(char* buff, int size, const char* str, int len)
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

//#include <queue>
//using namespace std;
//void GetFile(CString szFilePath)
//{
//	// 获取到盘符
//	//WaitForSingleObject(g_hMutex2, INFINITE);
//	//CString szFilePath = g_Drivers.back();
//	//szFilePath.Append(":");
//	//g_Drivers.pop_back();
//	//ReleaseMutex(g_hMutex2);
//	// 根据获取到的盘符开始遍历
//	queue<CString> qFolders;
//	qFolders.push(szFilePath);
//	WIN32_FIND_DATA FindFileData;
//	HANDLE hFile = NULL;
//	USES_CONVERSION;
//	while (qFolders.size() > 0)
//	{
//		// 开始遍历这个目录
//		CString TempFolder = qFolders.front();
//		TempFolder.Append("\\*.*");
//		hFile = FindFirstFile(TempFolder.GetBuffer(), &FindFileData);
//		do
//		{
//			// 拼接为完整路径
//			TempFolder = qFolders.front();
//			TempFolder.Append("\\");
//			TempFolder.Append(FindFileData.cFileName);
//			// 判断是不是目录
//			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
//			{
//				// 判断是不是本级目录或上级目录的名称，是的话则结束本次循环
//				if (!lstrcmp(FindFileData.cFileName, ".") || !lstrcmp(FindFileData.cFileName, ".."))
//					continue;
//				// 压入新的目录
//				qFolders.push(TempFolder);
//			}
//			else
//			{
//
//				//// 判断以下是不是Desktop_.ini文件
//				//if (!lstrcmp(FindFileData.cFileName, "Desktop_.ini"))
//				//{
//				//	//WaitForSingleObject(g_hMutex, INFINITE);
//				//	SetFileAttributes(TempFolder.GetBuffer(), FILE_ATTRIBUTE_ARCHIVE);
//				//	//if (remove(W2A(TempFolder.GetBuffer())) == 0)
//				//		//g_FileNum++;
//				//	//ReleaseMutex(g_hMutex);
//				//}
//			}
//		} while (FindNextFile(hFile, &FindFileData));
//		qFolders.pop();
//		if (hFile)
//		{
//			FindClose(hFile);
//			hFile = NULL;
//		}
//	}
//}




using namespace std;

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
		tempFolder.append("//*.*");
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
				folder_files->push_back(tempFolder);
				//fileCounts++;
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

//QueryFileCounts(L"D:\\feinno\\RunImage")

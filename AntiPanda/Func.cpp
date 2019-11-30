#include "stdafx.h"
#include "Func.h"
#include <TlHelp32.h>
#include <iostream>
#include <memory>
#include <windows.h>

CString csTxt = NULL;// �༭��ؼ�����ʾ

// ���ֲ�������
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
// ����Ȩ�ޣ����һЩ���޵Ĳ���
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
// �����ļ���ϣֵ���ж��Ƿ�δ�����ļ�
DWORD GenerateCRC32(BYTE* ptr, DWORD Size)
{
	DWORD crcTable[256], crcTmp1;
	//��̬����CRC-32��
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
	//����CRC32ֵ
	DWORD crcTmp2 = 0xFFFFFFFF;
	while (Size--)
	{
		crcTmp2 = ((crcTmp2 >> 8) & 0x00FFFFFF) ^ crcTable[(crcTmp2 ^ (*ptr)) & 0xFF];
		ptr++;
	}
	return (crcTmp2 ^ 0xFFFFFFFF);
}
// ����ȫ�̣�ɾ��ini�ļ����ݹ�������ٶ������Ľ�
DWORD WINAPI DeleteIniFile(LPVOID lpszPath)
{
	WIN32_FIND_DATA stFindFile;
	HANDLE hFindFile;
	// ɨ��·��
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
					// ȥ���ļ������ء�ϵͳ�Լ�ֻ������
					DWORD dwFileAttributes = GetFileAttributes(szFindFile);
					dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
					dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
					dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
					SetFileAttributes(szFindFile, dwFileAttributes);
					// ɾ��Desktop_.ini
					BOOL bRet = DeleteFile(szFindFile);
					csTxt += szFindFile;
					if (bRet)
					{
						csTxt += _T("ɾ���ɹ�\r\n");
					}
					else
					{
						csTxt += _T("ɾ��ʧ��\r\n");
					}
				}
			}
			ret = FindNextFile(hFindFile, &stFindFile);
		} while (ret != 0);
	}

	FindClose(hFindFile);

	return 0;
}
// ����ļ��Ƿ񱻸�Ⱦ���ļ��������Ƿ����ѵ���Ⱦ���
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
// �ݹ�����ļ����ٶ��������Ľ���
std::shared_ptr<std::vector<std::string> > fileList(const std::string& folder_path)
{
	static std::shared_ptr<std::vector<std::string> >
		folder_files(new std::vector<std::string>); //����ָ��, ��Ҫ����ʹ��

	WIN32_FIND_DATA FindData;
	HANDLE hError;

	int file_count(0);
	std::string file_path(folder_path); //·����
	std::string full_file_path; //ȫ·���� 

	file_path.append("/*.*");
	hError = FindFirstFile(file_path.c_str(), &FindData);
	if (hError == INVALID_HANDLE_VALUE) {
		//std::cout << "failed to search files." << std::endl;
		return nullptr;
	}
	while (FindNextFile(hError, &FindData))
	{
		//����".", "..", "-q"
		if (0 == strcmp(FindData.cFileName, ".") ||
			0 == strcmp(FindData.cFileName, "..") ||
			0 == strcmp(FindData.cFileName, "-q"))
		{
			continue;
		}
		//����·��
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
		full_file_path.clear(); //���Ŀ¼
	}
	return folder_files;
}
// �ǵݹ�����ļ�����˼·����δʹ��
std::shared_ptr<std::vector<std::string> >  QueryFileCounts(LPCTSTR Path)
{
	static std::shared_ptr<std::vector<std::string> >
		folder_files(new std::vector<std::string>); //����ָ��, ��Ҫ����ʹ��

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


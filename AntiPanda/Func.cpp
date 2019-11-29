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

#define MAX_PATH 500
DWORD WINAPI FindFiles(LPVOID lpszPath)
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
					FindFiles(szFindFile);
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

DWORD WINAPI FindFiles2(LPVOID lpszPath)
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

				//���ҵ� WhBoy��λ�ô��ڲ�����С�����Ǹ�Ⱦ��־�����ļ�����Ⱦ
				if (MyStrPos(pFile, dwNum, "WhBoy", 5))
				{
					// ��ԭ�ļ���ȡ���ڴ�
					DWORD dwRead = 0;
					// �����Ϣ����: strlen(szTargetPath)����Ǿ���·���ĳ��ȣ������ļ���,�������һ��0���ټ���û��
					WORD dwSignLen = 5 + strlen(szFindFile) + 12;// whboy + ������ + .exe.xxxxxx
					DWORD dwNormalSize = dwTotalSize - 0x7531 - dwSignLen;// �ܴ�С-������С
					BYTE *pFileBuff = (BYTE*)malloc(dwNormalSize);
					SetFilePointer(hFile, 0x7531, NULL, FILE_BEGIN);//���ļ�ָ��ָ�򲡶���β����ԭ�ļ���ͷ
					ReadFile(hFile, pFileBuff, dwNormalSize, &dwRead, NULL);
					CloseHandle(hFile);

					// �ָ��ļ�
					DeleteFile(szFindFile);//��ɾ������Ⱦ�ģ��ٴ����µģ������ԭ�ļ�����
					HANDLE hsFile = CreateFile(szFindFile,
						GENERIC_WRITE, FILE_SHARE_READ, NULL,
						CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					if (hsFile != INVALID_HANDLE_VALUE) // ��������ɹ�
					{
						// ������д�뵽ԭ�ļ�����ûȥ��β���������䲻Ӱ���������
						BOOL bRet = WriteFile(hsFile, pFileBuff, dwNormalSize, &dwRead, NULL);//here
						if (bRet == 0)
						{
							csTxt += szFindFile;
							csTxt += _T(": �޸�ʧ�� \r\n");
						}
						else
						{
							csTxt += szFindFile;
							csTxt += _T(": �޸��ɹ� \r\n");
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


int findsub(char *str1, char *str2, long sizes)
{
	int i = 0, j = 0;
	while (sizes - i) //���ٸ��ַ����Ⱦ�ִ�ж��ٴ�
	{
		for (; str1[i] != str2[0]; i++);//����ÿ���ַ��Ƚ϶�����Ⱦ�i++

		if (str1[i] == str2[0])//�ж��״����
		{
			for (j = 0; str1[i + j] == str2[j]; j++);//����ÿ���ַ��Ƚ϶���Ⱦ�j++

			if (str2[j] == '\0')//ֱ�����ַ���2���Ƚ��궼���
			{
				if (i > 0x7531)// WhBoy����Ҳ�����ڲ��������������ڲ�����Сλ�ò��������ı�����ڴ�
					return i;
			}
			// �����ַ���2�г����ַ���1�ĵ�һ��λ��
		}
		i++; //����Ⱦͼ���������
	}
	return -1;//���û���ҵ����ʵķ���-1.
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
//	// ��ȡ���̷�
//	//WaitForSingleObject(g_hMutex2, INFINITE);
//	//CString szFilePath = g_Drivers.back();
//	//szFilePath.Append(":");
//	//g_Drivers.pop_back();
//	//ReleaseMutex(g_hMutex2);
//	// ���ݻ�ȡ�����̷���ʼ����
//	queue<CString> qFolders;
//	qFolders.push(szFilePath);
//	WIN32_FIND_DATA FindFileData;
//	HANDLE hFile = NULL;
//	USES_CONVERSION;
//	while (qFolders.size() > 0)
//	{
//		// ��ʼ�������Ŀ¼
//		CString TempFolder = qFolders.front();
//		TempFolder.Append("\\*.*");
//		hFile = FindFirstFile(TempFolder.GetBuffer(), &FindFileData);
//		do
//		{
//			// ƴ��Ϊ����·��
//			TempFolder = qFolders.front();
//			TempFolder.Append("\\");
//			TempFolder.Append(FindFileData.cFileName);
//			// �ж��ǲ���Ŀ¼
//			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
//			{
//				// �ж��ǲ��Ǳ���Ŀ¼���ϼ�Ŀ¼�����ƣ��ǵĻ����������ѭ��
//				if (!lstrcmp(FindFileData.cFileName, ".") || !lstrcmp(FindFileData.cFileName, ".."))
//					continue;
//				// ѹ���µ�Ŀ¼
//				qFolders.push(TempFolder);
//			}
//			else
//			{
//
//				//// �ж������ǲ���Desktop_.ini�ļ�
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
		folder_files(new std::vector<std::string>); //����ָ��, ��Ҫ����ʹ��

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

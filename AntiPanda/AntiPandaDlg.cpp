
// AntiPandaDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "AntiPanda.h"
#include "AntiPandaDlg.h"
#include "afxdialogex.h"
#include "Func.h"
#include <string>
using namespace std;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CAntiPandaDlg 对话框



CAntiPandaDlg::CAntiPandaDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_ANTIPANDA_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAntiPandaDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAntiPandaDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_KILL, &CAntiPandaDlg::OnBnClickedButtonKill)
	ON_BN_CLICKED(IDC_BUTTON_DELVIRUS, &CAntiPandaDlg::OnBnClickedButtonDelvirus)
	ON_BN_CLICKED(IDC_BUTTON_DELINI, &CAntiPandaDlg::OnBnClickedButtonDelini)
	ON_BN_CLICKED(IDC_BUTTON_REPAIRREG, &CAntiPandaDlg::OnBnClickedButtonRepairreg)
	ON_BN_CLICKED(IDC_BUTTON_REPAIRFILE, &CAntiPandaDlg::OnBnClickedButtonRepairfile)
END_MESSAGE_MAP()


// CAntiPandaDlg 消息处理程序

BOOL CAntiPandaDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CAntiPandaDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CAntiPandaDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CAntiPandaDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CAntiPandaDlg::OnBnClickedButtonKill()
{
	// TODO: 在此添加控件通知处理程序代码

	// 结束病毒进程
	BOOL bRet = FALSE;		// 操作是否成功
	DWORD dwPid = 0;		// 病毒进程ID
	// 1 查找进程
	bRet = FindVirusProcess("spo0lsv.exe", &dwPid);
	if (bRet == TRUE)
	{
		csTxt = _T("发现病毒进程：spo0lsv.exe\r\n");
		//SetDlgItemText(IDC_EDIT1, csTxt);
		// 2 提升权限
		bRet = EnableDebugPrivilege(SE_DEBUG_NAME);
		if (bRet == FALSE)
			csTxt += _T("提升权限：失败\r\n");
		else
			csTxt += _T("提升权限：成功\r\n");
		//SetDlgItemText(IDC_EDIT1, csTxt);
		// 3 打开进程获取句柄
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (hProcess == INVALID_HANDLE_VALUE)
		{
			csTxt += _T("获取进程句柄：失败\r\n");
			return;
		}
		// 4 结束进程
		bRet = TerminateProcess(hProcess, 0);
		if (bRet == TRUE)
			csTxt += _T("结束病毒进程：成功\r\n");
		else
			csTxt += _T("结束病毒进程：失败\r\n");
		//SetDlgItemText(IDC_EDIT1, csTxt);
		CloseHandle(hProcess);
	}
	else
	{
		csTxt += _T("未发现病毒进程：spo0lsv.exe\r\n");
	}
	SetDlgItemText(IDC_EDIT1, csTxt);// 信息实时显示
}

void CAntiPandaDlg::OnBnClickedButtonDelvirus()
{
	// TODO: 在此添加控件通知处理程序代码

	// 删除病毒文件
	char szTargetPath[MAX_PATH] = { 0 };
	// 1 获取绝对路径
	GetSystemDirectory(szTargetPath, MAX_PATH);
	lstrcat(szTargetPath, "\\drivers\\spo0lsv.exe");
	if (GetFileAttributes(szTargetPath) != 0xFFFFFFFF)
	{
		// 2 打开文件获取内容
		HANDLE hFile = CreateFile(szTargetPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			AfxMessageBox("Create Error");
			return;
		}
		DWORD dwSize = GetFileSize(hFile, NULL);
		if (dwSize == 0xFFFFFFFF)
		{
			AfxMessageBox("GetFileSize Error");
			return;
		}
		BYTE *pFile = (BYTE*)malloc(dwSize);
		if (pFile == NULL)
		{
			AfxMessageBox("malloc Error");
			return;
		}
		DWORD dwNum = 0;
		ReadFile(hFile, pFile, dwSize, &dwNum, NULL);
		// 3 计算文件散列值
		DWORD dwCrc32 = GenerateCRC32(pFile, dwSize);
		if (pFile != NULL)
		{
			free(pFile);
			pFile = NULL;
		}
		CloseHandle(hFile);
		// 4 通过散列值判断是否是目标文件
		if (dwCrc32 == 0xE334747C || dwCrc32 == 0xF7C3654D)
		{
			// 5 去除文件的隐藏、系统、只读属性
			DWORD dwFileAttributes = GetFileAttributes(szTargetPath);
			dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
			dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
			dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
			SetFileAttributes(szTargetPath, dwFileAttributes);
			// 6 删除spoclsv.exe
			BOOL bRet = DeleteFile(szTargetPath);
			if (bRet)
				csTxt += _T("spo0lsv.exe病毒删除：成功\r\n");
			else
				csTxt += _T("spo0lsv.exe病毒删除：失败\r\n");
		}
	}
	else
	{
		csTxt += _T("未发现病毒文件：spo0lsv.exe\r\n");
	}
	SetDlgItemText(IDC_EDIT1, csTxt);
}

void CAntiPandaDlg::OnBnClickedButtonRepairreg()
{
	// TODO: 在此添加控件通知处理程序代码

	// 修复注册表：删除病毒启动项
	HKEY hKeyHKCU = NULL;
	LONG lSize = MAXBYTE;
	char cData[MAXBYTE] = { 0 };
	char RegRun[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	// 1 打开注册表：启动项
	long lRet = RegOpenKey(HKEY_CURRENT_USER, RegRun, &hKeyHKCU);
	if (lRet == ERROR_SUCCESS)
	{
		csTxt += _T("读取注册表启动项：成功\r\n");
		// 2 是否存在病毒启动项
		lRet = RegQueryValueEx(hKeyHKCU, "svcshare", NULL, NULL, (unsigned char *)cData, (unsigned long *)&lSize);
		if (lRet == ERROR_SUCCESS)
		{
			csTxt += _T("注册表启动项：发现病毒记录\r\n");
			// 3 删除病毒启动项
			lRet = RegDeleteValue(hKeyHKCU, "svcshare");
			if (lRet == ERROR_SUCCESS)
				csTxt += _T("注册表：病毒启动项删除成功\r\n");
			else
				csTxt += _T("注册表：病毒启动项删除失败\r\n");
		}
		else
		{
			csTxt += _T("注册表启动项：未发现病毒记录\r\n");
		}
		RegCloseKey(hKeyHKCU);
	}
	else
	{
		csTxt += _T("读取注册表启动项：失败\r\n");
	}
	SetDlgItemText(IDC_EDIT1, csTxt);
}

void CAntiPandaDlg::OnBnClickedButtonDelini()
{
	// TODO: 在此添加控件通知处理程序代码
	// 删除setup.exe、autorun.inf、Desktop_.ini
	BOOL bRet = FALSE;
	char szDriverString[MAXBYTE] = { 0 };
	char *pTmp = NULL;
	// 1 获取驱动器列表（之间用0隔开，最后0结尾
	GetLogicalDriveStrings(MAXBYTE, szDriverString);
	pTmp = szDriverString;
	// 2 每次取出一个（0相隔
	while (*pTmp)
	{
		// 3 构造绝对路径
		char szAutorunPath[MAX_PATH] = { 0 };
		char szSetupPath[MAX_PATH] = { 0 };
		lstrcat(szAutorunPath, pTmp);
		lstrcat(szAutorunPath, "autorun.inf");
		lstrcat(szSetupPath, pTmp);
		lstrcat(szSetupPath, "setup.exe");
		// 4 查找文件
		if (GetFileAttributes(szSetupPath) == 0xFFFFFFFF)
		{
			csTxt += pTmp;
			csTxt += _T("  未发现：setup.exe文件\r\n");
			SetDlgItemText(IDC_EDIT1, csTxt);
		}
		else
		{
			csTxt += pTmp;
			csTxt += _T("  发现：setup.exe文件");
			SetDlgItemText(IDC_EDIT1, csTxt);
			// 4 打开文件获取内容
			HANDLE hFile = CreateFile(szSetupPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				AfxMessageBox("Create Error");
				return;
			}
			DWORD dwSize = GetFileSize(hFile, NULL);
			if (dwSize == 0xFFFFFFFF)
			{
				AfxMessageBox("GetFileSize Error");
				return;
			}
			BYTE *pFile = (BYTE*)malloc(dwSize);
			if (pFile == NULL)
			{
				AfxMessageBox("malloc Error");
				return;
			}
			DWORD dwNum = 0;
			ReadFile(hFile, pFile, dwSize, &dwNum, NULL);
			// 5 计算文件散列值
			DWORD dwCrc32 = GenerateCRC32(pFile, dwSize);
			if (pFile != NULL)
			{
				free(pFile);
				pFile = NULL;
			}
			CloseHandle(hFile);
			// 6 通过散列值判断是否是目标文件
			if (dwCrc32 == 0xE334747C || dwCrc32 == 0xF7C3654D)
			{
				// 7 去除文件的隐藏、系统以及只读属性
				DWORD dwFileAttributes = GetFileAttributes(szSetupPath);
				dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
				dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
				dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
				SetFileAttributes(szSetupPath, dwFileAttributes);
				// 8 删除setup.exe
				bRet = DeleteFile(szSetupPath);
				if (bRet)
				{
					csTxt += pTmp;
					csTxt += _T("  setup.exe文件删除：成功\r\n");
				}
				else
				{
					csTxt += pTmp;
					csTxt += _T("  setup.exe文件删除：失败\r\n");
				}
				SetDlgItemText(IDC_EDIT1, csTxt);
			}
		}
		// 9 去除文件的隐藏、系统以及只读属性
		DWORD dwFileAttributes = GetFileAttributes(szAutorunPath);
		dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
		dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
		dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
		SetFileAttributes(szAutorunPath, dwFileAttributes);
		// 10 删除autorun.inf（在这认为:删除失败就是不存在
		bRet = DeleteFile(szAutorunPath);
		csTxt += pTmp;
		if (bRet)
			csTxt += _T("  autorun.inf：删除成功\r\n");
		else
			csTxt += _T("  未发现：autorun.inf文件\r\n");
		SetDlgItemText(IDC_EDIT1, csTxt);
		// 11 删除Desktop_.ini
		DeleteIniFile(pTmp);
		//fileList(pTmp);
		// 12 检查下一个盘符
		pTmp += 4;// 'C://'4个字符
	}
}

void CAntiPandaDlg::OnBnClickedButtonRepairfile()
{
	// TODO: 在此添加控件通知处理程序代码
	//AfxMessageBox("正在开发");

	BOOL bRet = FALSE;
	char szDriverString[MAXBYTE] = { 0 };
	// 1 获取驱动器列表（之间用0隔开，最后0结尾
	GetLogicalDriveStrings(MAXBYTE, szDriverString);
	char *pTmp = szDriverString;
	// 2 每次取出一个（0相隔
	while (*pTmp)
	{
		//FindFiles2(pTmp);
		std::shared_ptr<std::vector<std::string> > folder_files;
		//folder_files = fileList(pTmp);
		//GetFile(tmp);
		folder_files=QueryFileCounts(pTmp);
		if (folder_files)
		{
			for (size_t i = 0; i != folder_files->size(); ++i)
			{
				//std::cout << i + 1 << " : " << (*folder_files)[i] << std::endl;
				//打开文件获取内容
				DWORD dwNum = 0;
				//char szTargetPath[MAX_PATH] = "C:\\Users\\ry1yn\\Desktop\\AutoRuns.ex";
				//char szTargetPath[MAX_PATH] = { (char )(*folder_files)[i].c_str() };
				HANDLE hFile = CreateFile((*folder_files)[i].c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				DWORD dwTotalSize = GetFileSize(hFile, NULL);
				char *pFile = (char*)malloc(dwTotalSize);
				ReadFile(hFile, pFile, dwTotalSize, &dwNum, NULL);
				//若找到 WhBoy且位置大于病毒大小，则是感染标志，则文件被感染
				if (IsInfected(pFile, dwNum, "WhBoy", 5))
				{
					// 将原文件读取到内存
					DWORD dwRead = 0;
					// 标记信息长度: strlen(szTargetPath)求的是绝对路径的长度，而非文件名,程序后面一堆0，少几个没事
					WORD dwSignLen = 5 + strlen((*folder_files)[i].c_str()) + 12;// whboy + 程序名 + .exe.xxxxxx
					DWORD dwNormalSize = dwTotalSize - 0x7531 - dwSignLen;// 总大小-病毒大小
					BYTE *pFileBuff = (BYTE*)malloc(dwNormalSize);
					SetFilePointer(hFile, 0x7531, NULL, FILE_BEGIN);//将文件指针指向病毒结尾，即原文件开头
					ReadFile(hFile, pFileBuff, dwNormalSize, &dwRead, NULL);
					CloseHandle(hFile);
					// 恢复文件
					DeleteFile((*folder_files)[i].c_str());//先删除被感染的，再创建新的，来存放原文件内容
					HANDLE hsFile = CreateFile((*folder_files)[i].c_str(),
						GENERIC_WRITE, FILE_SHARE_READ, NULL,
						CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					if (hsFile != INVALID_HANDLE_VALUE) // 如果创建成功
					{
						// 将内容写入到原文件（暂没去掉尾部特征，其不影响程序运行
						BOOL bRet = WriteFile(hsFile, pFileBuff, dwNormalSize, &dwRead, NULL);//here
						if (bRet == 0)
						{
							csTxt += (*folder_files)[i].c_str();
							csTxt += _T(": 修复失败 \r\n");
						}
						else
						{
							csTxt += (*folder_files)[i].c_str();
							csTxt += _T(": 修复成功 \r\n");
						}
						SetDlgItemText(IDC_EDIT1, csTxt);
					}
					CloseHandle(hsFile);
				}
			}

		}
		// 检查下一个盘符
		pTmp += 4;// 'C://'4个字符
	}
	csTxt += _T(" 操作完成\r\n");
	SetDlgItemText(IDC_EDIT1, csTxt);
}

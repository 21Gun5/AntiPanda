
// AntiPandaDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "AntiPanda.h"
#include "AntiPandaDlg.h"
#include "afxdialogex.h"
#include "Func.h"

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
	// 1 结束病毒进程spo0
	BOOL bIsFindVirusProcess = FALSE;
	DWORD dwPid = 0;
	bIsFindVirusProcess = FindTargetProcess("spo0lsv.exe", &dwPid);
	//bIsFindVirusProcess = FindTargetProcess("notepad.exe", &dwPid);
	if (bIsFindVirusProcess == TRUE)
	{
		csTxt = _T("遍历进程\r\n");
		csTxt += _T("发现病毒进程:spoclsv.exe\r\n");
		csTxt += _T("准备查杀\r\n");
		SetDlgItemText(IDC_EDIT1, csTxt);
		// 提升权限
		bIsFindVirusProcess = EnableDebugPrivilege(SE_DEBUG_NAME);
		if (bIsFindVirusProcess == FALSE)
		{
			csTxt += _T("提升权限失败\r\n");
		}
		else
		{
			csTxt += _T("提升权限成功！\r\n");
		}
		SetDlgItemText(IDC_EDIT1, csTxt);
		// 打开并尝试结束病毒进程
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (hProcess == INVALID_HANDLE_VALUE)
		{
			csTxt += _T("无法结束病毒进程\r\n");
			return;
		}
		bIsFindVirusProcess = TerminateProcess(hProcess, 0);
		if (bIsFindVirusProcess == FALSE)
		{
			csTxt += _T("无法结束病毒进程\r\n");
			return;
		}
		csTxt += _T("病毒进程已经结束\r\n");
		SetDlgItemText(IDC_EDIT1, csTxt);
		CloseHandle(hProcess);
	}
	else
	{
		csTxt += _T("未发现spoclsv.exe病毒进程\r\n");
	}
	// 2 删除病毒文件spo0
	Sleep(10);
	char szSysPath[MAX_PATH] = { 0 };
	GetSystemDirectory(szSysPath, MAX_PATH);
	lstrcat(szSysPath, "\\drivers\\spo0lsv.exe");
	csTxt += _T("检查硬盘中是否存在spo0lsv.exe文件...\r\n");
	if (GetFileAttributes(szSysPath) == 0xFFFFFFFF)
	{
		csTxt += _T("spoclsv.exe病毒文件不存在\r\n");
	}
	else
	{
		csTxt += _T("spoclsv.exe病毒文件存在，正在计算散列值\r\n");
		HANDLE hFile = CreateFile(szSysPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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
		// 计算spoclsv.exe的散列值
		DWORD dwCrc32 = CRC32(pFile, dwSize);
		if (pFile != NULL)
		{
			free(pFile);
			pFile = NULL;
		}
		CloseHandle(hFile);
		// 0x89240FCD是“熊猫烧香”病毒的散列值

		if (dwCrc32 == 0xE334747C || dwCrc32 == 0xF7C3654D)//E334747C //F7C3654D
		{
			csTxt += _T("spoclsv.exe校验和验证成功，正在删除...\r\n");
			// 去除文件的隐藏、系统以及只读属性
			DWORD dwFileAttributes = GetFileAttributes(szSysPath);
			dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
			dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
			dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
			SetFileAttributes(szSysPath, dwFileAttributes);
			// 删除spoclsv.exe
			bIsFindVirusProcess = DeleteFile(szSysPath);
			if (bIsFindVirusProcess)
			{
				csTxt += _T("spoclsv.exe病毒被删除！\r\n");
			}
			else
			{
				csTxt += _T("spoclsv.exe病毒无法删除\r\n");
			}
		}
		else
		{
			csTxt += _T("spoclsv.exe校验和验证失败\r\n");
		}
	}
	SetDlgItemText(IDC_EDIT1, csTxt);
	Sleep(10);

	//  3 删除每个盘符下的setup.exe与autorun.inf，以及Desktop_.ini
	char szDriverString[MAXBYTE] = { 0 };
	char *pTmp = NULL;
	//获取字符串类型的驱动器列表  
	GetLogicalDriveStrings(MAXBYTE, szDriverString);
	pTmp = szDriverString;
	while (*pTmp)
	{
		char szAutorunPath[MAX_PATH] = { 0 };
		char szSetupPath[MAX_PATH] = { 0 };
		lstrcat(szAutorunPath, pTmp);
		lstrcat(szAutorunPath, "autorun.inf");
		lstrcat(szSetupPath, pTmp);
		lstrcat(szSetupPath, "setup.exe");

		if (GetFileAttributes(szSetupPath) == 0xFFFFFFFF)
		{
			csTxt += pTmp;
			csTxt += _T("setup.exe病毒文件不存在\r\n");
		}
		else
		{
			csTxt += pTmp;
			csTxt += _T("setup.exe病毒文件存在，正在进行计算校验和...\r\n");
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

			DWORD dwCrc32 = CRC32(pFile, dwSize);
			if (pFile != NULL)
			{
				free(pFile);
				pFile = NULL;
			}
			CloseHandle(hFile);

			if (dwCrc32 == 0xE334747C || dwCrc32 == 0xF7C3654D)
			{
				csTxt += _T("校验和验证成功，正在删除...\r\n");
				// 去除文件的隐藏、系统以及只读属性
				DWORD dwFileAttributes = GetFileAttributes(szSetupPath);
				dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
				dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
				dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
				SetFileAttributes(szSetupPath, dwFileAttributes);
				// 删除setup.exe
				bIsFindVirusProcess = DeleteFile(szSetupPath);
				if (bIsFindVirusProcess)
				{
					csTxt += pTmp;
					csTxt += _T("setup.exe病毒被删除!\r\n");
				}
				else
				{
					csTxt += pTmp;
					csTxt += _T("setup.exe病毒无法删除\r\n");
				}
			}
			else
			{
				csTxt += _T("校验和验证失败\r\n");
			}
		}
		// 去除文件的隐藏、系统以及只读属性
		DWORD dwFileAttributes = GetFileAttributes(szAutorunPath);
		dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
		dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
		dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
		SetFileAttributes(szAutorunPath, dwFileAttributes);
		// 删除autorun.inf
		bIsFindVirusProcess = DeleteFile(szAutorunPath);
		csTxt += pTmp;
		if (bIsFindVirusProcess)
		{
			csTxt += _T("autorun.inf被删除!\r\n");
		}
		else
		{
			csTxt += _T("autorun.inf不存在或无法删除\r\n");
		}
		// 删除Desktop_.ini
		FindFiles(pTmp);
		// 检查下一个盘符
		pTmp += 4;
	}
	Sleep(10);

	// 4 修复注册表内容，删除病毒启动项并修复文件的隐藏显示
	csTxt += _T("正在检查注册表...\r\n");
	SetDlgItemText(IDC_EDIT1, csTxt);
	// 首先检查启动项
	char RegRun[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	HKEY hKeyHKCU = NULL;
	LONG lSize = MAXBYTE;
	char cData[MAXBYTE] = { 0 };

	long lRet = RegOpenKey(HKEY_CURRENT_USER, RegRun, &hKeyHKCU);
	if (lRet == ERROR_SUCCESS)
	{
		lRet = RegQueryValueEx(hKeyHKCU, "svcshare", NULL, NULL, (unsigned char *)cData, (unsigned long *)&lSize);
		if (lRet == ERROR_SUCCESS)
		{
			if (lstrcmp(cData, "C:\\WINDOWS\\system32\\drivers\\spoclsv.exe") == 0)
			{
				csTxt += _T("注册表启动项中存在病毒信息\r\n");
			}

			lRet = RegDeleteValue(hKeyHKCU, "svcshare");
			if (lRet == ERROR_SUCCESS)
			{
				csTxt += _T("注册表启动项中的病毒信息已删除！\r\n");
			}
			else
			{
				csTxt += _T("注册表启动项中的病毒信息无法删除\r\n");
			}
		}
		else
		{
			csTxt += _T("注册表启动项中不存在病毒信息\r\n");
		}
		RegCloseKey(hKeyHKCU);
	}
	else
	{
		csTxt += _T("注册表启动项信息读取失败\r\n");
	}
	// 接下来修复文件的隐藏显示，需要将CheckedValue的值设置为1
	char RegHide[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL";
	HKEY hKeyHKLM = NULL;
	DWORD dwFlag = 1;

	long lRetHide = RegOpenKey(HKEY_LOCAL_MACHINE, RegHide, &hKeyHKLM);
	if (lRetHide == ERROR_SUCCESS)
	{
		csTxt += _T("检测注册表的文件隐藏选项...\r\n");
		if (ERROR_SUCCESS == RegSetValueEx(
			hKeyHKLM,             //subkey handle  
			"CheckedValue",       //value name  
			0,                    //must be zero  
			REG_DWORD,            //value type  
			(CONST BYTE*)&dwFlag, //pointer to value data  
			4))                   //length of value data
		{
			csTxt += _T("注册表修复完毕！\r\n");
		}
		else
		{
			csTxt += _T("无法恢复注册表的文件隐藏选项\r\n");
		}
	}

	// 病毒查杀完成
	csTxt += _T("病毒查杀完成，请使用专业杀毒软件进行全面扫描！\r\n");
	SetDlgItemText(IDC_EDIT1, csTxt);

}

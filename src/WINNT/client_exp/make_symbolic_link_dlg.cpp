/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include "stdafx.h"
#include <winsock2.h>
#include <ws2tcpip.h>

extern "C" {
#include <afs/param.h>
#include <afs/stds.h>
}

#include "afs_shl_ext.h"
#include "make_symbolic_link_dlg.h"
#include "gui2fs.h"
#include "msgs.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CMakeMountPointDlg dialog


CMakeSymbolicLinkDlg::CMakeSymbolicLinkDlg(CWnd* pParent /*=NULL*/)
	: CDialog()
{
	InitModalIndirect (TaLocale_GetDialogResource (CMakeSymbolicLinkDlg::IDD), pParent);

	//{{AFX_DATA_INIT(CMakeSymbolicLinkDlg)
	m_strName = _T("");
	m_strDir = _T("");
	//}}AFX_DATA_INIT
}


void CMakeSymbolicLinkDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CMakeSymbolicLinkDlg)
	DDX_Control(pDX, IDOK, m_OK);
	DDX_Control(pDX, IDC_NAME, m_Name);
	DDX_Control(pDX, IDC_DIR, m_Dir);
	DDX_Text(pDX, IDC_NAME, m_strName);
	DDV_MaxChars(pDX, m_strName, 63);
	DDX_Text(pDX, IDC_DIR, m_strDir);
	DDV_MaxChars(pDX, m_strDir, 255);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CMakeSymbolicLinkDlg, CDialog)
	//{{AFX_MSG_MAP(CMakeSymbolicLinkDlg)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CMakeSymbolicLinkDlg message handlers

void CMakeSymbolicLinkDlg::OnOK()
{
    UINT code;
    UpdateData(TRUE);
    CString strName;
    CString strTarget;
    m_Name.GetWindowText(strName);
    m_Dir.GetWindowText(strTarget);
    if (!IsPathInAfs(m_sBase)) {
        MessageBeep((UINT)-1);
        strTarget+=" - Path is not in AFS directory";
        AfxMessageBox(strTarget,MB_ICONERROR);
        return;
    }
    if (m_sBase.GetLength()>MAX_PATH-2)
    {
        MessageBeep((UINT)-1);
        ShowMessageBox(IDS_CURRENT_DIRECTORY_PATH_TOO_LONG,MB_ICONERROR,IDS_CURRENT_DIRECTORY_PATH_TOO_LONG);
    }
    if (!SetCurrentDirectory(m_sBase))
    {
        MessageBeep((UINT)-1);
        ShowMessageBox(IDS_UNABLE_TO_SET_CURRENT_DIRECTORY,MB_ICONERROR,IDS_UNABLE_TO_SET_CURRENT_DIRECTORY);
        return;
    }
    if ((code=MakeSymbolicLink(strName,strTarget))!=0){
        MessageBeep((UINT)-1);
        ShowMessageBox(IDS_UNABLE_TO_CREATE_SYMBOLIC_LINK,MB_ICONERROR,IDS_UNABLE_TO_CREATE_SYMBOLIC_LINK,GetAfsError(code, strName));
        return;
    }
    CDialog::OnOK();
}
/*
void CMakeSymbolicLinkDlg::OnChangeName()
{
	CString strName;
	m_Name.GetWindowText(strName);
	if (strName.GetLength() > 63) {
		MessageBeep((UINT)-1);
		m_Name.SetWindowText(m_strName);
	} else
		m_strName = strName;
	CheckEnableOk();
}

void CMakeSymbolicLinkDlg::OnChangeDir()
{
	m_Dir.GetWindowText(m_strDir);
    if (!IsPathInAfs(m_strDir)) {
		MessageBeep((UINT)-1);
		m_Dir.SetWindowText(m_strDir);
	}
	CheckEnableOk();
}
*/
void CMakeSymbolicLinkDlg::CheckEnableOk()
{
	BOOL bEnable = FALSE;

	if ((m_strName.GetLength() > 0) && (m_strDir.GetLength() > 0))
		bEnable = TRUE;

	m_OK.EnableWindow(bEnable);
}

BOOL CMakeSymbolicLinkDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	m_Dir.SetWindowText(m_strDir);
	m_Name.SetWindowText(m_strName);
	UpdateData(FALSE);

	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afxpriv.h>
#include "stdafx.h"
#include "PropFile.h"
#include "PropACL.h"
#include "PropVolume.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shtypes.h>
#include <shlwapi.h>

extern "C" {
#include <afs/param.h>
#include <afs/stds.h>
#include <afs/afs_consts.h>
}

#include <atlconv.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "afs_shl_ext.h"
#include "shell_ext.h"
#include "volume_info.h"
#include "set_afs_acl.h"
#include "gui2fs.h"
#include "make_mount_point_dlg.h"
#include "msgs.h"
#include "server_status_dlg.h"
#include "auth_dlg.h"
#include "submounts_dlg.h"
#include "make_symbolic_link_dlg.h"
#include <WINNT\afsreg.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")


ULONG nCMRefCount = 0;	// IContextMenu ref count
ULONG nSERefCount = 0;	// IShellExtInit ref count
ULONG nICRefCount=0;
ULONG nTPRefCount=0;
ULONG nXPRefCount=0;
UINT nPSRefCount=0;

#define PCCHAR(str)	((char *)(const char *)str)
static char space[AFS_PIOCTL_MAXSIZE];

static BOOL IsADir(const CString& strName)
{
    struct _stat statbuf;

    if (_tstat(strName, &statbuf) < 0)
	return FALSE;

    return statbuf.st_mode & _S_IFDIR;
}

/////////////////////////////////////////////////////////////////////////////
// CShellExt

IMPLEMENT_DYNCREATE(CShellExt, CCmdTarget)
IMPLEMENT_DYNCREATE(CShellExt2, CCmdTarget)
#define REG_CLIENT_PARMS_KEY    "SYSTEM\\CurrentControlSet\\Services\\TransarcAFSDaemon\\Parameters"
#define OVERLAYENABLED 1

CShellExt::CShellExt()
{
    HKEY NPKey;
    EnableAutomation();
    nCMRefCount++;
    HRESULT hr;
    UINT code;
    DWORD ShellOption,LSPsize,LSPtype;
    m_overlayObject = 0;
    hr = SHGetMalloc(&m_pAlloc);
    m_bIsOverlayEnabled=FALSE;
    if (FAILED(hr))
	m_pAlloc = NULL;
    RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PARAM_SUBKEY,0, (IsWow64()?KEY_WOW64_64KEY:0)|KEY_QUERY_VALUE, &NPKey);
    LSPsize=sizeof(ShellOption);
    code=RegQueryValueEx(NPKey, _T("ShellOption"), NULL,
			  &LSPtype, (LPBYTE)&ShellOption, &LSPsize);
    RegCloseKey (NPKey);
    m_bIsOverlayEnabled=((code==0) && (LSPtype==REG_DWORD) && ((ShellOption & OVERLAYENABLED)!=0));

    INITCOMMONCONTROLSEX used = {
        sizeof(INITCOMMONCONTROLSEX),
        ICC_DATE_CLASSES | ICC_WIN95_CLASSES | ICC_BAR_CLASSES | ICC_USEREX_CLASSES
    };
    InitCommonControlsEx(&used);

    TRACE("Create CShellExt, Ref count %d/n",nCMRefCount);
}

CShellExt::~CShellExt()
{
    if(m_pAlloc)
	m_pAlloc->Release();
    nCMRefCount--;
    TRACE("Destroy CShellExt, Ref count %d/n",nCMRefCount);
}


void CShellExt::OnFinalRelease()
{
    // When the last reference for an automation object is released
    // OnFinalRelease is called.  The base class will automatically
    // deletes the object.  Add additional cleanup required for your
    // object before calling the base class.

    CCmdTarget::OnFinalRelease();
}


BEGIN_MESSAGE_MAP(CShellExt, CCmdTarget)
    //{{AFX_MSG_MAP(CShellExt)
    // NOTE - the ClassWizard will add and remove mapping macros here.
    //}}AFX_MSG_MAP
END_MESSAGE_MAP()

BEGIN_DISPATCH_MAP(CShellExt, CCmdTarget)
    //{{AFX_DISPATCH_MAP(CShellExt)
    // NOTE - the ClassWizard will add and remove mapping macros here.
    //}}AFX_DISPATCH_MAP
END_DISPATCH_MAP()

// Note: we add support for IID_IShellExt to support typesafe binding
//  from VBA.  This IID must match the GUID that is attached to the
//  dispinterface in the .ODL file.

#ifndef _WIN64
// 32-bit
// {DC515C27-6CAC-11D1-BAE7-00C04FD140D2}
static const IID IID_IShellExt =
{ 0xdc515c27, 0x6cac, 0x11d1, { 0xba, 0xe7, 0x0, 0xc0, 0x4f, 0xd1, 0x40, 0xd2 } };
static const IID IID_IShellExt2 =
{ 0xdc515c27, 0x6cac, 0x11d1, { 0xba, 0xe7, 0x0, 0xc0, 0x4f, 0xd1, 0x40, 0xd3 } };
#else
// 64-bit
// {5f820ca1-3dde-11db-b2ce-001558092db5}
static const IID IID_IShellExt =
{ 0x5f820ca1, 0x3dde, 0x11db, {0xb2, 0xce, 0x00, 0x15, 0x58, 0x09, 0x2d, 0xb5 } };
static const IID IID_IShellExt2 =
{ 0x5f820ca1, 0x3dde, 0x11db, {0xb2, 0xce, 0x00, 0x15, 0x58, 0x09, 0x2d, 0xb6 } };
#endif

BEGIN_INTERFACE_MAP(CShellExt, CCmdTarget)
    INTERFACE_PART(CShellExt, IID_IShellExt, Dispatch)
    INTERFACE_PART(CShellExt, IID_IContextMenu, MenuExt)
    INTERFACE_PART(CShellExt, IID_IShellExtInit, ShellInit)
    INTERFACE_PART(CShellExt, IID_IShellIconOverlayIdentifier, IconExt)
    INTERFACE_PART(CShellExt, IID_IQueryInfo , ToolTipExt)
    INTERFACE_PART(CShellExt, IID_IPersistFile , PersistFileExt)
    INTERFACE_PART(CShellExt, IID_IShellPropSheetExt , PropertySheetExt)
END_INTERFACE_MAP()

#ifndef _WIN64
    // 32-bit
IMPLEMENT_OLECREATE(CShellExt, _STR_EXT_TITLE, 0xdc515c27, 0x6cac, 0x11d1, 0xba, 0xe7, 0x0, 0xc0, 0x4f, 0xd1, 0x40, 0xd2)
IMPLEMENT_OLECREATE(CShellExt2, _STR_EXT_TITLE, 0xdc515c27, 0x6cac, 0x11d1, 0xba, 0xe7, 0x0, 0xc0, 0x4f, 0xd1, 0x40, 0xd3)
#else
    // 64-bit
IMPLEMENT_OLECREATE(CShellExt, _STR_EXT_TITLE, 0x5f820ca1, 0x3dde, 0x11db, 0xb2, 0xce, 0x0, 0x15, 0x58, 0x09, 0x2d, 0xb5)
IMPLEMENT_OLECREATE(CShellExt2, _STR_EXT_TITLE, 0x5f820ca1, 0x3dde, 0x11db, 0xb2, 0xce, 0x0, 0x15, 0x58, 0x09, 0x2d, 0xb6)
#endif


/////////////////////////////////////////////////////////////////////////////
// CShellExt message handlers
/////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
// IUnknown for IContextMenu
/////////////////////////////////////////////////////////////////////////////
STDMETHODIMP CShellExt::XMenuExt::QueryInterface(REFIID riid, void** ppv)
{
    METHOD_PROLOGUE(CShellExt, MenuExt);

    return pThis->ExternalQueryInterface(&riid, ppv);
}

STDMETHODIMP_(ULONG) CShellExt::XMenuExt::AddRef(void)
{
    return ++nCMRefCount;
}

STDMETHODIMP_(ULONG) CShellExt::XMenuExt::Release(void)
{
    if (nCMRefCount > 0)
	nCMRefCount--;

    return nCMRefCount;
}

/////////////////////////////////////////////////////////////////////////////
// IConextMenu Functions
/////////////////////////////////////////////////////////////////////////////
STDMETHODIMP CShellExt::XMenuExt::QueryContextMenu(HMENU hMenu,UINT indexMenu,
						   UINT idCmdFirst, UINT idCmdLast,UINT uFlags)
{
    METHOD_PROLOGUE(CShellExt, MenuExt);

    // Don't add any menu items if we're being asked to deal with this file as a shortcut.
    if (uFlags & CMF_VERBSONLY)
	return MAKE_HRESULT(SEVERITY_SUCCESS, FACILITY_NULL, (USHORT)0);

    if (!pThis->m_bIsPathInAFS)
	return MAKE_HRESULT(SEVERITY_SUCCESS, FACILITY_NULL, (USHORT)0);

    // Check to see if there's already an AFS menu here; if so, remove it
    int nItemsNow = GetMenuItemCount (hMenu);
    CString strAfsItemText = GetMessageString(IDS_AFS_ITEM);
    CString strDeleteText = GetMessageString(IDS_MENU_DELETE);
    CString strCutText = GetMessageString(IDS_MENU_CUT);
    LPCTSTR pszAfsItemText = (LPCTSTR)strAfsItemText;
    for (int iItem = 0; iItem < nItemsNow; iItem++) {
	TCHAR szItemText[256];
	if (!GetMenuString (hMenu, iItem, szItemText, 256, MF_BYPOSITION))
	    continue;
	if (lstrcmp (szItemText, pszAfsItemText)==0) {
	    DeleteMenu (hMenu, iItem, MF_BYPOSITION);
	    continue;
	}
	if (((lstrcmp(szItemText,strDeleteText)==0)||(lstrcmp(szItemText,strCutText)==0))&&((pThis->m_bIsSymlink)||(pThis->m_bIsMountpoint))) {
        DeleteMenu (hMenu, iItem, MF_BYPOSITION);
	    continue;
	}
    }
    int indexShellMenu = 0;

    // Create the AFS submenu using the allowed ID's.
    HMENU hAfsMenu = CreatePopupMenu();
    int indexAfsMenu = 0;

    // Only enable the ACL menu item if a single directory is selected
    int nSingleDirOnly = MF_GRAYED;
    if (pThis->m_bDirSelected && (pThis->m_astrFileNames.GetSize() == 1))
	nSingleDirOnly = MF_ENABLED;
    ::InsertMenu(hAfsMenu, indexAfsMenu++, MF_STRING | MF_BYPOSITION | nSingleDirOnly, idCmdFirst + IDM_ACL_SET, GetMessageString(IDS_ACLS_ITEM));

    // Volume/Partition submenu of the AFS submenu
    HMENU hVolPartMenu = CreatePopupMenu();
    int indexVolPartMenu = 0;
    ::InsertMenu(hVolPartMenu, indexVolPartMenu++, MF_STRING | MF_BYPOSITION, idCmdFirst + IDM_VOLUME_PROPERTIES, GetMessageString(IDS_VOL_PART_PROPS_ITEM));
    ::InsertMenu(hVolPartMenu, indexVolPartMenu++, MF_STRING | MF_BYPOSITION, idCmdFirst + IDM_VOLUMEPARTITION_UPDATENAMEIDTABLE, GetMessageString(IDS_VOL_PART_REFRESH_ITEM));
    ::InsertMenu(hAfsMenu, indexAfsMenu++, MF_STRING | MF_BYPOSITION | MF_POPUP, (UINT)hVolPartMenu, GetMessageString(IDS_VOL_PART_ITEM));

    // Mount Point submenu of the AFS submenu
    HMENU hMountPointMenu = CreatePopupMenu();
    int indexMountPointMenu = 0;
    int nMountPointSelected = MF_GRAYED;
    for (int n = pThis->m_astrFileNames.GetSize() - 1 ; n >= 0; n--) {
	if ( IsMountPoint(pThis->m_astrFileNames[n]) ) {
	    nMountPointSelected = MF_ENABLED;
	    break;
	}
    }
    ::InsertMenu(hMountPointMenu, indexMountPointMenu++, MF_STRING | MF_BYPOSITION, idCmdFirst + IDM_MOUNTPOINT_SHOW, GetMessageString(IDS_MP_SHOW_ITEM));
    ::InsertMenu(hMountPointMenu, indexMountPointMenu++, MF_STRING | MF_BYPOSITION | nMountPointSelected, idCmdFirst + IDM_MOUNTPOINT_REMOVE, GetMessageString(IDS_MP_REMOVE_ITEM));
    ::InsertMenu(hMountPointMenu, indexMountPointMenu++, MF_STRING | MF_BYPOSITION, idCmdFirst + IDM_MOUNTPOINT_MAKE, GetMessageString(IDS_MP_MAKE_ITEM));
    ::InsertMenu(hAfsMenu, indexAfsMenu++, MF_STRING | MF_BYPOSITION | MF_POPUP, (UINT)hMountPointMenu, GetMessageString(IDS_MOUNT_POINT_ITEM));

    ::InsertMenu(hAfsMenu, indexAfsMenu++, MF_STRING | MF_BYPOSITION, idCmdFirst + IDM_FLUSH, GetMessageString(IDS_FLUSH_FILE_DIR_ITEM));
    ::InsertMenu(hAfsMenu, indexAfsMenu++, MF_STRING | MF_BYPOSITION, idCmdFirst + IDM_FLUSH_VOLUME, GetMessageString(IDS_FLUSH_VOLUME_ITEM));
    ::InsertMenu(hAfsMenu, indexAfsMenu++, MF_STRING | MF_BYPOSITION, idCmdFirst + IDM_SHOW_SERVER, GetMessageString(IDS_SHOW_FILE_SERVERS_ITEM));
    ::InsertMenu(hAfsMenu, indexAfsMenu++, MF_STRING | MF_BYPOSITION, idCmdFirst + IDM_SHOWCELL, GetMessageString(IDS_SHOW_CELL_ITEM));
    ::InsertMenu(hAfsMenu, indexAfsMenu++, MF_STRING | MF_BYPOSITION, idCmdFirst + IDM_SERVER_STATUS, GetMessageString(IDS_SHOW_SERVER_STATUS_ITEM));

    HMENU hSymbolicMenu = CreatePopupMenu();
    int indexSymbolicMenu = 0;
    int nSymlinkSelected = MF_GRAYED;
    for (int n = pThis->m_astrFileNames.GetSize() - 1 ; n >= 0; n--) {
	if ( IsSymlink(pThis->m_astrFileNames[n]) ) {
	    nSymlinkSelected = MF_ENABLED;
	    break;
	}
    }

    ::InsertMenu(hSymbolicMenu, indexSymbolicMenu++, MF_STRING | MF_BYPOSITION, idCmdFirst + IDM_SYMBOLICLINK_ADD, GetMessageString(IDS_SYMBOLICLINK_ADD));
    ::InsertMenu(hSymbolicMenu, indexSymbolicMenu++, MF_STRING | MF_BYPOSITION | nSymlinkSelected, idCmdFirst + IDM_SYMBOLICLINK_SHOW, GetMessageString(IDS_SYMBOLICLINK_SHOW));
    ::InsertMenu(hSymbolicMenu, indexSymbolicMenu++, MF_STRING | MF_BYPOSITION | nSymlinkSelected, idCmdFirst + IDM_SYMBOLICLINK_REMOVE, GetMessageString(IDS_SYMBOLICLINK_REMOVE));
    ::InsertMenu(hAfsMenu, indexAfsMenu++, MF_STRING | MF_BYPOSITION | MF_POPUP, (UINT)hSymbolicMenu, GetMessageString(IDS_SYMBOLIC_LINK_ITEM));

    // The Submounts menu has been removed because the AFS tray icon
    // and control panel now support mapping drives directly to an AFS
    // path.
    //
    //HMENU hSubmountMenu = CreatePopupMenu();
    //int indexSubmountMenu = 0;
    //::InsertMenu(hSubmountMenu, indexSubmountMenu++, MF_STRING | MF_BYPOSITION | nSingleDirOnly, idCmdFirst + IDM_SUBMOUNTS_CREATE, GetMessageString(IDS_SUBMOUNTS_CREATE_ITEM));
    //::InsertMenu(hSubmountMenu, indexSubmountMenu++, MF_STRING | MF_BYPOSITION, idCmdFirst + IDM_SUBMOUNTS_EDIT, GetMessageString(IDS_SUBMOUNTS_EDIT_ITEM));
    //::InsertMenu(hAfsMenu, indexAfsMenu++, MF_STRING | MF_BYPOSITION | MF_POPUP, (UINT)hSubmountMenu, GetMessageString(IDS_SUBMOUNTS_ITEM));

    // Add a separator
    ::InsertMenu (hMenu, indexMenu + indexShellMenu++, MF_STRING | MF_BYPOSITION | MF_SEPARATOR, 0, TEXT(""));

    // Add the AFS submenu to the shell's menu
    ::InsertMenu(hMenu, indexMenu + indexShellMenu++, MF_STRING | MF_BYPOSITION | MF_POPUP, (UINT)hAfsMenu, GetMessageString(IDS_AFS_ITEM));

    // Add a separator after us
    ::InsertMenu (hMenu, indexMenu + indexShellMenu++, MF_STRING | MF_BYPOSITION | MF_SEPARATOR, 0, TEXT(""));

    return MAKE_HRESULT(SEVERITY_SUCCESS, FACILITY_NULL,
			 (USHORT)indexAfsMenu + indexVolPartMenu + indexMountPointMenu + indexShellMenu + indexSymbolicMenu);
}

STDMETHODIMP CShellExt::XMenuExt::InvokeCommand(LPCMINVOKECOMMANDINFO lpici)
{
    METHOD_PROLOGUE(CShellExt, MenuExt);

    if (HIWORD(lpici->lpVerb ))
        return E_FAIL;

    AddRef();

    CStringArray &files = pThis->m_astrFileNames;

    switch (LOWORD(lpici->lpVerb))
    {
    case IDM_AUTHENTICATION:	{
	CAuthDlg dlg;
	dlg.DoModal();
	break;
    }

    case IDM_ACL_SET:			{
	CSetAfsAcl dlg;
	ASSERT(files.GetSize() == 1);
	dlg.SetDir(files[0]);
	dlg.DoModal();
	break;
    }

    case IDM_VOLUME_PROPERTIES:	{
	CVolumeInfo dlg;
	dlg.SetFiles(files);
	dlg.DoModal();
	break;
    }

    case IDM_VOLUMEPARTITION_UPDATENAMEIDTABLE:
	CheckVolumes();
	break;

    case IDM_MOUNTPOINT_SHOW:
	ListMount(files);
	break;

    case IDM_MOUNTPOINT_REMOVE:	{
	int nChoice = ShowMessageBox(IDS_REALLY_DEL_MOUNT_POINTS, MB_ICONQUESTION | MB_YESNO, IDS_REALLY_DEL_MOUNT_POINTS);
	if (nChoice == IDYES)
	    RemoveMount(files);
	break;
    }

    case IDM_MOUNTPOINT_MAKE:	{
	CMakeMountPointDlg dlg;
	ASSERT(files.GetSize() == 1);
	dlg.SetDir(files[0]);
	dlg.DoModal();
	break;
    }

    case IDM_FLUSH:
	Flush(files);
	break;

    case IDM_FLUSH_VOLUME:
	FlushVolume(files);
	break;

    case IDM_SHOW_SERVER:
	WhereIs(files);
	break;

    case IDM_SHOWCELL:
	WhichCell(files);
	break;

    case IDM_SERVER_STATUS: {
	CServerStatusDlg dlg;
	dlg.DoModal();
	break;
    }

        /*
	case IDM_SUBMOUNTS_EDIT:	{
	CSubmountsDlg dlg;
	dlg.DoModal();
	break;
	}
	case IDM_SUBMOUNTS_CREATE:	{
	ASSERT(files.GetSize() == 1);
	CSubmountsDlg dlg;
	dlg.SetAddOnlyMode(files[0]);
	dlg.DoModal();
	break;
	}
        */
    case IDM_SYMBOLICLINK_REMOVE: {
	if (files.GetSize()>1)
	    break;
	CString msg=files.GetAt(0);
	int i;
	if ((i=msg.ReverseFind('\\'))>0)
	    msg=msg.Left(i+1);
	else if ((i=msg.ReverseFind(':'))>0)
	    msg=msg.Left(i+1)+"\\";
	if (!SetCurrentDirectory(msg))
	{
	    MessageBeep((UINT)-1);
	    ShowMessageBox(IDS_UNABLE_TO_SET_CURRENT_DIRECTORY,MB_OK,IDS_UNABLE_TO_SET_CURRENT_DIRECTORY);
	    break;
	}
	msg=files.GetAt(0);
	if ((i=msg.ReverseFind('\\'))>0||((i=msg.ReverseFind(':'))>0))
	    msg=msg.Right(msg.GetLength()-i-1);
	int nChoice = ShowMessageBox(IDS_REALLY_REMOVE_SYMLINK, MB_ICONQUESTION | MB_YESNO, IDS_REALLY_REMOVE_SYMLINK,msg);
	if (nChoice == IDYES)
	    RemoveSymlink(files.GetAt(0));
	break;
    }

    case IDM_SYMBOLICLINK_ADD: {
	CStringA msg(files.GetAt(0));
	int i;
	if ((i=msg.ReverseFind('\\'))>0)
	    msg=msg.Left(i+1);
	else if ((i=msg.ReverseFind(':'))>0)
	    msg=msg.Left(i+1)+"\\";
	CMakeSymbolicLinkDlg dlg;
	dlg.Setbase(msg);
	dlg.DoModal();
	break;
    }

    case IDM_SYMBOLICLINK_SHOW:
	ListSymlink(files);
	break;

    case IDM_REMOVE_SYMLINK:	{
	if (files.GetSize()>1)
	    break;
	int nChoice = ShowMessageBox(IDS_REALLY_REMOVE_SYMLINK, MB_ICONQUESTION | MB_YESNO, IDS_REALLY_REMOVE_SYMLINK);
	if (nChoice == IDYES)
	    RemoveSymlink(files.GetAt(0));
	}
	break;
    default:
	ASSERT(FALSE);
	Release();
	return E_INVALIDARG;
    }

    Release();

    return NOERROR;
}

STDMETHODIMP CShellExt::XMenuExt::GetCommandString(UINT_PTR idCmd, UINT uType,
    UINT* pwReserved, LPSTR pszName, UINT cchMax)
{
    if (uType != GCS_HELPTEXT)
	return NOERROR;			// ?????????????????????????????????????????????????

    UINT nCmdStrID;

    AfxSetResourceHandle(theApp.m_hInstance);

    switch (idCmd)
    {
    case IDM_AUTHENTICATION:
	nCmdStrID = ID_AUTHENTICATE;
	break;

    case IDM_ACL_SET:
	nCmdStrID = ID_ACL_SET;
	break;

    case IDM_VOLUME_PROPERTIES:
	nCmdStrID = ID_VOLUME_PROPERTIES;
	break;

    case IDM_VOLUMEPARTITION_UPDATENAMEIDTABLE:
	nCmdStrID = ID_VOLUMEPARTITION_UPDATENAMEIDTABLE;
	break;

    case IDM_MOUNTPOINT_SHOW:
	nCmdStrID = ID_MOUNTPOINT_SHOW;
	break;

    case IDM_MOUNTPOINT_REMOVE:
	nCmdStrID = ID_MOUNTPOINT_REMOVE;
	break;

    case IDM_MOUNTPOINT_MAKE:
	nCmdStrID = ID_MOUNTPOINT_MAKE;
	break;

    case IDM_FLUSH:
	nCmdStrID = ID_FLUSH;
	break;

    case IDM_FLUSH_VOLUME:
	nCmdStrID = ID_VOLUME_FLUSH;
	break;

    case IDM_SHOW_SERVER:
	nCmdStrID = ID_WHEREIS;
	break;

    case IDM_SHOWCELL:
	nCmdStrID = ID_SHOWCELL;
	break;

    case IDM_SERVER_STATUS:
	nCmdStrID = ID_SERVER_STATUS;
	break;

    case IDM_SYMBOLICLINK_ADD:
	nCmdStrID = ID_SYMBOLICLINK_ADD;
	break;

    case IDM_SYMBOLICLINK_SHOW:
	nCmdStrID = ID_SYMBOLICLINK_SHOW;
	break;

    case IDM_SYMBOLICLINK_REMOVE:
	nCmdStrID = ID_SYMBOLICLINK_REMOVE;
	break;

    case IDM_REMOVE_SYMLINK:
	nCmdStrID= ID_REMOVE_SYMLINK;
	break;

    default:
	ASSERT(FALSE);
	Release();
	return E_INVALIDARG;
    }

    CString strMsg;
    LoadString (strMsg, nCmdStrID);

    _tcsncpy((LPTSTR) pszName, strMsg, cchMax);

    return NOERROR;
}

/////////////////////////////////////////////////////////////////////////////
// IUnknown for IShellExtInit
/////////////////////////////////////////////////////////////////////////////
STDMETHODIMP CShellExt::XShellInit::QueryInterface(REFIID riid, void** ppv)
{
    METHOD_PROLOGUE(CShellExt, ShellInit);

    return pThis->ExternalQueryInterface(&riid, ppv);
}

STDMETHODIMP_(ULONG) CShellExt::XShellInit::AddRef(void)
{
    return ++nSERefCount;
}

STDMETHODIMP_(ULONG) CShellExt::XShellInit::Release(void)
{
    if (nSERefCount > 0)
	nSERefCount--;

    return nSERefCount;
}

/////////////////////////////////////////////////////////////////////////////
// IShellInit Functions
/////////////////////////////////////////////////////////////////////////////
STDMETHODIMP CShellExt::XShellInit::Initialize(LPCITEMIDLIST pidlFolder, IDataObject *pdobj, HKEY hkeyProgID)
{
    METHOD_PROLOGUE(CShellExt, ShellInit);

    HRESULT hres = E_FAIL;
    FORMATETC fmte = {CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
    STGMEDIUM medium;

    // We must have a data object
    if ((pdobj == NULL) && (pidlFolder == NULL))
        return E_FAIL;

    pThis->m_bIsSymlink=false;
    pThis->m_bIsMountpoint=false;
    pThis->m_bIsPathInAFS=false;
    pThis->m_bDirSelected=false;

    if (pdobj) {
        //  Use the given IDataObject to get a list of filenames (CF_HDROP)
        hres = pdobj->GetData(&fmte, &medium);
        if (FAILED(hres)) {
        return E_FAIL;
        }

        int nNumFiles = DragQueryFile((HDROP)medium.hGlobal, 0xFFFFFFFF, NULL, 0);
        if (nNumFiles == 0)
            hres = E_FAIL;
        else {
            pThis->m_bDirSelected = FALSE;

            for (int ii = 0; ii < nNumFiles; ii++) {
                CString strFileName;

                // Get the size of the file name string
                int nNameLen = DragQueryFile((HDROP)medium.hGlobal, ii, 0, 0);

                // Make room for it in our string object
                LPTSTR pszFileNameBuf = strFileName.GetBuffer(nNameLen + 1);	// +1 for the terminating NULL
                ASSERT(pszFileNameBuf);

                // Get the file name
                DragQueryFile((HDROP)medium.hGlobal, ii, pszFileNameBuf, nNameLen + 1);

                strFileName.ReleaseBuffer();
                if (!IsPathInAfs(strFileName)) {
                pThis->m_astrFileNames.RemoveAll();
                pThis->m_bIsPathInAFS=false;
                break;
                } else {
                pThis->m_bIsSymlink=pThis->m_bIsSymlink||IsSymlink(strFileName);
                pThis->m_bIsMountpoint=pThis->m_bIsMountpoint||IsMountPoint(strFileName);
                pThis->m_bIsPathInAFS=true;
                }

                if (IsADir(strFileName))
                pThis->m_bDirSelected = TRUE;

                pThis->m_astrFileNames.Add(strFileName);
            }
            //	Release the data
            ReleaseStgMedium(&medium);
        }
    }
    if ((pThis->m_astrFileNames.GetSize() == 0)&&(pidlFolder)) {
        // if there are no valid files selected, try the folder background
        IShellFolder *parentFolder = NULL;
        STRRET name;
        TCHAR * szDisplayName = NULL;

        hres = ::SHGetDesktopFolder(&parentFolder);
        if (FAILED(hres))
            return hres;

        hres = parentFolder->GetDisplayNameOf(pidlFolder, SHGDN_NORMAL | SHGDN_FORPARSING, &name);
        if (FAILED(hres)) {
            parentFolder->Release();
            return hres;
        }

        hres = StrRetToStr (&name, pidlFolder, &szDisplayName);
        if (FAILED(hres))
            return hres;
        parentFolder->Release();
        if (szDisplayName) {
            pThis->m_bDirSelected = TRUE;
            CString strFileName = CString(szDisplayName);
            if (IsPathInAfs(strFileName)) {
                pThis->m_bIsSymlink=IsSymlink(strFileName);
                pThis->m_bIsMountpoint=IsMountPoint(strFileName);
                pThis->m_bIsPathInAFS=true;
                pThis->m_astrFileNames.Add(strFileName);
            }
            CoTaskMemFree(szDisplayName);
        }
    }
	if (pThis->m_astrFileNames.GetSize() > 0)
	    hres = NOERROR;
	else
	    hres = E_FAIL;

    return hres;
}

STDMETHODIMP CShellExt::XIconExt::QueryInterface(REFIID riid, void** ppv)
{
    METHOD_PROLOGUE(CShellExt, IconExt);
    return pThis->ExternalQueryInterface(&riid, ppv);
}

STDMETHODIMP_(ULONG) CShellExt::XIconExt::AddRef(void)
{
    return ++nICRefCount;
}

STDMETHODIMP_(ULONG) CShellExt::XIconExt::Release(void)
{
    if (nICRefCount > 0)
	nICRefCount--;

    return nICRefCount;
}


/////////////////////////////////////////////////////////////////////////////
// IIconHandler Functions
/////////////////////////////////////////////////////////////////////////////

STDMETHODIMP CShellExt::XIconExt::GetOverlayInfo(LPWSTR pwszIconFile
	,int cchMax,int* pIndex,DWORD* pdwFlags)
{
    METHOD_PROLOGUE(CShellExt, IconExt);
    if(IsBadWritePtr(pIndex, sizeof(int)))
	return E_INVALIDARG;
    if(IsBadWritePtr(pdwFlags, sizeof(DWORD)))
	return E_INVALIDARG;

    // The icons must reside in the same path as this dll
    TCHAR szModule[MAX_PATH];
    GetModuleFileName(theApp.m_hInstance, szModule, MAX_PATH);
    TCHAR * slash = _tcsrchr(szModule, '\\');
    if (slash) {
        *slash = 0;
        switch (pThis->GetOverlayObject())
        {
            case 0:
                _tcscat(szModule, _T("\\link.ico"));
            break;
            case 1:
                _tcscat(szModule, _T("\\mount.ico"));
            break;
        }
    }
#ifndef UNICODE
    MultiByteToWideChar( CP_ACP,0,szModule,-1,pwszIconFile,cchMax);
#else
    _tcsncpy(pwszIconFile, szModule, cchMax);
#endif
    *pIndex = 0;
    *pdwFlags = ISIOI_ICONFILE;
    return S_OK;
}

STDMETHODIMP CShellExt::XIconExt::GetPriority(int* pPriority)
{
    if(IsBadWritePtr(pPriority, sizeof(int)))
	return E_INVALIDARG;
    *pPriority = 0;
    return S_OK;
}

STDMETHODIMP CShellExt::XIconExt::IsMemberOf(LPCWSTR pwszPath,DWORD dwAttrib)
{
    METHOD_PROLOGUE(CShellExt, IconExt);
    TCHAR szPath[MAX_PATH];
#ifdef UNICODE
    _tcscpy(szPath, pwszPath);
#else
    WideCharToMultiByte( CP_ACP,0,pwszPath,-1,szPath,MAX_PATH,NULL,NULL);
#endif
	if (!IsPathInAfs(szPath))
		return S_FALSE;

    if ((pThis->GetOverlayObject() == 0)&&(IsSymlink(szPath))) {
        return S_OK;
    }
    if ((pThis->GetOverlayObject() == 1)&&(IsMountPoint(szPath))) {
        return S_OK;
    }
    return S_FALSE;
}

/*  TOOL TIP INFO IMPLIMENTION   */

STDMETHODIMP CShellExt::XToolTipExt::QueryInterface(REFIID riid, void** ppv)
{
    METHOD_PROLOGUE(CShellExt, ToolTipExt);
    return pThis->ExternalQueryInterface(&riid, ppv);
}

STDMETHODIMP_(ULONG) CShellExt::XToolTipExt::AddRef(void)
{
    return ++nTPRefCount;
}

STDMETHODIMP_(ULONG) CShellExt::XToolTipExt::Release(void)
{
    if (nTPRefCount> 0)
	nTPRefCount--;

    return nTPRefCount;
}

STDMETHODIMP CShellExt::XToolTipExt::GetInfoTip(DWORD dwFlags, LPWSTR *ppwszTip)
{
    METHOD_PROLOGUE(CShellExt, ToolTipExt);

    if ((_tcslen(pThis->m_szFile) == 0)||(!IsPathInAfs(pThis->m_szFile)))
    {
        *ppwszTip=NULL;
        return S_OK;
    }
    bool bIsSymlink = !!IsSymlink(pThis->m_szFile);
    bool bIsMountpoint = !!IsMountPoint(pThis->m_szFile);
    if ((!bIsSymlink) && (!bIsMountpoint))
    {
	*ppwszTip=NULL;
	return S_OK;
    }
    USES_CONVERSION;
    // dwFlags is currently unused.
    CString sInfo;
    if (bIsSymlink)
        sInfo = GetSymlink(pThis->m_szFile);
    else if (bIsMountpoint)
        sInfo = GetMountpoint(pThis->m_szFile);
    *ppwszTip = (WCHAR*) (pThis->m_pAlloc)->Alloc((1+sInfo.GetLength())*sizeof(WCHAR));
    if (*ppwszTip)
        wcscpy(*ppwszTip, (WCHAR*)T2COLE((LPCTSTR)sInfo));

    return S_OK;
}
STDMETHODIMP CShellExt::XToolTipExt::GetInfoFlags(LPDWORD pdwFlags)
{
    *pdwFlags = 0;
    return S_OK;
}

//////////                          IPersistFile
///////                            PersistFileExt

STDMETHODIMP CShellExt::XPersistFileExt::QueryInterface(REFIID riid, void** ppv)
{
    METHOD_PROLOGUE(CShellExt, PersistFileExt);
    return pThis->ExternalQueryInterface(&riid, ppv);
}

STDMETHODIMP_(ULONG) CShellExt::XPersistFileExt::AddRef(void)
{
    return ++nXPRefCount;
}

STDMETHODIMP_(ULONG) CShellExt::XPersistFileExt::Release(void)
{
    if (nXPRefCount> 0)
	nXPRefCount--;

    return nXPRefCount;
}

STDMETHODIMP	CShellExt::XPersistFileExt::Load(LPCOLESTR wszFile, DWORD dwMode)
{
    METHOD_PROLOGUE(CShellExt, PersistFileExt);
    USES_CONVERSION;
    _tcscpy(pThis->m_szFile, OLE2T((WCHAR*)wszFile));
    return S_OK;
}

STDMETHODIMP CShellExt::XPersistFileExt::GetClassID(LPCLSID)
{
    return E_NOTIMPL;
}

STDMETHODIMP CShellExt::XPersistFileExt::IsDirty(VOID)
{
    return E_NOTIMPL;
}

STDMETHODIMP CShellExt::XPersistFileExt::Save(LPCOLESTR, BOOL)
{
    return E_NOTIMPL;
}

STDMETHODIMP CShellExt::XPersistFileExt::SaveCompleted(LPCOLESTR)
{
    return E_NOTIMPL;
}

STDMETHODIMP CShellExt::XPersistFileExt::GetCurFile(LPOLESTR FAR*)
{
    return E_NOTIMPL;
}

// IShellPropSheetExt
STDMETHODIMP CShellExt::XPropertySheetExt::QueryInterface(REFIID riid, void** ppv)
{
    METHOD_PROLOGUE(CShellExt, PropertySheetExt);
    return pThis->ExternalQueryInterface(&riid, ppv);
}

STDMETHODIMP_(ULONG) CShellExt::XPropertySheetExt::AddRef(void)
{
    return ++nPSRefCount;
}

STDMETHODIMP_(ULONG) CShellExt::XPropertySheetExt::Release(void)
{
    if (nPSRefCount> 0)
	nPSRefCount--;

    return nPSRefCount;
}

BOOL CALLBACK PageProc (HWND hwnd, UINT uMessage, WPARAM wParam, LPARAM lParam)
{
    PropertyPage * sheetpage;

    if (uMessage == WM_INITDIALOG)
    {
        sheetpage = (PropertyPage*) ((LPPROPSHEETPAGE) lParam)->lParam;
        SetWindowLongPtr (hwnd, GWLP_USERDATA, (LONG_PTR) sheetpage);
        sheetpage->SetHwnd(hwnd);
    }
    else
    {
        sheetpage = (PropertyPage*) GetWindowLongPtr (hwnd, GWLP_USERDATA);
    }

    if (sheetpage != 0L)
        return sheetpage->PropPageProc(hwnd, uMessage, wParam, lParam);
    else
        return FALSE;
}

UINT CALLBACK PropPageCallbackProc ( HWND /*hwnd*/, UINT uMsg, LPPROPSHEETPAGE ppsp )
{
    // Delete the page before closing.
    if (PSPCB_CREATE == uMsg)
        return TRUE;
    if (PSPCB_RELEASE == uMsg)
    {
        PropertyPage* sheetpage = (PropertyPage*) ppsp->lParam;
        delete sheetpage;
    }
    return TRUE;
}

STDMETHODIMP CShellExt::XPropertySheetExt::AddPages(LPFNADDPROPSHEETPAGE lpfnAddPage, LPARAM lParam)
{
    METHOD_PROLOGUE(CShellExt, PropertySheetExt);

    if(pThis->m_bIsPathInAFS) {
        // add the property page for files/folder/mount points/symlinks
        PROPSHEETPAGE psp;
        SecureZeroMemory(&psp, sizeof(PROPSHEETPAGE));
        HPROPSHEETPAGE hPage;
        CPropFile *filesheet = NULL;
        CPropVolume *volsheet = NULL;
        CPropACL * aclsheet = NULL;

        filesheet = new CPropFile(pThis->m_astrFileNames);

        if (filesheet == NULL)
            return E_OUTOFMEMORY;

        HINSTANCE hInst = 0;
        TaLocale_GetResource(RT_DIALOG, MAKEINTRESOURCE(IDD_PROPPAGE_FILE), LANG_USER_DEFAULT, &hInst);
        filesheet->m_hInst = hInst;
        filesheet->m_bIsMountpoint = pThis->m_bIsMountpoint;
        filesheet->m_bIsSymlink = pThis->m_bIsSymlink;
        filesheet->m_bIsDir = pThis->m_bDirSelected;
        psp.dwSize = sizeof (psp);
        psp.dwFlags = PSP_USEREFPARENT | PSP_USETITLE | PSP_USECALLBACK | PSP_USETITLE;
        psp.hInstance = hInst;
        psp.pszTemplate = MAKEINTRESOURCE(IDD_PROPPAGE_FILE);
        psp.pszIcon = NULL;
        psp.pszTitle = _T("AFS");
        psp.pfnDlgProc = (DLGPROC) PageProc;
        psp.lParam = (LPARAM) filesheet;
        psp.pfnCallback = PropPageCallbackProc;
        psp.pcRefParent = (UINT*) &nPSRefCount;

        hPage = CreatePropertySheetPage (&psp);

        if (hPage != NULL) {
            if (!lpfnAddPage (hPage, lParam)) {
                delete filesheet;
                DestroyPropertySheetPage (hPage);
            }
        }

        // add the property page for Volume Data
        SecureZeroMemory(&psp, sizeof(PROPSHEETPAGE));
        volsheet = new CPropVolume(pThis->m_astrFileNames);
        if (volsheet == NULL)
            return E_OUTOFMEMORY;

        hInst = 0;
        TaLocale_GetResource(RT_DIALOG, MAKEINTRESOURCE(IDD_PROPPAGE_VOLUME), LANG_USER_DEFAULT, &hInst);
        volsheet->m_hInst = hInst;
        volsheet->m_bIsMountpoint = pThis->m_bIsMountpoint;
        volsheet->m_bIsSymlink = pThis->m_bIsSymlink;
        volsheet->m_bIsDir = pThis->m_bDirSelected;
        psp.dwSize = sizeof (psp);
        psp.dwFlags = PSP_USEREFPARENT | PSP_USETITLE | PSP_USECALLBACK | PSP_USETITLE;
        psp.hInstance = hInst;
        psp.pszTemplate = MAKEINTRESOURCE(IDD_PROPPAGE_VOLUME);
        psp.pszIcon = NULL;
        psp.pszTitle = _T("AFS Volume");
        psp.pfnDlgProc = (DLGPROC) PageProc;
        psp.lParam = (LPARAM) volsheet;
        psp.pfnCallback = PropPageCallbackProc;
        psp.pcRefParent = (UINT*) &nPSRefCount;

        hPage = CreatePropertySheetPage (&psp);

        if (hPage != NULL) {
            if (!lpfnAddPage (hPage, lParam)) {
                delete volsheet;
                DestroyPropertySheetPage (hPage);
            }
        }

        if(pThis->m_bDirSelected) {
            // add the property page for ACLs
            SecureZeroMemory(&psp, sizeof(PROPSHEETPAGE));

            aclsheet = new CPropACL(pThis->m_astrFileNames);
            if (aclsheet == NULL)
                return E_OUTOFMEMORY;

            hInst = 0;
            TaLocale_GetResource(RT_DIALOG, MAKEINTRESOURCE(IDD_PROPPAGE_ACL), LANG_USER_DEFAULT, &hInst);
            aclsheet->m_hInst = hInst;
            aclsheet->m_bIsMountpoint = pThis->m_bIsMountpoint;
            aclsheet->m_bIsSymlink = pThis->m_bIsSymlink;
            aclsheet->m_bIsDir = pThis->m_bDirSelected;
            psp.dwSize = sizeof (psp);
            psp.dwFlags = PSP_USEREFPARENT | PSP_USETITLE | PSP_USECALLBACK | PSP_USETITLE;
            psp.hInstance = hInst;
            psp.pszTemplate = MAKEINTRESOURCE(IDD_PROPPAGE_ACL);
            psp.pszIcon = NULL;
            psp.pszTitle = _T("AFS ACL");
            psp.pfnDlgProc = (DLGPROC) PageProc;
            psp.lParam = (LPARAM) aclsheet;
            psp.pfnCallback = PropPageCallbackProc;
            psp.pcRefParent = (UINT*) &nPSRefCount;

            hPage = CreatePropertySheetPage (&psp);

            if (hPage != NULL) {
                if (!lpfnAddPage (hPage, lParam)) {
                    delete aclsheet;
                    DestroyPropertySheetPage (hPage);
                }
            }
        }
    }

    return S_OK;
}

STDMETHODIMP CShellExt::XPropertySheetExt::ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE pfnReplacePage, LPARAM lParam)
{
    return E_FAIL;
}

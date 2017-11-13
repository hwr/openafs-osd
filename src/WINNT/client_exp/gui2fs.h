/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef __GUI2FS_H__
#define __GUI2FS_H__

#include "volume_inf.h"

void Flush(const CStringArray& files);
void FlushVolume(const CStringArray& files);
void WSCellCmd();
void WhichCell(CStringArray& files);
BOOL CheckVolumes();
void SetCacheSize(LONG nNewCacheSize);
void WhereIs(CStringArray& files);
CString GetAfsError(int code, const TCHAR *filename = 0);
void CleanACL(CStringArray& names);
BOOL GetRights(const CString& strDir, CStringArray& strNormal, CStringArray& strNegative);
BOOL SaveACL(const CString& strCellName, const CString& strDir, const CStringArray& normal, const CStringArray& negative);
BOOL CopyACL(const CString& strToDir, const CStringArray& normal, const CStringArray& negative, BOOL bClear);
BOOL ListMount(CStringArray& files);
BOOL MakeMount(const CString& strDir, const CString& strVolName, const CString& strCellName, BOOL bRW);
BOOL RemoveMount(CStringArray& files);
BOOL RemoveSymlink(const CString& symlink);
BOOL GetVolumeInfo(CString strFile, CVolInfo& volInfo, BOOL bFollow=TRUE);
BOOL SetVolInfo(CVolInfo& volInfo);
enum WHICH_CELLS { LOCAL_CELL = 0, SPECIFIC_CELL = 1, ALL_CELLS = 2 };
BOOL CheckServers(const CString& strCellName, WHICH_CELLS nCellsToCheck, BOOL bFast);
BOOL GetTokenInfo(CStringArray& tokenInfo);
BOOL GetFID(const CString& path, CString& fidstring, BOOL bLiteral = TRUE);
BOOL IsPathInAfs(const CString& strPath);
BOOL IsSymlink(const CString& name);
BOOL IsMountPoint(const CString& name);
UINT MakeSymbolicLink(const CString&,const CString&);
void ListSymbolicLinkPath(CString&,CString&,UINT nlenPath);
BOOL ListSymlink(CStringArray& files);
CString GetCellName(const CString& strPath, BOOL bFollow = TRUE);
CString GetServer(const CString& strPath, BOOL bFollow = TRUE);
void GetServers( const CString& strPath, CStringArray& servers, BOOL bFollow = TRUE );
CString GetOwner(const CString& strPath, BOOL bFollow = TRUE);
CString GetGroup(const CString& strPath, BOOL bFollow = TRUE);
BOOL GetUnixModeBits(const CString& strPath, CString& user, CString& group, CString& other, CString& suid);
void SetUnixModeBits(const CStringArray& files, const CString& user, const CString& group, const CString& other, const CString& suid);
CString GetMountpoint(const CString& strPath);
CString GetSymlink(const CString& strPath);
#endif //__GUI2FS_H__

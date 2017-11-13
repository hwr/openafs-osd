/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef _VOLUME_INF_H_
#define _VOLUME_INF_H_

class CVolInfo
{
public:
	CString m_strFilePath;
	CString m_strFileName;
	CString m_strName;
        CString m_strAvail;
	unsigned __int64 m_nID;
	unsigned __int64 m_nQuota;
	unsigned __int64 m_nNewQuota;
	unsigned __int64 m_nUsed;
	unsigned __int64 m_nPartSize;
	unsigned __int64 m_nPartFree;
	int m_nDup;
	CString m_strErrorMsg;
};


#endif // _VOLUME_INF_H_


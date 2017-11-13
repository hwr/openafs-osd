/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <roken.h>

#include <windows.h>
#include <shlobj.h>

#include <afs/errmap_nt.h>

#include "afsreg.h"
#include "afssw.h"

static int
StringDataRead(const char *keyName, const char *valueName, char **bufPP);

static int
StringDataWrite(const char *keyName, const char *valueName, const char *data);

static int
DwordDataRead(const char *keyName, const char *valueName, DWORD *data);



/* Functions for accessing AFS software configuration information. */

/*
 * afssw_GetServerInstallDir() -- Get directory in which AFS server software is
 *     installed.  Sets *bufPP to point to allocated buffer containing string.
 *
 * RETURN CODES: 0 success, -1 failed (errno set)
 */
int
afssw_GetServerInstallDir(char **bufPP)  /* [out] data buffer */
{
    return StringDataRead(AFSREG_SVR_SW_VERSION_KEY,
			  AFSREG_SVR_SW_VERSION_DIR_VALUE,
			  bufPP);
}


/*
 * afssw_GetClientInstallDir() -- Get directory in which AFS client software is
 *     installed.  Sets *bufPP to point to allocated buffer containing string.
 *
 * RETURN CODES: 0 success, -1 failed (errno set)
 */
int
afssw_GetClientInstallDir(char **bufPP)   /* [out] data buffer */
{
    int retval = StringDataRead(AFSREG_CLT_SW_VERSION_KEY,
			  AFSREG_CLT_SW_VERSION_DIR_VALUE,
			  bufPP);
    if (retval)
	retval = StringDataRead(AFSREG_CLT_TOOLS_SW_VERSION_KEY,
			  AFSREG_CLT_SW_VERSION_DIR_VALUE,
			  bufPP);
    return retval;
}

/*
 * afssw_GetClientCellServDBDir() -- Get directory in which AFS client CellServDB
 * file is installed.  Sets *bufPP to point to allocated buffer containing string.
 *
 * RETURN CODES: 0 success, -1 failed (errno set)
 */
int
afssw_GetClientCellServDBDir(char **bufPP)   /* [out] data buffer */
{
    char wdir[512];
    int tlen;
    char *path = NULL;
    DWORD cbPath;

    cbPath = GetEnvironmentVariable("AFSCONF", NULL, 0);
    if (cbPath) {
        cbPath += 2;
        path = malloc(cbPath);
        if (path) {
            GetEnvironmentVariable("AFSCONF", path, cbPath);
            tlen = (int)strlen(path);
            if (path[tlen-1] != '\\') {
                strncat(path, "\\", cbPath);
                path[cbPath-1] = '\0';
            }
            *bufPP = path;
            return 0;
        }
    }

    if (!StringDataRead(AFSREG_CLT_OPENAFS_KEY,
			  AFSREG_CLT_OPENAFS_CELLSERVDB_DIR_VALUE,
                         &path)) {
        tlen = (int)strlen(path);
        if (path[tlen-1] != '\\') {
            char * newPath = malloc(tlen+2);
            if (newPath) {
                _snprintf(newPath,tlen+2,"%s\\",path);
                free(path);
                path = newPath;
            }
        }
        *bufPP = path;
        return 0;
    }

    /*
     * Try to find the All Users\Application Data\OpenAFS\Client directory.
     * If it exists and it contains a CellServDB file, return that.
     * Otherwise, return the Install Directory for backward compatibility.
     * SHGetFolderPath requires wdir to be of length MAX_PATH which is 260.
     */
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL,
                                    SHGFP_TYPE_CURRENT, wdir)))
    {   HANDLE fh;

        tlen = (int)strlen(wdir);
        if (wdir[tlen-1] != '\\') {
            strncat(wdir, "\\", sizeof(wdir));
            wdir[sizeof(wdir)-1] = '\0';
            tlen++;
        }
        strncat(wdir, "OpenAFS\\Client\\CellServDB", sizeof(wdir));
        wdir[sizeof(wdir)-1] = '\0';

        fh = CreateFile(wdir, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fh != INVALID_HANDLE_VALUE) {
            CloseHandle(fh);
            tlen += (int)strlen("OpenAFS\\Client\\");
            wdir[tlen] = '\0';
            *bufPP = strdup(wdir);
            return 0;
        }
    }

    return afssw_GetClientInstallDir(bufPP);
}


/*
 * afssw_GetClientCellName() -- Get name of cell in which AFS client is
 *     configured.  Sets *bufPP to point to allocated buffer containing string.
 *
 * RETURN CODES: 0 success, -1 failed (errno set)
 */
int
afssw_GetClientCellName(char **bufPP)  /* [out] data buffer */
{
    return StringDataRead(AFSREG_CLT_SVC_PARAM_KEY,
			  AFSREG_CLT_SVC_PARAM_CELL_VALUE,
			  bufPP);
}


/*
 * afssw_SetClientCellName() -- Set name of cell in which AFS client is
 *     configured.
 *
 * RETURN CODES: 0 success, -1 failed (errno set)
 */
int
afssw_SetClientCellName(const char *cellName)
{
    return StringDataWrite(AFSREG_CLT_SVC_PARAM_KEY,
			   AFSREG_CLT_SVC_PARAM_CELL_VALUE,
			   cellName);
}


/*
 * afssw_GetServerVersion() -- Get version number of installed server.
 *
 * RETURN CODES: 0 success, -1 failed (errno set)
 */
int
afssw_GetServerVersion(unsigned *major,  /* major version number */
		       unsigned *minor,  /* minor version number */
		       unsigned *patch)  /* patch level */
{
    DWORD dwMajor, dwMinor, dwPatch;

    if (DwordDataRead(AFSREG_SVR_SW_VERSION_KEY,
		      AFSREG_SVR_SW_VERSION_MAJOR_VALUE,
		      &dwMajor) ||

	DwordDataRead(AFSREG_SVR_SW_VERSION_KEY,
		      AFSREG_SVR_SW_VERSION_MINOR_VALUE,
		      &dwMinor) ||

	DwordDataRead(AFSREG_SVR_SW_VERSION_KEY,
		      AFSREG_SVR_SW_VERSION_PATCH_VALUE,
		      &dwPatch)) {
	/* a read failed */
	return -1;
    } else {
	/* return values */
	*major = dwMajor;
	*minor = dwMinor;
	*patch = dwPatch;
	return 0;
    }
}


/*
 * afssw_GetClientVersion() -- Get version number of installed client.
 *
 * RETURN CODES: 0 success, -1 failed (errno set)
 */
int
afssw_GetClientVersion(unsigned *major,  /* major version number */
		       unsigned *minor,  /* minor version number */
		       unsigned *patch)  /* patch level */
{
    DWORD dwMajor, dwMinor, dwPatch;

    if (DwordDataRead(AFSREG_CLT_SW_VERSION_KEY,
		      AFSREG_CLT_SW_VERSION_MAJOR_VALUE,
		      &dwMajor) ||

	DwordDataRead(AFSREG_CLT_SW_VERSION_KEY,
		      AFSREG_CLT_SW_VERSION_MINOR_VALUE,
		      &dwMinor) ||

	DwordDataRead(AFSREG_CLT_SW_VERSION_KEY,
		      AFSREG_CLT_SW_VERSION_PATCH_VALUE,
		      &dwPatch)) {
	/* a read failed */
	return -1;
    } else {
	/* return values */
	*major = dwMajor;
	*minor = dwMinor;
	*patch = dwPatch;
	return 0;
    }
}




/* ----------------------- local functions ------------------------- */

/*
 * StringDataRead() -- read registry data of type REG_SZ and return in
 *     allocated buffer.
 *
 * RETURN CODES: 0 success, -1 failed (errno set)
 */
static int
StringDataRead(const char *keyName, const char *valueName, char **bufPP)
{
    long status;
    HKEY key;

    if (bufPP == NULL) {
	errno = EINVAL;
	return -1;
    }

    status = RegOpenKeyAlt(AFSREG_NULL_KEY, keyName, KEY_READ, 0, &key, NULL);

    if (status == ERROR_SUCCESS) {
	DWORD dataType;
	char *dataBuf = NULL;

	status = RegQueryValueAlt(key, valueName, &dataType, &dataBuf, NULL);

	if (status == ERROR_SUCCESS) {
	    if (dataType == REG_SZ) {
		*bufPP = dataBuf;
	    } else {
		/* invalid data type */
		free(dataBuf);
		status = ERROR_INVALID_DATA;
	    }
	}
	(void)RegCloseKey(key);
    }

    if (status) {
	errno = nterr_nt2unix(status, EIO);
	return -1;
    }
    return 0;
}


/*
 * StringDataWrite() -- write registry data of type REG_SZ.
 *
 * RETURN CODES: 0 success, -1 failed (errno set)
 */
static int
StringDataWrite(const char *keyName, const char *valueName, const char *data)
{
    long status;
    HKEY key;

    if (data == NULL) {
	errno = EINVAL;
	return -1;
    }

    status = RegOpenKeyAlt(AFSREG_NULL_KEY,
			   keyName, KEY_WRITE, 1 /* create */, &key, NULL);

    if (status == ERROR_SUCCESS) {
	status = RegSetValueEx(key,
			       valueName,
			       0, REG_SZ, data, (DWORD)strlen(data) + 1);

	(void)RegCloseKey(key);
    }

    if (status) {
	errno = nterr_nt2unix(status, EIO);
	return -1;
    }
    return 0;
}


/*
 * DwordDataRead() -- read registry data of type REG_DWORD.
 *
 * RETURN CODES: 0 success, -1 failed (errno set)
 */
static int
DwordDataRead(const char *keyName, const char *valueName, DWORD *data)
{
    long status;
    HKEY key;

    status = RegOpenKeyAlt(AFSREG_NULL_KEY, keyName, KEY_READ, 0, &key, NULL);

    if (status == ERROR_SUCCESS) {
	DWORD dataType;
	DWORD dataBuf;
	DWORD dataSize = sizeof(DWORD);

	status = RegQueryValueEx(key, valueName,
				 NULL, &dataType, (void *)&dataBuf, &dataSize);

	if (status == ERROR_SUCCESS) {
	    if (dataType == REG_DWORD) {
		*data = dataBuf;
	    } else {
		/* invalid data type */
		status = ERROR_INVALID_DATA;
	    }
	}
	(void)RegCloseKey(key);
    }

    if (status) {
	errno = nterr_nt2unix(status, EIO);
	return -1;
    }
    return 0;
}

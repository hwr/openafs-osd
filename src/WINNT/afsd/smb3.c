
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
#include <roken.h>

#include <afs/stds.h>

#include <windows.h>
#pragma warning(push)
#pragma warning(disable: 4005)
#include <ntstatus.h>
#define SECURITY_WIN32
#include <security.h>
#include <sddl.h>
#include <lmaccess.h>
#pragma warning(pop)
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <osi.h>

#include "afsd.h"
#include <WINNT\afsreg.h>

#include "smb.h"
#include "msrpc.h"
#include <strsafe.h>

extern osi_hyper_t hzero;

smb_packet_t *smb_Directory_Watches = NULL;
osi_mutex_t smb_Dir_Watch_Lock;

smb_tran2Dispatch_t smb_tran2DispatchTable[SMB_TRAN2_NOPCODES];

smb_tran2Dispatch_t smb_rapDispatchTable[SMB_RAP_NOPCODES];

/* protected by the smb_globalLock */
smb_tran2Packet_t *smb_tran2AssemblyQueuep;

const clientchar_t **smb_ExecutableExtensions = NULL;

/* retrieve a held reference to a user structure corresponding to an incoming
 * request */
cm_user_t *smb_GetTran2User(smb_vc_t *vcp, smb_tran2Packet_t *inp)
{
    smb_user_t *uidp;
    cm_user_t *up = NULL;

    uidp = smb_FindUID(vcp, inp->uid, 0);
    if (!uidp)
	return NULL;

    up = smb_GetUserFromUID(uidp);

    smb_ReleaseUID(uidp);

    return up;
}

/*
 * Return boolean specifying if the path name is thought to be an
 * executable file.  For now .exe or .dll.
 */
afs_uint32 smb_IsExecutableFileName(const clientchar_t *name)
{
    int i, j, len;

    if ( smb_ExecutableExtensions == NULL || name == NULL)
        return 0;

    len = (int)cm_ClientStrLen(name);

    for ( i=0; smb_ExecutableExtensions[i]; i++) {
        j = len - (int)cm_ClientStrLen(smb_ExecutableExtensions[i]);
        if (cm_ClientStrCmpI(smb_ExecutableExtensions[i], &name[j]) == 0)
            return 1;
    }

    return 0;
}

/*
 * Return extended attributes.
 * Right now, we aren't using any of the "new" bits, so this looks exactly
 * like smb_Attributes() (see smb.c).
 */
unsigned long smb_ExtAttributes(cm_scache_t *scp)
{
    unsigned long attrs;

    if (scp->fileType == CM_SCACHETYPE_DIRECTORY ||
        scp->fileType == CM_SCACHETYPE_MOUNTPOINT ||
        scp->fileType == CM_SCACHETYPE_INVALID)
    {
        attrs = SMB_ATTR_DIRECTORY;
#ifdef SPECIAL_FOLDERS
        attrs |= SMB_ATTR_SYSTEM;		/* FILE_ATTRIBUTE_SYSTEM */
#endif /* SPECIAL_FOLDERS */
    } else if (scp->fileType == CM_SCACHETYPE_DFSLINK) {
        attrs = SMB_ATTR_DIRECTORY | SMB_ATTR_SPARSE_FILE;
    } else if (scp->fid.vnode & 0x1)
        attrs = SMB_ATTR_DIRECTORY;
    else
        attrs = 0;

    /*
     * We used to mark a file RO if it was in an RO volume, but that
     * turns out to be impolitic in NT.  See defect 10007.
     */
#ifdef notdef
    if ((scp->unixModeBits & 0200) == 0 || (scp->flags & CM_SCACHEFLAG_RO))
        attrs |= SMB_ATTR_READONLY;		/* Read-only */
#else
    if ((scp->unixModeBits & 0200) == 0)
        attrs |= SMB_ATTR_READONLY;		/* Read-only */
#endif

    if (attrs == 0)
        attrs = SMB_ATTR_NORMAL;		/* FILE_ATTRIBUTE_NORMAL */

    return attrs;
}

int smb_V3IsStarMask(clientchar_t *maskp)
{
    clientchar_t tc;

    while (tc = *maskp++)
        if (tc == '?' || tc == '*' || tc == '<' || tc == '>')
            return 1;
    return 0;
}

void OutputDebugF(clientchar_t * format, ...) {
    va_list args;
    clientchar_t vbuffer[1024];

    va_start( args, format );
    cm_ClientStrPrintfV(vbuffer, lengthof(vbuffer), format, args);
    osi_Log1(smb_logp, "%S", osi_LogSaveClientString(smb_logp, vbuffer));
}

void OutputDebugHexDump(unsigned char * buffer, int len) {
    int i,j,k;
    char buf[256];
    static char tr[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    OutputDebugF(_C("Hexdump length [%d]"),len);

    for (i=0;i<len;i++) {
        if(!(i%16)) {
            if(i) {
                osi_Log1(smb_logp, "%s", osi_LogSaveString(smb_logp, buf));
            }
            StringCchPrintfA(buf, lengthof(buf), "%5x", i);
            memset(buf+5,' ',80);
            buf[85] = 0;
        }

        j = (i%16);
        j = j*3 + 7 + ((j>7)?1:0);
        k = buffer[i];

        buf[j] = tr[k / 16]; buf[j+1] = tr[k % 16];

        j = (i%16);
        j = j + 56 + ((j>7)?1:0);

        buf[j] = (k>32 && k<127)?k:'.';
    }
    if(i) {
        osi_Log1(smb_logp, "%s", osi_LogSaveString(smb_logp, buf));
    }
}

#define SMB_EXT_SEC_PACKAGE_NAME "Negotiate"

void smb_NegotiateExtendedSecurity(void ** secBlob, int * secBlobLength) {
    SECURITY_STATUS status, istatus;
    CredHandle creds = {0,0};
    TimeStamp expiry;
    SecBufferDesc secOut;
    SecBuffer secTok;
    CtxtHandle ctx;
    ULONG flags;

    *secBlob = NULL;
    *secBlobLength = 0;

    OutputDebugF(_C("Negotiating Extended Security"));

    status = AcquireCredentialsHandle( NULL,
                                       SMB_EXT_SEC_PACKAGE_NAME,
                                       SECPKG_CRED_INBOUND,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &creds,
                                       &expiry);

    if (status != SEC_E_OK) {
        /* Really bad. We return an empty security blob */
        OutputDebugF(_C("AcquireCredentialsHandle failed with %lX"), status);
        goto nes_0;
    }

    secOut.cBuffers = 1;
    secOut.pBuffers = &secTok;
    secOut.ulVersion = SECBUFFER_VERSION;

    secTok.BufferType = SECBUFFER_TOKEN;
    secTok.cbBuffer = 0;
    secTok.pvBuffer = NULL;

    ctx.dwLower = ctx.dwUpper = 0;

    status = AcceptSecurityContext( &creds,
                                    NULL,
                                    NULL,
                                    ASC_REQ_CONNECTION | ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY,
                                    SECURITY_NETWORK_DREP,
                                    &ctx,
                                    &secOut,
                                    &flags,
                                    &expiry
                                    );

    if (status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE) {
        OutputDebugF(_C("Completing token..."));
        istatus = CompleteAuthToken(&ctx, &secOut);
        if ( istatus != SEC_E_OK )
            OutputDebugF(_C("Token completion failed: %x"), istatus);
    }

    if (status == SEC_I_COMPLETE_AND_CONTINUE || status == SEC_I_CONTINUE_NEEDED) {
        if (secTok.pvBuffer) {
            *secBlobLength = secTok.cbBuffer;
            *secBlob = malloc( secTok.cbBuffer );
            memcpy(*secBlob, secTok.pvBuffer, secTok.cbBuffer );
        }
    } else {
        if ( status != SEC_E_OK )
            OutputDebugF(_C("AcceptSecurityContext status != CONTINUE  %lX"), status);
    }

    /* Discard partial security context */
    DeleteSecurityContext(&ctx);

    if (secTok.pvBuffer) FreeContextBuffer( secTok.pvBuffer );

    /* Discard credentials handle.  We'll reacquire one when we get the session setup X */
    FreeCredentialsHandle(&creds);

  nes_0:
    return;
}

afs_uint32
smb_GetLogonSID(HANDLE hToken, PSID *ppsid)
{
    BOOL bSuccess = FALSE;
    DWORD dwIndex;
    DWORD dwLength = 0;
    PTOKEN_GROUPS ptg = NULL;

    // Verify the parameter passed in is not NULL.
    if (NULL == ppsid)
        goto Cleanup;

    // Get required buffer size and allocate the TOKEN_GROUPS buffer.

    if (!GetTokenInformation( hToken,         // handle to the access token
                              TokenGroups,    // get information about the token's groups
                              (LPVOID) ptg,   // pointer to TOKEN_GROUPS buffer
                              0,              // size of buffer
                              &dwLength       // receives required buffer size
                              ))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            goto Cleanup;

        ptg = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(),
                                        HEAP_ZERO_MEMORY, dwLength);

        if (ptg == NULL)
            goto Cleanup;
    }

    // Get the token group information from the access token.

    if (!GetTokenInformation( hToken,         // handle to the access token
                              TokenGroups,    // get information about the token's groups
                              (LPVOID) ptg,   // pointer to TOKEN_GROUPS buffer
                              dwLength,       // size of buffer
                              &dwLength       // receives required buffer size
                              ))
    {
        goto Cleanup;
    }

    // Loop through the groups to find the logon SID.
    for (dwIndex = 0; dwIndex < ptg->GroupCount; dwIndex++) {
        if ((ptg->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID) ==  SE_GROUP_LOGON_ID)
        {
            // Found the logon SID; make a copy of it.

            dwLength = GetLengthSid(ptg->Groups[dwIndex].Sid);
            *ppsid = (PSID) HeapAlloc(GetProcessHeap(),
                                       HEAP_ZERO_MEMORY, dwLength);
            if (*ppsid == NULL)
                goto Cleanup;
            if (!CopySid(dwLength, *ppsid, ptg->Groups[dwIndex].Sid))
            {
                HeapFree(GetProcessHeap(), 0, (LPVOID)*ppsid);
                goto Cleanup;
            }
            bSuccess = TRUE;
            break;
        }
    }

  Cleanup:

    // Free the buffer for the token groups.
    if (ptg != NULL)
        HeapFree(GetProcessHeap(), 0, (LPVOID)ptg);

    return bSuccess;
}

afs_uint32
smb_GetUserSID(HANDLE hToken, PSID *ppsid)
{
    BOOL bSuccess = FALSE;
    DWORD dwLength = 0;
    PTOKEN_USER ptu = NULL;

    // Verify the parameter passed in is not NULL.
    if (NULL == ppsid)
        goto Cleanup;

    // Get required buffer size and allocate the TOKEN_USER buffer.

    if (!GetTokenInformation( hToken,         // handle to the access token
                              TokenUser,      // get information about the token's user
                              (LPVOID) ptu,   // pointer to TOKEN_USER buffer
                              0,              // size of buffer
                              &dwLength       // receives required buffer size
                              ))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            goto Cleanup;

        ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(),
                                        HEAP_ZERO_MEMORY, dwLength);

        if (ptu == NULL)
            goto Cleanup;
    }

    // Get the token group information from the access token.

    if (!GetTokenInformation( hToken,         // handle to the access token
                              TokenUser,      // get information about the token's user
                              (LPVOID) ptu,   // pointer to TOKEN_USER buffer
                              dwLength,       // size of buffer
                              &dwLength       // receives required buffer size
                              ))
    {
        goto Cleanup;
    }

    // Found the user SID; make a copy of it.
    dwLength = GetLengthSid(ptu->User.Sid);
    *ppsid = (PSID) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
    if (*ppsid == NULL)
        goto Cleanup;
    if (!CopySid(dwLength, *ppsid, ptu->User.Sid))
    {
        HeapFree(GetProcessHeap(), 0, (LPVOID)*ppsid);
        goto Cleanup;
    }
    bSuccess = TRUE;

  Cleanup:

    // Free the buffer for the token groups.
    if (ptu != NULL)
        HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);

    return bSuccess;
}

void
smb_FreeSID (PSID psid)
{
    HeapFree(GetProcessHeap(), 0, (LPVOID)psid);
}


struct smb_ext_context {
    CredHandle creds;
    CtxtHandle ctx;
    int partialTokenLen;
    void * partialToken;
};

long smb_AuthenticateUserExt(smb_vc_t * vcp, clientchar_t * usern,
                             char * secBlobIn, int secBlobInLength,
                             char ** secBlobOut, int * secBlobOutLength,
                             wchar_t **secSidString) {
    SECURITY_STATUS status, istatus;
    CredHandle creds;
    TimeStamp expiry;
    long code = 0;
    SecBufferDesc secBufIn;
    SecBuffer secTokIn;
    SecBufferDesc secBufOut;
    SecBuffer secTokOut;
    CtxtHandle ctx;
    struct smb_ext_context * secCtx = NULL;
    struct smb_ext_context * newSecCtx = NULL;
    void * assembledBlob = NULL;
    int assembledBlobLength = 0;
    ULONG flags;

    OutputDebugF(_C("In smb_AuthenticateUserExt"));

    *secBlobOut = NULL;
    *secBlobOutLength = 0;
    *secSidString = NULL;

    if (vcp->flags & SMB_VCFLAG_AUTH_IN_PROGRESS) {
        secCtx = vcp->secCtx;
        lock_ObtainMutex(&vcp->mx);
        vcp->flags &= ~SMB_VCFLAG_AUTH_IN_PROGRESS;
        vcp->secCtx = NULL;
        lock_ReleaseMutex(&vcp->mx);
    }

    if (secBlobIn) {
        OutputDebugF(_C("Received incoming token:"));
        OutputDebugHexDump(secBlobIn,secBlobInLength);
    }

    if (secCtx) {
        OutputDebugF(_C("Continuing with existing context."));
        creds = secCtx->creds;
        ctx = secCtx->ctx;

        if (secCtx->partialToken) {
            assembledBlobLength = secCtx->partialTokenLen + secBlobInLength;
            assembledBlob = malloc(assembledBlobLength);
            memcpy(assembledBlob,secCtx->partialToken, secCtx->partialTokenLen);
            memcpy(((BYTE *)assembledBlob) + secCtx->partialTokenLen, secBlobIn, secBlobInLength);
        }
    } else {
        status = AcquireCredentialsHandle( NULL,
                                           SMB_EXT_SEC_PACKAGE_NAME,
                                           SECPKG_CRED_INBOUND,
                                           NULL,
                                           NULL,
                                           NULL,
                                           NULL,
                                           &creds,
                                           &expiry);

        if (status != SEC_E_OK) {
            OutputDebugF(_C("Can't acquire Credentials handle [%lX]"), status);
            code = CM_ERROR_BADPASSWORD; /* means "try again when I'm sober" */
            goto aue_0;
        }

        ctx.dwLower = 0;
        ctx.dwUpper = 0;
    }

    secBufIn.cBuffers = 1;
    secBufIn.pBuffers = &secTokIn;
    secBufIn.ulVersion = SECBUFFER_VERSION;

    secTokIn.BufferType = SECBUFFER_TOKEN;
    if (assembledBlob) {
        secTokIn.cbBuffer = assembledBlobLength;
        secTokIn.pvBuffer = assembledBlob;
    } else {
        secTokIn.cbBuffer = secBlobInLength;
        secTokIn.pvBuffer = secBlobIn;
    }

    secBufOut.cBuffers = 1;
    secBufOut.pBuffers = &secTokOut;
    secBufOut.ulVersion = SECBUFFER_VERSION;

    secTokOut.BufferType = SECBUFFER_TOKEN;
    secTokOut.cbBuffer = 0;
    secTokOut.pvBuffer = NULL;

    status = AcceptSecurityContext( &creds,
                                    ((secCtx)?&ctx:NULL),
                                    &secBufIn,
                                    ASC_REQ_CONNECTION | ASC_REQ_EXTENDED_ERROR	| ASC_REQ_ALLOCATE_MEMORY,
                                    SECURITY_NETWORK_DREP,
                                    &ctx,
                                    &secBufOut,
                                    &flags,
                                    &expiry
                                    );

    if (status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE) {
        OutputDebugF(_C("Completing token..."));
        istatus = CompleteAuthToken(&ctx, &secBufOut);
        if ( istatus != SEC_E_OK )
            OutputDebugF(_C("Token completion failed: %lX"), istatus);
    }

    if (status == SEC_I_COMPLETE_AND_CONTINUE || status == SEC_I_CONTINUE_NEEDED) {
        OutputDebugF(_C("Continue needed"));

        newSecCtx = malloc(sizeof(*newSecCtx));

        newSecCtx->creds = creds;
        newSecCtx->ctx = ctx;
        newSecCtx->partialToken = NULL;
        newSecCtx->partialTokenLen = 0;

        lock_ObtainMutex( &vcp->mx );
        vcp->flags |= SMB_VCFLAG_AUTH_IN_PROGRESS;
        vcp->secCtx = newSecCtx;
        lock_ReleaseMutex( &vcp->mx );

        code = CM_ERROR_GSSCONTINUE;
    }

    if ((status == SEC_I_COMPLETE_NEEDED || status == SEC_E_OK ||
          status == SEC_I_COMPLETE_AND_CONTINUE || status == SEC_I_CONTINUE_NEEDED) &&
         secTokOut.pvBuffer) {
        OutputDebugF(_C("Need to send token back to client"));

        *secBlobOutLength = secTokOut.cbBuffer;
        *secBlobOut = malloc(secTokOut.cbBuffer);
        memcpy(*secBlobOut, secTokOut.pvBuffer, secTokOut.cbBuffer);

        OutputDebugF(_C("Outgoing token:"));
        OutputDebugHexDump(*secBlobOut,*secBlobOutLength);
    } else if (status == SEC_E_INCOMPLETE_MESSAGE) {
        OutputDebugF(_C("Incomplete message"));

        newSecCtx = malloc(sizeof(*newSecCtx));

        newSecCtx->creds = creds;
        newSecCtx->ctx = ctx;
        newSecCtx->partialToken = malloc(secTokOut.cbBuffer);
        memcpy(newSecCtx->partialToken, secTokOut.pvBuffer, secTokOut.cbBuffer);
        newSecCtx->partialTokenLen = secTokOut.cbBuffer;

        lock_ObtainMutex( &vcp->mx );
        vcp->flags |= SMB_VCFLAG_AUTH_IN_PROGRESS;
        vcp->secCtx = newSecCtx;
        lock_ReleaseMutex( &vcp->mx );

        code = CM_ERROR_GSSCONTINUE;
    }

    if (status == SEC_E_OK || status == SEC_I_COMPLETE_NEEDED) {
        /* woo hoo! */
        HANDLE hToken = 0;
        SecPkgContext_NamesW names;

        OutputDebugF(_C("Authentication completed"));
        OutputDebugF(_C("Returned flags : [%lX]"), flags);

        if (!QueryContextAttributesW(&ctx, SECPKG_ATTR_NAMES, &names)) {
            OutputDebugF(_C("Received name [%s]"), names.sUserName);
            cm_ClientStrCpy(usern, SMB_MAX_USERNAME_LENGTH, names.sUserName);
            cm_ClientStrLwr(usern); /* in tandem with smb_GetNormalizedUsername */
            FreeContextBuffer(names.sUserName);
        } else {
            /* Force the user to retry if the context is invalid */
            OutputDebugF(_C("QueryContextAttributes Names failed [%x]"), GetLastError());
            code = CM_ERROR_BADPASSWORD;
        }

        /* Obtain the user's SID */
        if (code == 0 && !QuerySecurityContextToken(((secCtx)?&ctx:NULL), &hToken)) {
            PSID pSid = 0;
            OutputDebugF(_C("Received hToken"));

            if (smb_GetUserSID(hToken, &pSid))
                ConvertSidToStringSidW(pSid, secSidString);

            if (pSid)
                smb_FreeSID(pSid);
            CloseHandle(hToken);
        } else {
            OutputDebugF(_C("QueryContextToken failed [%x]"), GetLastError());
        }
    } else if (!code) {
        switch ( status ) {
        case SEC_E_INVALID_TOKEN:
            OutputDebugF(_C("Returning bad password :: INVALID_TOKEN"));
            break;
        case SEC_E_INVALID_HANDLE:
            OutputDebugF(_C("Returning bad password :: INVALID_HANDLE"));
            break;
        case SEC_E_LOGON_DENIED:
            OutputDebugF(_C("Returning bad password :: LOGON_DENIED"));
            break;
        case SEC_E_UNKNOWN_CREDENTIALS:
            OutputDebugF(_C("Returning bad password :: UNKNOWN_CREDENTIALS"));
            break;
        case SEC_E_NO_CREDENTIALS:
            OutputDebugF(_C("Returning bad password :: NO_CREDENTIALS"));
            break;
        case SEC_E_CONTEXT_EXPIRED:
            OutputDebugF(_C("Returning bad password :: CONTEXT_EXPIRED"));
            break;
        case SEC_E_INCOMPLETE_CREDENTIALS:
            OutputDebugF(_C("Returning bad password :: INCOMPLETE_CREDENTIALS"));
            break;
        case SEC_E_WRONG_PRINCIPAL:
            OutputDebugF(_C("Returning bad password :: WRONG_PRINCIPAL"));
            break;
        case SEC_E_TIME_SKEW:
            OutputDebugF(_C("Returning bad password :: TIME_SKEW"));
            break;
        default:
            OutputDebugF(_C("Returning bad password :: Status == %lX"), status);
        }
        code = CM_ERROR_BADPASSWORD;
    }

    if (secCtx) {
        if (secCtx->partialToken) free(secCtx->partialToken);
        free(secCtx);
    }

    if (assembledBlob) {
        free(assembledBlob);
    }

    if (secTokOut.pvBuffer)
        FreeContextBuffer(secTokOut.pvBuffer);

    if (code != CM_ERROR_GSSCONTINUE) {
        DeleteSecurityContext(&ctx);
        FreeCredentialsHandle(&creds);
    }

  aue_0:
    return code;
}

#define P_LEN 256
#define P_RESP_LEN 128

/* LsaLogonUser expects input parameters to be in a contiguous block of memory.
   So put stuff in a struct. */
struct Lm20AuthBlob {
    MSV1_0_LM20_LOGON lmlogon;
    BYTE ciResponse[P_RESP_LEN];    /* Unicode representation */
    BYTE csResponse[P_RESP_LEN];    /* ANSI representation */
    WCHAR accountNameW[P_LEN];
    WCHAR primaryDomainW[P_LEN];
    WCHAR workstationW[MAX_COMPUTERNAME_LENGTH + 1];
    TOKEN_GROUPS tgroups;
    TOKEN_SOURCE tsource;
};

long smb_AuthenticateUserLM(smb_vc_t *vcp, clientchar_t * accountName, clientchar_t * primaryDomain, char * ciPwd, unsigned ciPwdLength, char * csPwd, unsigned csPwdLength)
{
    NTSTATUS nts, ntsEx;
    struct Lm20AuthBlob lmAuth;
    PMSV1_0_LM20_LOGON_PROFILE lmprofilep;
    QUOTA_LIMITS quotaLimits;
    DWORD size;
    ULONG lmprofilepSize;
    LUID lmSession;
    HANDLE lmToken;

    OutputDebugF(_C("In smb_AuthenticateUser for user [%s] domain [%s]"), accountName, primaryDomain);
    OutputDebugF(_C("ciPwdLength is %d and csPwdLength is %d"), ciPwdLength, csPwdLength);

    if (ciPwdLength > P_RESP_LEN || csPwdLength > P_RESP_LEN) {
        OutputDebugF(_C("ciPwdLength or csPwdLength is too long"));
        return CM_ERROR_BADPASSWORD;
    }

    memset(&lmAuth,0,sizeof(lmAuth));

    lmAuth.lmlogon.MessageType = MsV1_0NetworkLogon;

    lmAuth.lmlogon.LogonDomainName.Buffer = lmAuth.primaryDomainW;
    cm_ClientStringToUtf16(primaryDomain, -1, lmAuth.primaryDomainW, P_LEN);
    lmAuth.lmlogon.LogonDomainName.Length = (USHORT)(wcslen(lmAuth.primaryDomainW) * sizeof(WCHAR));
    lmAuth.lmlogon.LogonDomainName.MaximumLength = P_LEN * sizeof(WCHAR);

    lmAuth.lmlogon.UserName.Buffer = lmAuth.accountNameW;
    cm_ClientStringToUtf16(accountName, -1, lmAuth.accountNameW, P_LEN);
    lmAuth.lmlogon.UserName.Length = (USHORT)(wcslen(lmAuth.accountNameW) * sizeof(WCHAR));
    lmAuth.lmlogon.UserName.MaximumLength = P_LEN * sizeof(WCHAR);

    lmAuth.lmlogon.Workstation.Buffer = lmAuth.workstationW;
    lmAuth.lmlogon.Workstation.MaximumLength = (MAX_COMPUTERNAME_LENGTH + 1) * sizeof(WCHAR);
    size = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(lmAuth.workstationW, &size);
    lmAuth.lmlogon.Workstation.Length = (USHORT)(wcslen(lmAuth.workstationW) * sizeof(WCHAR));

    memcpy(lmAuth.lmlogon.ChallengeToClient, vcp->encKey, MSV1_0_CHALLENGE_LENGTH);

    lmAuth.lmlogon.CaseInsensitiveChallengeResponse.Buffer = lmAuth.ciResponse;
    lmAuth.lmlogon.CaseInsensitiveChallengeResponse.Length = ciPwdLength;
    lmAuth.lmlogon.CaseInsensitiveChallengeResponse.MaximumLength = P_RESP_LEN;
    memcpy(lmAuth.ciResponse, ciPwd, ciPwdLength);

    lmAuth.lmlogon.CaseSensitiveChallengeResponse.Buffer = lmAuth.csResponse;
    lmAuth.lmlogon.CaseSensitiveChallengeResponse.Length = csPwdLength;
    lmAuth.lmlogon.CaseSensitiveChallengeResponse.MaximumLength = P_RESP_LEN;
    memcpy(lmAuth.csResponse, csPwd, csPwdLength);

    lmAuth.lmlogon.ParameterControl = 0;

    lmAuth.tgroups.GroupCount = 0;
    lmAuth.tgroups.Groups[0].Sid = NULL;
    lmAuth.tgroups.Groups[0].Attributes = 0;

#ifdef _WIN64
    lmAuth.tsource.SourceIdentifier.HighPart = (DWORD)((LONG_PTR)vcp << 32);
#else
    lmAuth.tsource.SourceIdentifier.HighPart = 0;
#endif
    lmAuth.tsource.SourceIdentifier.LowPart = (DWORD)((LONG_PTR)vcp & _UI32_MAX);
    StringCchCopyA(lmAuth.tsource.SourceName, lengthof(lmAuth.tsource.SourceName),
                   "OpenAFS"); /* 8 char limit */

    nts = LsaLogonUser( smb_lsaHandle,
                        &smb_lsaLogonOrigin,
                        Network, /*3*/
                        smb_lsaSecPackage,
                        &lmAuth,
                        sizeof(lmAuth),
                        &lmAuth.tgroups,
                        &lmAuth.tsource,
                        &lmprofilep,
                        &lmprofilepSize,
                        &lmSession,
                        &lmToken,
                        &quotaLimits,
                        &ntsEx);

    if (nts != STATUS_SUCCESS || ntsEx != STATUS_SUCCESS)
        osi_Log2(smb_logp,"LsaLogonUser failure: nts %u ntsEx %u",
                  nts, ntsEx);

    OutputDebugF(_C("Return from LsaLogonUser is 0x%lX"), nts);
    OutputDebugF(_C("Extended status is 0x%lX"), ntsEx);

    if (nts == ERROR_SUCCESS) {
        /* free the token */
        LsaFreeReturnBuffer(lmprofilep);
        CloseHandle(lmToken);
        return 0;
    } else {
        /* No AFS for you */
        if (nts == 0xC000015BL)
            return CM_ERROR_BADLOGONTYPE;
        else /* our catchall is a bad password though we could be more specific */
            return CM_ERROR_BADPASSWORD;
    }
}

/* The buffer pointed to by usern is assumed to be at least SMB_MAX_USERNAME_LENGTH bytes */
long smb_GetNormalizedUsername(clientchar_t * usern, const clientchar_t * accountName, const clientchar_t * domainName)
{
    clientchar_t * atsign;
    const clientchar_t * domain;

    /* check if we have sane input */
    if ((cm_ClientStrLen(accountName) + cm_ClientStrLen(domainName) + 1) > SMB_MAX_USERNAME_LENGTH)
        return 1;

    /* we could get : [accountName][domainName]
       [user][domain]
       [user@domain][]
       [user][]/[user][?]
       [][]/[][?] */

    atsign = cm_ClientStrChr(accountName, '@');

    if (atsign) /* [user@domain][] -> [user@domain][domain] */
        domain = atsign + 1;
    else
        domain = domainName;

    /* if for some reason the client doesn't know what domain to use,
       it will either return an empty string or a '?' */
    if (!domain[0] || domain[0] == '?')
        /* Empty domains and empty usernames are usually sent from tokenless contexts.
           This way such logins will get an empty username (easy to check).  I don't know
           when a non-empty username would be supplied with an anonymous domain, but *shrug* */
        cm_ClientStrCpy(usern, SMB_MAX_USERNAME_LENGTH, accountName);
    else {
        /* TODO: what about WIN.MIT.EDU\user vs. WIN\user? */
        cm_ClientStrCpy(usern, SMB_MAX_USERNAME_LENGTH, domain);
        cm_ClientStrCat(usern, SMB_MAX_USERNAME_LENGTH, _C("\\"));
        if (atsign)
            cm_ClientStrCat(usern, SMB_MAX_USERNAME_LENGTH, accountName);
        else
            cm_ClientStrCat(usern, SMB_MAX_USERNAME_LENGTH, accountName);
    }

    cm_ClientStrLwr(usern);

    return 0;
}

/* When using SMB auth, all SMB sessions have to pass through here
 * first to authenticate the user.
 *
 * Caveat: If not using SMB auth, the protocol does not require
 * sending a session setup packet, which means that we can't rely on a
 * UID in subsequent packets.  Though in practice we get one anyway.
 */
/* SMB_COM_SESSION_SETUP_ANDX */
long smb_ReceiveV3SessionSetupX(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    char *tp;
    smb_user_t *uidp;
    unsigned short newUid;
    unsigned long caps = 0;
    smb_username_t *unp;
    clientchar_t *s1 = _C(" ");
    long code = 0;
    clientchar_t usern[SMB_MAX_USERNAME_LENGTH];
    int usernIsSID = 0;
    char *secBlobOut = NULL;
    int  secBlobOutLength = 0;
    wchar_t *secSidString = 0;
    int  maxBufferSize = 0;
    int  maxMpxCount = 0;
    int  vcNumber = 0;

    /* Check for bad conns */
    if (vcp->flags & SMB_VCFLAG_REMOTECONN)
        return CM_ERROR_REMOTECONN;

    /* maxBufferSize */
    maxBufferSize = smb_GetSMBParm(inp, 2);
    maxMpxCount = smb_GetSMBParm(inp, 3);
    vcNumber = smb_GetSMBParm(inp, 4);

    osi_Log3(smb_logp, "SESSION_SETUP_ANDX with MaxBufferSize=%d, MaxMpxCount=%d, VCNumber=%d",
             maxBufferSize, maxMpxCount, vcNumber);

    if (maxMpxCount > smb_maxMpxRequests) {
        LogEvent(EVENTLOG_INFORMATION_TYPE, MSG_SMB_MAX_MPX_COUNT, maxMpxCount, smb_maxMpxRequests);
        osi_Log2(smb_logp, "MaxMpxCount for client is too large (Client=%d, Server=%d)",
                 maxMpxCount, smb_maxMpxRequests);
    }

    if (maxBufferSize < SMB_PACKETSIZE) {
        LogEvent(EVENTLOG_INFORMATION_TYPE, MSG_SMB_MAX_BUFFER_SIZE, maxBufferSize, SMB_PACKETSIZE);
        osi_Log2(smb_logp, "MaxBufferSize for client is too small (Client=%d, Server=%d)",
                 maxBufferSize, SMB_PACKETSIZE);
    }

    if (vcNumber == 0) {
        osi_Log0(smb_logp, "Resetting all VCs");
        smb_MarkAllVCsDead(vcp);
    }

    if (vcp->flags & SMB_VCFLAG_USENT) {
        if (smb_authType == SMB_AUTH_EXTENDED) {
            /* extended authentication */
            char *secBlobIn;
            int secBlobInLength;

            OutputDebugF(_C("NT Session Setup: Extended"));

            if (!(vcp->flags & SMB_VCFLAG_SESSX_RCVD)) {
                caps = smb_GetSMBParm(inp,10) | (((unsigned long) smb_GetSMBParm(inp,11)) << 16);
            }

            secBlobInLength = smb_GetSMBParm(inp, 7);
            secBlobIn = smb_GetSMBData(inp, NULL);

            code = smb_AuthenticateUserExt(vcp, usern, secBlobIn, secBlobInLength, &secBlobOut, &secBlobOutLength, &secSidString);

            if (code == CM_ERROR_GSSCONTINUE) {
                size_t cb_data = 0;

                smb_SetSMBParm(outp, 2, 0);
                smb_SetSMBParm(outp, 3, secBlobOutLength);

                tp = smb_GetSMBData(outp, NULL);
                if (secBlobOutLength) {
                    memcpy(tp, secBlobOut, secBlobOutLength);
                    free(secBlobOut);
                    tp += secBlobOutLength;
                    cb_data += secBlobOutLength;
                }
                tp = smb_UnparseString(outp, tp, smb_ServerOS, &cb_data, 0);
                tp = smb_UnparseString(outp, tp, smb_ServerLanManager, &cb_data, 0);
                tp = smb_UnparseString(outp, tp, smb_ServerDomainName, &cb_data, 0);

                smb_SetSMBDataLength(outp, cb_data);
            }

            /* TODO: handle return code and continue auth. Also free secBlobOut if applicable. */
        } else {
            unsigned ciPwdLength, csPwdLength;
            char *ciPwd, *csPwd;
            clientchar_t *accountName;
            clientchar_t *primaryDomain;
            int  datalen;

            if (smb_authType == SMB_AUTH_NTLM)
                OutputDebugF(_C("NT Session Setup: NTLM"));
            else
                OutputDebugF(_C("NT Session Setup: None"));

            /* TODO: parse for extended auth as well */
            ciPwdLength = smb_GetSMBParm(inp, 7); /* case insensitive password length */
            csPwdLength = smb_GetSMBParm(inp, 8); /* case sensitive password length */

            tp = smb_GetSMBData(inp, &datalen);

            OutputDebugF(_C("Session packet data size [%d]"),datalen);

            ciPwd = tp;
            tp += ciPwdLength;
            csPwd = tp;
            tp += csPwdLength;

            accountName = smb_ParseString(inp, tp, &tp, 0);
            primaryDomain = smb_ParseString(inp, tp, NULL, 0);

            OutputDebugF(_C("Account Name: %s"),accountName);
            OutputDebugF(_C("Primary Domain: %s"), primaryDomain);
            OutputDebugF(_C("Case Sensitive Password: %s"),
                         csPwd && csPwd[0] ? _C("yes") : _C("no"));
            OutputDebugF(_C("Case Insensitive Password: %s"),
                         ciPwd && ciPwd[0] ? _C("yes") : _C("no"));

            if (smb_GetNormalizedUsername(usern, accountName, primaryDomain)) {
                /* shouldn't happen */
                code = CM_ERROR_BADSMB;
                goto after_read_packet;
            }

            /* capabilities are only valid for first session packet */
            if (!(vcp->flags & SMB_VCFLAG_SESSX_RCVD)) {
                caps = smb_GetSMBParm(inp, 11) | (((unsigned long)smb_GetSMBParm(inp, 12)) << 16);
            }

            if (smb_authType == SMB_AUTH_NTLM) {
                code = smb_AuthenticateUserLM(vcp, accountName, primaryDomain, ciPwd, ciPwdLength, csPwd, csPwdLength);
                if ( code )
                    OutputDebugF(_C("LM authentication failed [%d]"), code);
                else
                    OutputDebugF(_C("LM authentication succeeded"));
            }
        }
    }  else { /* V3 */
        unsigned ciPwdLength;
        char *ciPwd;
        clientchar_t *accountName;
        clientchar_t *primaryDomain;

        switch ( smb_authType ) {
        case SMB_AUTH_EXTENDED:
            OutputDebugF(_C("V3 Session Setup: Extended"));
            break;
        case SMB_AUTH_NTLM:
            OutputDebugF(_C("V3 Session Setup: NTLM"));
            break;
        default:
            OutputDebugF(_C("V3 Session Setup: None"));
        }
        ciPwdLength = smb_GetSMBParm(inp, 7);
        tp = smb_GetSMBData(inp, NULL);
        ciPwd = tp;
        tp += ciPwdLength;

        accountName = smb_ParseString(inp, tp, &tp, 0);
        primaryDomain = smb_ParseString(inp, tp, NULL, 0);

        OutputDebugF(_C("Account Name: %s"),accountName);
        OutputDebugF(_C("Primary Domain: %s"), primaryDomain);
        OutputDebugF(_C("Case Insensitive Password: %s"), ciPwd && ciPwd[0] ? _C("yes") : _C("no"));

        if ( smb_GetNormalizedUsername(usern, accountName, primaryDomain)) {
            /* shouldn't happen */
            code = CM_ERROR_BADSMB;
            goto after_read_packet;
        }

        /* even if we wanted extended auth, if we only negotiated V3, we have to fallback
         * to NTLM.
         */
        if (smb_authType == SMB_AUTH_NTLM || smb_authType == SMB_AUTH_EXTENDED) {
            code = smb_AuthenticateUserLM(vcp,accountName,primaryDomain,ciPwd,ciPwdLength,"",0);
            if ( code )
                OutputDebugF(_C("LM authentication failed [%d]"), code);
            else
                OutputDebugF(_C("LM authentication succeeded"));
        }
    }

  after_read_packet:
    /* note down that we received a session setup X and set the capabilities flag */
    if (!(vcp->flags & SMB_VCFLAG_SESSX_RCVD)) {
        lock_ObtainMutex(&vcp->mx);
        vcp->flags |= SMB_VCFLAG_SESSX_RCVD;
        /* for the moment we can only deal with NTSTATUS */
        if (caps & NTNEGOTIATE_CAPABILITY_NTSTATUS) {
            vcp->flags |= SMB_VCFLAG_STATUS32;
        }

#ifdef SMB_UNICODE
        if ((caps & NTNEGOTIATE_CAPABILITY_UNICODE) && smb_UseUnicode) {
            vcp->flags |= SMB_VCFLAG_USEUNICODE;
        }
#endif
        lock_ReleaseMutex(&vcp->mx);
    }

    /* code would be non-zero if there was an authentication failure.
       Ideally we would like to invalidate the uid for this session or break
       early to avoid accidently stealing someone else's tokens. */

    if (code) {
        if (secSidString)
            LocalFree(secSidString);
        return code;
    }

    /*
     * If the SidString for the user could be obtained, use that
     * for the user id
     */
    if (secSidString) {
        cm_ClientStrCpy(usern, SMB_MAX_USERNAME_LENGTH, secSidString);
        usernIsSID = 1;
    }

    OutputDebugF(_C("Received username=[%s]"), usern);

    /* On Windows 2000, this function appears to be called more often than
       it is expected to be called. This resulted in multiple smb_user_t
       records existing all for the same user session which results in all
       of the users tokens disappearing.

       To avoid this problem, we look for an existing smb_user_t record
       based on the users name, and use that one if we find it.
    */

    uidp = smb_FindUserByNameThisSession(vcp, usern);
    if (uidp) {   /* already there, so don't create a new one */
        unp = uidp->unp;
        newUid = uidp->userID;
        osi_Log3(smb_logp,"smb_ReceiveV3SessionSetupX FindUserByName:Lana[%d],lsn[%d],userid[%d]",
		 vcp->lana,vcp->lsn,newUid);
        smb_ReleaseUID(uidp);
    }
    else {
	cm_user_t *userp;

	/* do a global search for the username/machine name pair */
        unp = smb_FindUserByName(usern, vcp->rname, SMB_FLAG_CREATE);
 	lock_ObtainMutex(&unp->mx);
 	if (unp->flags & SMB_USERNAMEFLAG_AFSLOGON) {
 	    /* clear the afslogon flag so that the tickets can now
 	     * be freed when the refCount returns to zero.
 	     */
 	    unp->flags &= ~SMB_USERNAMEFLAG_AFSLOGON;
            if (usernIsSID)
                unp->flags |= SMB_USERNAMEFLAG_SID;
 	}
    if (usernIsSID)
        unp->flags |= SMB_USERNAMEFLAG_SID;
 	lock_ReleaseMutex(&unp->mx);

        /* Create a new UID and cm_user_t structure */
        userp = unp->userp;
        if (!userp)
            userp = cm_NewUser();
 	cm_HoldUserVCRef(userp);
	lock_ObtainMutex(&vcp->mx);
        if (!vcp->uidCounter)
            vcp->uidCounter++; /* handle unlikely wraparounds */
        newUid = (cm_ClientStrLen(usern)==0)?0:vcp->uidCounter++;
        lock_ReleaseMutex(&vcp->mx);

        /* Create a new smb_user_t structure and connect them up */
        lock_ObtainMutex(&unp->mx);
        unp->userp = userp;
        lock_ReleaseMutex(&unp->mx);

        uidp = smb_FindUID(vcp, newUid, SMB_FLAG_CREATE);
	if (uidp) {
	    lock_ObtainMutex(&uidp->mx);
	    uidp->unp = unp;
	    osi_Log4(smb_logp,"smb_ReceiveV3SessionSetupX MakeNewUser:VCP[%p],Lana[%d],lsn[%d],userid[%d]",vcp,vcp->lana,vcp->lsn,newUid);
	    lock_ReleaseMutex(&uidp->mx);
	    smb_ReleaseUID(uidp);
	}
    }

    /* Return UID to the client */
    ((smb_t *)outp)->uid = newUid;
    /* Also to the next chained message */
    ((smb_t *)inp)->uid = newUid;

    osi_Log3(smb_logp, "SMB3 session setup name %S creating ID %d%S",
             osi_LogSaveClientString(smb_logp, usern), newUid,
             osi_LogSaveClientString(smb_logp, s1));

    smb_SetSMBParm(outp, 2, 0);

    if (vcp->flags & SMB_VCFLAG_USENT) {
        if (smb_authType == SMB_AUTH_EXTENDED) {
            size_t cb_data = 0;

            smb_SetSMBParm(outp, 3, secBlobOutLength);

            tp = smb_GetSMBData(outp, NULL);
            if (secBlobOutLength) {
                memcpy(tp, secBlobOut, secBlobOutLength);
                free(secBlobOut);
                tp += secBlobOutLength;
                cb_data +=  secBlobOutLength;
            }

            tp = smb_UnparseString(outp, tp, smb_ServerOS, &cb_data, 0);
            tp = smb_UnparseString(outp, tp, smb_ServerLanManager, &cb_data, 0);
            tp = smb_UnparseString(outp, tp, smb_ServerDomainName, &cb_data, 0);

            smb_SetSMBDataLength(outp, cb_data);
        } else {
            smb_SetSMBDataLength(outp, 0);
        }
    } else {
        if (smb_authType == SMB_AUTH_EXTENDED) {
            size_t cb_data = 0;

            tp = smb_GetSMBData(outp, NULL);

            tp = smb_UnparseString(outp, tp, smb_ServerOS, &cb_data, 0);
            tp = smb_UnparseString(outp, tp, smb_ServerLanManager, &cb_data, 0);
            tp = smb_UnparseString(outp, tp, smb_ServerDomainName, &cb_data, 0);

            smb_SetSMBDataLength(outp, cb_data);
        } else {
            smb_SetSMBDataLength(outp, 0);
        }
    }

    if (secSidString)
        LocalFree(secSidString);
    return 0;
}

/* SMB_COM_LOGOFF_ANDX */
long smb_ReceiveV3UserLogoffX(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    smb_user_t *uidp;

    /* find the tree and free it */
    uidp = smb_FindUID(vcp, ((smb_t *)inp)->uid, 0);
    if (uidp) {
	smb_username_t * unp;

        osi_Log2(smb_logp, "SMB3 user logoffX uid %d name %S", uidp->userID,
                 osi_LogSaveClientString(smb_logp, (uidp->unp) ? uidp->unp->name: _C(" ")));

        lock_ObtainMutex(&uidp->mx);
        uidp->flags |= SMB_USERFLAG_DELETE;
	/*
         * it doesn't get deleted right away
         * because the vcp points to it
         */
	unp = uidp->unp;
        lock_ReleaseMutex(&uidp->mx);

#ifdef COMMENT
	/* we can't do this.  we get logoff messages prior to a session
	 * disconnect even though it doesn't mean the user is logging out.
	 * we need to create a new pioctl and EventLogoff handler to set
	 * SMB_USERNAMEFLAG_LOGOFF.
	 */
	if (unp && smb_LogoffTokenTransfer) {
	    lock_ObtainMutex(&unp->mx);
	    unp->flags |= SMB_USERNAMEFLAG_LOGOFF;
	    unp->last_logoff_t = osi_Time() + smb_LogoffTransferTimeout;
	    lock_ReleaseMutex(&unp->mx);
	}
#endif

	smb_ReleaseUID(uidp);
    }
    else
        osi_Log0(smb_logp, "SMB3 user logoffX");

    smb_SetSMBDataLength(outp, 0);
    return 0;
}

#define SMB_SUPPORT_SEARCH_BITS        0x0001
#define SMB_SHARE_IS_IN_DFS            0x0002

/* SMB_COM_TREE_CONNECT_ANDX */
long smb_ReceiveV3TreeConnectX(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    smb_tid_t *tidp;
    smb_user_t *uidp = NULL;
    unsigned short newTid;
    clientchar_t shareName[AFSPATHMAX];
    clientchar_t *sharePath;
    int shareFound;
    char *tp;
    clientchar_t *slashp;
    clientchar_t *pathp;
    clientchar_t *passwordp;
    clientchar_t *servicep;
    cm_user_t *userp = NULL;
    int ipc = 0;

    osi_Log0(smb_logp, "SMB3 receive tree connect");

    /* parse input parameters */
    tp = smb_GetSMBData(inp, NULL);
    passwordp = smb_ParseString(inp, tp, &tp, SMB_STRF_FORCEASCII);
    pathp = smb_ParseString(inp, tp, &tp, SMB_STRF_ANSIPATH);
    servicep = smb_ParseString(inp, tp, &tp, SMB_STRF_FORCEASCII);

    slashp = cm_ClientStrRChr(pathp, '\\');
    if (!slashp) {
        return CM_ERROR_BADSMB;
    }
    cm_ClientStrCpy(shareName, lengthof(shareName), slashp+1);

    osi_Log3(smb_logp, "Tree connect pathp[%S] shareName[%S] service[%S]",
             osi_LogSaveClientString(smb_logp, pathp),
             osi_LogSaveClientString(smb_logp, shareName),
             osi_LogSaveClientString(smb_logp, servicep));

    if (cm_ClientStrCmp(servicep, _C("IPC")) == 0 ||
        cm_ClientStrCmp(shareName, _C("IPC$")) == 0) {
#ifndef NO_IPC
        osi_Log0(smb_logp, "TreeConnectX connecting to IPC$");
        ipc = 1;
#else
        return CM_ERROR_NOIPC;
#endif
    }

    uidp = smb_FindUID(vcp, ((smb_t *)inp)->uid, 0);
    if (uidp)
	userp = smb_GetUserFromUID(uidp);

    lock_ObtainMutex(&vcp->mx);
    newTid = vcp->tidCounter++;
    lock_ReleaseMutex(&vcp->mx);

    tidp = smb_FindTID(vcp, newTid, SMB_FLAG_CREATE);

    if (!ipc) {
	if (!cm_ClientStrCmp(shareName, _C("*.")))
	    cm_ClientStrCpy(shareName, lengthof(shareName), _C("all"));
	shareFound = smb_FindShare(vcp, uidp, shareName, &sharePath);
	if (!shareFound) {
	    if (uidp)
		smb_ReleaseUID(uidp);
            smb_ReleaseTID(tidp, FALSE);
            return CM_ERROR_BADSHARENAME;
	}

	if (vcp->flags & SMB_VCFLAG_USENT)
        {
            int policy = smb_FindShareCSCPolicy(shareName);
            HKEY parmKey;
            DWORD code;
            DWORD dwAdvertiseDFS = 0, dwSize = sizeof(DWORD);

            code = RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PARAM_SUBKEY,
                                 0, KEY_QUERY_VALUE, &parmKey);
            if (code == ERROR_SUCCESS) {
                code = RegQueryValueEx(parmKey, "AdvertiseDFS", NULL, NULL,
                                       (BYTE *)&dwAdvertiseDFS, &dwSize);
                if (code != ERROR_SUCCESS)
                    dwAdvertiseDFS = 0;
                RegCloseKey (parmKey);
            }
            smb_SetSMBParm(outp, 2, SMB_SUPPORT_SEARCH_BITS |
                           (dwAdvertiseDFS ? SMB_SHARE_IS_IN_DFS : 0) |
                           (policy << 2));
        }
    } else {
        smb_SetSMBParm(outp, 2, 0);
        sharePath = NULL;
    }
    if (uidp)
	smb_ReleaseUID(uidp);

    lock_ObtainMutex(&tidp->mx);
    tidp->userp = userp;
    tidp->pathname = sharePath;
    if (ipc)
        tidp->flags |= SMB_TIDFLAG_IPC;
    lock_ReleaseMutex(&tidp->mx);
    smb_ReleaseTID(tidp, FALSE);

    ((smb_t *)outp)->tid = newTid;
    ((smb_t *)inp)->tid = newTid;
    tp = smb_GetSMBData(outp, NULL);
    if (!ipc) {
        size_t cb_data = 0;

        tp = smb_UnparseString(outp, tp, _C("A:"), &cb_data, SMB_STRF_FORCEASCII);
        tp = smb_UnparseString(outp, tp, _C("AFS"), &cb_data, 0);
        smb_SetSMBDataLength(outp, cb_data);
    } else {
        size_t cb_data = 0;

        tp = smb_UnparseString(outp, tp, _C("IPC"), &cb_data, SMB_STRF_FORCEASCII);
        smb_SetSMBDataLength(outp, cb_data);
    }

    osi_Log1(smb_logp, "SMB3 tree connect created ID %d", newTid);
    return 0;
}

/* must be called with global tran lock held */
smb_tran2Packet_t *smb_FindTran2Packet(smb_vc_t *vcp, smb_packet_t *inp)
{
    smb_tran2Packet_t *tp;
    smb_t *smbp;

    smbp = (smb_t *) inp->data;
    for (tp = smb_tran2AssemblyQueuep; tp; tp = (smb_tran2Packet_t *) osi_QNext(&tp->q)) {
        if (tp->vcp == vcp && tp->mid == smbp->mid && tp->tid == smbp->tid)
            return tp;
    }
    return NULL;
}

smb_tran2Packet_t *smb_NewTran2Packet(smb_vc_t *vcp, smb_packet_t *inp,
                                      int totalParms, int totalData)
{
    smb_tran2Packet_t *tp;
    smb_t *smbp;

    smbp = (smb_t *) inp->data;
    tp = malloc(sizeof(*tp));
    memset(tp, 0, sizeof(*tp));
    tp->vcp = vcp;
    smb_HoldVC(vcp);
    tp->curData = tp->curParms = 0;
    tp->totalData = totalData;
    tp->totalParms = totalParms;
    tp->tid = smbp->tid;
    tp->mid = smbp->mid;
    tp->uid = smbp->uid;
    tp->pid = smbp->pid;
    tp->res[0] = smbp->res[0];
    osi_QAdd((osi_queue_t **)&smb_tran2AssemblyQueuep, &tp->q);
    if (totalParms != 0)
        tp->parmsp = malloc(totalParms);
    if (totalData != 0)
        tp->datap = malloc(totalData);
    if (smbp->com == 0x25 || smbp->com == 0x26)
        tp->com = 0x25;
    else {
        tp->opcode = smb_GetSMBParm(inp, 14);
        tp->com = 0x32;
    }
    tp->flags |= SMB_TRAN2PFLAG_ALLOC;
#ifdef SMB_UNICODE
    if (WANTS_UNICODE(inp) && (vcp->flags & SMB_VCFLAG_USEUNICODE))
        tp->flags |= SMB_TRAN2PFLAG_USEUNICODE;
#endif
    return tp;
}

smb_tran2Packet_t *smb_GetTran2ResponsePacket(smb_vc_t *vcp,
                                              smb_tran2Packet_t *inp, smb_packet_t *outp,
                                              int totalParms, int totalData)
{
    smb_tran2Packet_t *tp;
    unsigned short parmOffset;
    unsigned short dataOffset;
    unsigned short dataAlign;

    tp = malloc(sizeof(*tp));
    memset(tp, 0, sizeof(*tp));
    smb_HoldVC(vcp);
    tp->vcp = vcp;
    tp->curData = tp->curParms = 0;
    tp->totalData = totalData;
    tp->totalParms = totalParms;
    tp->oldTotalParms = totalParms;
    tp->tid = inp->tid;
    tp->mid = inp->mid;
    tp->uid = inp->uid;
    tp->pid = inp->pid;
    tp->res[0] = inp->res[0];
    tp->opcode = inp->opcode;
    tp->com = inp->com;

    /*
     * We calculate where the parameters and data will start.
     * This calculation must parallel the calculation in
     * smb_SendTran2Packet.
     */

    parmOffset = 10*2 + 35;
    parmOffset++;			/* round to even */
    tp->parmsp = (unsigned short *) (outp->data + parmOffset);

    dataOffset = parmOffset + totalParms;
    dataAlign = dataOffset & 2;	/* quad-align */
    dataOffset += dataAlign;
    tp->datap = outp->data + dataOffset;

    return tp;
}

/* free a tran2 packet */
void smb_FreeTran2Packet(smb_tran2Packet_t *t2p)
{
    if (t2p->vcp) {
        smb_ReleaseVC(t2p->vcp);
	t2p->vcp = NULL;
    }
    if (t2p->flags & SMB_TRAN2PFLAG_ALLOC) {
        if (t2p->parmsp)
            free(t2p->parmsp);
        if (t2p->datap)
            free(t2p->datap);
    }
    if (t2p->name) {
	free(t2p->name);
	t2p->name = NULL;
    }
    while (t2p->stringsp) {
        cm_space_t * ns;

        ns = t2p->stringsp;
        t2p->stringsp = ns->nextp;
        cm_FreeSpace(ns);
    }
    free(t2p);
}

clientchar_t *smb_ParseStringT2Parm(smb_tran2Packet_t * p, unsigned char * inp,
                                    char ** chainpp, int flags)
{
    size_t cb;

#ifdef SMB_UNICODE
    if (!(p->flags & SMB_TRAN2PFLAG_USEUNICODE))
        flags |= SMB_STRF_FORCEASCII;
#endif

    cb = p->totalParms - (inp - (char *)p->parmsp);
    if (inp < (char *) p->parmsp ||
        inp >= ((char *) p->parmsp) + p->totalParms) {
#ifdef DEBUG_UNICODE
        DebugBreak();
#endif
        cb = p->totalParms;
    }

    return smb_ParseStringBuf((unsigned char *) p->parmsp, &p->stringsp,
                              inp, &cb, chainpp, flags);
}

/* called with a VC, an input packet to respond to, and an error code.
 * sends an error response.
 */
void smb_SendTran2Error(smb_vc_t *vcp, smb_tran2Packet_t *t2p,
                        smb_packet_t *tp, long code)
{
    smb_t *smbp;
    unsigned short errCode;
    unsigned char errClass;
    unsigned long NTStatus;

    if (vcp->flags & SMB_VCFLAG_STATUS32)
        smb_MapNTError(code, &NTStatus, FALSE);
    else
        smb_MapCoreError(code, vcp, &errCode, &errClass);

    smb_FormatResponsePacket(vcp, NULL, tp);
    smbp = (smb_t *) tp;

    /* We can handle long names */
    if (vcp->flags & SMB_VCFLAG_USENT)
        smbp->flg2 |= SMB_FLAGS2_IS_LONG_NAME;

    /* now copy important fields from the tran 2 packet */
    smbp->com = t2p->com;
    smbp->tid = t2p->tid;
    smbp->mid = t2p->mid;
    smbp->pid = t2p->pid;
    smbp->uid = t2p->uid;
    smbp->res[0] = t2p->res[0];
    if (vcp->flags & SMB_VCFLAG_STATUS32) {
        smbp->rcls = (unsigned char) (NTStatus & 0xff);
        smbp->reh = (unsigned char) ((NTStatus >> 8) & 0xff);
        smbp->errLow = (unsigned char) ((NTStatus >> 16) & 0xff);
        smbp->errHigh = (unsigned char) ((NTStatus >> 24) & 0xff);
        smbp->flg2 |= SMB_FLAGS2_32BIT_STATUS;
    }
    else {
        smbp->rcls = errClass;
        smbp->errLow = (unsigned char) (errCode & 0xff);
        smbp->errHigh = (unsigned char) ((errCode >> 8) & 0xff);
    }

    /* send packet */
    smb_SendPacket(vcp, tp);
}

void smb_SendTran2Packet(smb_vc_t *vcp, smb_tran2Packet_t *t2p, smb_packet_t *tp)
{
    smb_t *smbp;
    unsigned short parmOffset;
    unsigned short dataOffset;
    unsigned short totalLength;
    unsigned short dataAlign;
    char *datap;

    smb_FormatResponsePacket(vcp, NULL, tp);
    smbp = (smb_t *) tp;

    /* We can handle long names */
    if (vcp->flags & SMB_VCFLAG_USENT)
        smbp->flg2 |= SMB_FLAGS2_IS_LONG_NAME;

    /* now copy important fields from the tran 2 packet */
    smbp->com = t2p->com;
    smbp->tid = t2p->tid;
    smbp->mid = t2p->mid;
    smbp->pid = t2p->pid;
    smbp->uid = t2p->uid;
    smbp->res[0] = t2p->res[0];

    if (t2p->error_code) {
	if (vcp->flags & SMB_VCFLAG_STATUS32) {
	    unsigned long NTStatus;

	    smb_MapNTError(t2p->error_code, &NTStatus, FALSE);

	    smbp->rcls = (unsigned char) (NTStatus & 0xff);
	    smbp->reh = (unsigned char) ((NTStatus >> 8) & 0xff);
	    smbp->errLow = (unsigned char) ((NTStatus >> 16) & 0xff);
	    smbp->errHigh = (unsigned char) ((NTStatus >> 24) & 0xff);
	    smbp->flg2 |= SMB_FLAGS2_32BIT_STATUS;
	}
	else {
	    unsigned short errCode;
	    unsigned char errClass;

	    smb_MapCoreError(t2p->error_code, vcp, &errCode, &errClass);

	    smbp->rcls = errClass;
	    smbp->errLow = (unsigned char) (errCode & 0xff);
	    smbp->errHigh = (unsigned char) ((errCode >> 8) & 0xff);
	}
    }

    totalLength = 1 + t2p->totalData + t2p->totalParms;

    /* now add the core parameters (tran2 info) to the packet */
    smb_SetSMBParm(tp, 0, t2p->totalParms);	/* parm bytes */
    smb_SetSMBParm(tp, 1, t2p->totalData);	/* data bytes */
    smb_SetSMBParm(tp, 2, 0);		/* reserved */
    smb_SetSMBParm(tp, 3, t2p->totalParms);	/* parm bytes in this packet */
    parmOffset = 10*2 + 35;			/* parm offset in packet */
    parmOffset++;				/* round to even */
    smb_SetSMBParm(tp, 4, parmOffset);	/* 11 parm words plus *
    * hdr, bcc and wct */
    smb_SetSMBParm(tp, 5, 0);		/* parm displacement */
    smb_SetSMBParm(tp, 6, t2p->totalData);	/* data in this packet */
    dataOffset = parmOffset + t2p->oldTotalParms;
    dataAlign = dataOffset & 2;		/* quad-align */
    dataOffset += dataAlign;
    smb_SetSMBParm(tp, 7, dataOffset);	/* offset of data */
    smb_SetSMBParm(tp, 8, 0);		/* data displacement */
    smb_SetSMBParm(tp, 9, 0);		/* low: setup word count *
                                         * high: resvd */

    datap = smb_GetSMBData(tp, NULL);
    *datap++ = 0;				/* we rounded to even */

    totalLength += dataAlign;
    smb_SetSMBDataLength(tp, totalLength);

    /* next, send the datagram */
    smb_SendPacket(vcp, tp);
}

/* TRANS_SET_NMPIPE_STATE */
long smb_nmpipeSetState(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *op)
{
    smb_fid_t *fidp;
    int fd;
    int pipeState = 0x0100;	/* default */
    smb_tran2Packet_t *outp = NULL;

    fd = p->pipeParam;
    if (p->totalParms > 0)
	pipeState = p->parmsp[0];

    osi_Log2(smb_logp, "smb_nmpipeSetState for fd[%d] with state[0x%x]", fd, pipeState);

    fidp = smb_FindFID(vcp, fd, 0);
    if (!fidp) {
        osi_Log2(smb_logp, "smb_nmpipeSetState Unknown SMB Fid vcp 0x%p fid %d",
                 vcp, fd);
	return CM_ERROR_BADFD;
    }
    lock_ObtainMutex(&fidp->mx);
    if (pipeState & 0x8000)
	fidp->flags |= SMB_FID_BLOCKINGPIPE;
    if (pipeState & 0x0100)
	fidp->flags |= SMB_FID_MESSAGEMODEPIPE;
    lock_ReleaseMutex(&fidp->mx);

    outp = smb_GetTran2ResponsePacket(vcp, p, op, 0, 0);
    smb_SendTran2Packet(vcp, outp, op);
    smb_FreeTran2Packet(outp);

    smb_ReleaseFID(fidp);

    return 0;
}

long smb_nmpipeTransact(smb_vc_t * vcp, smb_tran2Packet_t *p, smb_packet_t *op)
{
    smb_fid_t *fidp;
    int fd;
    int is_rpc = 0;

    long code = 0;

    fd = p->pipeParam;

    osi_Log3(smb_logp, "smb_nmpipeTransact for fd[%d] %d bytes in, %d max bytes out",
	     fd, p->totalData, p->maxReturnData);

    fidp = smb_FindFID(vcp, fd, 0);
    if (!fidp) {
        osi_Log2(smb_logp, "smb_nmpipeTransact Unknown SMB Fid vcp 0x%p fid %d",
                 vcp, fd);
	return CM_ERROR_BADFD;
    }
    lock_ObtainMutex(&fidp->mx);
    if (fidp->flags & SMB_FID_RPC) {
	is_rpc = 1;
    }
    lock_ReleaseMutex(&fidp->mx);

    if (is_rpc) {
	code = smb_RPCNmpipeTransact(fidp, vcp, p, op);
	smb_ReleaseFID(fidp);
    } else {
	/* We only deal with RPC pipes */
        osi_Log2(smb_logp, "smb_nmpipeTransact Not a RPC vcp 0x%p fid %d",
                 vcp, fd);
	code = CM_ERROR_BADFD;
    }

    return code;
}


/* SMB_COM_TRANSACTION and SMB_COM_TRANSACTION_SECONDARY */
long smb_ReceiveV3Trans(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    smb_tran2Packet_t *asp;
    int totalParms;
    int totalData;
    int parmDisp;
    int dataDisp;
    int parmOffset;
    int dataOffset;
    int parmCount;
    int dataCount;
    int firstPacket;
    int rapOp;
    long code = 0;

    /* We sometimes see 0 word count.  What to do? */
    if (*inp->wctp == 0) {
        osi_Log0(smb_logp, "Transaction2 word count = 0");
	LogEvent(EVENTLOG_WARNING_TYPE, MSG_SMB_ZERO_TRANSACTION_COUNT);

        smb_SetSMBDataLength(outp, 0);
        smb_SendPacket(vcp, outp);
        return 0;
    }

    totalParms = smb_GetSMBParm(inp, 0);
    totalData = smb_GetSMBParm(inp, 1);

    firstPacket = (inp->inCom == 0x25);

    /* find the packet we're reassembling */
    lock_ObtainWrite(&smb_globalLock);
    asp = smb_FindTran2Packet(vcp, inp);
    if (!asp) {
        asp = smb_NewTran2Packet(vcp, inp, totalParms, totalData);
    }
    lock_ReleaseWrite(&smb_globalLock);

    /* now merge in this latest packet; start by looking up offsets */
    if (firstPacket) {
        parmDisp = dataDisp = 0;
        parmOffset = smb_GetSMBParm(inp, 10);
        dataOffset = smb_GetSMBParm(inp, 12);
        parmCount = smb_GetSMBParm(inp, 9);
        dataCount = smb_GetSMBParm(inp, 11);
	asp->setupCount = smb_GetSMBParmByte(inp, 13);
        asp->maxReturnParms = smb_GetSMBParm(inp, 2);
        asp->maxReturnData = smb_GetSMBParm(inp, 3);

        osi_Log3(smb_logp, "SMB3 received Trans init packet total data %d, cur data %d, max return data %d",
                  totalData, dataCount, asp->maxReturnData);

	if (asp->setupCount == 2) {
	    clientchar_t * pname;

	    asp->pipeCommand = smb_GetSMBParm(inp, 14);
	    asp->pipeParam = smb_GetSMBParm(inp, 15);
	    pname = smb_ParseString(inp, inp->wctp + 35, NULL, 0);
	    if (pname) {
		asp->name = cm_ClientStrDup(pname);
	    }

	    osi_Log2(smb_logp, "  Named Pipe command id [%d] with name [%S]",
		     asp->pipeCommand, osi_LogSaveClientString(smb_logp, asp->name));
	}
    }
    else {
        parmDisp = smb_GetSMBParm(inp, 4);
        parmOffset = smb_GetSMBParm(inp, 3);
        dataDisp = smb_GetSMBParm(inp, 7);
        dataOffset = smb_GetSMBParm(inp, 6);
        parmCount = smb_GetSMBParm(inp, 2);
        dataCount = smb_GetSMBParm(inp, 5);

        osi_Log2(smb_logp, "SMB3 received Trans aux packet parms %d, data %d",
                 parmCount, dataCount);
    }

    /* now copy the parms and data */
    if ( asp->totalParms > 0 && parmCount != 0 )
    {
        memcpy(((char *)asp->parmsp) + parmDisp, inp->data + parmOffset, parmCount);
    }
    if ( asp->totalData > 0 && dataCount != 0 ) {
        memcpy(asp->datap + dataDisp, inp->data + dataOffset, dataCount);
    }

    /* account for new bytes */
    asp->curData += dataCount;
    asp->curParms += parmCount;

    /* finally, if we're done, remove the packet from the queue and dispatch it */
    if (((asp->totalParms > 0 && asp->curParms > 0)
	 || asp->setupCount == 2) &&
        asp->totalData <= asp->curData &&
        asp->totalParms <= asp->curParms) {

        /* we've received it all */
        lock_ObtainWrite(&smb_globalLock);
        osi_QRemove((osi_queue_t **) &smb_tran2AssemblyQueuep, &asp->q);
        lock_ReleaseWrite(&smb_globalLock);

	switch(asp->setupCount) {
	case 0:
	    {			/* RAP */
		rapOp = asp->parmsp[0];

		if ( rapOp >= 0 && rapOp < SMB_RAP_NOPCODES &&
		     smb_rapDispatchTable[rapOp].procp) {

		    osi_Log4(smb_logp,"AFS Server - Dispatch-RAP %s vcp[%p] lana[%d] lsn[%d]",
			     myCrt_RapDispatch(rapOp),vcp,vcp->lana,vcp->lsn);

		    code = (*smb_rapDispatchTable[rapOp].procp)(vcp, asp, outp);

		    osi_Log4(smb_logp,"AFS Server - Dispatch-RAP return  code 0x%x vcp[%x] lana[%d] lsn[%d]",
			     code,vcp,vcp->lana,vcp->lsn);
		}
		else {
		    osi_Log4(smb_logp,"AFS Server - Dispatch-RAP [INVALID] op[%x] vcp[%p] lana[%d] lsn[%d]",
			     rapOp, vcp, vcp->lana, vcp->lsn);

		    code = CM_ERROR_BADOP;
		}
	    }
	    break;

	case 2:
	    {			/* Named pipe operation */
		osi_Log2(smb_logp, "Named Pipe: %s with name [%S]",
			 myCrt_NmpipeDispatch(asp->pipeCommand),
			 osi_LogSaveClientString(smb_logp, asp->name));

		code = CM_ERROR_BADOP;

		switch (asp->pipeCommand) {
		case SMB_TRANS_SET_NMPIPE_STATE:
		    code = smb_nmpipeSetState(vcp, asp, outp);
		    break;

		case SMB_TRANS_RAW_READ_NMPIPE:
		    break;

		case SMB_TRANS_QUERY_NMPIPE_STATE:
		    break;

		case SMB_TRANS_QUERY_NMPIPE_INFO:
		    break;

		case SMB_TRANS_PEEK_NMPIPE:
		    break;

		case SMB_TRANS_TRANSACT_NMPIPE:
		    code = smb_nmpipeTransact(vcp, asp, outp);
		    break;

		case SMB_TRANS_RAW_WRITE_NMPIPE:
		    break;

		case SMB_TRANS_READ_NMPIPE:
		    break;

		case SMB_TRANS_WRITE_NMPIPE:
		    break;

		case SMB_TRANS_WAIT_NMPIPE:
		    break;

		case SMB_TRANS_CALL_NMPIPE:
		    break;
		}
	    }
	    break;

	default:
	    code = CM_ERROR_BADOP;
	}

        /* if an error is returned, we're supposed to send an error packet,
         * otherwise the dispatched function already did the data sending.
         * We give dispatched proc the responsibility since it knows how much
         * space to allocate.
         */
        if (code != 0) {
            smb_SendTran2Error(vcp, asp, outp, code);
        }

        /* free the input tran 2 packet */
        smb_FreeTran2Packet(asp);
    }
    else if (firstPacket) {
        /* the first packet in a multi-packet request, we need to send an
         * ack to get more data.
         */
        smb_SetSMBDataLength(outp, 0);
        smb_SendPacket(vcp, outp);
    }

    return 0;
}

/* ANSI versions. */

#pragma pack(push, 1)

typedef struct smb_rap_share_info_0 {
    BYTE                shi0_netname[13];
} smb_rap_share_info_0_t;

typedef struct smb_rap_share_info_1 {
    BYTE                shi1_netname[13];
    BYTE                shi1_pad;
    WORD			shi1_type;
    DWORD			shi1_remark; /* char *shi1_remark; data offset */
} smb_rap_share_info_1_t;

typedef struct smb_rap_share_info_2 {
    BYTE		shi2_netname[13];
    BYTE		shi2_pad;
    WORD        	shi2_type;
    DWORD			shi2_remark; /* char *shi2_remark; data offset */
    WORD        	shi2_permissions;
    WORD        	shi2_max_uses;
    WORD        	shi2_current_uses;
    DWORD			shi2_path;  /* char *shi2_path; data offset */
    WORD        	shi2_passwd[9];
    WORD        	shi2_pad2;
} smb_rap_share_info_2_t;

#define SMB_RAP_MAX_SHARES 512

typedef struct smb_rap_share_list {
    int cShare;
    int maxShares;
    smb_rap_share_info_0_t * shares;
} smb_rap_share_list_t;

#pragma pack(pop)

int smb_rapCollectSharesProc(cm_scache_t *dscp, cm_dirEntry_t *dep, void *vrockp, osi_hyper_t *offp) {
    smb_rap_share_list_t * sp;

    if (dep->name[0] == '.' && (!dep->name[1] || (dep->name[1] == '.' && !dep->name[2])))
        return 0; /* skip over '.' and '..' */

    sp = (smb_rap_share_list_t *) vrockp;

    strncpy(sp->shares[sp->cShare].shi0_netname, dep->name, 12);
    sp->shares[sp->cShare].shi0_netname[12] = 0;

    sp->cShare++;

    if (sp->cShare >= sp->maxShares)
        return CM_ERROR_STOPNOW;
    else
        return 0;
}

/* RAP NetShareEnumRequest */
long smb_ReceiveRAPNetShareEnum(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *op)
{
    smb_tran2Packet_t *outp;
    unsigned short * tp;
    int len;
    int infoLevel;
    int bufsize;
    int outParmsTotal;	/* total parameter bytes */
    int outDataTotal;	/* total data bytes */
    int code = 0;
    DWORD rv;
    DWORD allSubmount = 0;
    USHORT nShares = 0;
    DWORD nRegShares = 0;
    DWORD nSharesRet = 0;
    HKEY hkParam;
    HKEY hkSubmount = NULL;
    smb_rap_share_info_1_t * shares;
    USHORT cshare = 0;
    char * cstrp;
    clientchar_t thisShare[AFSPATHMAX];
    int i,j;
    DWORD dw;
    int nonrootShares;
    smb_rap_share_list_t rootShares;
    cm_req_t req;
    cm_user_t * userp;
    osi_hyper_t thyper;
    cm_scache_t *rootScp;

    tp = p->parmsp + 1; /* skip over function number (always 0) */

    {
        clientchar_t * cdescp;

        cdescp = smb_ParseStringT2Parm(p, (char *) tp, (char **) &tp, SMB_STRF_FORCEASCII);
        if (cm_ClientStrCmp(cdescp,  _C("WrLeh")))
            return CM_ERROR_INVAL;
        cdescp = smb_ParseStringT2Parm(p, (char *) tp, (char **) &tp, SMB_STRF_FORCEASCII);
        if (cm_ClientStrCmp(cdescp,  _C("B13BWz")))
            return CM_ERROR_INVAL;
    }

    infoLevel = tp[0];
    bufsize = tp[1];

    if (infoLevel != 1) {
        return CM_ERROR_INVAL;
    }

    /* We are supposed to use the same ASCII data structure even if
       Unicode is negotiated, which ultimately means that the share
       names that we return must be at most 13 characters in length,
       including the NULL terminator.

       The RAP specification states that shares with names longer than
       12 characters should not be included in the enumeration.
       However, since we support prefix cell references and since many
       cell names are going to exceed 12 characters, we lie and send
       the first 12 characters.
    */

    /* first figure out how many shares there are */
    rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PARAM_SUBKEY, 0,
                      KEY_QUERY_VALUE, &hkParam);
    if (rv == ERROR_SUCCESS) {
        len = sizeof(allSubmount);
        rv = RegQueryValueEx(hkParam, "AllSubmount", NULL, NULL,
                             (BYTE *) &allSubmount, &len);
        if (rv != ERROR_SUCCESS || allSubmount != 0) {
            allSubmount = 1;
        }
        RegCloseKey (hkParam);
    }

    rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_OPENAFS_SUBKEY "\\Submounts",
                      0, KEY_QUERY_VALUE, &hkSubmount);
    if (rv == ERROR_SUCCESS) {
        rv = RegQueryInfoKey(hkSubmount, NULL, NULL, NULL, NULL,
                             NULL, NULL, &nRegShares, NULL, NULL, NULL, NULL);
        if (rv != ERROR_SUCCESS)
            nRegShares = 0;
    } else {
        hkSubmount = NULL;
    }

    /* fetch the root shares */
    rootShares.maxShares = SMB_RAP_MAX_SHARES;
    rootShares.cShare = 0;
    rootShares.shares = malloc( sizeof(smb_rap_share_info_0_t) * SMB_RAP_MAX_SHARES );

    smb_InitReq(&req);

    userp = smb_GetTran2User(vcp,p);

    thyper.HighPart = 0;
    thyper.LowPart = 0;

    rootScp = cm_RootSCachep(userp, &req);
    cm_HoldSCache(rootScp);
    cm_ApplyDir(rootScp, smb_rapCollectSharesProc, &rootShares, &thyper, userp, &req, NULL);
    cm_ReleaseSCache(rootScp);

    cm_ReleaseUser(userp);

    nShares = (USHORT)(rootShares.cShare + nRegShares + allSubmount);

#define REMARK_LEN 1
    outParmsTotal = 8; /* 4 dwords */
    outDataTotal = (sizeof(smb_rap_share_info_1_t) + REMARK_LEN) * nShares ;
    if(outDataTotal > bufsize) {
        nSharesRet = bufsize / (sizeof(smb_rap_share_info_1_t) + REMARK_LEN);
        outDataTotal = (sizeof(smb_rap_share_info_1_t) + REMARK_LEN) * nSharesRet;
    }
    else {
        nSharesRet = nShares;
    }

    outp = smb_GetTran2ResponsePacket(vcp, p, op, outParmsTotal, outDataTotal);

    /* now for the submounts */
    shares = (smb_rap_share_info_1_t *) outp->datap;
    cstrp = outp->datap + sizeof(smb_rap_share_info_1_t) * nSharesRet;

    memset(outp->datap, 0, (sizeof(smb_rap_share_info_1_t) + REMARK_LEN) * nSharesRet);

    if (allSubmount) {
        StringCchCopyA(shares[cshare].shi1_netname,
                       lengthof(shares[cshare].shi1_netname), "all" );
        shares[cshare].shi1_remark = (DWORD)(cstrp - outp->datap);
        /* type and pad are zero already */
        cshare++;
        cstrp+=REMARK_LEN;
    }

    if (hkSubmount) {
        for (dw=0; dw < nRegShares && cshare < nSharesRet; dw++) {
            len = sizeof(thisShare);
            rv = RegEnumValueW(hkSubmount, dw, thisShare, &len, NULL, NULL, NULL, NULL);
            if (rv == ERROR_SUCCESS &&
                cm_ClientStrLen(thisShare) &&
                (!allSubmount || cm_ClientStrCmpI(thisShare,_C("all")))) {
                cm_ClientStringToUtf8(thisShare, -1, shares[cshare].shi1_netname,
                                      lengthof( shares[cshare].shi1_netname ));
                shares[cshare].shi1_netname[sizeof(shares->shi1_netname)-1] = 0; /* unfortunate truncation */
                shares[cshare].shi1_remark = (DWORD)(cstrp - outp->datap);
                cshare++;
                cstrp+=REMARK_LEN;
            }
            else
                nShares--; /* uncount key */
        }

        RegCloseKey(hkSubmount);
    }

    nonrootShares = cshare;

    for (i=0; i < rootShares.cShare && cshare < nSharesRet; i++) {
        /* in case there are collisions with submounts, submounts have
           higher priority */
        for (j=0; j < nonrootShares; j++)
            if (!cm_stricmp_utf8(shares[j].shi1_netname, rootShares.shares[i].shi0_netname))
                break;

        if (j < nonrootShares) {
            nShares--; /* uncount */
            continue;
        }

        StringCchCopyA(shares[cshare].shi1_netname, lengthof(shares[cshare].shi1_netname),
                       rootShares.shares[i].shi0_netname);
        shares[cshare].shi1_remark = (DWORD)(cstrp - outp->datap);
        cshare++;
        cstrp+=REMARK_LEN;
    }

    outp->parmsp[0] = ((cshare == nShares)? ERROR_SUCCESS : ERROR_MORE_DATA);
    outp->parmsp[1] = 0;
    outp->parmsp[2] = cshare;
    outp->parmsp[3] = nShares;

    outp->totalData = (int)(cstrp - outp->datap);
    outp->totalParms = outParmsTotal;

    smb_SendTran2Packet(vcp, outp, op);
    smb_FreeTran2Packet(outp);

    free(rootShares.shares);

    return code;
}

/* RAP NetShareGetInfo */
long smb_ReceiveRAPNetShareGetInfo(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *op)
{
    smb_tran2Packet_t *outp;
    unsigned short * tp;
    clientchar_t * shareName;
    BOOL shareFound = FALSE;
    unsigned short infoLevel;
    unsigned short bufsize;
    int totalData;
    int totalParam;
    DWORD len;
    HKEY hkParam;
    HKEY hkSubmount;
    DWORD allSubmount;
    LONG rv;
    long code = 0;
    cm_scache_t *scp = NULL;
    cm_user_t   *userp;
    cm_req_t    req;

    smb_InitReq(&req);

    tp = p->parmsp + 1; /* skip over function number (always 1) */

    {
        clientchar_t * cdescp;

        cdescp = smb_ParseStringT2Parm(p, (char *) tp, (char **) &tp, SMB_STRF_FORCEASCII);
        if (cm_ClientStrCmp(cdescp,  _C("zWrLh")))

            return CM_ERROR_INVAL;

        cdescp = smb_ParseStringT2Parm(p, (char *) tp, (char **) &tp, SMB_STRF_FORCEASCII);
        if (cm_ClientStrCmp(cdescp,  _C("B13")) &&
            cm_ClientStrCmp(cdescp,  _C("B13BWz")) &&
            cm_ClientStrCmp(cdescp,  _C("B13BWzWWWzB9B")))

            return CM_ERROR_INVAL;
    }
    shareName = smb_ParseStringT2Parm(p, (char *) tp, (char **) &tp, SMB_STRF_FORCEASCII);

    infoLevel = *tp++;
    bufsize = *tp++;

    totalParam = 6;

    if (infoLevel == 0)
        totalData = sizeof(smb_rap_share_info_0_t);
    else if(infoLevel == SMB_INFO_STANDARD)
        totalData = sizeof(smb_rap_share_info_1_t) + 1; /* + empty string */
    else if(infoLevel == SMB_INFO_QUERY_EA_SIZE)
        totalData = sizeof(smb_rap_share_info_2_t) + 2; /* + two empty strings */
    else
        return CM_ERROR_INVAL;

    if(!cm_ClientStrCmpI(shareName, _C("all")) || !cm_ClientStrCmp(shareName,_C("*."))) {
        rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PARAM_SUBKEY, 0,
                          KEY_QUERY_VALUE, &hkParam);
        if (rv == ERROR_SUCCESS) {
            len = sizeof(allSubmount);
            rv = RegQueryValueEx(hkParam, "AllSubmount", NULL, NULL,
                                  (BYTE *) &allSubmount, &len);
            if (rv != ERROR_SUCCESS || allSubmount != 0) {
                allSubmount = 1;
            }
            RegCloseKey (hkParam);
        }

        if (allSubmount)
            shareFound = TRUE;

    } else {
        userp = smb_GetTran2User(vcp, p);
        if (!userp) {
            osi_Log1(smb_logp,"ReceiveRAPNetShareGetInfo unable to resolve user [%d]", p->uid);
            return CM_ERROR_BADSMB;
        }
        code = cm_NameI(cm_RootSCachep(userp, &req), shareName,
                         CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD | CM_FLAG_DFS_REFERRAL,
                         userp, NULL, &req, &scp);
        if (code == 0) {
            cm_ReleaseSCache(scp);
            shareFound = TRUE;
        } else {
            rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PARAM_SUBKEY "\\Submounts", 0,
                              KEY_QUERY_VALUE, &hkSubmount);
            if (rv == ERROR_SUCCESS) {
                rv = RegQueryValueExW(hkSubmount, shareName, NULL, NULL, NULL, NULL);
                if (rv == ERROR_SUCCESS) {
                    shareFound = TRUE;
                }
                RegCloseKey(hkSubmount);
            }
        }
    }

    if (!shareFound)
        return CM_ERROR_BADSHARENAME;

    outp = smb_GetTran2ResponsePacket(vcp, p, op, totalParam, totalData);
    memset(outp->datap, 0, totalData);

    outp->parmsp[0] = 0;
    outp->parmsp[1] = 0;
    outp->parmsp[2] = totalData;

    if (infoLevel == 0) {
        smb_rap_share_info_0_t * info = (smb_rap_share_info_0_t *) outp->datap;
        cm_ClientStringToUtf8(shareName, -1, info->shi0_netname,
                              lengthof(info->shi0_netname));
    } else if(infoLevel == SMB_INFO_STANDARD) {
        smb_rap_share_info_1_t * info = (smb_rap_share_info_1_t *) outp->datap;
        cm_ClientStringToUtf8(shareName, -1, info->shi1_netname, lengthof(info->shi1_netname));
        info->shi1_netname[sizeof(info->shi1_netname)-1] = 0;
        info->shi1_remark = (DWORD)(((unsigned char *) (info + 1)) - outp->datap);
        /* type and pad are already zero */
    } else { /* infoLevel==2 */
        smb_rap_share_info_2_t * info = (smb_rap_share_info_2_t *) outp->datap;
        cm_ClientStringToUtf8(shareName, -1, info->shi2_netname, lengthof(info->shi2_netname));
        info->shi2_remark = (DWORD)(((unsigned char *) (info + 1)) - outp->datap);
        info->shi2_permissions = ACCESS_ALL;
        info->shi2_max_uses = (unsigned short) -1;
        info->shi2_path = (DWORD)(1 + (((unsigned char *) (info + 1)) - outp->datap));
    }

    outp->totalData = totalData;
    outp->totalParms = totalParam;

    smb_SendTran2Packet(vcp, outp, op);
    smb_FreeTran2Packet(outp);

    return code;
}

#pragma pack(push, 1)

typedef struct smb_rap_wksta_info_10 {
    DWORD	wki10_computername;	/*char *wki10_computername;*/
    DWORD	wki10_username; /* char *wki10_username; */
    DWORD  	wki10_langroup;	/* char *wki10_langroup;*/
    BYTE  	wki10_ver_major;
    BYTE	wki10_ver_minor;
    DWORD	wki10_logon_domain;	/*char *wki10_logon_domain;*/
    DWORD	wki10_oth_domains; /* char *wki10_oth_domains;*/
} smb_rap_wksta_info_10_t;

#pragma pack(pop)

long smb_ReceiveRAPNetWkstaGetInfo(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *op)
{
    smb_tran2Packet_t *outp;
    long code = 0;
    int infoLevel;
    int bufsize;
    unsigned short * tp;
    int totalData;
    int totalParams;
    smb_rap_wksta_info_10_t * info;
    char * cstrp;
    smb_user_t *uidp;

    tp = p->parmsp + 1; /* Skip over function number */

    {
        clientchar_t * cdescp;

        cdescp = smb_ParseStringT2Parm(p, (unsigned char*) tp, (char **) &tp,
                                       SMB_STRF_FORCEASCII);
        if (cm_ClientStrCmp(cdescp,  _C("WrLh")))
            return CM_ERROR_INVAL;

        cdescp = smb_ParseStringT2Parm(p, (unsigned char*) tp, (char **) &tp,
                                       SMB_STRF_FORCEASCII);
        if (cm_ClientStrCmp(cdescp,  _C("zzzBBzz")))
            return CM_ERROR_INVAL;
    }

    infoLevel = *tp++;
    bufsize = *tp++;

    if (infoLevel != 10) {
        return CM_ERROR_INVAL;
    }

    totalParams = 6;

    /* infolevel 10 */
    totalData = sizeof(*info) +		/* info */
        MAX_COMPUTERNAME_LENGTH +	/* wki10_computername */
        SMB_MAX_USERNAME_LENGTH +	/* wki10_username */
        MAX_COMPUTERNAME_LENGTH +	/* wki10_langroup */
        MAX_COMPUTERNAME_LENGTH +	/* wki10_logon_domain */
        1;				/* wki10_oth_domains (null)*/

    outp = smb_GetTran2ResponsePacket(vcp, p, op, totalParams, totalData);

    memset(outp->parmsp,0,totalParams);
    memset(outp->datap,0,totalData);

    info = (smb_rap_wksta_info_10_t *) outp->datap;
    cstrp = (char *) (info + 1);

    info->wki10_computername = (DWORD) (cstrp - outp->datap);
    StringCbCopyA(cstrp, totalData, smb_localNamep);
    cstrp += strlen(cstrp) + 1;

    info->wki10_username = (DWORD) (cstrp - outp->datap);
    uidp = smb_FindUID(vcp, p->uid, 0);
    if (uidp) {
        lock_ObtainMutex(&uidp->mx);
        if(uidp->unp && uidp->unp->name)
            cm_ClientStringToUtf8(uidp->unp->name, -1,
                                  cstrp, totalData/sizeof(char) - (cstrp - outp->datap));
        lock_ReleaseMutex(&uidp->mx);
        smb_ReleaseUID(uidp);
    }
    cstrp += strlen(cstrp) + 1;

    info->wki10_langroup = (DWORD) (cstrp - outp->datap);
    StringCbCopyA(cstrp, totalData - (cstrp - outp->datap)*sizeof(char), "WORKGROUP");
    cstrp += strlen(cstrp) + 1;

    /* TODO: Not sure what values these should take, but these work */
    info->wki10_ver_major = 5;
    info->wki10_ver_minor = 1;

    info->wki10_logon_domain = (DWORD) (cstrp - outp->datap);
    cm_ClientStringToUtf8(smb_ServerDomainName, -1,
                          cstrp, totalData/sizeof(char) - (cstrp - outp->datap));
    cstrp += strlen(cstrp) + 1;

    info->wki10_oth_domains = (DWORD) (cstrp - outp->datap);
    cstrp ++; /* no other domains */

    outp->totalData = (unsigned short) (cstrp - outp->datap); /* actual data size */
    outp->parmsp[2] = outp->totalData;
    outp->totalParms = totalParams;

    smb_SendTran2Packet(vcp,outp,op);
    smb_FreeTran2Packet(outp);

    return code;
}

#pragma pack(push, 1)

typedef struct smb_rap_server_info_0 {
    BYTE    sv0_name[16];
} smb_rap_server_info_0_t;

typedef struct smb_rap_server_info_1 {
    BYTE            sv1_name[16];
    BYTE            sv1_version_major;
    BYTE            sv1_version_minor;
    DWORD           sv1_type;
    DWORD           sv1_comment_or_master_browser; /* char *sv1_comment_or_master_browser;*/
} smb_rap_server_info_1_t;

#pragma pack(pop)

char smb_ServerComment[] = "OpenAFS Client";
int smb_ServerCommentLen = sizeof(smb_ServerComment);

#define SMB_SV_TYPE_SERVER      	0x00000002L
#define SMB_SV_TYPE_NT              0x00001000L
#define SMB_SV_TYPE_SERVER_NT       0x00008000L

long smb_ReceiveRAPNetServerGetInfo(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *op)
{
    smb_tran2Packet_t *outp;
    long code = 0;
    int infoLevel;
    int bufsize;
    unsigned short * tp;
    int totalData;
    int totalParams;
    smb_rap_server_info_0_t * info0;
    smb_rap_server_info_1_t * info1;
    char * cstrp;

    tp = p->parmsp + 1; /* Skip over function number */

    {
        clientchar_t * cdescp;

        cdescp = smb_ParseStringT2Parm(p, (unsigned char *) tp, (char **) &tp,
                                       SMB_STRF_FORCEASCII);
        if (cm_ClientStrCmp(cdescp,  _C("WrLh")))
            return CM_ERROR_INVAL;
        cdescp = smb_ParseStringT2Parm(p, (unsigned char*) tp, (char **) &tp,
                                       SMB_STRF_FORCEASCII);
        if (cm_ClientStrCmp(cdescp,  _C("B16")) ||
            cm_ClientStrCmp(cdescp,  _C("B16BBDz")))
            return CM_ERROR_INVAL;
    }

    infoLevel = *tp++;
    bufsize = *tp++;

    if (infoLevel != 0 && infoLevel != 1) {
        return CM_ERROR_INVAL;
    }

    totalParams = 6;

    totalData =
        (infoLevel == 0) ? sizeof(smb_rap_server_info_0_t)
        : (sizeof(smb_rap_server_info_1_t) + smb_ServerCommentLen);

    outp = smb_GetTran2ResponsePacket(vcp, p, op, totalParams, totalData);

    memset(outp->parmsp,0,totalParams);
    memset(outp->datap,0,totalData);

    if (infoLevel == 0) {
        info0 = (smb_rap_server_info_0_t *) outp->datap;
        cstrp = (char *) (info0 + 1);
        StringCchCopyA(info0->sv0_name, lengthof(info0->sv0_name), "AFS");
    } else { /* infoLevel == SMB_INFO_STANDARD */
        info1 = (smb_rap_server_info_1_t *) outp->datap;
        cstrp = (char *) (info1 + 1);
        StringCchCopyA(info1->sv1_name, lengthof(info1->sv1_name), "AFS");

        info1->sv1_type =
            SMB_SV_TYPE_SERVER |
            SMB_SV_TYPE_NT |
            SMB_SV_TYPE_SERVER_NT;

        info1->sv1_version_major = 5;
        info1->sv1_version_minor = 1;
        info1->sv1_comment_or_master_browser = (DWORD) (cstrp - outp->datap);

        StringCbCopyA(cstrp, smb_ServerCommentLen, smb_ServerComment);

        cstrp += smb_ServerCommentLen / sizeof(char);
    }

    totalData = (DWORD)(cstrp - outp->datap);
    outp->totalData = min(bufsize,totalData); /* actual data size */
    outp->parmsp[0] = (outp->totalData == totalData)? 0 : ERROR_MORE_DATA;
    outp->parmsp[2] = totalData;
    outp->totalParms = totalParams;

    smb_SendTran2Packet(vcp,outp,op);
    smb_FreeTran2Packet(outp);

    return code;
}

/* SMB_COM_TRANSACTION2 and SMB_COM_TRANSACTION2_SECONDARY */
long smb_ReceiveV3Tran2A(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    smb_tran2Packet_t *asp;
    int totalParms;
    int totalData;
    int parmDisp;
    int dataDisp;
    int parmOffset;
    int dataOffset;
    int parmCount;
    int dataCount;
    int firstPacket;
    long code = 0;
    DWORD oldTime, newTime;

    /* We sometimes see 0 word count.  What to do? */
    if (*inp->wctp == 0) {
        osi_Log0(smb_logp, "Transaction2 word count = 0");
	LogEvent(EVENTLOG_WARNING_TYPE, MSG_SMB_ZERO_TRANSACTION_COUNT);

        smb_SetSMBDataLength(outp, 0);
        smb_SendPacket(vcp, outp);
        return 0;
    }

    totalParms = smb_GetSMBParm(inp, 0);
    totalData = smb_GetSMBParm(inp, 1);

    firstPacket = (inp->inCom == 0x32);

    /* find the packet we're reassembling */
    lock_ObtainWrite(&smb_globalLock);
    asp = smb_FindTran2Packet(vcp, inp);
    if (!asp) {
        asp = smb_NewTran2Packet(vcp, inp, totalParms, totalData);
    }
    lock_ReleaseWrite(&smb_globalLock);

    /* now merge in this latest packet; start by looking up offsets */
    if (firstPacket) {
        parmDisp = dataDisp = 0;
        parmOffset = smb_GetSMBParm(inp, 10);
        dataOffset = smb_GetSMBParm(inp, 12);
        parmCount = smb_GetSMBParm(inp, 9);
        dataCount = smb_GetSMBParm(inp, 11);
        asp->maxReturnParms = smb_GetSMBParm(inp, 2);
        asp->maxReturnData = smb_GetSMBParm(inp, 3);

        osi_Log3(smb_logp, "SMB3 received T2 init packet total data %d, cur data %d, max return data %d",
                 totalData, dataCount, asp->maxReturnData);
    }
    else {
        parmDisp = smb_GetSMBParm(inp, 4);
        parmOffset = smb_GetSMBParm(inp, 3);
        dataDisp = smb_GetSMBParm(inp, 7);
        dataOffset = smb_GetSMBParm(inp, 6);
        parmCount = smb_GetSMBParm(inp, 2);
        dataCount = smb_GetSMBParm(inp, 5);

        osi_Log2(smb_logp, "SMB3 received T2 aux packet parms %d, data %d",
                 parmCount, dataCount);
    }

    /* now copy the parms and data */
    if ( asp->totalParms > 0 && parmCount != 0 )
    {
        memcpy(((char *)asp->parmsp) + parmDisp, inp->data + parmOffset, parmCount);
    }
    if ( asp->totalData > 0 && dataCount != 0 ) {
        memcpy(asp->datap + dataDisp, inp->data + dataOffset, dataCount);
    }

    /* account for new bytes */
    asp->curData += dataCount;
    asp->curParms += parmCount;

    /* finally, if we're done, remove the packet from the queue and dispatch it */
    if (asp->totalParms > 0 &&
        asp->curParms > 0 &&
        asp->totalData <= asp->curData &&
        asp->totalParms <= asp->curParms) {
        /* we've received it all */
        lock_ObtainWrite(&smb_globalLock);
        osi_QRemove((osi_queue_t **) &smb_tran2AssemblyQueuep, &asp->q);
        lock_ReleaseWrite(&smb_globalLock);

        oldTime = GetTickCount();

        /* now dispatch it */
        if ( asp->opcode >= 0 && asp->opcode < 20 && smb_tran2DispatchTable[asp->opcode].procp) {
            osi_Log4(smb_logp,"AFS Server - Dispatch-2 %s vcp[%p] lana[%d] lsn[%d]",myCrt_2Dispatch(asp->opcode),vcp,vcp->lana,vcp->lsn);
            code = (*smb_tran2DispatchTable[asp->opcode].procp)(vcp, asp, outp);
        }
        else {
            osi_Log4(smb_logp,"AFS Server - Dispatch-2 [INVALID] op[%x] vcp[%p] lana[%d] lsn[%d]", asp->opcode, vcp, vcp->lana, vcp->lsn);
            code = CM_ERROR_BADOP;
        }

        /* if an error is returned, we're supposed to send an error packet,
         * otherwise the dispatched function already did the data sending.
         * We give dispatched proc the responsibility since it knows how much
         * space to allocate.
         */
        if (code != 0) {
            smb_SendTran2Error(vcp, asp, outp, code);
        }

        newTime = GetTickCount();
        if (newTime - oldTime > 45000) {
            smb_user_t *uidp;
            smb_fid_t *fidp;
            clientchar_t *treepath = NULL;  /* do not free */
            clientchar_t *pathname = NULL;
            cm_fid_t afid = {0,0,0,0,0};

            uidp = smb_FindUID(vcp, asp->uid, 0);
            smb_LookupTIDPath(vcp, asp->tid, &treepath);
            fidp = smb_FindFID(vcp, inp->fid, 0);

            if (fidp) {
                lock_ObtainMutex(&fidp->mx);
                if (fidp->NTopen_pathp)
                    pathname = fidp->NTopen_pathp;
                if (fidp->scp)
                    afid = fidp->scp->fid;
            } else {
                if (inp->stringsp->wdata)
                    pathname = inp->stringsp->wdata;
            }

            afsi_log("Request %s duration %d ms user 0x%x \"%S\" pid 0x%x mid 0x%x tid 0x%x \"%S\" path? \"%S\" afid (%d.%d.%d.%d)",
                      myCrt_2Dispatch(asp->opcode), newTime - oldTime,
                      asp->uid, uidp ? uidp->unp->name : NULL,
                      asp->pid, asp->mid, asp->tid,
                      treepath,
                      pathname,
                      afid.cell, afid.volume, afid.vnode, afid.unique);

            if (fidp)
                lock_ReleaseMutex(&fidp->mx);

            if (uidp)
                smb_ReleaseUID(uidp);
            if (fidp)
                smb_ReleaseFID(fidp);
        }

        /* free the input tran 2 packet */
        smb_FreeTran2Packet(asp);
    }
    else if (firstPacket) {
        /* the first packet in a multi-packet request, we need to send an
         * ack to get more data.
         */
        smb_SetSMBDataLength(outp, 0);
        smb_SendPacket(vcp, outp);
    }

    return 0;
}

/* TRANS2_OPEN2 */
long smb_ReceiveTran2Open(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *op)
{
    clientchar_t *pathp;
    smb_tran2Packet_t *outp;
    long code = 0;
    cm_space_t *spacep;
    int excl;
    cm_user_t *userp;
    cm_scache_t *dscp;		/* dir we're dealing with */
    cm_scache_t *scp;		/* file we're creating */
    cm_attr_t setAttr;
    smb_fid_t *fidp;
    int attributes;
    clientchar_t *lastNamep;
    afs_uint32 dosTime;
    int openFun;
    int trunc;
    int openMode;
    int extraInfo;
    int openAction;
    int parmSlot;			/* which parm we're dealing with */
    long returnEALength;
    clientchar_t *tidPathp;
    cm_req_t req;
    int created = 0;
    BOOL is_rpc = FALSE;
    BOOL is_ipc = FALSE;

    smb_InitReq(&req);

    scp = NULL;

    extraInfo = (p->parmsp[0] & 1);	/* return extra info */
    returnEALength = (p->parmsp[0] & 8);	/* return extended attr length */

    openFun = p->parmsp[6];		/* open function */
    excl = ((openFun & 3) == 0);
    trunc = ((openFun & 3) == 2);	/* truncate it */
    openMode = (p->parmsp[1] & 0x7);
    openAction = 0;			/* tracks what we did */

    attributes = p->parmsp[3];
    dosTime = p->parmsp[4] | (p->parmsp[5] << 16);

    pathp = smb_ParseStringT2Parm(p, (char *) (&p->parmsp[14]), NULL,
                                  SMB_STRF_ANSIPATH);

    outp = smb_GetTran2ResponsePacket(vcp, p, op, 40, 0);

    code = smb_LookupTIDPath(vcp, p->tid, &tidPathp);
    if (code == CM_ERROR_TIDIPC) {
	is_ipc = TRUE;
        osi_Log0(smb_logp, "Tran2Open received IPC TID");
    }

    spacep = cm_GetSpace();
    /* smb_StripLastComponent will strip "::$DATA" if present */
    smb_StripLastComponent(spacep->wdata, &lastNamep, pathp);

    if (lastNamep &&

        /* special case magic file name for receiving IOCTL requests
         * (since IOCTL calls themselves aren't getting through).
         */
        (cm_ClientStrCmpI(lastNamep,  _C(SMB_IOCTL_FILENAME)) == 0 ||

	 /* Or an RPC endpoint (is_rpc = TRUE assignment is intentional)*/
	 (is_ipc && MSRPC_IsWellKnownService(lastNamep) && (is_rpc = TRUE)))) {

	unsigned short file_type = 0;
	unsigned short device_state = 0;

        fidp = smb_FindFID(vcp, 0, SMB_FLAG_CREATE);

	if (is_rpc) {
	    code = smb_SetupRPCFid(fidp, lastNamep, &file_type, &device_state);
	    osi_Log2(smb_logp, "smb_ReceiveTran2Open Creating RPC Fid [%d] code [%d]",
                     fidp->fid, code);
	    if (code) {
		smb_ReleaseFID(fidp);
		smb_FreeTran2Packet(outp);
		osi_Log1(smb_logp, "smb_SetupRPCFid() failure code [%d]", code);
		return code;
	    }
	} else {
	    smb_SetupIoctlFid(fidp, spacep);
	    osi_Log1(smb_logp, "smb_ReceiveTran2Open Creating IOCTL Fid [%d]", fidp->fid);
	}

        /* copy out remainder of the parms */
        parmSlot = 0;
        outp->parmsp[parmSlot++] = fidp->fid;
        if (extraInfo) {
            outp->parmsp[parmSlot++] = 0;       /* attrs */
            outp->parmsp[parmSlot++] = 0;       /* mod time */
            outp->parmsp[parmSlot++] = 0;
            outp->parmsp[parmSlot++] = 0;       /* len */
            outp->parmsp[parmSlot++] = 0x7fff;
            outp->parmsp[parmSlot++] = openMode;
            outp->parmsp[parmSlot++] = file_type;
            outp->parmsp[parmSlot++] = device_state;
        }
        /* and the final "always present" stuff */
        outp->parmsp[parmSlot++] = 1;           /* openAction found existing file */
        /* next write out the "unique" ID */
        outp->parmsp[parmSlot++] = 0x1234;
        outp->parmsp[parmSlot++] = 0x5678;
        outp->parmsp[parmSlot++] = 0;
        if (returnEALength) {
            outp->parmsp[parmSlot++] = 0;
            outp->parmsp[parmSlot++] = 0;
        }

        outp->totalData = 0;
        outp->totalParms = parmSlot * 2;

        smb_SendTran2Packet(vcp, outp, op);

        smb_FreeTran2Packet(outp);

        /* and clean up fid reference */
        smb_ReleaseFID(fidp);
        return 0;
    }

#ifndef DFS_SUPPORT
    if (is_ipc) {
        osi_Log1(smb_logp, "Tran2Open rejecting IPC TID vcp %p", vcp);
	smb_FreeTran2Packet(outp);
	return CM_ERROR_BADFD;
    }
#endif

    if (!cm_IsValidClientString(pathp)) {
#ifdef DEBUG
        clientchar_t * hexp;

        hexp = cm_GetRawCharsAlloc(pathp, -1);
        osi_Log1(smb_logp, "Tran2Open rejecting invalid name. [%S]",
                 osi_LogSaveClientString(smb_logp, hexp));
        if (hexp)
            free(hexp);
#else
        osi_Log0(smb_logp, "Tran2Open rejecting invalid name");
#endif
        smb_FreeTran2Packet(outp);
        return CM_ERROR_BADNTFILENAME;
    }

#ifdef DEBUG_VERBOSE
    {
        char *hexp, *asciip;
        asciip = (lastNamep ? lastNamep : pathp);
        hexp = osi_HexifyString( asciip );
        DEBUG_EVENT2("AFS","T2Open H[%s] A[%s]", hexp, asciip);
        free(hexp);
    }
#endif

    userp = smb_GetTran2User(vcp, p);
    /* In the off chance that userp is NULL, we log and abandon */
    if (!userp) {
        osi_Log1(smb_logp, "ReceiveTran2Open user [%d] not resolvable", p->uid);
        smb_FreeTran2Packet(outp);
        return CM_ERROR_BADSMB;
    }

    dscp = NULL;
    code = cm_NameI(cm_RootSCachep(userp, &req), pathp,
                     CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                     userp, tidPathp, &req, &scp);
    if (code != 0) {
        if (code == CM_ERROR_NOSUCHFILE ||
            code == CM_ERROR_NOSUCHPATH ||
            code == CM_ERROR_BPLUS_NOMATCH)
            code = cm_NameI(cm_RootSCachep(userp, &req), spacep->wdata,
                            CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                            userp, tidPathp, &req, &dscp);
        cm_FreeSpace(spacep);

        if (code) {
            cm_ReleaseUser(userp);
            smb_FreeTran2Packet(outp);
            return code;
        }

#ifdef DFS_SUPPORT
        if (dscp->fileType == CM_SCACHETYPE_DFSLINK) {
            int pnc = cm_VolStatus_Notify_DFS_Mapping(dscp, tidPathp,
                                                      (clientchar_t*) spacep->data);
            cm_ReleaseSCache(dscp);
            cm_ReleaseUser(userp);
            smb_FreeTran2Packet(outp);
            if ( WANTS_DFS_PATHNAMES(p) || pnc )
                return CM_ERROR_PATH_NOT_COVERED;
            else
                return CM_ERROR_NOSUCHPATH;
        }
#endif /* DFS_SUPPORT */

        /* otherwise, scp points to the parent directory.  Do a lookup,
         * and truncate the file if we find it, otherwise we create the
         * file.
         */
        if (!lastNamep)
            lastNamep = pathp;
        else
            lastNamep++;
        code = cm_Lookup(dscp, lastNamep, CM_FLAG_CASEFOLD, userp,
                         &req, &scp);
        if (code && code != CM_ERROR_NOSUCHFILE && code != CM_ERROR_BPLUS_NOMATCH) {
            cm_ReleaseSCache(dscp);
            cm_ReleaseUser(userp);
            smb_FreeTran2Packet(outp);
            return code;
        }
    } else {
        /* macintosh is expensive to program for it */
        cm_FreeSpace(spacep);

#ifdef DFS_SUPPORT
        if (scp->fileType == CM_SCACHETYPE_DFSLINK) {
            int pnc = cm_VolStatus_Notify_DFS_Mapping(scp, tidPathp, lastNamep);
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
            smb_FreeTran2Packet(outp);
            if ( WANTS_DFS_PATHNAMES(p) || pnc )
                return CM_ERROR_PATH_NOT_COVERED;
            else
                return CM_ERROR_NOSUCHPATH;
        }
#endif /* DFS_SUPPORT */
    }

    /* if we get here, if code is 0, the file exists and is represented by
     * scp.  Otherwise, we have to create it.
     */
    if (code == 0) {
        code = cm_CheckOpen(scp, openMode, trunc, userp, &req);
        if (code) {
            if (dscp)
                cm_ReleaseSCache(dscp);
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
            smb_FreeTran2Packet(outp);
            return code;
        }

        if (excl) {
            /* oops, file shouldn't be there */
            if (dscp)
                cm_ReleaseSCache(dscp);
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
            smb_FreeTran2Packet(outp);
            return CM_ERROR_EXISTS;
        }

        if (trunc) {
            setAttr.mask = CM_ATTRMASK_LENGTH;
            setAttr.length.LowPart = 0;
            setAttr.length.HighPart = 0;
            code = cm_SetAttr(scp, &setAttr, userp, &req);
            openAction = 3;	/* truncated existing file */
        }
        else
            openAction = 1;	/* found existing file */
    }
    else if (!(openFun & 0x10)) {
        /* don't create if not found */
        if (dscp)
            cm_ReleaseSCache(dscp);
        osi_assertx(scp == NULL, "null cm_scache_t");
        cm_ReleaseUser(userp);
        smb_FreeTran2Packet(outp);
        return CM_ERROR_NOSUCHFILE;
    }
    else {
        osi_assertx(dscp != NULL && scp == NULL, "null dsc || non-null sc");
        openAction = 2;	/* created file */
        setAttr.mask = CM_ATTRMASK_CLIENTMODTIME;
        cm_UnixTimeFromSearchTime(&setAttr.clientModTime, dosTime);
        smb_SetInitialModeBitsForFile(attributes, &setAttr);

        code = cm_Create(dscp, lastNamep, 0, &setAttr, &scp, userp,
                          &req);
        if (code == 0) {
	    created = 1;
	    if (dscp->flags & CM_SCACHEFLAG_ANYWATCH)
		smb_NotifyChange(FILE_ACTION_ADDED,
				 FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_CREATION,
				  dscp, lastNamep, NULL, TRUE);
	} else if (!excl && code == CM_ERROR_EXISTS) {
            /* not an exclusive create, and someone else tried
             * creating it already, then we open it anyway.  We
             * don't bother retrying after this, since if this next
             * fails, that means that the file was deleted after we
             * started this call.
             */
            code = cm_Lookup(dscp, lastNamep, CM_FLAG_CASEFOLD,
                              userp, &req, &scp);
            if (code == 0) {
                if (trunc) {
                    setAttr.mask = CM_ATTRMASK_LENGTH;
                    setAttr.length.LowPart = 0;
                    setAttr.length.HighPart = 0;
                    code = cm_SetAttr(scp, &setAttr, userp,
                                       &req);
                }
            }	/* lookup succeeded */
        }
    }

    /* we don't need this any longer */
    if (dscp)
        cm_ReleaseSCache(dscp);

    if (code) {
        /* something went wrong creating or truncating the file */
        if (scp)
            cm_ReleaseSCache(scp);
        cm_ReleaseUser(userp);
        smb_FreeTran2Packet(outp);
        return code;
    }

    /* make sure we're about to open a file */
    if (scp->fileType != CM_SCACHETYPE_FILE) {
        code = 0;
        while (code == 0 && scp->fileType == CM_SCACHETYPE_SYMLINK) {
            cm_scache_t * targetScp = 0;
            code = cm_EvaluateSymLink(dscp, scp, &targetScp, userp, &req);
            if (code == 0) {
                /* we have a more accurate file to use (the
                 * target of the symbolic link).  Otherwise,
                 * we'll just use the symlink anyway.
                 */
                osi_Log2(smb_logp, "symlink vp %x to vp %x",
                          scp, targetScp);
                cm_ReleaseSCache(scp);
                scp = targetScp;
            }
        }
        if (scp->fileType != CM_SCACHETYPE_FILE) {
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
            smb_FreeTran2Packet(outp);
            return CM_ERROR_ISDIR;
        }
    }

    /* now all we have to do is open the file itself */
    fidp = smb_FindFID(vcp, 0, SMB_FLAG_CREATE);
    osi_assertx(fidp, "null smb_fid_t");

    cm_HoldUser(userp);
    lock_ObtainMutex(&fidp->mx);
    /* save a pointer to the vnode */
    osi_Log2(smb_logp,"smb_ReceiveTran2Open fidp 0x%p scp 0x%p", fidp, scp);
    fidp->scp = scp;
    lock_ObtainWrite(&scp->rw);
    scp->flags |= CM_SCACHEFLAG_SMB_FID;
    lock_ReleaseWrite(&scp->rw);

    /* and the user */
    fidp->userp = userp;

    /* compute open mode */
    if (openMode != 1)
	fidp->flags |= SMB_FID_OPENREAD_LISTDIR;
    if (openMode == 1 || openMode == 2)
        fidp->flags |= SMB_FID_OPENWRITE;

    /* remember that the file was newly created */
    if (created)
	fidp->flags |= SMB_FID_CREATED;

    lock_ReleaseMutex(&fidp->mx);

    smb_ReleaseFID(fidp);

    cm_Open(scp, 0, userp);

    /* copy out remainder of the parms */
    parmSlot = 0;
    outp->parmsp[parmSlot++] = fidp->fid;
    lock_ObtainRead(&scp->rw);
    if (extraInfo) {
        outp->parmsp[parmSlot++] = smb_Attributes(scp);
        cm_SearchTimeFromUnixTime(&dosTime, scp->clientModTime);
        outp->parmsp[parmSlot++] = (unsigned short)(dosTime & 0xffff);
        outp->parmsp[parmSlot++] = (unsigned short)((dosTime>>16) & 0xffff);
        outp->parmsp[parmSlot++] = (unsigned short) (scp->length.LowPart & 0xffff);
        outp->parmsp[parmSlot++] = (unsigned short) ((scp->length.LowPart >> 16) & 0xffff);
        outp->parmsp[parmSlot++] = openMode;
        outp->parmsp[parmSlot++] = 0;   /* file type 0 ==> normal file or dir */
        outp->parmsp[parmSlot++] = 0;   /* IPC junk */
    }
    /* and the final "always present" stuff */
    outp->parmsp[parmSlot++] = openAction;
    /* next write out the "unique" ID */
    outp->parmsp[parmSlot++] = (unsigned short) (scp->fid.vnode & 0xffff);
    outp->parmsp[parmSlot++] = (unsigned short) (scp->fid.volume & 0xffff);
    outp->parmsp[parmSlot++] = 0;
    if (returnEALength) {
        outp->parmsp[parmSlot++] = 0;
        outp->parmsp[parmSlot++] = 0;
    }
    lock_ReleaseRead(&scp->rw);
    outp->totalData = 0;		/* total # of data bytes */
    outp->totalParms = parmSlot * 2;	/* shorts are two bytes */

    smb_SendTran2Packet(vcp, outp, op);

    smb_FreeTran2Packet(outp);

    cm_ReleaseUser(userp);
    /* leave scp held since we put it in fidp->scp */
    return 0;
}

long smb_ReceiveTran2QFSInfoFid(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *op)
{
    unsigned short fid;
    unsigned short infolevel;

    infolevel = p->parmsp[0];
    fid = p->parmsp[1];
    osi_Log2(smb_logp, "T2 QFSInfoFid InfoLevel 0x%x fid 0x%x - NOT_SUPPORTED", infolevel, fid);

    return CM_ERROR_BAD_LEVEL;
}

/* TRANS2_QUERY_FS_INFORMATION */
long smb_ReceiveTran2QFSInfo(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *op)
{
    smb_tran2Packet_t *outp;
    smb_tran2QFSInfo_t qi;
    int responseSize;
    size_t sz = 0;

    osi_Log1(smb_logp, "T2 QFSInfo type 0x%x", p->parmsp[0]);

    switch (p->parmsp[0]) {
    case SMB_INFO_ALLOCATION:
        /* alloc info */
	responseSize = sizeof(qi.u.allocInfo);

        qi.u.allocInfo.FSID = 0;
        qi.u.allocInfo.sectorsPerAllocUnit = 1;
        qi.u.allocInfo.totalAllocUnits = 0x7fffffff;
        qi.u.allocInfo.availAllocUnits = 0x3fffffff;
        qi.u.allocInfo.bytesPerSector = 1024;
        break;

    case SMB_INFO_VOLUME:
        /* volume info */
        qi.u.volumeInfo.vsn = 1234;  /* Volume serial number */
        qi.u.volumeInfo.vnCount = 3; /* Number of characters in label (AFS\0)*/

        /* we're supposed to pad it out with zeroes to the end */
        memset(&qi.u.volumeInfo.label, 0, sizeof(qi.u.volumeInfo.label));
        smb_UnparseString(op, qi.u.volumeInfo.label, _C("AFS"), &sz, 0);

        responseSize = sizeof(unsigned long) + sizeof(char) + max(12, sz);
        break;

    case SMB_QUERY_FS_VOLUME_INFO:
        /* FS volume info */
	responseSize = sizeof(qi.u.FSvolumeInfo);

        {
            FILETIME ft = {0x832cf000, 0x01abfcc4}; /* October 1, 1982 00:00:00 +0600 */
            memcpy(&qi.u.FSvolumeInfo.vct, &ft, sizeof(ft));
        }

        qi.u.FSvolumeInfo.vsn = 1234;
        qi.u.FSvolumeInfo.vnCount = 6; /* This is always in Unicode */
        memset(&qi.u.FSvolumeInfo.label, 0, sizeof(qi.u.FSvolumeInfo.label));
        memcpy(qi.u.FSvolumeInfo.label, L"AFS", sizeof(L"AFS"));
        break;

    case SMB_QUERY_FS_SIZE_INFO:
        /* FS size info */
	responseSize = sizeof(qi.u.FSsizeInfo);

        qi.u.FSsizeInfo.totalAllocUnits.HighPart = 0;
	qi.u.FSsizeInfo.totalAllocUnits.LowPart= 0x7fffffff;
        qi.u.FSsizeInfo.availAllocUnits.HighPart = 0;
	qi.u.FSsizeInfo.availAllocUnits.LowPart= 0x3fffffff;
        qi.u.FSsizeInfo.sectorsPerAllocUnit = 1;
        qi.u.FSsizeInfo.bytesPerSector = 1024;
        break;

    case SMB_QUERY_FS_DEVICE_INFO:
        /* FS device info */
	responseSize = sizeof(qi.u.FSdeviceInfo);

        qi.u.FSdeviceInfo.devType = 0x14; /* network file system */
        qi.u.FSdeviceInfo.characteristics = 0x50; /* remote, virtual */
        break;

    case SMB_QUERY_FS_ATTRIBUTE_INFO:
        /* FS attribute info */

        /* attributes, defined in WINNT.H:
         *	FILE_CASE_SENSITIVE_SEARCH	0x1
         *	FILE_CASE_PRESERVED_NAMES	0x2
         *      FILE_UNICODE_ON_DISK            0x4
	 *      FILE_VOLUME_QUOTAS              0x10
         *	<no name defined>		0x4000
         *	   If bit 0x4000 is not set, Windows 95 thinks
         *	   we can't handle long (non-8.3) names,
         *	   despite our protestations to the contrary.
         */
        qi.u.FSattributeInfo.attributes = 0x4003;
        /* The maxCompLength is supposed to be in bytes */
#ifdef SMB_UNICODE
        qi.u.FSattributeInfo.attributes |= 0x04;
#endif
        qi.u.FSattributeInfo.maxCompLength = 255;
        smb_UnparseString(op, qi.u.FSattributeInfo.FSname, _C("AFS"), &sz, SMB_STRF_IGNORENUL);
        qi.u.FSattributeInfo.FSnameLength = sz;

	responseSize =
            sizeof(qi.u.FSattributeInfo.attributes) +
            sizeof(qi.u.FSattributeInfo.maxCompLength) +
            sizeof(qi.u.FSattributeInfo.FSnameLength) +
            sz;

        break;

    case SMB_INFO_UNIX: 	/* CIFS Unix Info */
    case SMB_INFO_MACOS: 	/* Mac FS Info */
    default:
	return CM_ERROR_BADOP;
    }

    outp = smb_GetTran2ResponsePacket(vcp, p, op, 0, responseSize);

    /* copy out return data, and set corresponding sizes */
    outp->totalParms = 0;
    outp->totalData = responseSize;
    memcpy(outp->datap, &qi, responseSize);

    /* send and free the packets */
    smb_SendTran2Packet(vcp, outp, op);
    smb_FreeTran2Packet(outp);

    return 0;
}

long smb_ReceiveTran2SetFSInfo(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *outp)
{
    osi_Log0(smb_logp,"ReceiveTran2SetFSInfo - NOT_SUPPORTED");
    return CM_ERROR_BADOP;
}

struct smb_ShortNameRock {
    clientchar_t *maskp;
    unsigned int vnode;
    clientchar_t *shortName;
    size_t shortNameLen;
};

int cm_GetShortNameProc(cm_scache_t *scp, cm_dirEntry_t *dep, void *vrockp,
                         osi_hyper_t *offp)
{
    struct smb_ShortNameRock *rockp;
    normchar_t normName[MAX_PATH];
    clientchar_t *shortNameEnd;

    rockp = vrockp;

    if (cm_FsStringToNormString(dep->name, -1, normName, sizeof(normName)/sizeof(clientchar_t)) == 0) {
        osi_Log1(smb_logp, "Skipping entry [%s]. Can't normalize FS string",
                 osi_LogSaveString(smb_logp, dep->name));
        return 0;
    }

    /* compare both names and vnodes, though probably just comparing vnodes
     * would be safe enough.
     */
    if (cm_NormStrCmpI(normName,  rockp->maskp) != 0)
        return 0;
    if (ntohl(dep->fid.vnode) != rockp->vnode)
        return 0;

    /* This is the entry */
    cm_Gen8Dot3Name(dep, rockp->shortName, &shortNameEnd);
    rockp->shortNameLen = shortNameEnd - rockp->shortName;

    return CM_ERROR_STOPNOW;
}

long cm_GetShortName(clientchar_t *pathp, cm_user_t *userp, cm_req_t *reqp,
	clientchar_t *tidPathp, int vnode, clientchar_t *shortName, size_t *shortNameLenp)
{
    struct smb_ShortNameRock rock;
    clientchar_t *lastNamep;
    cm_space_t *spacep;
    cm_scache_t *dscp;
    int caseFold = CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD;
    long code = 0;
    osi_hyper_t thyper;

    spacep = cm_GetSpace();
    /* smb_StripLastComponent will strip "::$DATA" if present */
    smb_StripLastComponent(spacep->wdata, &lastNamep, pathp);

    code = cm_NameI(cm_RootSCachep(userp, reqp), spacep->wdata,
                    caseFold, userp, tidPathp,
                    reqp, &dscp);
    cm_FreeSpace(spacep);
    if (code)
        return code;

#ifdef DFS_SUPPORT
    if (dscp->fileType == CM_SCACHETYPE_DFSLINK) {
        cm_ReleaseSCache(dscp);
        cm_ReleaseUser(userp);
#ifdef DEBUG
        DebugBreak();
#endif
        return CM_ERROR_PATH_NOT_COVERED;
    }
#endif /* DFS_SUPPORT */

    if (!lastNamep) lastNamep = pathp;
    else lastNamep++;
    thyper.LowPart = 0;
    thyper.HighPart = 0;
    rock.shortName = shortName;
    rock.vnode = vnode;
    rock.maskp = lastNamep;
    code = cm_ApplyDir(dscp, cm_GetShortNameProc, &rock, &thyper, userp, reqp, NULL);

    cm_ReleaseSCache(dscp);

    if (code == 0)
        return CM_ERROR_NOSUCHFILE;
    if (code == CM_ERROR_STOPNOW) {
        *shortNameLenp = rock.shortNameLen;
        return 0;
    }
    return code;
}

/* TRANS2_QUERY_PATH_INFORMATION */
long smb_ReceiveTran2QPathInfo(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *opx)
{
    smb_tran2Packet_t *outp;
    afs_uint32 dosTime;
    FILETIME ft;
    unsigned short infoLevel;
    smb_tran2QPathInfo_t qpi;
    int responseSize;
    unsigned short attributes;
    unsigned long extAttributes;
    clientchar_t shortName[13];
    size_t len;
    cm_user_t *userp;
    cm_space_t *spacep;
    cm_scache_t *scp, *dscp;
    int scp_rw_held = 0;
    int delonclose = 0;
    long code = 0;
    clientchar_t *pathp;
    clientchar_t *tidPathp;
    clientchar_t *lastComp;
    cm_req_t req;

    smb_InitReq(&req);

    infoLevel = p->parmsp[0];
    if (infoLevel == SMB_INFO_IS_NAME_VALID)
        responseSize = 0;
    else if (infoLevel == SMB_INFO_STANDARD)
        responseSize = sizeof(qpi.u.QPstandardInfo);
    else if (infoLevel == SMB_INFO_QUERY_EA_SIZE)
        responseSize = sizeof(qpi.u.QPeaSizeInfo);
    else if (infoLevel == SMB_QUERY_FILE_BASIC_INFO)
        responseSize = sizeof(qpi.u.QPfileBasicInfo);
    else if (infoLevel == SMB_QUERY_FILE_STANDARD_INFO)
	responseSize = sizeof(qpi.u.QPfileStandardInfo);
    else if (infoLevel == SMB_QUERY_FILE_EA_INFO)
        responseSize = sizeof(qpi.u.QPfileEaInfo);
    else if (infoLevel == SMB_QUERY_FILE_NAME_INFO)
        responseSize = sizeof(qpi.u.QPfileNameInfo);
    else if (infoLevel == SMB_QUERY_FILE_ALL_INFO)
        responseSize = sizeof(qpi.u.QPfileAllInfo);
    else if (infoLevel == SMB_QUERY_FILE_ALT_NAME_INFO)
        responseSize = sizeof(qpi.u.QPfileAltNameInfo);
    else if (infoLevel == SMB_QUERY_FILE_STREAM_INFO)
        responseSize = sizeof(qpi.u.QPfileStreamInfo);
    else {
        osi_Log2(smb_logp, "Bad Tran2QPathInfo op 0x%x infolevel 0x%x",
                  p->opcode, infoLevel);
        smb_SendTran2Error(vcp, p, opx, CM_ERROR_BAD_LEVEL);
        return 0;
    }
    memset(&qpi, 0, sizeof(qpi));

    pathp = smb_ParseStringT2Parm(p, (char *) (&p->parmsp[3]), NULL, SMB_STRF_ANSIPATH);
    osi_Log2(smb_logp, "T2 QPathInfo type 0x%x path \"%S\"", infoLevel,
              osi_LogSaveClientString(smb_logp, pathp));

    outp = smb_GetTran2ResponsePacket(vcp, p, opx, 2, responseSize);

    if (infoLevel > 0x100)
        outp->totalParms = 2;
    else
        outp->totalParms = 0;

    /* now, if we're at infoLevel 6, we're only being asked to check
     * the syntax, so we just OK things now.  In particular, we're *not*
     * being asked to verify anything about the state of any parent dirs.
     */
    if (infoLevel == SMB_INFO_IS_NAME_VALID) {
        smb_SendTran2Packet(vcp, outp, opx);
        smb_FreeTran2Packet(outp);
        return 0;
    }

    userp = smb_GetTran2User(vcp, p);
    if (!userp) {
        osi_Log1(smb_logp, "ReceiveTran2QPathInfo unable to resolve user [%d]", p->uid);
        smb_FreeTran2Packet(outp);
        return CM_ERROR_BADSMB;
    }

    code = smb_LookupTIDPath(vcp, p->tid, &tidPathp);
    if(code) {
        osi_Log1(smb_logp, "ReceiveTran2QPathInfo tid path lookup failure 0x%x", code);
        cm_ReleaseUser(userp);
        smb_SendTran2Error(vcp, p, opx, CM_ERROR_NOSUCHPATH);
        smb_FreeTran2Packet(outp);
        return 0;
    }

    osi_Log1(smb_logp, "T2 QPathInfo tidPathp \"%S\"",
              osi_LogSaveClientString(smb_logp, tidPathp));

    /*
     * If the query is regarding the special _._AFS_IOCTL_._ file
     * a reply must be sent even though the file doesn't exist.
     */
    if (cm_ClientStrCmpI(pathp, CM_IOCTL_FILENAME_W) == 0)
    {
        /* for info level 108, figure out short name */
        if (infoLevel == SMB_QUERY_FILE_ALT_NAME_INFO) {
            smb_UnparseString(opx, qpi.u.QPfileAltNameInfo.fileName, L"_IOCTL_.AFS", &len, SMB_STRF_IGNORENUL);
            qpi.u.QPfileAltNameInfo.fileNameLength = len;
            responseSize = sizeof(unsigned long) + len;
        }
        else if (infoLevel == SMB_QUERY_FILE_NAME_INFO) {
            smb_UnparseString(opx, qpi.u.QPfileNameInfo.fileName, CM_IOCTL_FILENAME_NOSLASH_W, &len, SMB_STRF_IGNORENUL);
            qpi.u.QPfileNameInfo.fileNameLength = len;
            responseSize = sizeof(unsigned long) + len;
        }
        else if (infoLevel == SMB_INFO_STANDARD || infoLevel == SMB_INFO_QUERY_EA_SIZE) {
            cm_SearchTimeFromUnixTime(&dosTime, 0);
            qpi.u.QPstandardInfo.creationDateTime = dosTime;
            qpi.u.QPstandardInfo.lastAccessDateTime = dosTime;
            qpi.u.QPstandardInfo.lastWriteDateTime = dosTime;
            qpi.u.QPstandardInfo.dataSize = 0;
            qpi.u.QPstandardInfo.allocationSize = 0;
            qpi.u.QPstandardInfo.attributes = SMB_ATTR_SYSTEM | SMB_ATTR_HIDDEN;
            qpi.u.QPstandardInfo.eaSize = 0;
        }
        else if (infoLevel == SMB_QUERY_FILE_BASIC_INFO) {
            cm_LargeSearchTimeFromUnixTime(&ft, 0);
            qpi.u.QPfileBasicInfo.creationTime = ft;
            qpi.u.QPfileBasicInfo.lastAccessTime = ft;
            qpi.u.QPfileBasicInfo.lastWriteTime = ft;
            qpi.u.QPfileBasicInfo.changeTime = ft;
            qpi.u.QPfileBasicInfo.attributes = SMB_ATTR_SYSTEM | SMB_ATTR_HIDDEN;
            qpi.u.QPfileBasicInfo.reserved = 0;
        }
        else if (infoLevel == SMB_QUERY_FILE_STANDARD_INFO) {
            qpi.u.QPfileStandardInfo.allocationSize.QuadPart = 0;
            qpi.u.QPfileStandardInfo.endOfFile.QuadPart = 0;
            qpi.u.QPfileStandardInfo.numberOfLinks = 1;
            qpi.u.QPfileStandardInfo.directory = 0;
            qpi.u.QPfileStandardInfo.reserved = 0;
            qpi.u.QPfileStandardInfo.deletePending = 0;
        }
        else if (infoLevel == SMB_QUERY_FILE_EA_INFO) {
            qpi.u.QPfileEaInfo.eaSize = 0;
        }
        else if (infoLevel == SMB_QUERY_FILE_ALL_INFO) {
            cm_LargeSearchTimeFromUnixTime(&ft, 0);
            qpi.u.QPfileAllInfo.creationTime = ft;
            qpi.u.QPfileAllInfo.lastAccessTime = ft;
            qpi.u.QPfileAllInfo.lastWriteTime = ft;
            qpi.u.QPfileAllInfo.changeTime = ft;
            qpi.u.QPfileAllInfo.attributes = SMB_ATTR_SYSTEM | SMB_ATTR_HIDDEN;
            qpi.u.QPfileAllInfo.allocationSize.QuadPart = 0;
            qpi.u.QPfileAllInfo.endOfFile.QuadPart = 0;
            qpi.u.QPfileAllInfo.numberOfLinks = 1;
            qpi.u.QPfileAllInfo.deletePending = 0;
            qpi.u.QPfileAllInfo.directory = 0;
            qpi.u.QPfileAllInfo.indexNumber.HighPart = 0;
            qpi.u.QPfileAllInfo.indexNumber.LowPart  = 0;
            qpi.u.QPfileAllInfo.eaSize = 0;
            qpi.u.QPfileAllInfo.accessFlags = 0;
            qpi.u.QPfileAllInfo.indexNumber2.HighPart = 0;
            qpi.u.QPfileAllInfo.indexNumber2.LowPart  = 0;
            qpi.u.QPfileAllInfo.currentByteOffset.HighPart = 0;
            qpi.u.QPfileAllInfo.currentByteOffset.LowPart = 0;
            qpi.u.QPfileAllInfo.mode = 0;
            qpi.u.QPfileAllInfo.alignmentRequirement = 0;

            smb_UnparseString(opx, qpi.u.QPfileAllInfo.fileName, CM_IOCTL_FILENAME_NOSLASH_W, &len, SMB_STRF_IGNORENUL);
            qpi.u.QPfileAllInfo.fileNameLength = len;
            responseSize -= (sizeof(qpi.u.QPfileAllInfo.fileName) - len);
        }
        else if (infoLevel == SMB_QUERY_FILE_STREAM_INFO) {
            size_t len = 0;
            /* For now we have no streams */
            qpi.u.QPfileStreamInfo.nextEntryOffset = 0;
            qpi.u.QPfileStreamInfo.streamSize.QuadPart = 0;
            qpi.u.QPfileStreamInfo.streamAllocationSize.QuadPart = 0;
            smb_UnparseString(opx, qpi.u.QPfileStreamInfo.fileName, L"::$DATA", &len, SMB_STRF_IGNORENUL);
            qpi.u.QPfileStreamInfo.streamNameLength = len;
            responseSize -= (sizeof(qpi.u.QPfileStreamInfo.fileName) - len);
        }

        outp->totalData = responseSize;
        goto done_afs_ioctl;
    }

    /*
     * XXX Strange hack XXX
     *
     * As of Patch 7 (13 January 98), we are having the following problem:
     * In NT Explorer 4.0, whenever we click on a directory, AFS gets
     * requests to look up "desktop.ini" in all the subdirectories.
     * This can cause zillions of timeouts looking up non-existent cells
     * and volumes, especially in the top-level directory.
     *
     * We have not found any way to avoid this or work around it except
     * to explicitly ignore the requests for mount points that haven't
     * yet been evaluated and for directories that haven't yet been
     * fetched.
     */
    if (infoLevel == SMB_QUERY_FILE_BASIC_INFO) {
        spacep = cm_GetSpace();
        /* smb_StripLastComponent will strip "::$DATA" if present */
        smb_StripLastComponent(spacep->wdata, &lastComp, pathp);
#ifndef SPECIAL_FOLDERS
        /* Make sure that lastComp is not NULL */
        if (lastComp) {
            if (cm_ClientStrCmpIA(lastComp,  _C("\\desktop.ini")) == 0) {
                code = cm_NameI(cm_RootSCachep(userp, &req), spacep->wdata,
                                 CM_FLAG_CASEFOLD
                                 | CM_FLAG_DIRSEARCH
                                 | CM_FLAG_FOLLOW,
                                 userp, tidPathp, &req, &dscp);
                if (code == 0) {
#ifdef DFS_SUPPORT
                    if (dscp->fileType == CM_SCACHETYPE_DFSLINK) {
                        int pnc = cm_VolStatus_Notify_DFS_Mapping(dscp, tidPathp,
                                                                  spacep->wdata);
                        if ( WANTS_DFS_PATHNAMES(p) || pnc )
                            code = CM_ERROR_PATH_NOT_COVERED;
                        else
                            code = CM_ERROR_NOSUCHPATH;
                    } else
#endif /* DFS_SUPPORT */
                    if (dscp->fileType == CM_SCACHETYPE_MOUNTPOINT && !dscp->mountRootFid.volume)
                        code = CM_ERROR_NOSUCHFILE;
                    else if (dscp->fileType == CM_SCACHETYPE_DIRECTORY) {
                        cm_buf_t *bp = buf_Find(&dscp->fid, &hzero);
                        if (bp) {
                            buf_Release(bp);
                            bp = NULL;
                        }
                        else
                            code = CM_ERROR_NOSUCHFILE;
                    }
                    cm_ReleaseSCache(dscp);
                    if (code) {
                        cm_FreeSpace(spacep);
                        cm_ReleaseUser(userp);
                        smb_SendTran2Error(vcp, p, opx, code);
                        smb_FreeTran2Packet(outp);
                        return 0;
                    }
                }
            }
        }
#endif /* SPECIAL_FOLDERS */

        cm_FreeSpace(spacep);
    }

    if (code == 0 ||
        code == CM_ERROR_NOSUCHFILE ||
        code == CM_ERROR_NOSUCHPATH ||
        code == CM_ERROR_BPLUS_NOMATCH) {
        /* now do namei and stat, and copy out the info */
        code = cm_NameI(cm_RootSCachep(userp, &req), pathp,
                        CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD, userp, tidPathp, &req, &scp);
    }

    if (code) {
        cm_ReleaseUser(userp);
        smb_SendTran2Error(vcp, p, opx, code);
        smb_FreeTran2Packet(outp);
        return 0;
    }

#ifdef DFS_SUPPORT
    if (scp->fileType == CM_SCACHETYPE_DFSLINK) {
        int pnc = cm_VolStatus_Notify_DFS_Mapping(scp, tidPathp, pathp);
        cm_ReleaseSCache(scp);
        cm_ReleaseUser(userp);
        if ( WANTS_DFS_PATHNAMES(p) || pnc )
            code = CM_ERROR_PATH_NOT_COVERED;
        else
            code = CM_ERROR_NOSUCHPATH;
        smb_SendTran2Error(vcp, p, opx, code);
        smb_FreeTran2Packet(outp);
        return 0;
    }
#endif /* DFS_SUPPORT */

    lock_ObtainWrite(&scp->rw);
    scp_rw_held = 2;
    code = cm_SyncOp(scp, NULL, userp, &req, 0,
                      CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    if (code)
        goto done;

    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);

    lock_ConvertWToR(&scp->rw);
    scp_rw_held = 1;

    len = 0;

    /* now we have the status in the cache entry, and everything is locked.
     * Marshall the output data.
     */
    /* for info level 108, figure out short name */
    if (infoLevel == SMB_QUERY_FILE_ALT_NAME_INFO) {
        code = cm_GetShortName(pathp, userp, &req,
                                tidPathp, scp->fid.vnode, shortName,
                               &len);
        if (code) {
            goto done;
        }

        smb_UnparseString(opx, qpi.u.QPfileAltNameInfo.fileName, shortName, &len, SMB_STRF_IGNORENUL);
	qpi.u.QPfileAltNameInfo.fileNameLength = len;
        responseSize = sizeof(unsigned long) + len;
    }
    else if (infoLevel == SMB_QUERY_FILE_NAME_INFO) {
        smb_UnparseString(opx, qpi.u.QPfileNameInfo.fileName, lastComp, &len, SMB_STRF_IGNORENUL);
	qpi.u.QPfileNameInfo.fileNameLength = len;
        responseSize = sizeof(unsigned long) + len;
    }
    else if (infoLevel == SMB_INFO_STANDARD || infoLevel == SMB_INFO_QUERY_EA_SIZE) {
        cm_SearchTimeFromUnixTime(&dosTime, scp->clientModTime);
	qpi.u.QPstandardInfo.creationDateTime = dosTime;
	qpi.u.QPstandardInfo.lastAccessDateTime = dosTime;
	qpi.u.QPstandardInfo.lastWriteDateTime = dosTime;
        qpi.u.QPstandardInfo.dataSize = scp->length.LowPart;
        qpi.u.QPstandardInfo.allocationSize = scp->length.LowPart;
        attributes = smb_Attributes(scp);
        qpi.u.QPstandardInfo.attributes = attributes;
	qpi.u.QPstandardInfo.eaSize = 0;
    }
    else if (infoLevel == SMB_QUERY_FILE_BASIC_INFO) {
        cm_LargeSearchTimeFromUnixTime(&ft, scp->clientModTime);
        qpi.u.QPfileBasicInfo.creationTime = ft;
        qpi.u.QPfileBasicInfo.lastAccessTime = ft;
        qpi.u.QPfileBasicInfo.lastWriteTime = ft;
        qpi.u.QPfileBasicInfo.changeTime = ft;
        extAttributes = smb_ExtAttributes(scp);
	qpi.u.QPfileBasicInfo.attributes = extAttributes;
	qpi.u.QPfileBasicInfo.reserved = 0;
    }
    else if (infoLevel == SMB_QUERY_FILE_STANDARD_INFO) {
	smb_fid_t * fidp;

        lock_ReleaseRead(&scp->rw);
        scp_rw_held = 0;
        fidp = smb_FindFIDByScache(vcp, scp);

        qpi.u.QPfileStandardInfo.allocationSize = scp->length;
        qpi.u.QPfileStandardInfo.endOfFile = scp->length;
        qpi.u.QPfileStandardInfo.numberOfLinks = scp->linkCount;
        qpi.u.QPfileStandardInfo.directory =
	    ((scp->fileType == CM_SCACHETYPE_DIRECTORY ||
	      scp->fileType == CM_SCACHETYPE_MOUNTPOINT ||
	      scp->fileType == CM_SCACHETYPE_INVALID) ? 1 : 0);
        qpi.u.QPfileStandardInfo.reserved = 0;

    	if (fidp) {
	    lock_ObtainMutex(&fidp->mx);
	    delonclose = fidp->flags & SMB_FID_DELONCLOSE;
	    lock_ReleaseMutex(&fidp->mx);
	    smb_ReleaseFID(fidp);
	}
        qpi.u.QPfileStandardInfo.deletePending = (delonclose ? 1 : 0);
    }
    else if (infoLevel == SMB_QUERY_FILE_EA_INFO) {
        qpi.u.QPfileEaInfo.eaSize = 0;
    }
    else if (infoLevel == SMB_QUERY_FILE_ALL_INFO) {
	smb_fid_t * fidp;

        lock_ReleaseRead(&scp->rw);
        scp_rw_held = 0;
        fidp = smb_FindFIDByScache(vcp, scp);

        cm_LargeSearchTimeFromUnixTime(&ft, scp->clientModTime);
        qpi.u.QPfileAllInfo.creationTime = ft;
        qpi.u.QPfileAllInfo.lastAccessTime = ft;
        qpi.u.QPfileAllInfo.lastWriteTime = ft;
        qpi.u.QPfileAllInfo.changeTime = ft;
        extAttributes = smb_ExtAttributes(scp);
	qpi.u.QPfileAllInfo.attributes = extAttributes;
        qpi.u.QPfileAllInfo.allocationSize = scp->length;
        qpi.u.QPfileAllInfo.endOfFile = scp->length;
        qpi.u.QPfileAllInfo.numberOfLinks = scp->linkCount;
        qpi.u.QPfileAllInfo.deletePending = 0;
        qpi.u.QPfileAllInfo.directory =
	    ((scp->fileType == CM_SCACHETYPE_DIRECTORY ||
	      scp->fileType == CM_SCACHETYPE_MOUNTPOINT ||
	      scp->fileType == CM_SCACHETYPE_INVALID) ? 1 : 0);
	qpi.u.QPfileAllInfo.indexNumber.HighPart = scp->fid.vnode;
	qpi.u.QPfileAllInfo.indexNumber.LowPart  = scp->fid.unique;
	qpi.u.QPfileAllInfo.eaSize = 0;
        qpi.u.QPfileAllInfo.accessFlags = 0;
        if (fidp) {
	    lock_ObtainMutex(&fidp->mx);
            if (fidp->flags & SMB_FID_OPENDELETE)
                qpi.u.QPfileAllInfo.accessFlags |= DELETE;
            if (fidp->flags & SMB_FID_OPENREAD_LISTDIR)
                qpi.u.QPfileAllInfo.accessFlags |= AFS_ACCESS_READ|AFS_ACCESS_EXECUTE;
            if (fidp->flags & SMB_FID_OPENWRITE)
                qpi.u.QPfileAllInfo.accessFlags |= AFS_ACCESS_WRITE;
            if (fidp->flags & SMB_FID_DELONCLOSE)
                qpi.u.QPfileAllInfo.deletePending = 1;
	    lock_ReleaseMutex(&fidp->mx);
	    smb_ReleaseFID(fidp);
        }
	qpi.u.QPfileAllInfo.indexNumber2.HighPart = scp->fid.cell;
	qpi.u.QPfileAllInfo.indexNumber2.LowPart  = scp->fid.volume;
	qpi.u.QPfileAllInfo.currentByteOffset.HighPart = 0;
	qpi.u.QPfileAllInfo.currentByteOffset.LowPart = 0;
	qpi.u.QPfileAllInfo.mode = 0;
	qpi.u.QPfileAllInfo.alignmentRequirement = 0;

        smb_UnparseString(opx, qpi.u.QPfileAllInfo.fileName, lastComp, &len, SMB_STRF_IGNORENUL);
	qpi.u.QPfileAllInfo.fileNameLength = len;
        responseSize -= (sizeof(qpi.u.QPfileAllInfo.fileName) - len);
    }
    else if (infoLevel == SMB_QUERY_FILE_STREAM_INFO) {
        size_t len = 0;
        /* For now we have no streams */
        qpi.u.QPfileStreamInfo.nextEntryOffset = 0;
        if (scp->fileType == CM_SCACHETYPE_FILE) {
            qpi.u.QPfileStreamInfo.streamSize = scp->length;
            qpi.u.QPfileStreamInfo.streamAllocationSize = scp->length;
            smb_UnparseString(opx, qpi.u.QPfileStreamInfo.fileName, L"::$DATA", &len, SMB_STRF_IGNORENUL);
            qpi.u.QPfileStreamInfo.streamNameLength = len;
            responseSize -= (sizeof(qpi.u.QPfileStreamInfo.fileName) - len);
        } else {
            qpi.u.QPfileStreamInfo.streamSize.QuadPart = 0;
            qpi.u.QPfileStreamInfo.streamAllocationSize.QuadPart = 0;
            smb_UnparseString(opx, qpi.u.QPfileStreamInfo.fileName, L"", &len, SMB_STRF_IGNORENUL);
            qpi.u.QPfileStreamInfo.streamNameLength = 0;
            responseSize = 0;
        }
    }
    outp->totalData = responseSize;

    /* send and free the packets */
  done:
    switch (scp_rw_held) {
    case 1:
	lock_ReleaseRead(&scp->rw);
        break;
    case 2:
        lock_ReleaseWrite(&scp->rw);
        break;
    }
    scp_rw_held = 0;
    cm_ReleaseSCache(scp);

  done_afs_ioctl:
    cm_ReleaseUser(userp);
    if (code == 0) {
	memcpy(outp->datap, &qpi, responseSize);
	smb_SendTran2Packet(vcp, outp, opx);
    } else {
        smb_SendTran2Error(vcp, p, opx, code);
    }
    smb_FreeTran2Packet(outp);

    return 0;
}

/* TRANS2_SET_PATH_INFORMATION */
long smb_ReceiveTran2SetPathInfo(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *opx)
{
#if 0
    osi_Log0(smb_logp,"ReceiveTran2SetPathInfo - NOT_SUPPORTED");
    return CM_ERROR_BADOP;
#else
    long code = 0;
    unsigned short infoLevel;
    clientchar_t * pathp;
    smb_tran2Packet_t *outp;
    smb_tran2QPathInfo_t *spi;
    cm_user_t *userp;
    cm_scache_t *scp, *dscp;
    cm_req_t req;
    cm_space_t *spacep;
    clientchar_t *tidPathp;
    clientchar_t *lastComp;

    smb_InitReq(&req);

    infoLevel = p->parmsp[0];
    osi_Log1(smb_logp,"ReceiveTran2SetPathInfo type 0x%x", infoLevel);
    if (infoLevel != SMB_INFO_STANDARD &&
	infoLevel != SMB_INFO_QUERY_EA_SIZE &&
	infoLevel != SMB_INFO_QUERY_ALL_EAS) {
        osi_Log2(smb_logp, "Bad Tran2SetPathInfo op 0x%x infolevel 0x%x",
                  p->opcode, infoLevel);
        smb_SendTran2Error(vcp, p, opx,
                           infoLevel == SMB_INFO_QUERY_ALL_EAS ? CM_ERROR_EAS_NOT_SUPPORTED : CM_ERROR_BAD_LEVEL);
        return 0;
    }

    pathp = smb_ParseStringT2Parm(p, (char *) (&p->parmsp[3]), NULL, SMB_STRF_ANSIPATH);

    osi_Log2(smb_logp, "T2 SetPathInfo infolevel 0x%x path %S", infoLevel,
              osi_LogSaveClientString(smb_logp, pathp));

    userp = smb_GetTran2User(vcp, p);
    if (!userp) {
    	osi_Log1(smb_logp,"ReceiveTran2SetPathInfo unable to resolve user [%d]", p->uid);
    	code = CM_ERROR_BADSMB;
    	goto done;
    }

    code = smb_LookupTIDPath(vcp, p->tid, &tidPathp);
    if (code == CM_ERROR_TIDIPC) {
        /* Attempt to use a TID allocated for IPC.  The client
         * is probably looking for DCE RPC end points which we
         * don't support OR it could be looking to make a DFS
         * referral request.
         */
        osi_Log0(smb_logp, "Tran2Open received IPC TID");
        cm_ReleaseUser(userp);
        return CM_ERROR_NOSUCHPATH;
    }

    /*
    * XXX Strange hack XXX
    *
    * As of Patch 7 (13 January 98), we are having the following problem:
    * In NT Explorer 4.0, whenever we click on a directory, AFS gets
    * requests to look up "desktop.ini" in all the subdirectories.
    * This can cause zillions of timeouts looking up non-existent cells
    * and volumes, especially in the top-level directory.
    *
    * We have not found any way to avoid this or work around it except
    * to explicitly ignore the requests for mount points that haven't
    * yet been evaluated and for directories that haven't yet been
    * fetched.
    */
    if (infoLevel == SMB_QUERY_FILE_BASIC_INFO) {
        spacep = cm_GetSpace();
        /* smb_StripLastComponent will strip "::$DATA" if present */
        smb_StripLastComponent(spacep->wdata, &lastComp, pathp);
#ifndef SPECIAL_FOLDERS
        /* Make sure that lastComp is not NULL */
        if (lastComp) {
            if (cm_ClientStrCmpI(lastComp,  _C("\\desktop.ini")) == 0) {
                code = cm_NameI(cm_RootSCachep(userp, &req), spacep->wdata,
                                 CM_FLAG_CASEFOLD
                                 | CM_FLAG_DIRSEARCH
                                 | CM_FLAG_FOLLOW,
                                 userp, tidPathp, &req, &dscp);
                if (code == 0) {
#ifdef DFS_SUPPORT
                    if (dscp->fileType == CM_SCACHETYPE_DFSLINK) {
                        int pnc = cm_VolStatus_Notify_DFS_Mapping(dscp, tidPathp,
                                                                  spacep->wdata);
                        if ( WANTS_DFS_PATHNAMES(p) || pnc )
                            code = CM_ERROR_PATH_NOT_COVERED;
                        else
                            code = CM_ERROR_NOSUCHPATH;
                    } else
#endif /* DFS_SUPPORT */
                    if (dscp->fileType == CM_SCACHETYPE_MOUNTPOINT && !dscp->mountRootFid.volume)
                        code = CM_ERROR_NOSUCHFILE;
                    else if (dscp->fileType == CM_SCACHETYPE_DIRECTORY) {
                        cm_buf_t *bp = buf_Find(&dscp->fid, &hzero);
                        if (bp) {
                            buf_Release(bp);
                            bp = NULL;
                        }
                        else
                            code = CM_ERROR_NOSUCHFILE;
                    }
                    cm_ReleaseSCache(dscp);
                    if (code) {
                        cm_FreeSpace(spacep);
                        cm_ReleaseUser(userp);
                        smb_SendTran2Error(vcp, p, opx, code);
                        return 0;
                    }
                }
            }
        }
#endif /* SPECIAL_FOLDERS */

        cm_FreeSpace(spacep);
    }

    if (code == 0 ||
        code == CM_ERROR_NOSUCHFILE ||
        code == CM_ERROR_NOSUCHPATH ||
        code == CM_ERROR_BPLUS_NOMATCH) {
        /* now do namei and stat, and copy out the info */
        code = cm_NameI(cm_RootSCachep(userp, &req), pathp,
                        CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD, userp, tidPathp, &req, &scp);
    }

    if (code) {
        cm_ReleaseUser(userp);
        smb_SendTran2Error(vcp, p, opx, code);
        return 0;
    }

    outp = smb_GetTran2ResponsePacket(vcp, p, opx, 2, 0);

    outp->totalParms = 2;
    outp->totalData = 0;

    spi = (smb_tran2QPathInfo_t *)p->datap;
    if (infoLevel == SMB_INFO_STANDARD || infoLevel == SMB_INFO_QUERY_EA_SIZE) {
        cm_attr_t attr;

        /* lock the vnode with a callback; we need the current status
         * to determine what the new status is, in some cases.
         */
        lock_ObtainWrite(&scp->rw);
        code = cm_SyncOp(scp, NULL, userp, &req, 0,
                          CM_SCACHESYNC_GETSTATUS
                         | CM_SCACHESYNC_NEEDCALLBACK);
        if (code) {
	    lock_ReleaseWrite(&scp->rw);
            goto done;
        }
	cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);

        /* prepare for setattr call */
        attr.mask = CM_ATTRMASK_LENGTH;
        attr.length.LowPart = spi->u.QPstandardInfo.dataSize;
        attr.length.HighPart = 0;

	if (spi->u.QPstandardInfo.lastWriteDateTime != 0) {
	    cm_UnixTimeFromSearchTime(&attr.clientModTime, spi->u.QPstandardInfo.lastWriteDateTime);
            attr.mask |= CM_ATTRMASK_CLIENTMODTIME;
        }

        if (spi->u.QPstandardInfo.attributes != 0) {
            if ((scp->unixModeBits & 0200)
                 && (spi->u.QPstandardInfo.attributes & SMB_ATTR_READONLY) != 0) {
                /* make a writable file read-only */
                attr.mask |= CM_ATTRMASK_UNIXMODEBITS;
                attr.unixModeBits = scp->unixModeBits & ~0222;
            }
            else if ((scp->unixModeBits & 0200) == 0
                      && (spi->u.QPstandardInfo.attributes & SMB_ATTR_READONLY) == 0) {
                /* make a read-only file writable */
                attr.mask |= CM_ATTRMASK_UNIXMODEBITS;
                attr.unixModeBits = scp->unixModeBits | 0222;
            }
        }
        lock_ReleaseRead(&scp->rw);

        /* call setattr */
        if (attr.mask)
            code = cm_SetAttr(scp, &attr, userp, &req);
        else
            code = 0;
    }
    else if (infoLevel == SMB_INFO_QUERY_ALL_EAS) {
	/* we don't support EAs */
	code = CM_ERROR_EAS_NOT_SUPPORTED;
    }

  done:
    cm_ReleaseSCache(scp);
    cm_ReleaseUser(userp);
    if (code == 0)
        smb_SendTran2Packet(vcp, outp, opx);
    else
        smb_SendTran2Error(vcp, p, opx, code);
    smb_FreeTran2Packet(outp);

    return 0;
#endif
}

/* TRANS2_QUERY_FILE_INFORMATION */
long smb_ReceiveTran2QFileInfo(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *opx)
{
    smb_tran2Packet_t *outp;
    FILETIME ft;
    unsigned long attributes;
    unsigned short infoLevel;
    int responseSize;
    unsigned short fid;
    int delonclose = 0;
    cm_user_t *userp;
    smb_fid_t *fidp;
    cm_scache_t *scp;
    smb_tran2QFileInfo_t qfi;
    long code = 0;
    int  readlock = 0;
    cm_req_t req;

    smb_InitReq(&req);

    fid = p->parmsp[0];
    fidp = smb_FindFID(vcp, fid, 0);

    if (fidp == NULL) {
        osi_Log2(smb_logp, "Tran2QFileInfo Unknown SMB Fid vcp 0x%p fid %d",
                 vcp, fid);
        smb_SendTran2Error(vcp, p, opx, CM_ERROR_BADFD);
        return 0;
    }

    lock_ObtainMutex(&fidp->mx);
    if (fidp->scp && (fidp->scp->flags & CM_SCACHEFLAG_DELETED)) {
        lock_ReleaseMutex(&fidp->mx);
        smb_SendTran2Error(vcp, p, opx, CM_ERROR_NOSUCHFILE);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        return 0;
    }
    lock_ReleaseMutex(&fidp->mx);

    infoLevel = p->parmsp[1];
    if (infoLevel == SMB_QUERY_FILE_BASIC_INFO)
        responseSize = sizeof(qfi.u.QFbasicInfo);
    else if (infoLevel == SMB_QUERY_FILE_STANDARD_INFO)
        responseSize = sizeof(qfi.u.QFstandardInfo);
    else if (infoLevel == SMB_QUERY_FILE_EA_INFO)
        responseSize = sizeof(qfi.u.QFeaInfo);
    else if (infoLevel == SMB_QUERY_FILE_NAME_INFO)
        responseSize = sizeof(qfi.u.QFfileNameInfo);
    else if (infoLevel == SMB_QUERY_FILE_STREAM_INFO)
        responseSize = sizeof(qfi.u.QFfileStreamInfo);
    else {
        osi_Log2(smb_logp, "Bad Tran2QFileInfo op 0x%x infolevel 0x%x",
                  p->opcode, infoLevel);
        smb_SendTran2Error(vcp, p, opx, CM_ERROR_BAD_LEVEL);
        smb_ReleaseFID(fidp);
        return 0;
    }
    osi_Log2(smb_logp, "T2 QFileInfo type 0x%x fid %d", infoLevel, fid);
    memset(&qfi, 0, sizeof(qfi));

    outp = smb_GetTran2ResponsePacket(vcp, p, opx, 2, responseSize);

    if (infoLevel > 0x100)
        outp->totalParms = 2;
    else
        outp->totalParms = 0;

    userp = smb_GetTran2User(vcp, p);
    if (!userp) {
    	osi_Log1(smb_logp, "ReceiveTran2QFileInfo unable to resolve user [%d]", p->uid);
    	code = CM_ERROR_BADSMB;
    	goto done;
    }

    lock_ObtainMutex(&fidp->mx);
    delonclose = fidp->flags & SMB_FID_DELONCLOSE;
    scp = fidp->scp;
    osi_Log2(smb_logp,"smb_ReleaseTran2QFileInfo fidp 0x%p scp 0x%p", fidp, scp);
    cm_HoldSCache(scp);
    lock_ReleaseMutex(&fidp->mx);
    lock_ObtainWrite(&scp->rw);
    code = cm_SyncOp(scp, NULL, userp, &req, 0,
                      CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    if (code)
        goto done;

    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);

    lock_ConvertWToR(&scp->rw);
    readlock = 1;

    /* now we have the status in the cache entry, and everything is locked.
     * Marshall the output data.
     */

    if (infoLevel == SMB_QUERY_FILE_BASIC_INFO) {
        if (fidp->flags & SMB_FID_IOCTL) {
            cm_LargeSearchTimeFromUnixTime(&ft, 0);
            attributes = SMB_ATTR_SYSTEM | SMB_ATTR_HIDDEN;
        } else {
            cm_LargeSearchTimeFromUnixTime(&ft, scp->clientModTime);
            attributes = smb_ExtAttributes(scp);
        }
        qfi.u.QFbasicInfo.creationTime = ft;
        qfi.u.QFbasicInfo.lastAccessTime = ft;
        qfi.u.QFbasicInfo.lastWriteTime = ft;
        qfi.u.QFbasicInfo.lastChangeTime = ft;
        qfi.u.QFbasicInfo.attributes = attributes;
    }
    else if (infoLevel == SMB_QUERY_FILE_STANDARD_INFO) {
        if (fidp->flags & SMB_FID_IOCTL) {
            qfi.u.QFstandardInfo.allocationSize.QuadPart = 0;
            qfi.u.QFstandardInfo.endOfFile.QuadPart = 0;
            qfi.u.QFstandardInfo.numberOfLinks = 1;
            qfi.u.QFstandardInfo.deletePending = 0;
            qfi.u.QFstandardInfo.directory = 0;
        } else {
            qfi.u.QFstandardInfo.allocationSize = scp->length;
            qfi.u.QFstandardInfo.endOfFile = scp->length;
            qfi.u.QFstandardInfo.numberOfLinks = scp->linkCount;
            qfi.u.QFstandardInfo.deletePending = (delonclose ? 1 : 0);
            qfi.u.QFstandardInfo.directory =
                ((scp->fileType == CM_SCACHETYPE_DIRECTORY ||
                   scp->fileType == CM_SCACHETYPE_MOUNTPOINT ||
                   scp->fileType == CM_SCACHETYPE_INVALID)? 1 : 0);
        }
    }
    else if (infoLevel == SMB_QUERY_FILE_EA_INFO) {
        qfi.u.QFeaInfo.eaSize = 0;
    }
    else if (infoLevel == SMB_QUERY_FILE_NAME_INFO) {
        size_t len = 0;
        clientchar_t *name;

	lock_ReleaseRead(&scp->rw);
	lock_ObtainMutex(&fidp->mx);
	lock_ObtainRead(&scp->rw);
        if (fidp->NTopen_wholepathp)
            name = fidp->NTopen_wholepathp;
        else
            name = _C("\\");	/* probably can't happen */
	lock_ReleaseMutex(&fidp->mx);

        smb_UnparseString(opx, qfi.u.QFfileNameInfo.fileName, name, &len, SMB_STRF_IGNORENUL);
        responseSize = len + 4;	/* this is actually what we want to return */
        qfi.u.QFfileNameInfo.fileNameLength = len;
    }
    else if (infoLevel == SMB_QUERY_FILE_STREAM_INFO) {
        size_t len = 0;

        if (scp->fileType == CM_SCACHETYPE_DIRECTORY ||
            scp->fileType == CM_SCACHETYPE_MOUNTPOINT ||
            scp->fileType == CM_SCACHETYPE_INVALID) {
            /* Do not return the alternate streams for directories */
            responseSize = 0;
        } else {
            /* For now we have no alternate streams */
            qfi.u.QFfileStreamInfo.nextEntryOffset = 0;

            if (fidp->flags & SMB_FID_IOCTL) {
                qfi.u.QFfileStreamInfo.streamSize.QuadPart = 0;
                qfi.u.QFfileStreamInfo.streamAllocationSize.QuadPart = 0;
            } else {
                qfi.u.QFfileStreamInfo.streamSize = scp->length;
                qfi.u.QFfileStreamInfo.streamAllocationSize = scp->length;
            }

            smb_UnparseString(opx, qfi.u.QFfileStreamInfo.fileName, L"::$DATA", &len, SMB_STRF_IGNORENUL);
            qfi.u.QFfileStreamInfo.streamNameLength = len;
            responseSize -= (sizeof(qfi.u.QFfileStreamInfo.fileName) - len);
        }
    }
    outp->totalData = responseSize;

    /* send and free the packets */
  done:
    if (readlock)
        lock_ReleaseRead(&scp->rw);
    else
        lock_ReleaseWrite(&scp->rw);
    cm_ReleaseSCache(scp);
    cm_ReleaseUser(userp);
    smb_ReleaseFID(fidp);
    if (code == 0) {
	memcpy(outp->datap, &qfi, responseSize);
        smb_SendTran2Packet(vcp, outp, opx);
    } else {
        smb_SendTran2Error(vcp, p, opx, code);
    }
    smb_FreeTran2Packet(outp);

    return 0;
}


/* TRANS2_SET_FILE_INFORMATION */
long smb_ReceiveTran2SetFileInfo(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *opx)
{
    long code = 0;
    unsigned short fid;
    smb_fid_t *fidp;
    unsigned short infoLevel;
    smb_tran2Packet_t *outp;
    cm_user_t *userp = NULL;
    cm_scache_t *scp = NULL;
    cm_req_t req;

    smb_InitReq(&req);

    fid = p->parmsp[0];
    fidp = smb_FindFID(vcp, fid, 0);

    if (fidp == NULL) {
        osi_Log2(smb_logp, "Tran2SetFileInfo Unknown SMB Fid vcp 0x%p fid %d",
                 vcp, fid);
        smb_SendTran2Error(vcp, p, opx, CM_ERROR_BADFD);
        return 0;
    }

    infoLevel = p->parmsp[1];
    osi_Log2(smb_logp,"ReceiveTran2SetFileInfo type 0x%x fid %d", infoLevel, fid);
    if (infoLevel > SMB_SET_FILE_END_OF_FILE_INFO || infoLevel < SMB_SET_FILE_BASIC_INFO) {
        osi_Log2(smb_logp, "Bad Tran2SetFileInfo op 0x%x infolevel 0x%x",
                  p->opcode, infoLevel);
        smb_SendTran2Error(vcp, p, opx, CM_ERROR_BAD_LEVEL);
        smb_ReleaseFID(fidp);
        return 0;
    }

    lock_ObtainMutex(&fidp->mx);
    if (fidp->scp && (fidp->scp->flags & CM_SCACHEFLAG_DELETED)) {
        lock_ReleaseMutex(&fidp->mx);
        smb_SendTran2Error(vcp, p, opx, CM_ERROR_NOSUCHFILE);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        return 0;
    }

    if (infoLevel == SMB_SET_FILE_DISPOSITION_INFO &&
	!(fidp->flags & SMB_FID_OPENDELETE)) {
	osi_Log3(smb_logp,"smb_ReceiveTran2SetFileInfo !SMB_FID_OPENDELETE fidp 0x%p scp 0x%p fidp->flags 0x%x",
		  fidp, fidp->scp, fidp->flags);
	lock_ReleaseMutex(&fidp->mx);
        smb_ReleaseFID(fidp);
        smb_SendTran2Error(vcp, p, opx, CM_ERROR_NOACCESS);
        return 0;
    }
    if ((infoLevel == SMB_SET_FILE_ALLOCATION_INFO ||
	 infoLevel == SMB_SET_FILE_END_OF_FILE_INFO)
         && !(fidp->flags & SMB_FID_OPENWRITE)) {
	osi_Log3(smb_logp,"smb_ReceiveTran2SetFileInfo !SMB_FID_OPENWRITE fidp 0x%p scp 0x%p fidp->flags 0x%x",
		  fidp, fidp->scp, fidp->flags);
	lock_ReleaseMutex(&fidp->mx);
        smb_ReleaseFID(fidp);
        smb_SendTran2Error(vcp, p, opx, CM_ERROR_NOACCESS);
        return 0;
    }

    scp = fidp->scp;
    osi_Log2(smb_logp,"smb_ReceiveTran2SetFileInfo fidp 0x%p scp 0x%p", fidp, scp);
    cm_HoldSCache(scp);
    lock_ReleaseMutex(&fidp->mx);

    outp = smb_GetTran2ResponsePacket(vcp, p, opx, 2, 0);

    outp->totalParms = 2;
    outp->totalData = 0;

    userp = smb_GetTran2User(vcp, p);
    if (!userp) {
    	osi_Log1(smb_logp,"ReceiveTran2SetFileInfo unable to resolve user [%d]", p->uid);
    	code = CM_ERROR_BADSMB;
    	goto done;
    }

    if (infoLevel == SMB_SET_FILE_BASIC_INFO) {
        FILETIME lastMod;
        unsigned int attribute;
        cm_attr_t attr;
	smb_tran2QFileInfo_t *sfi;

	sfi = (smb_tran2QFileInfo_t *)p->datap;

	/* lock the vnode with a callback; we need the current status
         * to determine what the new status is, in some cases.
         */
        lock_ObtainWrite(&scp->rw);
        code = cm_SyncOp(scp, NULL, userp, &req, 0,
                          CM_SCACHESYNC_GETSTATUS
                         | CM_SCACHESYNC_NEEDCALLBACK);
        if (code) {
	    lock_ReleaseWrite(&scp->rw);
            goto done;
	}

	cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);

	lock_ReleaseWrite(&scp->rw);
	lock_ObtainMutex(&fidp->mx);
	lock_ObtainRead(&scp->rw);

        /* prepare for setattr call */
        attr.mask = 0;

        lastMod = sfi->u.QFbasicInfo.lastWriteTime;
        /* when called as result of move a b, lastMod is (-1, -1).
         * If the check for -1 is not present, timestamp
         * of the resulting file will be 1969 (-1)
         */
        if (LargeIntegerNotEqualToZero(*((LARGE_INTEGER *)&lastMod)) &&
             lastMod.dwLowDateTime != -1 && lastMod.dwHighDateTime != -1) {
            attr.mask |= CM_ATTRMASK_CLIENTMODTIME;
            cm_UnixTimeFromLargeSearchTime(&attr.clientModTime, &lastMod);
            fidp->flags |= SMB_FID_MTIMESETDONE;
        }

        attribute = sfi->u.QFbasicInfo.attributes;
        if (attribute != 0) {
            if ((scp->unixModeBits & 0200)
                 && (attribute & SMB_ATTR_READONLY) != 0) {
                /* make a writable file read-only */
                attr.mask |= CM_ATTRMASK_UNIXMODEBITS;
                attr.unixModeBits = scp->unixModeBits & ~0222;
            }
            else if ((scp->unixModeBits & 0200) == 0
                      && (attribute & SMB_ATTR_READONLY) == 0) {
                /* make a read-only file writable */
                attr.mask |= CM_ATTRMASK_UNIXMODEBITS;
                attr.unixModeBits = scp->unixModeBits | 0222;
            }
        }
        lock_ReleaseRead(&scp->rw);
	lock_ReleaseMutex(&fidp->mx);

        /* call setattr */
        if (attr.mask)
            code = cm_SetAttr(scp, &attr, userp, &req);
        else
            code = 0;
    }
    else if (infoLevel == SMB_SET_FILE_DISPOSITION_INFO) {
	int delflag = *((char *)(p->datap));
	osi_Log3(smb_logp,"smb_ReceiveTran2SetFileInfo Delete? %d fidp 0x%p scp 0x%p",
		 delflag, fidp, scp);
        if (*((char *)(p->datap))) {	/* File is Deleted */
            code = cm_CheckNTDelete(fidp->NTopen_dscp, scp, userp,
                                     &req);
            if (code == 0) {
		lock_ObtainMutex(&fidp->mx);
                fidp->flags |= SMB_FID_DELONCLOSE;
		lock_ReleaseMutex(&fidp->mx);
	    } else {
		osi_Log3(smb_logp,"smb_ReceiveTran2SetFileInfo CheckNTDelete fidp 0x%p scp 0x%p code 0x%x",
			 fidp, scp, code);
	    }
	}
        else {
            code = 0;
	    lock_ObtainMutex(&fidp->mx);
            fidp->flags &= ~SMB_FID_DELONCLOSE;
	    lock_ReleaseMutex(&fidp->mx);
        }
    }
    else if (infoLevel == SMB_SET_FILE_ALLOCATION_INFO ||
	     infoLevel == SMB_SET_FILE_END_OF_FILE_INFO) {
        LARGE_INTEGER size = *((LARGE_INTEGER *)(p->datap));
        cm_attr_t attr;

        attr.mask = CM_ATTRMASK_LENGTH;
        attr.length.LowPart = size.LowPart;
        attr.length.HighPart = size.HighPart;
        code = cm_SetAttr(scp, &attr, userp, &req);
    }

  done:
    cm_ReleaseSCache(scp);
    cm_ReleaseUser(userp);
    smb_ReleaseFID(fidp);
    if (code == 0)
        smb_SendTran2Packet(vcp, outp, opx);
    else
        smb_SendTran2Error(vcp, p, opx, code);
    smb_FreeTran2Packet(outp);

    return 0;
}

/* TRANS2_FSCTL */
long
smb_ReceiveTran2FSCTL(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *outp)
{
    osi_Log0(smb_logp,"ReceiveTran2FSCTL - NOT_SUPPORTED");
    return CM_ERROR_BADOP;
}

/* TRANS2_IOCTL2 */
long
smb_ReceiveTran2IOCTL(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *outp)
{
    osi_Log0(smb_logp,"ReceiveTran2IOCTL - NOT_SUPPORTED");
    return CM_ERROR_BADOP;
}

/* TRANS2_FIND_NOTIFY_FIRST */
long
smb_ReceiveTran2FindNotifyFirst(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *outp)
{
    osi_Log0(smb_logp,"ReceiveTran2FindNotifyFirst - NOT_SUPPORTED");
    return CM_ERROR_BADOP;
}

/* TRANS2_FIND_NOTIFY_NEXT */
long
smb_ReceiveTran2FindNotifyNext(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *outp)
{
    osi_Log0(smb_logp,"ReceiveTran2FindNotifyNext - NOT_SUPPORTED");
    return CM_ERROR_BADOP;
}

/* TRANS2_CREATE_DIRECTORY */
long
smb_ReceiveTran2CreateDirectory(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *outp)
{
    osi_Log0(smb_logp,"ReceiveTran2CreateDirectory - NOT_SUPPORTED");
    return CM_ERROR_BADOP;
}

/* TRANS2_SESSION_SETUP */
long
smb_ReceiveTran2SessionSetup(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *outp)
{
    osi_Log0(smb_logp,"ReceiveTran2SessionSetup - NOT_SUPPORTED");
    return CM_ERROR_BADOP;
}

struct smb_v2_referral {
    USHORT ServerType;
    USHORT ReferralFlags;
    ULONG  Proximity;
    ULONG  TimeToLive;
    USHORT DfsPathOffset;
    USHORT DfsAlternativePathOffset;
    USHORT NetworkAddressOffset;
};

/* TRANS2_GET_DFS_REFERRAL */
long
smb_ReceiveTran2GetDFSReferral(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *op)
{
    /* This is a UNICODE only request (bit15 of Flags2) */
    /* The TID must be IPC$ */

    /* The documentation for the Flags response field is contradictory */

    /* Use Version 1 Referral Element Format */
    /* ServerType = 0; indicates the next server should be queried for the file */
    /* ReferralFlags = 0x01; PathConsumed characters should be stripped */
    /* Node = UnicodeString of UNC path of the next share name */
#ifdef DFS_SUPPORT
    long code = 0;
    int maxReferralLevel = 0;
    clientchar_t requestFileName[1024] = _C("");
    clientchar_t referralPath[1024] = _C("");
    smb_tran2Packet_t *outp = 0;
    cm_user_t *userp = 0;
    cm_scache_t *scp = 0;
    cm_scache_t *dscp = 0;
    cm_req_t req;
    CPINFO CodePageInfo;
    int i, nbnLen, reqLen, refLen;
    int idx;

    smb_InitReq(&req);

    maxReferralLevel = p->parmsp[0];

    GetCPInfo(CP_ACP, &CodePageInfo);
    cm_Utf16ToClientString(&p->parmsp[1], -1, requestFileName, lengthof(requestFileName));

    osi_Log2(smb_logp,"ReceiveTran2GetDfsReferral [%d][%S]",
             maxReferralLevel, osi_LogSaveClientString(smb_logp, requestFileName));

    nbnLen = (int)cm_ClientStrLen(cm_NetbiosNameC);
    reqLen = (int)cm_ClientStrLen(requestFileName);

    if (reqLen > nbnLen + 2 && requestFileName[0] == '\\' &&
        !cm_ClientStrCmpNI(cm_NetbiosNameC, &requestFileName[1], nbnLen) &&
        requestFileName[nbnLen+1] == '\\')
    {
        int found = 0;

        if (!cm_ClientStrCmpNI(_C("all"), &requestFileName[nbnLen+2], 3) ||
            !cm_ClientStrCmpNI(_C("*."), &requestFileName[nbnLen+2], 2)) {
            found = 1;
            cm_ClientStrCpy(referralPath, lengthof(referralPath), requestFileName);
            refLen = reqLen;
        } else {
            userp = smb_GetTran2User(vcp, p);
            if (!userp) {
                osi_Log1(smb_logp,"ReceiveTran2GetDfsReferral unable to resolve user [%d]", p->uid);
                code = CM_ERROR_BADSMB;
                goto done;
            }

            /*
             * We have a requested path.  Check to see if it is something
             * we know about.
             *
             * But be careful because the name that we might be searching
             * for might be a known name with the final character stripped
             * off.
             */
            code = cm_NameI(cm_RootSCachep(userp, &req), &requestFileName[nbnLen+2],
                            CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD | CM_FLAG_DFS_REFERRAL,
                            userp, NULL, &req, &scp);
            if (code == 0 ||
                code == CM_ERROR_ALLDOWN ||
                code == CM_ERROR_ALLBUSY ||
                code == CM_ERROR_ALLOFFLINE ||
                code == CM_ERROR_NOSUCHCELL ||
                code == CM_ERROR_NOSUCHVOLUME ||
                code == CM_ERROR_NOACCESS) {
                /* Yes it is. */
                found = 1;
                cm_ClientStrCpy(referralPath, lengthof(referralPath), requestFileName);
                refLen = reqLen;
            } else if (code == CM_ERROR_PATH_NOT_COVERED ) {
                clientchar_t temp[1024];
                clientchar_t pathName[1024];
                clientchar_t *lastComponent;
                /*
                 * we have a msdfs link somewhere in the path
                 * we should figure out where in the path the link is.
                 * and return it.
                 */
                osi_Log1(smb_logp,"ReceiveTran2GetDfsReferral PATH_NOT_COVERED [%S]", requestFileName);

                cm_ClientStrCpy(temp, lengthof(temp), &requestFileName[nbnLen+2]);

                do {
                    if (dscp) {
                        cm_ReleaseSCache(dscp);
                        dscp = 0;
                    }
                    if (scp) {
                        cm_ReleaseSCache(scp);
                        scp = 0;
                    }
                    /* smb_StripLastComponent will strip "::$DATA" if present */
                    smb_StripLastComponent(pathName, &lastComponent, temp);

                    code = cm_NameI(cm_RootSCachep(userp, &req), pathName,
                                    CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                                    userp, NULL, &req, &dscp);
                    if (code == 0) {
                        code = cm_NameI(dscp, ++lastComponent,
                                        CM_FLAG_CASEFOLD,
                                        userp, NULL, &req, &scp);
                        if (code == 0 && scp->fileType == CM_SCACHETYPE_DFSLINK)
                            break;
                    }
                } while (code == CM_ERROR_PATH_NOT_COVERED);

                /* scp should now be the DfsLink we are looking for */
                if (scp) {
                    /* figure out how much of the input path was used */
                    reqLen = (int)(nbnLen+2 + cm_ClientStrLen(pathName) + 1 + cm_ClientStrLen(lastComponent));

                    cm_FsStringToClientString(&scp->mountPointStringp[strlen("msdfs:")], -1,
                                              referralPath, lengthof(referralPath));
                    refLen = (int)cm_ClientStrLen(referralPath);
                    found = 1;
                }
            } else {
                clientchar_t shareName[MAX_PATH + 1];
                clientchar_t *p, *q;
                /* we may have a sharename that is a volume reference */

                for (p = &requestFileName[nbnLen+2], q = shareName; *p && *p != '\\'; p++, q++)
                {
                    *q = *p;
                }
                *q = '\0';

                if (smb_FindShare(vcp, vcp->usersp, shareName, &p)) {
                    code = cm_NameI(cm_RootSCachep(userp, &req), _C(""),
                                    CM_FLAG_CASEFOLD | CM_FLAG_FOLLOW,
                                    userp, p, &req, &scp);
                    free(p);

                    if (code == 0) {
                        found = 1;
                        cm_ClientStrCpy(referralPath, lengthof(referralPath),
                                        requestFileName);
                        refLen = reqLen;
                    }
                }
            }
        }

        if (found)
        {
            USHORT * sp;
            struct smb_v2_referral * v2ref;
            outp = smb_GetTran2ResponsePacket(vcp, p, op, 0, 2 * (refLen + 8));

            sp = (USHORT *)outp->datap;
            idx = 0;
            sp[idx++] = reqLen;   /* path consumed */
            sp[idx++] = 1;        /* number of referrals */
            sp[idx++] = 0x03;     /* flags */
#ifdef DFS_VERSION_1
            sp[idx++] = 1;        /* Version Number */
            sp[idx++] = refLen + 4;  /* Referral Size */
            sp[idx++] = 1;        /* Type = SMB Server */
            sp[idx++] = 0;        /* Do not strip path consumed */
            for ( i=0;i<=refLen; i++ )
                sp[i+idx] = referralPath[i];
#else /* DFS_VERSION_2 */
            sp[idx++] = 2;      /* Version Number */
            sp[idx++] = sizeof(struct smb_v2_referral);     /* Referral Size */
            idx += (sizeof(struct smb_v2_referral) / 2);
            v2ref = (struct smb_v2_referral *) &sp[5];
            v2ref->ServerType = 1;  /* SMB Server */
            v2ref->ReferralFlags = 0x03;
            v2ref->Proximity = 0;   /* closest */
            v2ref->TimeToLive = 3600; /* seconds */
            v2ref->DfsPathOffset = idx * 2;
            v2ref->DfsAlternativePathOffset = idx * 2;
            v2ref->NetworkAddressOffset = 0;
            for ( i=0;i<=refLen; i++ )
                sp[i+idx] = referralPath[i];
#endif
        } else {
            code = CM_ERROR_NOSUCHPATH;
        }
    } else {
        code = CM_ERROR_NOSUCHPATH;
    }

  done:
    if (dscp)
        cm_ReleaseSCache(dscp);
    if (scp)
        cm_ReleaseSCache(scp);
    if (userp)
        cm_ReleaseUser(userp);
    if (code == 0)
        smb_SendTran2Packet(vcp, outp, op);
    else
        smb_SendTran2Error(vcp, p, op, code);
    if (outp)
        smb_FreeTran2Packet(outp);

    return 0;
#else /* DFS_SUPPORT */
    osi_Log0(smb_logp,"ReceiveTran2GetDfsReferral - NOT_SUPPORTED");
    return CM_ERROR_NOSUCHDEVICE;
#endif /* DFS_SUPPORT */
}

/* TRANS2_REPORT_DFS_INCONSISTENCY */
long
smb_ReceiveTran2ReportDFSInconsistency(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *outp)
{
    /* This is a UNICODE only request (bit15 of Flags2) */

    /* There is nothing we can do about this operation.  The client is going to
     * tell us that there is a Version 1 Referral Element for which there is a DFS Error.
     * Unfortunately, there is really nothing we can do about it other then log it
     * somewhere.  Even then I don't think there is anything for us to do.
     * So let's return an error value.
     */

    osi_Log0(smb_logp,"ReceiveTran2ReportDFSInconsistency - NOT_SUPPORTED");
    return CM_ERROR_BADOP;
}

static long
smb_ApplyV3DirListPatches(cm_scache_t *dscp, smb_dirListPatch_t **dirPatchespp,
                          clientchar_t * tidPathp, clientchar_t * relPathp,
                          int infoLevel, cm_user_t *userp, cm_req_t *reqp)
{
    long code = 0;
    cm_scache_t *scp;
    cm_scache_t *targetScp;			/* target if scp is a symlink */
    afs_uint32 dosTime;
    FILETIME ft;
    unsigned short attr;
    unsigned long lattr;
    smb_dirListPatch_t *patchp;
    smb_dirListPatch_t *npatchp;
    afs_uint32 rights;
    afs_int32 mustFake = 0;
    afs_int32 nobulkstat = 0;
    clientchar_t path[AFSPATHMAX];

    lock_ObtainWrite(&dscp->rw);
    code = cm_FindACLCache(dscp, userp, &rights);
    if (code == -1) {
        code = cm_SyncOp(dscp, NULL, userp, reqp, PRSFS_READ,
                          CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
        if (code == 0)
            cm_SyncOpDone(dscp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
        if (code == CM_ERROR_NOACCESS) {
            mustFake = 1;
            code = 0;
        }
    }
    lock_ReleaseWrite(&dscp->rw);
    if (code)
        goto cleanup;

    if (!mustFake) {    /* Bulk Stat */
        afs_uint32 count;
        cm_bulkStat_t *bsp = malloc(sizeof(cm_bulkStat_t));

        memset(bsp, 0, sizeof(cm_bulkStat_t));
        bsp->userp = userp;

      restart_patchset:
        for (patchp = *dirPatchespp, count=0;
             patchp;
             patchp = (smb_dirListPatch_t *) osi_QNext(&patchp->q)) {
            cm_scache_t *tscp = NULL;
            int i;

            /* Do not look for a cm_scache_t or bulkstat an ioctl entry */
            if (patchp->flags & SMB_DIRLISTPATCH_IOCTL)
                continue;

            code = cm_GetSCache(&patchp->fid, &dscp->fid, &tscp, userp, reqp);
            if (code == 0) {
                if (lock_TryWrite(&tscp->rw)) {
                    /* we have an entry that we can look at */
#ifdef AFS_FREELANCE_CLIENT
                    if (dscp->fid.cell == AFS_FAKE_ROOT_CELL_ID && dscp->fid.volume == AFS_FAKE_ROOT_VOL_ID) {
                        code = cm_SyncOp(tscp, NULL, userp, reqp, 0,
                                          CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
                        if (code == 0)
                            cm_SyncOpDone(tscp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);

                        lock_ReleaseWrite(&tscp->rw);
                        cm_ReleaseSCache(tscp);
                        continue;
                    }
#endif /* AFS_FREELANCE_CLIENT */
                    if (!cm_EAccesFindEntry(userp, &tscp->fid) && cm_HaveCallback(tscp)) {
                        /* we have a callback on it.  Don't bother
                        * fetching this stat entry, since we're happy
                        * with the info we have.
                        */
                        lock_ReleaseWrite(&tscp->rw);
                        cm_ReleaseSCache(tscp);
                        continue;
                    }

                    if (nobulkstat) {
                        code = cm_SyncOp(tscp, NULL, userp, reqp, 0,
                                          CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
                        lock_ReleaseWrite(&tscp->rw);
                        cm_ReleaseSCache(tscp);
                        continue;
                    }

                    lock_ReleaseWrite(&tscp->rw);
                } /* got lock */
                cm_ReleaseSCache(tscp);
            }	/* found entry */

            i = bsp->counter++;
            bsp->fids[i].Volume = patchp->fid.volume;
            bsp->fids[i].Vnode = patchp->fid.vnode;
            bsp->fids[i].Unique = patchp->fid.unique;

            if (bsp->counter == AFSCBMAX) {
                code = cm_TryBulkStatRPC(dscp, bsp, userp, reqp);
                memset(bsp, 0, sizeof(cm_bulkStat_t));
                bsp->userp = userp;

                if (code == CM_ERROR_BULKSTAT_FAILURE) {
                    /*
                    * If bulk stat cannot be used for this directory
                    * we must perform individual fetch status calls.
                    * Restart from the beginning of the patch series.
                    */
                    nobulkstat = 1;
                    goto restart_patchset;
                }
            }
        }

        if (bsp->counter > 0)
            code = cm_TryBulkStatRPC(dscp, bsp, userp, reqp);

        free(bsp);
    }

    for( patchp = *dirPatchespp;
         patchp;
         patchp = (smb_dirListPatch_t *) osi_QNext(&patchp->q)) {
        cm_ClientStrPrintfN(path, lengthof(path),_C("%s\\%S"),
                            relPathp ? relPathp : _C(""), patchp->dep->name);
        reqp->relPathp = path;
        reqp->tidPathp = tidPathp;

        if (patchp->flags & SMB_DIRLISTPATCH_IOCTL) {
            /* Plug in fake timestamps. A time stamp of 0 causes 'invalid parameter'
               errors in the client. */
            if (infoLevel >= SMB_FIND_FILE_DIRECTORY_INFO) {
                smb_V3FileAttrsLong * fa = (smb_V3FileAttrsLong *) patchp->dptr;

                /* 1969-12-31 23:59:59 +00 */
                ft.dwHighDateTime = 0x19DB200;
                ft.dwLowDateTime = 0x5BB78980;

                /* copy to Creation Time */
                fa->creationTime = ft;
                fa->lastAccessTime = ft;
                fa->lastWriteTime = ft;
                fa->lastChangeTime = ft;
                fa->extFileAttributes = SMB_ATTR_SYSTEM | SMB_ATTR_HIDDEN;
            } else {
                smb_V3FileAttrsShort * fa = (smb_V3FileAttrsShort *) patchp->dptr;

                /* 1969-12-31 23:59:58 +00*/
                dosTime = 0xEBBFBF7D;

                fa->creationDateTime = MAKELONG(HIWORD(dosTime),LOWORD(dosTime));
                fa->lastAccessDateTime = fa->creationDateTime;
                fa->lastWriteDateTime = fa->creationDateTime;
                fa->attributes = SMB_ATTR_SYSTEM|SMB_ATTR_HIDDEN;
            }
            continue;
        }

        code = cm_GetSCache(&patchp->fid, &dscp->fid, &scp, userp, reqp);
        reqp->relPathp = reqp->tidPathp = NULL;
        if (code)
            continue;

        lock_ObtainWrite(&scp->rw);
        if (mustFake || cm_EAccesFindEntry(userp, &scp->fid) || !cm_HaveCallback(scp)) {
            lock_ReleaseWrite(&scp->rw);

            /* Plug in fake timestamps. A time stamp of 0 causes 'invalid parameter'
               errors in the client. */
            if (infoLevel >= SMB_FIND_FILE_DIRECTORY_INFO) {
                smb_V3FileAttrsLong * fa = (smb_V3FileAttrsLong *) patchp->dptr;

                /* 1969-12-31 23:59:59 +00 */
                ft.dwHighDateTime = 0x19DB200;
                ft.dwLowDateTime = 0x5BB78980;

                /* copy to Creation Time */
                fa->creationTime = ft;
                fa->lastAccessTime = ft;
                fa->lastWriteTime = ft;
                fa->lastChangeTime = ft;

                switch (scp->fileType) {
                case CM_SCACHETYPE_DIRECTORY:
                case CM_SCACHETYPE_MOUNTPOINT:
                case CM_SCACHETYPE_INVALID:
                    fa->extFileAttributes = SMB_ATTR_DIRECTORY;
                    break;
                case CM_SCACHETYPE_SYMLINK:
                    if (cm_TargetPerceivedAsDirectory(scp->mountPointStringp))
                        fa->extFileAttributes = SMB_ATTR_DIRECTORY;
                    else
                        fa->extFileAttributes = SMB_ATTR_NORMAL;
                    break;
                default:
                    /* if we get here we either have a normal file
                     * or we have a file for which we have never
                     * received status info.  In this case, we can
                     * check the even/odd value of the entry's vnode.
                     * odd means it is to be treated as a directory
                     * and even means it is to be treated as a file.
                     */
                    if (mustFake && (scp->fid.vnode & 0x1))
                        fa->extFileAttributes = SMB_ATTR_DIRECTORY;
                    else
                        fa->extFileAttributes = SMB_ATTR_NORMAL;
                }
                /* merge in hidden attribute */
                if ( patchp->flags & SMB_DIRLISTPATCH_DOTFILE ) {
                    fa->extFileAttributes |= SMB_ATTR_HIDDEN;
                }
            } else {
                smb_V3FileAttrsShort * fa = (smb_V3FileAttrsShort *) patchp->dptr;

                /* 1969-12-31 23:59:58 +00*/
                dosTime = 0xEBBFBF7D;

                fa->creationDateTime = MAKELONG(HIWORD(dosTime),LOWORD(dosTime));
                fa->lastAccessDateTime = fa->creationDateTime;
                fa->lastWriteDateTime = fa->creationDateTime;

                /* set the attribute */
                switch (scp->fileType) {
                case CM_SCACHETYPE_DIRECTORY:
                case CM_SCACHETYPE_MOUNTPOINT:
                case CM_SCACHETYPE_INVALID:
                    fa->attributes = SMB_ATTR_DIRECTORY;
                    break;
                case CM_SCACHETYPE_SYMLINK:
                    if (cm_TargetPerceivedAsDirectory(scp->mountPointStringp))
                        fa->attributes = SMB_ATTR_DIRECTORY;
                    else
                        fa->attributes = SMB_ATTR_NORMAL;
                    break;
                default:
                    /* if we get here we either have a normal file
                     * or we have a file for which we have never
                     * received status info.  In this case, we can
                     * check the even/odd value of the entry's vnode.
                     * even means it is to be treated as a directory
                     * and odd means it is to be treated as a file.
                     */
                    if (mustFake && (scp->fid.vnode & 0x1))
                        fa->attributes = SMB_ATTR_DIRECTORY;
                    else
                        fa->attributes = SMB_ATTR_NORMAL;
                }

                /* merge in hidden (dot file) attribute */
                if ( patchp->flags & SMB_DIRLISTPATCH_DOTFILE ) {
                    fa->attributes |= SMB_ATTR_HIDDEN;
                }
            }

            cm_ReleaseSCache(scp);
            continue;
        }

        /* now watch for a symlink */
        code = 0;
        while (code == 0 && scp->fileType == CM_SCACHETYPE_SYMLINK) {
            lock_ReleaseWrite(&scp->rw);
            cm_ClientStrPrintfN(path, lengthof(path), _C("%s\\%S"),
                                relPathp ? relPathp : _C(""), patchp->dep->name);
            reqp->relPathp = path;
            reqp->tidPathp = tidPathp;
            code = cm_EvaluateSymLink(dscp, scp, &targetScp, userp, reqp);
            reqp->relPathp = reqp->tidPathp = NULL;
            if (code == 0) {
                /* we have a more accurate file to use (the
                 * target of the symbolic link).  Otherwise,
                 * we'll just use the symlink anyway.
                 */
                osi_Log2(smb_logp, "symlink vp %x to vp %x",
                          scp, targetScp);
                cm_ReleaseSCache(scp);
                scp = targetScp;
            }
            lock_ObtainWrite(&scp->rw);
        }

        lock_ConvertWToR(&scp->rw);

        if (infoLevel >= SMB_FIND_FILE_DIRECTORY_INFO) {
            smb_V3FileAttrsLong * fa = (smb_V3FileAttrsLong *) patchp->dptr;

            /* get filetime */
            cm_LargeSearchTimeFromUnixTime(&ft, scp->clientModTime);

            fa->creationTime = ft;
            fa->lastAccessTime = ft;
            fa->lastWriteTime = ft;
            fa->lastChangeTime = ft;

            /* Use length for both file length and alloc length */
            fa->endOfFile = scp->length;
            fa->allocationSize = scp->length;

            /* Copy attributes */
            lattr = smb_ExtAttributes(scp);
            if ((code == CM_ERROR_NOSUCHPATH &&
                (scp->fileType == CM_SCACHETYPE_SYMLINK &&
                cm_TargetPerceivedAsDirectory(scp->mountPointStringp))) ||
                code == CM_ERROR_PATH_NOT_COVERED && scp->fileType == CM_SCACHETYPE_DFSLINK) {
                if (lattr == SMB_ATTR_NORMAL)
                    lattr = SMB_ATTR_DIRECTORY;
                else
                    lattr |= SMB_ATTR_DIRECTORY;
            }
            /* merge in hidden (dot file) attribute */
            if ( patchp->flags & SMB_DIRLISTPATCH_DOTFILE ) {
                if (lattr == SMB_ATTR_NORMAL)
                    lattr = SMB_ATTR_HIDDEN;
                else
                    lattr |= SMB_ATTR_HIDDEN;
            }

            fa->extFileAttributes = lattr;
        } else {
            smb_V3FileAttrsShort * fa = (smb_V3FileAttrsShort *) patchp->dptr;

            /* get dos time */
            cm_SearchTimeFromUnixTime(&dosTime, scp->clientModTime);

            fa->creationDateTime = MAKELONG(HIWORD(dosTime), LOWORD(dosTime));
            fa->lastAccessDateTime = fa->creationDateTime;
            fa->lastWriteDateTime = fa->creationDateTime;

            /* copy out file length and alloc length,
             * using the same for both
             */
            fa->dataSize = scp->length.LowPart;
            fa->allocationSize = scp->length.LowPart;

            /* finally copy out attributes as short */
            attr = smb_Attributes(scp);
            /* merge in hidden (dot file) attribute */
            if ( patchp->flags & SMB_DIRLISTPATCH_DOTFILE ) {
                if (lattr == SMB_ATTR_NORMAL)
                    lattr = SMB_ATTR_HIDDEN;
                else
                    lattr |= SMB_ATTR_HIDDEN;
            }
            fa->attributes = attr;
        }

        lock_ReleaseRead(&scp->rw);
        cm_ReleaseSCache(scp);
    }

    /* now free the patches */
    for (patchp = *dirPatchespp; patchp; patchp = npatchp) {
        npatchp = (smb_dirListPatch_t *) osi_QNext(&patchp->q);
        free(patchp);
    }

    /* and mark the list as empty */
    *dirPatchespp = NULL;

  cleanup:
    return code;
}

/* smb_ReceiveTran2SearchDir implements both
 * Tran2_Find_First and Tran2_Find_Next
 */
#define TRAN2_FIND_FLAG_CLOSE_SEARCH		0x01
#define TRAN2_FIND_FLAG_CLOSE_SEARCH_IF_END	0x02
#define TRAN2_FIND_FLAG_RETURN_RESUME_KEYS	0x04
#define TRAN2_FIND_FLAG_CONTINUE_SEARCH		0x08
#define TRAN2_FIND_FLAG_BACKUP_INTENT		0x10

/* this is an optimized handler for T2SearchDir that handles the case
   where there are no wildcards in the search path.  I.e. an
   application is using FindFirst(Ex) to get information about a
   single file or directory.  It will attempt to do a single lookup.
   If that fails, then smb_ReceiveTran2SearchDir() will fall back to
   the usual mechanism.

   This function will return either CM_ERROR_NOSUCHFILE or SUCCESS.

   TRANS2_FIND_FIRST2 and TRANS2_FIND_NEXT2
   */
long smb_T2SearchDirSingle(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *opx)
{
    int attribute;
    long nextCookie;
    long code = 0, code2 = 0;
    clientchar_t *pathp = 0;
    int maxCount;
    smb_dirListPatch_t *dirListPatchesp;
    smb_dirListPatch_t *curPatchp;
    size_t orbytes;			/* # of bytes in this output record */
    size_t ohbytes;			/* # of bytes, except file name */
    size_t onbytes;			/* # of bytes in name, incl. term. null */
    cm_scache_t *scp = NULL;
    cm_scache_t *targetScp = NULL;
    cm_user_t *userp = NULL;
    char *op;				/* output data ptr */
    char *origOp;			/* original value of op */
    cm_space_t *spacep;			/* for pathname buffer */
    unsigned long maxReturnData;	/* max # of return data */
    long maxReturnParms;		/* max # of return parms */
    long bytesInBuffer;			/* # data bytes in the output buffer */
    clientchar_t *maskp;			/* mask part of path */
    int infoLevel;
    int searchFlags;
    int eos;
    smb_tran2Packet_t *outp;		/* response packet */
    clientchar_t *tidPathp = 0;
    int align;
    clientchar_t shortName[13];		/* 8.3 name if needed */
    int NeedShortName;
    clientchar_t *shortNameEnd;
    cm_dirEntry_t * dep = NULL;
    cm_req_t req;
    char * s;
    void * attrp = NULL;
    smb_tran2Find_t * fp;
    int afs_ioctl = 0;                  /* is this query for _._AFS_IOCTL_._? */
    cm_dirFid_t dfid;

    smb_InitReq(&req);

    eos = 0;
    osi_assertx(p->opcode == 1, "invalid opcode");

    /* find first; obtain basic parameters from request */

    /* note that since we are going to failover to regular
     * processing at smb_ReceiveTran2SearchDir(), we shouldn't
     * modify any of the input parameters here. */
    attribute = p->parmsp[0];
    maxCount = p->parmsp[1];
    infoLevel = p->parmsp[3];
    searchFlags = p->parmsp[2];
    pathp = smb_ParseStringT2Parm(p, (char *) &(p->parmsp[6]), NULL, SMB_STRF_ANSIPATH);
    nextCookie = 0;
    maskp = cm_ClientStrRChr(pathp,  '\\');
    if (maskp == NULL)
	maskp = pathp;
    else
	maskp++;	/* skip over backslash */
    /* track if this is likely to match a lot of entries */

    osi_Log2(smb_logp, "smb_T2SearchDirSingle : path[%S], mask[%S]",
             osi_LogSaveClientString(smb_logp, pathp),
             osi_LogSaveClientString(smb_logp, maskp));

    switch ( infoLevel ) {
    case SMB_INFO_STANDARD:
	s = "InfoStandard";
        ohbytes = sizeof(fp->u.FstandardInfo);
    	break;

    case SMB_INFO_QUERY_EA_SIZE:
        ohbytes = sizeof(fp->u.FeaSizeInfo);
	s = "InfoQueryEaSize";
    	break;

    case SMB_INFO_QUERY_EAS_FROM_LIST:
        ohbytes = sizeof(fp->u.FeasFromListInfo);
	s = "InfoQueryEasFromList";
    	break;

    case SMB_FIND_FILE_DIRECTORY_INFO:
	s = "FindFileDirectoryInfo";
        ohbytes = sizeof(fp->u.FfileDirectoryInfo);
    	break;

    case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
	s = "FindFileFullDirectoryInfo";
        ohbytes = sizeof(fp->u.FfileFullDirectoryInfo);
    	break;

    case SMB_FIND_FILE_NAMES_INFO:
	s = "FindFileNamesInfo";
        ohbytes = sizeof(fp->u.FfileNamesInfo);
    	break;

    case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
	s = "FindFileBothDirectoryInfo";
        ohbytes = sizeof(fp->u.FfileBothDirectoryInfo);
    	break;

    default:
	s = "unknownInfoLevel";
        ohbytes = 0;
    }

    osi_Log1(smb_logp, "smb_T2SearchDirSingle info level: %s", s);

    osi_Log4(smb_logp,
             "smb_T2SearchDirSingle attr 0x%x, info level 0x%x, max count %d, flags 0x%x",
             attribute, infoLevel, maxCount, searchFlags);

    if (ohbytes == 0) {
        osi_Log1(smb_logp, "Unsupported InfoLevel 0x%x", infoLevel);
        return CM_ERROR_INVAL;
    }

    if (infoLevel >= SMB_FIND_FILE_DIRECTORY_INFO)
        searchFlags &= ~TRAN2_FIND_FLAG_RETURN_RESUME_KEYS;	/* no resume keys */

    if (searchFlags & TRAN2_FIND_FLAG_RETURN_RESUME_KEYS)
        ohbytes += 4;

    dirListPatchesp = NULL;

    maxReturnData = p->maxReturnData;
    maxReturnParms = 10;	/* return params for findfirst, which
                                   is the only one we handle.*/

    outp = smb_GetTran2ResponsePacket(vcp, p, opx, maxReturnParms,
                                      maxReturnData);

    osi_Log2(smb_logp, "T2SDSingle search dir count %d [%S]",
             maxCount, osi_LogSaveClientString(smb_logp, pathp));

    /* bail out if request looks bad */
    if (!pathp) {
        smb_FreeTran2Packet(outp);
        return CM_ERROR_BADSMB;
    }

    userp = smb_GetTran2User(vcp, p);
    if (!userp) {
    	osi_Log1(smb_logp, "T2SDSingle search dir unable to resolve user [%d]", p->uid);
    	smb_FreeTran2Packet(outp);
    	return CM_ERROR_BADSMB;
    }

    /* try to get the vnode for the path name next */
    spacep = cm_GetSpace();
    /* smb_StripLastComponent will strip "::$DATA" if present */
    smb_StripLastComponent(spacep->wdata, NULL, pathp);
    code = smb_LookupTIDPath(vcp, p->tid, &tidPathp);
    if (code) {
        cm_ReleaseUser(userp);
        smb_SendTran2Error(vcp, p, opx, CM_ERROR_NOFILES);
        smb_FreeTran2Packet(outp);
        return 0;
    }

    code = cm_NameI(cm_RootSCachep(userp, &req), spacep->wdata,
                    CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                    userp, tidPathp, &req, &scp);
    cm_FreeSpace(spacep);

    if (code) {
        cm_ReleaseUser(userp);
	smb_SendTran2Error(vcp, p, opx, code);
        smb_FreeTran2Packet(outp);
        return 0;
    }

#ifdef DFS_SUPPORT_BUT_NOT_FIND_FIRST
    if (scp->fileType == CM_SCACHETYPE_DFSLINK) {
        int pnc = cm_VolStatus_Notify_DFS_Mapping(scp, tidPathp, spacep->data);
	cm_ReleaseSCache(scp);
	cm_ReleaseUser(userp);
        if ( WANTS_DFS_PATHNAMES(p) || pnc )
	    code = CM_ERROR_PATH_NOT_COVERED;
	else
	    code = CM_ERROR_NOSUCHPATH;
	smb_SendTran2Error(vcp, p, opx, code);
	smb_FreeTran2Packet(outp);
	return 0;
    }
#endif /* DFS_SUPPORT */
    osi_Log1(smb_logp,"T2SDSingle scp 0x%p", scp);

    afs_ioctl = (cm_ClientStrCmpI(maskp, CM_IOCTL_FILENAME_NOSLASH_W) == 0);

    /*
     * If we are not searching for _._AFS_IOCTL_._, then we need to obtain
     * the target scp.
     */
    if (!afs_ioctl) {
        /* now do a single case sensitive lookup for the file in question */
        code = cm_Lookup(scp, maskp, CM_FLAG_NOMOUNTCHASE, userp, &req, &targetScp);

        /*
         * if a case sensitive match failed, we try a case insensitive
         * one next.
         */
        if (code == CM_ERROR_NOSUCHFILE || code == CM_ERROR_BPLUS_NOMATCH)
            code = cm_Lookup(scp, maskp, CM_FLAG_NOMOUNTCHASE | CM_FLAG_CASEFOLD, userp, &req, &targetScp);

        if (code == 0 && targetScp->fid.vnode == 0) {
            cm_ReleaseSCache(targetScp);
            code = CM_ERROR_NOSUCHFILE;
        }

        if (code) {
            /*
             * if we can't find the directory entry, this block will
             * return CM_ERROR_NOSUCHFILE, which we will pass on to
             * smb_ReceiveTran2SearchDir().
             */
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
            if (code != CM_ERROR_NOSUCHFILE && code != CM_ERROR_BPLUS_NOMATCH) {
                smb_SendTran2Error(vcp, p, opx, code);
                code = 0;
            }
            smb_FreeTran2Packet(outp);
            return code;
        }
    }

    /* now that we have the target in sight, we proceed with filling
       up the return data. */

    op = origOp = outp->datap;
    bytesInBuffer = 0;

    if (searchFlags & TRAN2_FIND_FLAG_RETURN_RESUME_KEYS) {
        /* skip over resume key */
        op += 4;
    }

    fp = (smb_tran2Find_t *) op;

    if (infoLevel == SMB_FIND_FILE_BOTH_DIRECTORY_INFO &&
        cm_shortNames && !cm_Is8Dot3(maskp)) {

        /*
         * Since the _._AFS_IOCTL_._ file does not actually exist
         * we will make up a per directory FID equivalent to the
         * directory vnode and the uniqifier 0.
         */
        if (afs_ioctl) {
            dfid.vnode = htonl(scp->fid.vnode);
            dfid.unique = htonl(0);
        } else {
            dfid.vnode = htonl(targetScp->fid.vnode);
            dfid.unique = htonl(targetScp->fid.unique);
        }

        cm_Gen8Dot3NameIntW(maskp, &dfid, shortName, &shortNameEnd);
        NeedShortName = 1;
    } else {
        NeedShortName = 0;
    }

    osi_Log4(smb_logp, "T2SDSingle dir vn %u uniq %u name %S (%S)",
             ntohl(dfid.vnode),
             ntohl(dfid.unique),
             osi_LogSaveClientString(smb_logp, pathp),
             (NeedShortName)? osi_LogSaveClientString(smb_logp, shortName) : _C(""));

    /* Eliminate entries that don't match requested attributes */
    if (smb_hideDotFiles && !(attribute & SMB_ATTR_HIDDEN) &&
        smb_IsDotFile(maskp)) {

        code = CM_ERROR_NOSUCHFILE;
        osi_Log0(smb_logp, "T2SDSingle skipping hidden file");
        goto skip_file;

    }

    if (!(attribute & SMB_ATTR_DIRECTORY) &&
        !afs_ioctl &&
        (targetScp->fileType == CM_SCACHETYPE_DIRECTORY ||
         targetScp->fileType == CM_SCACHETYPE_MOUNTPOINT ||
         targetScp->fileType == CM_SCACHETYPE_DFSLINK ||
         targetScp->fileType == CM_SCACHETYPE_INVALID)) {

        code = CM_ERROR_NOSUCHFILE;
        osi_Log0(smb_logp, "T2SDSingle skipping directory or bad link");
        goto skip_file;

    }

    /* add header to name & term. null */
    onbytes = 0;
    smb_UnparseString(opx, NULL, maskp, &onbytes, SMB_STRF_ANSIPATH|SMB_STRF_IGNORENUL);
    orbytes = ohbytes + onbytes;

    /* now, we round up the record to a 4 byte alignment, and we make
     * sure that we have enough room here for even the aligned version
     * (so we don't have to worry about an * overflow when we pad
     * things out below).  That's the reason for the alignment
     * arithmetic below.
     */
    if (infoLevel >= SMB_FIND_FILE_DIRECTORY_INFO)
        align = (4 - (orbytes & 3)) & 3;
    else
        align = 0;

    if (orbytes + align > maxReturnData) {

        /* even though this request is unlikely to succeed with a
           failover, we do it anyway. */
        code = CM_ERROR_NOSUCHFILE;
        osi_Log1(smb_logp, "T2 dir search exceed max return data %d",
                 maxReturnData);
        goto skip_file;
    }

    /* this is one of the entries to use: it is not deleted and it
     * matches the star pattern we're looking for.  Put out the name,
     * preceded by its length.
     */
    /* First zero everything else */
    memset(origOp, 0, orbytes);

    onbytes = 0;
    smb_UnparseString(opx, origOp + ohbytes, maskp, &onbytes, SMB_STRF_ANSIPATH|SMB_STRF_IGNORENUL);

    switch (infoLevel) {
    case SMB_INFO_STANDARD:
        fp->u.FstandardInfo.fileNameLength = onbytes;
        attrp = &fp->u.FstandardInfo.fileAttrs;
        break;

    case SMB_INFO_QUERY_EA_SIZE:
        fp->u.FeaSizeInfo.fileNameLength = onbytes;
        attrp = &fp->u.FeaSizeInfo.fileAttrs;
        fp->u.FeaSizeInfo.eaSize = 0;
        break;

    case SMB_INFO_QUERY_EAS_FROM_LIST:
        fp->u.FeasFromListInfo.fileNameLength = onbytes;
        attrp = &fp->u.FeasFromListInfo.fileAttrs;
        fp->u.FeasFromListInfo.eaSize = 0;
        break;

    case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
        if (NeedShortName) {
#ifdef SMB_UNICODE
            int nchars;

            nchars = cm_ClientStringToUtf16(shortName, cm_ClientStrLen(shortName),
                                            fp->u.FfileBothDirectoryInfo.shortName,
                                            sizeof(fp->u.FfileBothDirectoryInfo.shortName)/sizeof(wchar_t));
            if (nchars > 0)
                fp->u.FfileBothDirectoryInfo.shortNameLength = nchars*sizeof(wchar_t);
            else
                fp->u.FfileBothDirectoryInfo.shortNameLength = 0;
            fp->u.FfileBothDirectoryInfo.reserved = 0;
#else
            strcpy(fp->u.FfileBothDirectoryInfo.shortName,
                   shortName);
            fp->u.FfileBothDirectoryInfo.shortNameLength = cm_ClientStrLen(shortName);
#endif
    }
        /* Fallthrough */

    case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
        fp->u.FfileFullDirectoryInfo.eaSize = 0;
        /* Fallthrough */

    case SMB_FIND_FILE_DIRECTORY_INFO:
        fp->u.FfileDirectoryInfo.nextEntryOffset = 0;
        fp->u.FfileDirectoryInfo.fileIndex = 0;
        attrp = &fp->u.FfileDirectoryInfo.fileAttrs;
        fp->u.FfileDirectoryInfo.fileNameLength = onbytes;
        break;

    case SMB_FIND_FILE_NAMES_INFO:
        fp->u.FfileNamesInfo.nextEntryOffset = 0;
        fp->u.FfileNamesInfo.fileIndex = 0;
        fp->u.FfileNamesInfo.fileNameLength = onbytes;
        break;

    default:
        /* we shouldn't hit this case */
        osi_assertx(FALSE, "Unknown query type");
    }

    if (infoLevel != SMB_FIND_FILE_NAMES_INFO) {
        osi_assert(attrp != NULL);

        curPatchp = malloc(sizeof(*curPatchp));
        osi_QAdd((osi_queue_t **) &dirListPatchesp,
                 &curPatchp->q);
        curPatchp->dptr = attrp;

        if (smb_hideDotFiles && smb_IsDotFile(maskp)) {
            curPatchp->flags = SMB_DIRLISTPATCH_DOTFILE;
        } else {
            curPatchp->flags = 0;
        }

        /* temp */
        {
            int namelen = cm_ClientStringToFsString(maskp, -1, NULL, 0);
            dep = (cm_dirEntry_t *)malloc(sizeof(cm_dirEntry_t)+namelen);
            cm_ClientStringToFsString(maskp, -1, dep->name, namelen);
        }

        if (afs_ioctl) {
            cm_SetFid(&curPatchp->fid, scp->fid.cell, scp->fid.volume, scp->fid.vnode, 0);
            dep->fid.vnode = scp->fid.vnode;
            dep->fid.unique = 0;
            curPatchp->flags |= SMB_DIRLISTPATCH_IOCTL;
        } else {
            cm_SetFid(&curPatchp->fid, targetScp->fid.cell, targetScp->fid.volume, targetScp->fid.vnode, targetScp->fid.unique);
            dep->fid.vnode = targetScp->fid.vnode;
            dep->fid.unique = targetScp->fid.unique;
        }

        curPatchp->dep = dep;
    }

    if (searchFlags & TRAN2_FIND_FLAG_RETURN_RESUME_KEYS) {
        /* put out resume key */
        *((u_long *)origOp) = 0;
    }

    /* Adjust byte ptr and count */
    origOp += orbytes;	/* skip entire record */
    bytesInBuffer += orbytes;

    /* and pad the record out */
    while (--align >= 0) {
        *origOp++ = 0;
        bytesInBuffer++;
    }

    /* apply the patches */
    code2 = smb_ApplyV3DirListPatches(scp, &dirListPatchesp, tidPathp, spacep->wdata, infoLevel, userp, &req);

    outp->parmsp[0] = 0;
    outp->parmsp[1] = 1;        /* number of names returned */
    outp->parmsp[2] = 1;        /* end of search */
    outp->parmsp[3] = 0;        /* nothing wrong with EAS */
    outp->parmsp[4] = 0;

    outp->totalParms = 10;      /* in bytes */

    outp->totalData = bytesInBuffer;

    osi_Log0(smb_logp, "T2SDSingle done.");

    if (code != CM_ERROR_NOSUCHFILE && code != CM_ERROR_BPLUS_NOMATCH) {
	if (code)
	    smb_SendTran2Error(vcp, p, opx, code);
	else
	    smb_SendTran2Packet(vcp, outp, opx);
	code = 0;
    }

 skip_file:
    smb_FreeTran2Packet(outp);
    if (dep)
        free(dep);
    if (scp)
        cm_ReleaseSCache(scp);
    if (targetScp)
        cm_ReleaseSCache(targetScp);
    cm_ReleaseUser(userp);

    return code;
}


/* TRANS2_FIND_FIRST2 and TRANS2_FIND_NEXT2 */
long smb_ReceiveTran2SearchDir(smb_vc_t *vcp, smb_tran2Packet_t *p, smb_packet_t *opx)
{
    int attribute;
    long nextCookie;
    char *tp;
    long code = 0, code2 = 0;
    clientchar_t *pathp;
    cm_dirEntry_t *dep = 0;
    int maxCount;
    smb_dirListPatch_t *dirListPatchesp = 0;
    smb_dirListPatch_t *curPatchp = 0;
    cm_buf_t *bufferp;
    long temp;
    size_t orbytes;			/* # of bytes in this output record */
    size_t ohbytes;			/* # of bytes, except file name */
    size_t onbytes;			/* # of bytes in name, incl. term. null */
    osi_hyper_t dirLength;
    osi_hyper_t bufferOffset;
    osi_hyper_t curOffset;
    osi_hyper_t thyper;
    smb_dirSearch_t *dsp;
    cm_scache_t *scp;
    long entryInDir;
    long entryInBuffer;
    cm_pageHeader_t *pageHeaderp;
    cm_user_t *userp = NULL;
    int slotInPage;
    int returnedNames;
    long nextEntryCookie;
    int numDirChunks;		/* # of 32 byte dir chunks in this entry */
    char *op;			/* output data ptr */
    char *origOp;			/* original value of op */
    cm_space_t *spacep;		/* for pathname buffer */
    unsigned long maxReturnData;		/* max # of return data */
    unsigned long maxReturnParms;		/* max # of return parms */
    long bytesInBuffer;		/* # data bytes in the output buffer */
    int starPattern;
    clientchar_t *maskp;			/* mask part of path */
    int infoLevel;
    int searchFlags;
    int eos;
    smb_tran2Packet_t *outp;	/* response packet */
    clientchar_t *tidPathp;
    unsigned int align;
    clientchar_t shortName[13];		/* 8.3 name if needed */
    int NeedShortName;
    int foundInexact;
    clientchar_t *shortNameEnd;
    int fileType;
    cm_fid_t fid;
    cm_req_t req;
    void * attrp;
    char * s;
    smb_tran2Find_t * fp;

    smb_InitReq(&req);

    eos = 0;
    if (p->opcode == 1) {
        /* find first; obtain basic parameters from request */
        attribute = p->parmsp[0];
        maxCount = p->parmsp[1];
        infoLevel = p->parmsp[3];
        searchFlags = p->parmsp[2];
        pathp = smb_ParseStringT2Parm(p, (char *) (&p->parmsp[6]), NULL, SMB_STRF_ANSIPATH);
        nextCookie = 0;
        maskp = cm_ClientStrRChr(pathp,  '\\');
        if (maskp == NULL)
            maskp = pathp;
        else
            maskp++;	/* skip over backslash */

        /* track if this is likely to match a lot of entries */
        starPattern = smb_V3IsStarMask(maskp);

#ifndef NOFINDFIRSTOPTIMIZE
        if (!starPattern) {
            /* if this is for a single directory or file, we let the
               optimized routine handle it.  The only error it
	       returns is CM_ERROR_NOSUCHFILE.  The  */
            code = smb_T2SearchDirSingle(vcp, p, opx);

            /* we only failover if we see a CM_ERROR_NOSUCHFILE */
            if (code != CM_ERROR_NOSUCHFILE) {
#ifdef USE_BPLUS
                /* unless we are using the BPlusTree */
                if (code == CM_ERROR_BPLUS_NOMATCH)
                    code = CM_ERROR_NOSUCHFILE;
#endif /* USE_BPLUS */
                return code;
            }
        }
#endif  /* NOFINDFIRSTOPTIMIZE */
        dir_enums++;

        dsp = smb_NewDirSearch(1);
        dsp->attribute = attribute;
        cm_ClientStrCpy(dsp->mask, lengthof(dsp->mask),  maskp);	/* and save mask */
    }
    else {
        osi_assertx(p->opcode == 2, "invalid opcode");
        /* find next; obtain basic parameters from request or open dir file */
        dsp = smb_FindDirSearch(p->parmsp[0]);
        maxCount = p->parmsp[1];
        infoLevel = p->parmsp[2];
        nextCookie = p->parmsp[3] | (p->parmsp[4] << 16);
        searchFlags = p->parmsp[5];
        if (!dsp) {
            osi_Log2(smb_logp, "T2 search dir bad search ID: id %d nextCookie 0x%x",
                     p->parmsp[0], nextCookie);
            return CM_ERROR_BADFD;
        }
        attribute = dsp->attribute;
        pathp = NULL;
        maskp = dsp->mask;
        starPattern = 1;	/* assume, since required a Find Next */
    }

    switch ( infoLevel ) {
    case SMB_INFO_STANDARD:
	s = "InfoStandard";
        ohbytes = sizeof(fp->u.FstandardInfo);
    	break;

    case SMB_INFO_QUERY_EA_SIZE:
        ohbytes = sizeof(fp->u.FeaSizeInfo);
	s = "InfoQueryEaSize";
    	break;

    case SMB_INFO_QUERY_EAS_FROM_LIST:
        ohbytes = sizeof(fp->u.FeasFromListInfo);
	s = "InfoQueryEasFromList";
    	break;

    case SMB_FIND_FILE_DIRECTORY_INFO:
	s = "FindFileDirectoryInfo";
        ohbytes = sizeof(fp->u.FfileDirectoryInfo);
    	break;

    case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
	s = "FindFileFullDirectoryInfo";
        ohbytes = sizeof(fp->u.FfileFullDirectoryInfo);
    	break;

    case SMB_FIND_FILE_NAMES_INFO:
	s = "FindFileNamesInfo";
        ohbytes = sizeof(fp->u.FfileNamesInfo);
    	break;

    case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
	s = "FindFileBothDirectoryInfo";
        ohbytes = sizeof(fp->u.FfileBothDirectoryInfo);
    	break;

    default:
	s = "unknownInfoLevel";
        ohbytes = 0;
    }

    osi_Log1(smb_logp, "T2 search dir info level: %s", s);

    osi_Log4(smb_logp,
              "T2 search dir attr 0x%x, info level 0x%x, max count %d, flags 0x%x",
              attribute, infoLevel, maxCount, searchFlags);

    osi_Log3(smb_logp, "...T2 search op %d, id %d, nextCookie 0x%x",
              p->opcode, dsp->cookie, nextCookie);

    if (ohbytes == 0) {
        osi_Log1(smb_logp, "Unsupported InfoLevel 0x%x", infoLevel);
        smb_ReleaseDirSearch(dsp);
        return CM_ERROR_INVAL;
    }

    if (infoLevel >= SMB_FIND_FILE_DIRECTORY_INFO)
        searchFlags &= ~TRAN2_FIND_FLAG_RETURN_RESUME_KEYS;	/* no resume keys */

    if (searchFlags & TRAN2_FIND_FLAG_RETURN_RESUME_KEYS)
        ohbytes += 4;

    dirListPatchesp = NULL;

    maxReturnData = p->maxReturnData;
    if (p->opcode == 1)	/* find first */
        maxReturnParms = 10;	/* bytes */
    else
        maxReturnParms = 8;	/* bytes */

    outp = smb_GetTran2ResponsePacket(vcp, p, opx, maxReturnParms,
                                      maxReturnData);

    if (maxCount > 500)
        maxCount = 500;

    osi_Log2(smb_logp, "T2 receive search dir count %d [%S]",
             maxCount, osi_LogSaveClientString(smb_logp, pathp));

    /* bail out if request looks bad */
    if (p->opcode == 1 && !pathp) {
        smb_ReleaseDirSearch(dsp);
        smb_FreeTran2Packet(outp);
        return CM_ERROR_BADSMB;
    }

    osi_Log3(smb_logp, "T2 search dir id %d, nextCookie 0x%x, attr 0x%x",
             dsp->cookie, nextCookie, attribute);

    userp = smb_GetTran2User(vcp, p);
    if (!userp) {
    	osi_Log1(smb_logp, "T2 search dir unable to resolve user [%d]", p->uid);
    	smb_ReleaseDirSearch(dsp);
    	smb_FreeTran2Packet(outp);
    	return CM_ERROR_BADSMB;
    }

    /* try to get the vnode for the path name next */
    lock_ObtainMutex(&dsp->mx);
    if (dsp->scp) {
        scp = dsp->scp;
	osi_Log2(smb_logp,"smb_ReceiveTran2SearchDir dsp 0x%p scp 0x%p", dsp, scp);
        cm_HoldSCache(scp);
        code = 0;
    } else {
        spacep = cm_GetSpace();
        /* smb_StripLastComponent will strip "::$DATA" if present */
        smb_StripLastComponent(spacep->wdata, NULL, pathp);
        code = smb_LookupTIDPath(vcp, p->tid, &tidPathp);
        if (code) {
            cm_ReleaseUser(userp);
            smb_SendTran2Error(vcp, p, opx, CM_ERROR_NOFILES);
            smb_FreeTran2Packet(outp);
            lock_ReleaseMutex(&dsp->mx);
            smb_DeleteDirSearch(dsp);
            smb_ReleaseDirSearch(dsp);
            return 0;
        }

        cm_ClientStrCpy(dsp->tidPath, lengthof(dsp->tidPath), tidPathp ? tidPathp : _C("/"));
        cm_ClientStrCpy(dsp->relPath, lengthof(dsp->relPath), spacep->wdata);

        code = cm_NameI(cm_RootSCachep(userp, &req), spacep->wdata,
                        CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                        userp, tidPathp, &req, &scp);
        cm_FreeSpace(spacep);

        if (code == 0) {
#ifdef DFS_SUPPORT_BUT_NOT_FIND_FIRST
            if (scp->fileType == CM_SCACHETYPE_DFSLINK) {
                int pnc = cm_VolStatus_Notify_DFS_Mapping(scp, tidPathp, spacep->data);
                cm_ReleaseSCache(scp);
                cm_ReleaseUser(userp);
                if ( WANTS_DFS_PATHNAMES(p) || pnc )
                    code = CM_ERROR_PATH_NOT_COVERED;
                else
                    code = CM_ERROR_NOSUCHPATH;
                smb_SendTran2Error(vcp, p, opx, code);
                smb_FreeTran2Packet(outp);
                lock_ReleaseMutex(&dsp->mx);
                smb_DeleteDirSearch(dsp);
                smb_ReleaseDirSearch(dsp);
                return 0;
            }
#endif /* DFS_SUPPORT */
            dsp->scp = scp;
	    osi_Log2(smb_logp,"smb_ReceiveTran2SearchDir dsp 0x%p scp 0x%p", dsp, scp);
            /* we need one hold for the entry we just stored into,
             * and one for our own processing.  When we're done
             * with this function, we'll drop the one for our own
             * processing.  We held it once from the namei call,
             * and so we do another hold now.
             */
            cm_HoldSCache(scp);
            dsp->flags |= SMB_DIRSEARCH_BULKST;
        }
    }
    lock_ReleaseMutex(&dsp->mx);
    if (code) {
        cm_ReleaseUser(userp);
        smb_FreeTran2Packet(outp);
        smb_DeleteDirSearch(dsp);
        smb_ReleaseDirSearch(dsp);
        return code;
    }

    /* get the directory size */
    lock_ObtainWrite(&scp->rw);
    code = cm_SyncOp(scp, NULL, userp, &req, 0,
                     CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    if (code) {
        lock_ReleaseWrite(&scp->rw);
        cm_ReleaseSCache(scp);
        cm_ReleaseUser(userp);
        smb_FreeTran2Packet(outp);
        smb_DeleteDirSearch(dsp);
        smb_ReleaseDirSearch(dsp);
        return code;
    }

    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);

  startsearch:
    dirLength = scp->length;
    bufferp = NULL;
    bufferOffset.LowPart = bufferOffset.HighPart = 0;
    curOffset.HighPart = 0;
    curOffset.LowPart = nextCookie;
    origOp = outp->datap;

    foundInexact = 0;
    code = 0;
    returnedNames = 0;
    bytesInBuffer = 0;
    while (1) {
        normchar_t normName[MAX_PATH]; /* Normalized name */
        clientchar_t cfileName[MAX_PATH]; /* Non-normalized name */

        op = origOp;
        if (searchFlags & TRAN2_FIND_FLAG_RETURN_RESUME_KEYS)
            /* skip over resume key */
            op += 4;

        fp = (smb_tran2Find_t *) op;

        /* make sure that curOffset.LowPart doesn't point to the first
         * 32 bytes in the 2nd through last dir page, and that it doesn't
         * point at the first 13 32-byte chunks in the first dir page,
         * since those are dir and page headers, and don't contain useful
         * information.
         */
        temp = curOffset.LowPart & (2048-1);
        if (curOffset.HighPart == 0 && curOffset.LowPart < 2048) {
            /* we're in the first page */
            if (temp < 13*32) temp = 13*32;
        }
        else {
            /* we're in a later dir page */
            if (temp < 32) temp = 32;
        }

        /* make sure the low order 5 bits are zero */
        temp &= ~(32-1);

        /* now put temp bits back ito curOffset.LowPart */
        curOffset.LowPart &= ~(2048-1);
        curOffset.LowPart |= temp;

        /* check if we've passed the dir's EOF */
        if (LargeIntegerGreaterThanOrEqualTo(curOffset, dirLength)) {
            osi_Log0(smb_logp, "T2 search dir passed eof");
            eos = 1;
            break;
        }

        /* check if we've returned all the names that will fit in the
         * response packet; we check return count as well as the number
         * of bytes requested.  We check the # of bytes after we find
         * the dir entry, since we'll need to check its size.
         */
        if (returnedNames >= maxCount) {
            osi_Log2(smb_logp, "T2 search dir returnedNames %d >= maxCount %d",
                      returnedNames, maxCount);
            break;
        }

        /* when we have obtained as many entries as can be processed in
         * a single Bulk Status call to the file server, apply the dir listing
         * patches.
         */
        if (returnedNames > 0 && returnedNames % AFSCBMAX == 0) {
            lock_ReleaseWrite(&scp->rw);
            code2 = smb_ApplyV3DirListPatches(scp, &dirListPatchesp, dsp->tidPath,
                                               dsp->relPath, infoLevel, userp, &req);
            lock_ObtainWrite(&scp->rw);
        }
        /* Then check to see if we have time left to process more entries */
        if (GetTickCount() - req.startTime > (RDRtimeout - 15) * 1000) {
            osi_Log0(smb_logp, "T2 search dir RDRtimeout exceeded");
            break;
        }

        /* see if we can use the bufferp we have now; compute in which
         * page the current offset would be, and check whether that's
         * the offset of the buffer we have.  If not, get the buffer.
         */
        thyper.HighPart = curOffset.HighPart;
        thyper.LowPart = curOffset.LowPart & ~(cm_data.buf_blockSize-1);
        if (!bufferp || !LargeIntegerEqualTo(thyper, bufferOffset)) {
            /* wrong buffer */
            if (bufferp) {
                buf_Release(bufferp);
                bufferp = NULL;
            }
            lock_ReleaseWrite(&scp->rw);
            code = buf_Get(scp, &thyper, &req, 0, &bufferp);
            lock_ObtainWrite(&scp->rw);
            if (code) {
                osi_Log2(smb_logp, "T2 search dir buf_Get scp %x failed %d", scp, code);
                break;
            }

            bufferOffset = thyper;

            /* now get the data in the cache */
            while (1) {
                code = cm_SyncOp(scp, bufferp, userp, &req,
                                 PRSFS_LOOKUP,
                                 CM_SCACHESYNC_NEEDCALLBACK
                                 | CM_SCACHESYNC_READ);
                if (code) {
                    osi_Log2(smb_logp, "T2 search dir cm_SyncOp scp %x failed %d", scp, code);
                    break;
                }

                if (cm_HaveBuffer(scp, bufferp, 0)) {
                    osi_Log2(smb_logp, "T2 search dir !HaveBuffer scp %x bufferp %x", scp, bufferp);
                    cm_SyncOpDone(scp, bufferp, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_READ);
                    break;
                }

                /* otherwise, load the buffer and try again */
                code = cm_GetBuffer(scp, bufferp, NULL, userp,
                                    &req);
		cm_SyncOpDone(scp, bufferp, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_READ);
                if (code) {
                    osi_Log3(smb_logp, "T2 search dir cm_GetBuffer failed scp %x bufferp %x code %d",
                              scp, bufferp, code);
                    break;
                }
            }
            if (code) {
                buf_Release(bufferp);
                bufferp = NULL;
                break;
            }
        }	/* if (wrong buffer) ... */

        /* now we have the buffer containing the entry we're interested
         * in; copy it out if it represents a non-deleted entry.
         */
        entryInDir = curOffset.LowPart & (2048-1);
        entryInBuffer = curOffset.LowPart & (cm_data.buf_blockSize - 1);

        /* page header will help tell us which entries are free.  Page
         * header can change more often than once per buffer, since
         * AFS 3 dir page size may be less than (but not more than)
         * a buffer package buffer.
         */
        /* only look intra-buffer */
        temp = curOffset.LowPart & (cm_data.buf_blockSize - 1);
        temp &= ~(2048 - 1);	/* turn off intra-page bits */
        pageHeaderp = (cm_pageHeader_t *) (bufferp->datap + temp);

        /* now determine which entry we're looking at in the page.
         * If it is free (there's a free bitmap at the start of the
         * dir), we should skip these 32 bytes.
         */
        slotInPage = (entryInDir & 0x7e0) >> 5;
        if (!(pageHeaderp->freeBitmap[slotInPage>>3] &
            (1 << (slotInPage & 0x7)))) {
            /* this entry is free */
            numDirChunks = 1;	/* only skip this guy */
            goto nextEntry;
        }

        tp = bufferp->datap + entryInBuffer;
        dep = (cm_dirEntry_t *) tp;	/* now points to AFS3 dir entry */

        /* while we're here, compute the next entry's location, too,
         * since we'll need it when writing out the cookie into the dir
         * listing stream.
         *
         * XXXX Probably should do more sanity checking.
         */
        numDirChunks = cm_NameEntries(dep->name, &onbytes);

        /* compute offset of cookie representing next entry */
        nextEntryCookie = curOffset.LowPart + (CM_DIR_CHUNKSIZE * numDirChunks);

        if (dep->fid.vnode == 0)
            goto nextEntry;             /* This entry is not in use */

        if (cm_FsStringToClientString(dep->name, -1, cfileName, lengthof(cfileName)) == 0 ||
            cm_ClientStringToNormString(cfileName, -1, normName, lengthof(normName)) == 0) {

            osi_Log1(smb_logp, "Skipping entry [%s].  Can't convert or normalize FS String",
                     osi_LogSaveString(smb_logp, dep->name));
            goto nextEntry;
        }

        /* Need 8.3 name? */
        NeedShortName = 0;
        if (infoLevel == SMB_FIND_FILE_BOTH_DIRECTORY_INFO &&
            cm_shortNames &&
            !cm_Is8Dot3(cfileName)) {
            cm_Gen8Dot3Name(dep, shortName, &shortNameEnd);
            NeedShortName = 1;
        }

        osi_Log4(smb_logp, "T2 search dir vn %u uniq %u name %S (%S)",
                 dep->fid.vnode, dep->fid.unique,
                 osi_LogSaveClientString(smb_logp, cfileName),
                 NeedShortName ? osi_LogSaveClientString(smb_logp, shortName) : _C(""));

        /* When matching, we are using doing a case fold if we have a wildcard mask.
         * If we get a non-wildcard match, it's a lookup for a specific file.
         */
        if (cm_MatchMask(normName, maskp, (starPattern? CM_FLAG_CASEFOLD : 0)) ||
            (NeedShortName && cm_MatchMask(shortName, maskp, CM_FLAG_CASEFOLD)))
        {
            /* Eliminate entries that don't match requested attributes */
            if (smb_hideDotFiles && !(dsp->attribute & SMB_ATTR_HIDDEN) &&
                smb_IsDotFile(cfileName)) {
                osi_Log0(smb_logp, "T2 search dir skipping hidden");
                goto nextEntry; /* no hidden files */
            }

            if (!(dsp->attribute & SMB_ATTR_DIRECTORY))  /* no directories */
            {
                /* We have already done the cm_TryBulkStat above */
                cm_SetFid(&fid, scp->fid.cell, scp->fid.volume,
                          ntohl(dep->fid.vnode), ntohl(dep->fid.unique));
                fileType = cm_FindFileType(&fid);
                /* osi_Log2(smb_logp, "smb_ReceiveTran2SearchDir: file %s "
                 * "has filetype %d", dep->name, fileType);
                 */
                if ( fileType == CM_SCACHETYPE_DIRECTORY ||
                     fileType == CM_SCACHETYPE_MOUNTPOINT ||
                     fileType == CM_SCACHETYPE_DFSLINK ||
                     fileType == CM_SCACHETYPE_INVALID)
                    osi_Log0(smb_logp, "T2 search dir skipping directory or bad link");
                goto nextEntry;
            }

            /* finally check if this name will fit */
            onbytes = 0;
            smb_UnparseString(opx, NULL, cfileName, &onbytes, SMB_STRF_ANSIPATH|SMB_STRF_IGNORENUL);
            orbytes = ohbytes + onbytes;

            /* now, we round up the record to a 4 byte alignment,
             * and we make sure that we have enough room here for
             * even the aligned version (so we don't have to worry
             * about an overflow when we pad things out below).
             * That's the reason for the alignment arithmetic below.
             */
            if (infoLevel >= SMB_FIND_FILE_DIRECTORY_INFO)
                align = (4 - (orbytes & 3)) & 3;
            else
                align = 0;

            if (orbytes + bytesInBuffer + align > maxReturnData) {
                osi_Log1(smb_logp, "T2 dir search exceed max return data %d",
                         maxReturnData);
                break;
            }

            /* this is one of the entries to use: it is not deleted
             * and it matches the star pattern we're looking for.
             * Put out the name, preceded by its length.
             */
            /* First zero everything else */
            memset(origOp, 0, orbytes);

            onbytes = 0;
            smb_UnparseString(opx, origOp + ohbytes, cfileName, &onbytes, SMB_STRF_ANSIPATH|SMB_STRF_IGNORENUL);

            switch (infoLevel) {
            case SMB_INFO_STANDARD:
                fp->u.FstandardInfo.fileNameLength = onbytes;
                attrp = &fp->u.FstandardInfo.fileAttrs;
                break;

            case SMB_INFO_QUERY_EA_SIZE:
                fp->u.FeaSizeInfo.fileNameLength = onbytes;
                attrp = &fp->u.FeaSizeInfo.fileAttrs;
                fp->u.FeaSizeInfo.eaSize = 0;
                break;

            case SMB_INFO_QUERY_EAS_FROM_LIST:
                fp->u.FeasFromListInfo.fileNameLength = onbytes;
                attrp = &fp->u.FeasFromListInfo.fileAttrs;
                fp->u.FeasFromListInfo.eaSize = 0;
                break;

            case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
                if (NeedShortName) {
#ifdef SMB_UNICODE
                    int nchars;

                    nchars = cm_ClientStringToUtf16(shortName, cm_ClientStrLen(shortName),
                                                    fp->u.FfileBothDirectoryInfo.shortName,
                                                    sizeof(fp->u.FfileBothDirectoryInfo.shortName)/sizeof(wchar_t));
                    if (nchars > 0)
                        fp->u.FfileBothDirectoryInfo.shortNameLength = nchars*sizeof(wchar_t);
                    else
                        fp->u.FfileBothDirectoryInfo.shortNameLength = 0;
                    fp->u.FfileBothDirectoryInfo.reserved = 0;
#else
                    cm_ClientStrCpy(fp->u.FfileBothDirectoryInfo.shortName,
                                    lengthof(fp->u.FfileBothDirectoryInfo.shortName),
                                    shortName);
                    fp->u.FfileBothDirectoryInfo.shortNameLength = cm_ClientStrLen(shortName);
#endif
                }
                /* Fallthrough */

            case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
                fp->u.FfileFullDirectoryInfo.eaSize = 0;
                /* Fallthrough */

            case SMB_FIND_FILE_DIRECTORY_INFO:
                fp->u.FfileDirectoryInfo.nextEntryOffset = orbytes + align;
                fp->u.FfileDirectoryInfo.fileIndex = nextEntryCookie;
                attrp = &fp->u.FfileDirectoryInfo.fileAttrs;
                fp->u.FfileDirectoryInfo.fileNameLength = onbytes;
                break;

            case SMB_FIND_FILE_NAMES_INFO:
                fp->u.FfileNamesInfo.nextEntryOffset = orbytes + align;
                fp->u.FfileNamesInfo.fileIndex = nextEntryCookie;
                fp->u.FfileNamesInfo.fileNameLength = onbytes;
                attrp = NULL;
                break;

            default:
                /* we shouldn't hit this case */
                osi_assertx(FALSE, "Unknown query type");
            }

            /* now, adjust the # of entries copied */
            returnedNames++;

            /* now we emit the attribute.  This is tricky, since
             * we need to really stat the file to find out what
             * type of entry we've got.  Right now, we're copying
             * out data from a buffer, while holding the scp
             * locked, so it isn't really convenient to stat
             * something now.  We'll put in a place holder
             * now, and make a second pass before returning this
             * to get the real attributes.  So, we just skip the
             * data for now, and adjust it later.  We allocate a
             * patch record to make it easy to find this point
             * later.  The replay will happen at a time when it is
             * safe to unlock the directory.
             */
            if (infoLevel != SMB_FIND_FILE_NAMES_INFO) {
                osi_assert(attrp != NULL);
                curPatchp = malloc(sizeof(*curPatchp));
                osi_QAdd((osi_queue_t **) &dirListPatchesp, &curPatchp->q);
                curPatchp->dptr = attrp;

                if (smb_hideDotFiles && smb_IsDotFile(cfileName)) {
                    curPatchp->flags = SMB_DIRLISTPATCH_DOTFILE;
                } else {
                    curPatchp->flags = 0;
                }

                cm_SetFid(&curPatchp->fid, scp->fid.cell, scp->fid.volume, ntohl(dep->fid.vnode), ntohl(dep->fid.unique));

                /* temp */
                curPatchp->dep = dep;
            }

            if (searchFlags & TRAN2_FIND_FLAG_RETURN_RESUME_KEYS)
                /* put out resume key */
                *((u_long *)origOp) = nextEntryCookie;

            /* Adjust byte ptr and count */
            origOp += orbytes;	/* skip entire record */
            bytesInBuffer += orbytes;

            /* and pad the record out */
            while (align-- > 0) {
                *origOp++ = 0;
                bytesInBuffer++;
            }
        }	/* if we're including this name */
        else if (!starPattern &&
                 !foundInexact &&
                 cm_MatchMask(normName, maskp, CM_FLAG_CASEFOLD)) {
            /* We were looking for exact matches, but here's an inexact one*/
            foundInexact = 1;
        }

      nextEntry:
        /* and adjust curOffset to be where the new cookie is */
        thyper.HighPart = 0;
        thyper.LowPart = CM_DIR_CHUNKSIZE * numDirChunks;
        curOffset = LargeIntegerAdd(thyper, curOffset);
    } /* while copying data for dir listing */

    /* If we didn't get a star pattern, we did an exact match during the first pass.
     * If there were no exact matches found, we fail over to inexact matches by
     * marking the query as a star pattern (matches all case permutations), and
     * re-running the query.
     */
    if (returnedNames == 0 && !starPattern && foundInexact) {
        osi_Log0(smb_logp,"T2 Search: No exact matches. Re-running for inexact matches");
        starPattern = 1;
        goto startsearch;
    }

    /* release the mutex */
    lock_ReleaseWrite(&scp->rw);
    if (bufferp) {
        buf_Release(bufferp);
	bufferp = NULL;
    }

    /*
     * Finally, process whatever entries we have left.
     */
    code2 = smb_ApplyV3DirListPatches(scp, &dirListPatchesp, dsp->tidPath,
                                      dsp->relPath, infoLevel, userp, &req);

    /* now put out the final parameters */
    if (returnedNames == 0)
        eos = 1;
    if (p->opcode == 1) {
        /* find first */
        outp->parmsp[0] = (unsigned short) dsp->cookie;
        outp->parmsp[1] = returnedNames;
        outp->parmsp[2] = eos;
        outp->parmsp[3] = 0;		/* nothing wrong with EAS */
        outp->parmsp[4] = 0;
        /* don't need last name to continue
         * search, cookie is enough.  Normally,
         * this is the offset of the file name
         * of the last entry returned.
         */
        outp->totalParms = 10;	/* in bytes */
    }
    else {
        /* find next */
        outp->parmsp[0] = returnedNames;
        outp->parmsp[1] = eos;
        outp->parmsp[2] = 0;	/* EAS error */
        outp->parmsp[3] = 0;	/* last name, as above */
        outp->totalParms = 8;	/* in bytes */
    }

    /* return # of bytes in the buffer */
    outp->totalData = bytesInBuffer;

    /* Return error code if unsuccessful on first request */
    if (code == 0 && p->opcode == 1 && returnedNames == 0)
        code = CM_ERROR_NOSUCHFILE;

    osi_Log4(smb_logp, "T2 search dir done, opcode %d, id %d, %d names, code %d",
             p->opcode, dsp->cookie, returnedNames, code);

    /* if we're supposed to close the search after this request, or if
     * we're supposed to close the search if we're done, and we're done,
     * or if something went wrong, close the search.
     */
    if ((searchFlags & TRAN2_FIND_FLAG_CLOSE_SEARCH) ||
	(returnedNames == 0) ||
        ((searchFlags & TRAN2_FIND_FLAG_CLOSE_SEARCH_IF_END) && eos) ||
	code != 0)
        smb_DeleteDirSearch(dsp);

    if (code)
        smb_SendTran2Error(vcp, p, opx, code);
    else
        smb_SendTran2Packet(vcp, outp, opx);

    smb_FreeTran2Packet(outp);
    smb_ReleaseDirSearch(dsp);
    cm_ReleaseSCache(scp);
    cm_ReleaseUser(userp);
    return 0;
}

/* SMB_COM_FIND_CLOSE2 */
long smb_ReceiveV3FindClose(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    int dirHandle;
    smb_dirSearch_t *dsp;

    dirHandle = smb_GetSMBParm(inp, 0);

    osi_Log1(smb_logp, "SMB3 find close handle %d", dirHandle);

    dsp = smb_FindDirSearch(dirHandle);

    if (!dsp)
        return CM_ERROR_BADFD;

    /* otherwise, we have an FD to destroy */
    smb_DeleteDirSearch(dsp);
    smb_ReleaseDirSearch(dsp);

    /* and return results */
    smb_SetSMBDataLength(outp, 0);

    return 0;
}


/* SMB_COM_FIND_NOTIFY_CLOSE */
long smb_ReceiveV3FindNotifyClose(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    smb_SetSMBDataLength(outp, 0);
    return 0;
}

/* SMB_COM_OPEN_ANDX */
long smb_ReceiveV3OpenX(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    clientchar_t *pathp;
    long code = 0;
    cm_space_t *spacep;
    int excl;
    cm_user_t *userp;
    cm_scache_t *dscp;		/* dir we're dealing with */
    cm_scache_t *scp;		/* file we're creating */
    cm_attr_t setAttr;
    smb_fid_t *fidp;
    int attributes;
    clientchar_t *lastNamep;
    unsigned long dosTime;
    int openFun;
    int trunc;
    int openMode;
    int extraInfo;
    int openAction;
    int parmSlot;			/* which parm we're dealing with */
    clientchar_t *tidPathp;
    cm_req_t req;
    int created = 0;
    BOOL is_rpc = FALSE;
    BOOL is_ipc = FALSE;

    smb_InitReq(&req);

    scp = NULL;

    extraInfo = (smb_GetSMBParm(inp, 2) & 1); /* return extra info */
    openFun = smb_GetSMBParm(inp, 8); /* open function */
    excl = ((openFun & 3) == 0);
    trunc = ((openFun & 3) == 2); /* truncate it */
    openMode = (smb_GetSMBParm(inp, 3) & 0x7);
    openAction = 0;             /* tracks what we did */

    attributes = smb_GetSMBParm(inp, 5);
    dosTime = smb_GetSMBParm(inp, 6) | (smb_GetSMBParm(inp, 7) << 16);

    pathp = smb_ParseASCIIBlock(inp, smb_GetSMBData(inp, NULL), NULL,
                                SMB_STRF_ANSIPATH);
    if (!pathp)
        return CM_ERROR_BADSMB;

    code = smb_LookupTIDPath(vcp, ((smb_t *)inp)->tid, &tidPathp);
    if (code) {
	if (code == CM_ERROR_TIDIPC) {
	    is_ipc = TRUE;
	} else {
	    return CM_ERROR_NOSUCHPATH;
	}
    }

    spacep = inp->spacep;
    /* smb_StripLastComponent will strip "::$DATA" if present */
    smb_StripLastComponent(spacep->wdata, &lastNamep, pathp);

    if (lastNamep &&

        /* special case magic file name for receiving IOCTL requests
         * (since IOCTL calls themselves aren't getting through).
         */
        (cm_ClientStrCmpIA(lastNamep,  _C(SMB_IOCTL_FILENAME)) == 0 ||

	 /* Or an RPC endpoint (is_rpc = TRUE assignment is intentional) */
         (is_ipc && MSRPC_IsWellKnownService(lastNamep) && (is_rpc = TRUE)))) {

	unsigned short file_type = 0;
	unsigned short device_state = 0;

        fidp = smb_FindFID(vcp, 0, SMB_FLAG_CREATE);
	if (is_rpc) {
	    code = smb_SetupRPCFid(fidp, lastNamep, &file_type, &device_state);
	    osi_Log1(smb_logp, "OpenAndX Setting up RPC on fid[%d]", fidp->fid);
	    if (code) {
		osi_Log1(smb_logp, "smb_SetupRPCFid failure code [%d]", code);
		smb_ReleaseFID(fidp);
		return code;
	    }
	} else {
	    smb_SetupIoctlFid(fidp, spacep);
	    osi_Log1(smb_logp, "OpenAndX Setting up IOCTL on fid[%d]", fidp->fid);
	}

        /* set inp->fid so that later read calls in same msg can find fid */
        inp->fid = fidp->fid;

        /* copy out remainder of the parms */
        parmSlot = 2;
        smb_SetSMBParm(outp, parmSlot, fidp->fid); parmSlot++;
        if (extraInfo) {
            smb_SetSMBParm(outp, parmSlot, /* attrs */ 0); parmSlot++;
            smb_SetSMBParm(outp, parmSlot, 0); parmSlot++;	/* mod time */
            smb_SetSMBParm(outp, parmSlot, 0); parmSlot++;
            smb_SetSMBParm(outp, parmSlot, 0); parmSlot++;	/* len */
            smb_SetSMBParm(outp, parmSlot, 0x7fff); parmSlot++;
            smb_SetSMBParm(outp, parmSlot, openMode); parmSlot++;
            smb_SetSMBParm(outp, parmSlot, file_type); parmSlot++;
            smb_SetSMBParm(outp, parmSlot, device_state); parmSlot++;
        }
        /* and the final "always present" stuff */
        smb_SetSMBParm(outp, parmSlot, /* openAction found existing file */ 1); parmSlot++;
        /* next write out the "unique" ID */
        smb_SetSMBParm(outp, parmSlot, 0x1234); parmSlot++;
        smb_SetSMBParm(outp, parmSlot, 0x5678); parmSlot++;
        smb_SetSMBParm(outp, parmSlot, 0); parmSlot++;
        smb_SetSMBDataLength(outp, 0);

        /* and clean up fid reference */
        smb_ReleaseFID(fidp);
        return 0;
    }

#ifndef DFS_SUPPORT
    if (is_ipc) {
	osi_Log0(smb_logp, "NTOpenX rejecting IPC TID");
	return CM_ERROR_BADFD;
    }
#endif

    if (!cm_IsValidClientString(pathp)) {
#ifdef DEBUG
        clientchar_t * hexp;

        hexp = cm_GetRawCharsAlloc(pathp, -1);
        osi_Log1(smb_logp, "NTOpenX rejecting invalid name. [%S]",
                 osi_LogSaveClientString(smb_logp, hexp));
        if (hexp)
            free(hexp);
#else
        osi_Log0(smb_logp, "NTOpenX rejecting invalid name");
#endif
        return CM_ERROR_BADNTFILENAME;
    }

#ifdef DEBUG_VERBOSE
    {
    	char *hexp, *asciip;
    	asciip = (lastNamep ? lastNamep : pathp );
    	hexp = osi_HexifyString(asciip);
    	DEBUG_EVENT2("AFS", "V3Open H[%s] A[%s]", hexp, asciip );
    	free(hexp);
    }
#endif
    userp = smb_GetUserFromVCP(vcp, inp);

    dscp = NULL;
    code = cm_NameI(cm_RootSCachep(userp, &req), pathp,
                    CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                    userp, tidPathp, &req, &scp);

#ifdef DFS_SUPPORT
    if (code == 0 && scp->fileType == CM_SCACHETYPE_DFSLINK) {
        int pnc = cm_VolStatus_Notify_DFS_Mapping(scp, tidPathp, pathp);
        cm_ReleaseSCache(scp);
        cm_ReleaseUser(userp);
        if ( WANTS_DFS_PATHNAMES(inp) || pnc )
            return CM_ERROR_PATH_NOT_COVERED;
        else
            return CM_ERROR_NOSUCHPATH;
    }
#endif /* DFS_SUPPORT */

    if (code != 0) {
        if (code == CM_ERROR_NOSUCHFILE ||
            code == CM_ERROR_NOSUCHPATH ||
            code == CM_ERROR_BPLUS_NOMATCH)
            code = cm_NameI(cm_RootSCachep(userp, &req), spacep->wdata,
                            CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                            userp, tidPathp, &req, &dscp);
        if (code) {
            cm_ReleaseUser(userp);
            return code;
        }

#ifdef DFS_SUPPORT
        if (dscp->fileType == CM_SCACHETYPE_DFSLINK) {
            int pnc = cm_VolStatus_Notify_DFS_Mapping(dscp, tidPathp,
                                                      spacep->wdata);
            cm_ReleaseSCache(dscp);
            cm_ReleaseUser(userp);
            if ( WANTS_DFS_PATHNAMES(inp) || pnc )
                return CM_ERROR_PATH_NOT_COVERED;
            else
                return CM_ERROR_NOSUCHPATH;
        }
#endif /* DFS_SUPPORT */
        /* otherwise, scp points to the parent directory.  Do a lookup,
         * and truncate the file if we find it, otherwise we create the
         * file.
         */
        if (!lastNamep)
            lastNamep = pathp;
        else
            lastNamep++;
        code = cm_Lookup(dscp, lastNamep, CM_FLAG_CASEFOLD, userp,
                          &req, &scp);
        if (code && code != CM_ERROR_NOSUCHFILE && code != CM_ERROR_BPLUS_NOMATCH) {
            cm_ReleaseSCache(dscp);
            cm_ReleaseUser(userp);
            return code;
        }
    }

    /* if we get here, if code is 0, the file exists and is represented by
     * scp.  Otherwise, we have to create it.  The dir may be represented
     * by dscp, or we may have found the file directly.  If code is non-zero,
     * scp is NULL.
     */
    if (code == 0) {
        code = cm_CheckOpen(scp, openMode, trunc, userp, &req);
        if (code) {
            if (dscp) cm_ReleaseSCache(dscp);
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
            return code;
        }

        if (excl) {
            /* oops, file shouldn't be there */
            if (dscp)
                cm_ReleaseSCache(dscp);
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
            return CM_ERROR_EXISTS;
        }

        if (trunc) {
            setAttr.mask = CM_ATTRMASK_LENGTH;
            setAttr.length.LowPart = 0;
            setAttr.length.HighPart = 0;
            code = cm_SetAttr(scp, &setAttr, userp, &req);
            openAction = 3;	/* truncated existing file */
        }
        else openAction = 1;	/* found existing file */
    }
    else if (!(openFun & SMB_ATTR_DIRECTORY)) {
        /* don't create if not found */
        if (dscp) cm_ReleaseSCache(dscp);
        cm_ReleaseUser(userp);
        return CM_ERROR_NOSUCHFILE;
    }
    else {
        osi_assertx(dscp != NULL, "null cm_scache_t");
        osi_Log1(smb_logp, "smb_ReceiveV3OpenX creating file %S",
                 osi_LogSaveClientString(smb_logp, lastNamep));
        openAction = 2;	/* created file */
        setAttr.mask = CM_ATTRMASK_CLIENTMODTIME;
        smb_UnixTimeFromDosUTime(&setAttr.clientModTime, dosTime);
        smb_SetInitialModeBitsForFile(attributes, &setAttr);

        code = cm_Create(dscp, lastNamep, 0, &setAttr, &scp, userp,
                         &req);
        if (code == 0) {
	    created = 1;
	    if (dscp->flags & CM_SCACHEFLAG_ANYWATCH)
		smb_NotifyChange(FILE_ACTION_ADDED,
				 FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_CREATION,
				 dscp, lastNamep, NULL, TRUE);
	} else if (!excl && code == CM_ERROR_EXISTS) {
            /* not an exclusive create, and someone else tried
             * creating it already, then we open it anyway.  We
             * don't bother retrying after this, since if this next
             * fails, that means that the file was deleted after we
             * started this call.
             */
            code = cm_Lookup(dscp, lastNamep, CM_FLAG_CASEFOLD,
                             userp, &req, &scp);
            if (code == 0) {
                if (trunc) {
                    setAttr.mask = CM_ATTRMASK_LENGTH;
                    setAttr.length.LowPart = 0;
                    setAttr.length.HighPart = 0;
                    code = cm_SetAttr(scp, &setAttr, userp, &req);
                }
            }	/* lookup succeeded */
        }
    }

    /* we don't need this any longer */
    if (dscp)
        cm_ReleaseSCache(dscp);

    if (code) {
        /* something went wrong creating or truncating the file */
        if (scp)
            cm_ReleaseSCache(scp);
        cm_ReleaseUser(userp);
        return code;
    }

    /* make sure we're about to open a file */
    if (scp->fileType != CM_SCACHETYPE_FILE) {
        cm_ReleaseSCache(scp);
        cm_ReleaseUser(userp);
        return CM_ERROR_ISDIR;
    }

    /* now all we have to do is open the file itself */
    fidp = smb_FindFID(vcp, 0, SMB_FLAG_CREATE);
    osi_assertx(fidp, "null smb_fid_t");

    cm_HoldUser(userp);
    lock_ObtainMutex(&fidp->mx);
    /* save a pointer to the vnode */
    fidp->scp = scp;
    lock_ObtainWrite(&scp->rw);
    scp->flags |= CM_SCACHEFLAG_SMB_FID;
    lock_ReleaseWrite(&scp->rw);
    osi_Log2(smb_logp,"smb_ReceiveV3OpenX fidp 0x%p scp 0x%p", fidp, scp);
    /* also the user */
    fidp->userp = userp;

    /* compute open mode */
    if (openMode != 1)
        fidp->flags |= SMB_FID_OPENREAD_LISTDIR;
    if (openMode == 1 || openMode == 2)
        fidp->flags |= SMB_FID_OPENWRITE;

    /* remember if the file was newly created */
    if (created)
	fidp->flags |= SMB_FID_CREATED;

    lock_ReleaseMutex(&fidp->mx);
    smb_ReleaseFID(fidp);

    cm_Open(scp, 0, userp);

    /* set inp->fid so that later read calls in same msg can find fid */
    inp->fid = fidp->fid;

    /* copy out remainder of the parms */
    parmSlot = 2;
    smb_SetSMBParm(outp, parmSlot, fidp->fid); parmSlot++;
    lock_ObtainRead(&scp->rw);
    if (extraInfo) {
        smb_SetSMBParm(outp, parmSlot, smb_Attributes(scp)); parmSlot++;
        smb_DosUTimeFromUnixTime(&dosTime, scp->clientModTime);
        smb_SetSMBParm(outp, parmSlot, dosTime & 0xffff); parmSlot++;
        smb_SetSMBParm(outp, parmSlot, (dosTime>>16) & 0xffff); parmSlot++;
        smb_SetSMBParm(outp, parmSlot, scp->length.LowPart & 0xffff); parmSlot++;
        smb_SetSMBParm(outp, parmSlot, (scp->length.LowPart >> 16) & 0xffff); parmSlot++;
        smb_SetSMBParm(outp, parmSlot, openMode); parmSlot++;
        smb_SetSMBParm(outp, parmSlot, 0); parmSlot++; /* file type 0 ==> normal file or dir */
        smb_SetSMBParm(outp, parmSlot, 0); parmSlot++; /* IPC junk */
    }
    /* and the final "always present" stuff */
    smb_SetSMBParm(outp, parmSlot, openAction); parmSlot++;
    /* next write out the "unique" ID */
    smb_SetSMBParm(outp, parmSlot, scp->fid.vnode & 0xffff); parmSlot++;
    smb_SetSMBParm(outp, parmSlot, scp->fid.volume & 0xffff); parmSlot++;
    smb_SetSMBParm(outp, parmSlot, 0); parmSlot++;
    lock_ReleaseRead(&scp->rw);
    smb_SetSMBDataLength(outp, 0);

    osi_Log1(smb_logp, "SMB OpenX opening fid %d", fidp->fid);

    cm_ReleaseUser(userp);
    /* leave scp held since we put it in fidp->scp */
    return 0;
}

static void smb_GetLockParams(unsigned char LockType,
                              char ** buf,
                              unsigned int * ppid,
                              LARGE_INTEGER * pOffset,
                              LARGE_INTEGER * pLength)
{
    if (LockType & LOCKING_ANDX_LARGE_FILES) {
        /* Large Files */
        *ppid = *((USHORT *) *buf);
        pOffset->HighPart = *((LONG *)(*buf + 4));
        pOffset->LowPart = *((DWORD *)(*buf + 8));
        pLength->HighPart = *((LONG *)(*buf + 12));
        pLength->LowPart = *((DWORD *)(*buf + 16));
        *buf += 20;
    }
    else {
        /* Not Large Files */
        *ppid = *((USHORT *) *buf);
        pOffset->HighPart = 0;
        pOffset->LowPart = *((DWORD *)(*buf + 2));
        pLength->HighPart = 0;
        pLength->LowPart = *((DWORD *)(*buf + 6));
        *buf += 10;
    }
}

/* SMB_COM_LOCKING_ANDX */
long smb_ReceiveV3LockingX(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    cm_req_t req;
    cm_user_t *userp;
    unsigned short fid;
    smb_fid_t *fidp;
    cm_scache_t *scp;
    unsigned char LockType;
    unsigned short NumberOfUnlocks, NumberOfLocks;
    afs_uint32 Timeout;
    char *op;
    char *op_locks;
    LARGE_INTEGER LOffset, LLength;
    smb_waitingLockRequest_t *wlRequest = NULL;
    cm_file_lock_t *lockp;
    long code = 0;
    int i;
    cm_key_t key;
    unsigned int pid;
    afs_uint32 smb_vc_hold_required = 0;

    smb_InitReq(&req);

    fid = smb_GetSMBParm(inp, 2);
    fid = smb_ChainFID(fid, inp);

    fidp = smb_FindFID(vcp, fid, 0);
    if (!fidp) {
        osi_Log2(smb_logp, "V3LockingX Unknown SMB Fid vcp 0x%p fid %d",
                 vcp, fid);
	return CM_ERROR_BADFD;
    }
    lock_ObtainMutex(&fidp->mx);
    if (fidp->scp && (fidp->scp->flags & CM_SCACHEFLAG_DELETED)) {
        lock_ReleaseMutex(&fidp->mx);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        return CM_ERROR_NOSUCHFILE;
    }

    if (fidp->flags & SMB_FID_IOCTL) {
        osi_Log0(smb_logp, "smb_ReceiveV3Locking BadFD");
	lock_ReleaseMutex(&fidp->mx);
	smb_ReleaseFID(fidp);
        return CM_ERROR_BADFD;
    }
    scp = fidp->scp;
    osi_Log2(smb_logp,"smb_ReceiveV3LockingX fidp 0x%p scp 0x%p", fidp, scp);
    cm_HoldSCache(scp);
    lock_ReleaseMutex(&fidp->mx);

    /* set inp->fid so that later read calls in same msg can find fid */
    inp->fid = fid;

    userp = smb_GetUserFromVCP(vcp, inp);
    smb_HoldVC(vcp);

    lock_ObtainWrite(&scp->rw);
    code = cm_SyncOp(scp, NULL, userp, &req, 0,
                      CM_SCACHESYNC_NEEDCALLBACK
			 | CM_SCACHESYNC_GETSTATUS
			 | CM_SCACHESYNC_LOCK);
    if (code) {
        osi_Log1(smb_logp, "smb_ReceiveV3Locking SyncOp failure code 0x%x", code);
        goto doneSync;
    }

    LockType = smb_GetSMBParm(inp, 3) & 0xff;
    Timeout = (smb_GetSMBParm(inp, 5) << 16) + smb_GetSMBParm(inp, 4);
    NumberOfUnlocks = smb_GetSMBParm(inp, 6);
    NumberOfLocks = smb_GetSMBParm(inp, 7);

    if (!(fidp->flags & SMB_FID_OPENWRITE) &&
        !(LockType & LOCKING_ANDX_SHARED_LOCK)) {
        /* somebody wants exclusive locks on a file that they only
           opened for reading.  We downgrade this to a shared lock. */
        osi_Log0(smb_logp, "smb_ReceiveV3Locking reinterpreting exclusive lock as shared for read-only fid");
        LockType |= LOCKING_ANDX_SHARED_LOCK;
    }

    if (LockType & LOCKING_ANDX_CHANGE_LOCKTYPE) {
        /* AFS does not support atomic changes of lock types from read or write and vice-versa */
        osi_Log0(smb_logp, "smb_ReceiveV3Locking received unsupported request [LOCKING_ANDX_CHANGE_LOCKTYPE]");
        code = CM_ERROR_BADOP;
        goto done;

    }

    op = smb_GetSMBData(inp, NULL);

    if (LockType & LOCKING_ANDX_CANCEL_LOCK) {
        /* Cancel outstanding lock requests */
        smb_waitingLock_t * wl;

        for (i=0; i<NumberOfLocks; i++) {
            smb_GetLockParams(LockType, &op, &pid, &LOffset, &LLength);

            key = cm_GenerateKey(vcp->vcID, pid, fidp->fid);

            lock_ObtainWrite(&smb_globalLock);
            for (wlRequest = smb_allWaitingLocks; wlRequest; wlRequest = (smb_waitingLockRequest_t *) osi_QNext(&wlRequest->q))
            {
                for (wl = wlRequest->locks; wl; wl = (smb_waitingLock_t *) osi_QNext(&wl->q)) {
                    if (cm_KeyEquals(&wl->key, &key, 0) && LargeIntegerEqualTo(wl->LOffset, LOffset) &&
                        LargeIntegerEqualTo(wl->LLength, LLength)) {
                        wl->state = SMB_WAITINGLOCKSTATE_CANCELLED;
                        goto found_lock_request;
                    }
                }
            }
          found_lock_request:
            lock_ReleaseWrite(&smb_globalLock);
        }
        code = 0;
        smb_SetSMBDataLength(outp, 0);
        goto done;
    }


    for (i=0; i<NumberOfUnlocks; i++) {
        smb_GetLockParams(LockType, &op, &pid, &LOffset, &LLength);

        key = cm_GenerateKey(vcp->vcID, pid, fidp->fid);

        code = cm_Unlock(scp, LockType, LOffset, LLength, key, 0, userp, &req);

        if (code)
            goto done;
    }

    op_locks = op;

    for (i=0; i<NumberOfLocks; i++) {
        smb_GetLockParams(LockType, &op, &pid, &LOffset, &LLength);

        key = cm_GenerateKey(vcp->vcID, pid, fidp->fid);

        code = cm_Lock(scp, LockType, LOffset, LLength, key, (Timeout != 0),
                        userp, &req, &lockp);

	if (code == CM_ERROR_NOACCESS && LockType == LockWrite &&
	    (fidp->flags & (SMB_FID_OPENREAD_LISTDIR | SMB_FID_OPENWRITE)) == SMB_FID_OPENREAD_LISTDIR)
	{
	    code = cm_Lock(scp, LockRead, LOffset, LLength, key, (Timeout != 0),
			    userp, &req, &lockp);
	}

        if (code == CM_ERROR_LOCK_NOT_GRANTED && Timeout != 0) {
            smb_waitingLock_t * wLock;

            /* Put on waiting list */
            if(wlRequest == NULL) {
                int j;
                char * opt;
                cm_key_t tkey;
                LARGE_INTEGER tOffset, tLength;

                wlRequest = malloc(sizeof(smb_waitingLockRequest_t));

                osi_assertx(wlRequest != NULL, "null wlRequest");

                wlRequest->vcp = vcp;
                smb_vc_hold_required = 1;
                wlRequest->scp = scp;
		osi_Log2(smb_logp,"smb_ReceiveV3LockingX wlRequest 0x%p scp 0x%p", wlRequest, scp);
                cm_HoldSCache(scp);
                wlRequest->inp = smb_CopyPacket(inp);
                wlRequest->outp = smb_CopyPacket(outp);
                wlRequest->lockType = LockType;
                wlRequest->msTimeout = Timeout;
                wlRequest->start_t = osi_Time();
                wlRequest->locks = NULL;

                /* The waiting lock request needs to have enough
                   information to undo all the locks in the request.
                   We do the following to store info about locks that
                   have already been granted.  Sure, we can get most
                   of the info from the packet, but the packet doesn't
                   hold the result of cm_Lock call.  In practice we
                   only receive packets with one or two locks, so we
                   are only wasting a few bytes here and there and
                   only for a limited period of time until the waiting
                   lock times out or is freed. */

                for(opt = op_locks, j=i; j > 0; j--) {
                    smb_GetLockParams(LockType, &opt, &pid, &tOffset, &tLength);

                    tkey = cm_GenerateKey(vcp->vcID, pid, fidp->fid);

                    wLock = malloc(sizeof(smb_waitingLock_t));

                    osi_assertx(wLock != NULL, "null smb_waitingLock_t");

                    wLock->key = tkey;
                    wLock->LOffset = tOffset;
                    wLock->LLength = tLength;
                    wLock->lockp = NULL;
                    wLock->state = SMB_WAITINGLOCKSTATE_DONE;
                    osi_QAdd((osi_queue_t **) &wlRequest->locks,
                             &wLock->q);
                }
            }

            wLock = malloc(sizeof(smb_waitingLock_t));

            osi_assertx(wLock != NULL, "null smb_waitingLock_t");

            wLock->key = key;
            wLock->LOffset = LOffset;
            wLock->LLength = LLength;
            wLock->lockp = lockp;
            wLock->state = SMB_WAITINGLOCKSTATE_WAITING;
            osi_QAdd((osi_queue_t **) &wlRequest->locks,
                     &wLock->q);

            osi_Log1(smb_logp, "smb_ReceiveV3Locking WaitingLock created 0x%p",
                     wLock);

            code = 0;
            continue;
        }

        if (code) {
            osi_Log1(smb_logp, "smb_ReceiveV3Locking cm_Lock failure code 0x%x", code);
            break;
        }
    }

    if (code) {

        /* Since something went wrong with the lock number i, we now
           have to go ahead and release any locks acquired before the
           failure.  All locks before lock number i (of which there
           are i of them) have either been successful or are waiting.
           Either case requires calling cm_Unlock(). */

        /* And purge the waiting lock */
        if(wlRequest != NULL) {
            smb_waitingLock_t * wl;
            smb_waitingLock_t * wlNext;
            long ul_code;

            for(wl = wlRequest->locks; wl; wl = wlNext) {

                wlNext = (smb_waitingLock_t *) osi_QNext(&wl->q);

                ul_code = cm_Unlock(scp, LockType, wl->LOffset, wl->LLength, wl->key, 0, userp, &req);

                if(ul_code != 0) {
                    osi_Log1(smb_logp, "smb_ReceiveV3Locking cm_Unlock returns code %d", ul_code);
                } else {
                    osi_Log0(smb_logp, "smb_ReceiveV3Locking cm_Unlock successful");
                }

                osi_QRemove((osi_queue_t **) &wlRequest->locks, &wl->q);
                free(wl);

            }

            smb_ReleaseVC(wlRequest->vcp);
            cm_ReleaseSCache(wlRequest->scp);
            smb_FreePacket(wlRequest->inp);
            smb_FreePacket(wlRequest->outp);

            free(wlRequest);

            wlRequest = NULL;
        }

    } else {

        if (wlRequest != NULL) {

            lock_ObtainWrite(&smb_globalLock);
            osi_QAdd((osi_queue_t **)&smb_allWaitingLocks,
                     &wlRequest->q);
            osi_Wakeup((LONG_PTR)&smb_allWaitingLocks);
            lock_ReleaseWrite(&smb_globalLock);

            /* don't send reply immediately */
            outp->flags |= SMB_PACKETFLAG_NOSEND;
        }

        smb_SetSMBDataLength(outp, 0);
    }

  done:
    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_LOCK);

  doneSync:
    lock_ReleaseWrite(&scp->rw);
    cm_ReleaseSCache(scp);
    cm_ReleaseUser(userp);
    smb_ReleaseFID(fidp);
    if (!smb_vc_hold_required)
        smb_HoldVC(vcp);

    return code;
}

/* SMB_COM_QUERY_INFORMATION2 */
long smb_ReceiveV3GetAttributes(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    unsigned short fid;
    smb_fid_t *fidp;
    cm_scache_t *scp;
    long code = 0;
    afs_uint32 searchTime;
    cm_user_t *userp;
    cm_req_t req;
    int readlock = 0;

    smb_InitReq(&req);

    fid = smb_GetSMBParm(inp, 0);
    fid = smb_ChainFID(fid, inp);

    fidp = smb_FindFID(vcp, fid, 0);
    if (!fidp) {
        osi_Log2(smb_logp, "V3GetAttributes Unknown SMB Fid vcp 0x%p fid %d",
                 vcp, fid);
	return CM_ERROR_BADFD;
    }
    lock_ObtainMutex(&fidp->mx);
    if (fidp->scp && (fidp->scp->flags & CM_SCACHEFLAG_DELETED)) {
        lock_ReleaseMutex(&fidp->mx);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        return CM_ERROR_NOSUCHFILE;
    }

    if (fidp->flags & SMB_FID_IOCTL) {
	lock_ReleaseMutex(&fidp->mx);
	smb_ReleaseFID(fidp);
        return CM_ERROR_BADFD;
    }
    scp = fidp->scp;
    osi_Log2(smb_logp,"smb_ReceiveV3GetAttributes fidp 0x%p scp 0x%p", fidp, scp);
    cm_HoldSCache(scp);
    lock_ReleaseMutex(&fidp->mx);

    userp = smb_GetUserFromVCP(vcp, inp);


    /* otherwise, stat the file */
    lock_ObtainWrite(&scp->rw);
    code = cm_SyncOp(scp, NULL, userp, &req, 0,
                     CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    if (code)
	goto done;

    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);

    lock_ConvertWToR(&scp->rw);
    readlock = 1;

    /* decode times.  We need a search time, but the response to this
     * call provides the date first, not the time, as returned in the
     * searchTime variable.  So we take the high-order bits first.
     */
    cm_SearchTimeFromUnixTime(&searchTime, scp->clientModTime);
    smb_SetSMBParm(outp, 0, (searchTime >> 16) & 0xffff);	/* ctime */
    smb_SetSMBParm(outp, 1, searchTime & 0xffff);
    smb_SetSMBParm(outp, 2, (searchTime >> 16) & 0xffff);	/* atime */
    smb_SetSMBParm(outp, 3, searchTime & 0xffff);
    smb_SetSMBParm(outp, 4, (searchTime >> 16) & 0xffff);	/* mtime */
    smb_SetSMBParm(outp, 5, searchTime & 0xffff);

    /* now handle file size and allocation size */
    smb_SetSMBParm(outp, 6, scp->length.LowPart & 0xffff);		/* file size */
    smb_SetSMBParm(outp, 7, (scp->length.LowPart >> 16) & 0xffff);
    smb_SetSMBParm(outp, 8, scp->length.LowPart & 0xffff);		/* alloc size */
    smb_SetSMBParm(outp, 9, (scp->length.LowPart >> 16) & 0xffff);

    /* file attribute */
    smb_SetSMBParm(outp, 10, smb_Attributes(scp));

    /* and finalize stuff */
    smb_SetSMBDataLength(outp, 0);
    code = 0;

  done:
    if (readlock)
        lock_ReleaseRead(&scp->rw);
    else
        lock_ReleaseWrite(&scp->rw);
    cm_ReleaseSCache(scp);
    cm_ReleaseUser(userp);
    smb_ReleaseFID(fidp);
    return code;
}

/* SMB_COM_SET_INFORMATION2 */
long smb_ReceiveV3SetAttributes(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    unsigned short fid;
    smb_fid_t *fidp;
    cm_scache_t *scp;
    long code = 0;
    afs_uint32 searchTime;
    time_t unixTime;
    cm_user_t *userp;
    cm_attr_t attrs;
    cm_req_t req;

    smb_InitReq(&req);

    fid = smb_GetSMBParm(inp, 0);
    fid = smb_ChainFID(fid, inp);

    fidp = smb_FindFID(vcp, fid, 0);
    if (!fidp) {
        osi_Log2(smb_logp, "V3SetAttributes Unknown SMB Fid vcp 0x%p fid %d",
                 vcp, fid);
	return CM_ERROR_BADFD;
    }
    lock_ObtainMutex(&fidp->mx);
    if (fidp->scp && (fidp->scp->flags & CM_SCACHEFLAG_DELETED)) {
        lock_ReleaseMutex(&fidp->mx);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        return CM_ERROR_NOSUCHFILE;
    }

    if (fidp->flags & SMB_FID_IOCTL) {
	lock_ReleaseMutex(&fidp->mx);
	smb_ReleaseFID(fidp);
        return CM_ERROR_BADFD;
    }
    scp = fidp->scp;
    osi_Log2(smb_logp,"smb_ReceiveV3SetAttributes fidp 0x%p scp 0x%p", fidp, scp);
    cm_HoldSCache(scp);
    lock_ReleaseMutex(&fidp->mx);

    userp = smb_GetUserFromVCP(vcp, inp);

    /* now prepare to call cm_setattr.  This message only sets various times,
     * and AFS only implements mtime, and we'll set the mtime if that's
     * requested.  The others we'll ignore.
     */
    searchTime = smb_GetSMBParm(inp, 5) | (smb_GetSMBParm(inp, 6) << 16);

    if (searchTime != 0) {
        cm_UnixTimeFromSearchTime(&unixTime, searchTime);

        if ( unixTime != -1 ) {
            attrs.mask = CM_ATTRMASK_CLIENTMODTIME;
            attrs.clientModTime = unixTime;
            code = cm_SetAttr(scp, &attrs, userp, &req);

            osi_Log1(smb_logp, "SMB receive V3SetAttributes [fid=%ld]", fid);
        } else {
            osi_Log1(smb_logp, "**cm_UnixTimeFromSearchTime failed searchTime=%ld", searchTime);
        }
    }
    else
	code = 0;

    cm_ReleaseSCache(scp);
    cm_ReleaseUser(userp);
    smb_ReleaseFID(fidp);
    return code;
}

/* SMB_COM_WRITE_ANDX */
long smb_ReceiveV3WriteX(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    osi_hyper_t offset;
    long count, written = 0, total_written = 0;
    unsigned short fd;
    unsigned pid;
    smb_fid_t *fidp;
    smb_t *smbp = (smb_t*) inp;
    long code = 0;
    cm_scache_t *scp;
    cm_user_t *userp;
    char *op;
    int inDataBlockCount;

    fd = smb_GetSMBParm(inp, 2);
    count = smb_GetSMBParm(inp, 10);

    offset.HighPart = 0;
    offset.LowPart = smb_GetSMBParm(inp, 3) | (smb_GetSMBParm(inp, 4) << 16);

    if (*inp->wctp == 14) {
        /* we have a request with 64-bit file offsets */
        offset.HighPart = smb_GetSMBParm(inp, 12) | (smb_GetSMBParm(inp, 13) << 16);
    }

    op = inp->data + smb_GetSMBParm(inp, 11);
    inDataBlockCount = count;

    osi_Log4(smb_logp, "smb_ReceiveV3WriteX fid %d, off 0x%x:%08x, size 0x%x",
             fd, offset.HighPart, offset.LowPart, count);

    fd = smb_ChainFID(fd, inp);
    fidp = smb_FindFID(vcp, fd, 0);
    if (!fidp) {
        osi_Log2(smb_logp, "smb_ReceiveV3WriteX Unknown SMB Fid vcp 0x%p fid %d",
                 vcp, fd);
        return CM_ERROR_BADFD;
    }
    lock_ObtainMutex(&fidp->mx);
    if (fidp->scp && (fidp->scp->flags & CM_SCACHEFLAG_DELETED)) {
        lock_ReleaseMutex(&fidp->mx);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        return CM_ERROR_NOSUCHFILE;
    }

    if (fidp->flags & SMB_FID_IOCTL) {
	lock_ReleaseMutex(&fidp->mx);
        code = smb_IoctlV3Write(fidp, vcp, inp, outp);
	smb_ReleaseFID(fidp);
	return code;
    }

    if (fidp->flags & SMB_FID_RPC) {
	lock_ReleaseMutex(&fidp->mx);
        code = smb_RPCV3Write(fidp, vcp, inp, outp);
	smb_ReleaseFID(fidp);
	return code;
    }

    if (!fidp->scp) {
        lock_ReleaseMutex(&fidp->mx);
        smb_ReleaseFID(fidp);
        return CM_ERROR_BADFDOP;
    }

    scp = fidp->scp;
    cm_HoldSCache(scp);
    lock_ReleaseMutex(&fidp->mx);

    userp = smb_GetUserFromVCP(vcp, inp);

    /* special case: 0 bytes transferred means there is no data
       transferred.  A slight departure from SMB_COM_WRITE where this
       means that we are supposed to truncate the file at this
       position. */

    {
        cm_key_t key;
        LARGE_INTEGER LOffset;
        LARGE_INTEGER LLength;

        pid = smbp->pid;
        key = cm_GenerateKey(vcp->vcID, pid, fd);

        LOffset.HighPart = offset.HighPart;
        LOffset.LowPart = offset.LowPart;
        LLength.HighPart = 0;
        LLength.LowPart = count;

        lock_ObtainWrite(&scp->rw);
        code = cm_LockCheckWrite(scp, LOffset, LLength, key);
        lock_ReleaseWrite(&scp->rw);

        if (code)
            goto done;
    }

    /*
     * Work around bug in NT client
     *
     * When copying a file, the NT client should first copy the data,
     * then copy the last write time.  But sometimes the NT client does
     * these in the wrong order, so the data copies would inadvertently
     * cause the last write time to be overwritten.  We try to detect this,
     * and don't set client mod time if we think that would go against the
     * intention.
     */
    lock_ObtainMutex(&fidp->mx);
    if ((fidp->flags & SMB_FID_MTIMESETDONE) != SMB_FID_MTIMESETDONE) {
        lock_ObtainWrite(&fidp->scp->rw);
        scp->mask |= CM_SCACHEMASK_CLIENTMODTIME;
        scp->clientModTime = time(NULL);
        lock_ReleaseWrite(&fidp->scp->rw);
    }
    lock_ReleaseMutex(&fidp->mx);

    code = 0;
    while ( code == 0 && count > 0 ) {
	code = smb_WriteData(fidp, &offset, count, op, userp, &written);
	if (code == 0 && written == 0)
            code = CM_ERROR_PARTIALWRITE;

        offset = LargeIntegerAdd(offset,
                                 ConvertLongToLargeInteger(written));
        count -= written;
        total_written += written;
        written = 0;
    }

    /* slots 0 and 1 are reserved for request chaining and will be
       filled in when we return. */
    smb_SetSMBParm(outp, 2, total_written);
    smb_SetSMBParm(outp, 3, 0); /* reserved */
    smb_SetSMBParm(outp, 4, 0); /* reserved */
    smb_SetSMBParm(outp, 5, 0); /* reserved */
    smb_SetSMBDataLength(outp, 0);

 done:

    cm_ReleaseSCache(scp);
    cm_ReleaseUser(userp);
    smb_ReleaseFID(fidp);

    return code;
}

/* SMB_COM_READ_ANDX */
long smb_ReceiveV3ReadX(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    osi_hyper_t offset;
    long count;
    long finalCount = 0;
    unsigned short fd;
    unsigned pid;
    smb_fid_t *fidp;
    smb_t *smbp = (smb_t*) inp;
    long code = 0;
    cm_scache_t *scp;
    cm_user_t *userp;
    cm_key_t key;
    char *op;

    fd = smb_GetSMBParm(inp, 2); /* File ID */
    count = smb_GetSMBParm(inp, 5); /* MaxCount */
    offset.LowPart = smb_GetSMBParm(inp, 3) | (smb_GetSMBParm(inp, 4) << 16);

    if (*inp->wctp == 12) {
        /* a request with 64-bit offsets */
        offset.HighPart = smb_GetSMBParm(inp, 10) | (smb_GetSMBParm(inp, 11) << 16);

        if (LargeIntegerLessThanZero(offset)) {
            osi_Log2(smb_logp, "smb_ReceiveV3Read offset too large (0x%x:%08x)",
                     offset.HighPart, offset.LowPart);
            return CM_ERROR_BADSMB;
        }
    } else {
        offset.HighPart = 0;
    }

    osi_Log4(smb_logp, "smb_ReceiveV3Read fd %d, off 0x%x:%08x, size 0x%x",
             fd, offset.HighPart, offset.LowPart, count);

    fd = smb_ChainFID(fd, inp);
    fidp = smb_FindFID(vcp, fd, 0);
    if (!fidp) {
        osi_Log2(smb_logp, "smb_ReceiveV3Read Unknown SMB Fid vcp 0x%p fid %d",
                 vcp, fd);
        return CM_ERROR_BADFD;
    }

    lock_ObtainMutex(&fidp->mx);

    if (fidp->flags & SMB_FID_IOCTL) {
	lock_ReleaseMutex(&fidp->mx);
	inp->fid = fd;
        code = smb_IoctlV3Read(fidp, vcp, inp, outp);
	smb_ReleaseFID(fidp);
	return code;
    }

    if (fidp->flags & SMB_FID_RPC) {
	lock_ReleaseMutex(&fidp->mx);
	inp->fid = fd;
        code = smb_RPCV3Read(fidp, vcp, inp, outp);
	smb_ReleaseFID(fidp);
	return code;
    }

    if (fidp->scp && (fidp->scp->flags & CM_SCACHEFLAG_DELETED)) {
        lock_ReleaseMutex(&fidp->mx);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        return CM_ERROR_NOSUCHFILE;
    }

    if (!fidp->scp) {
        lock_ReleaseMutex(&fidp->mx);
        smb_ReleaseFID(fidp);
        return CM_ERROR_BADFDOP;
    }

    scp = fidp->scp;
    cm_HoldSCache(scp);

    lock_ReleaseMutex(&fidp->mx);

    pid = smbp->pid;
    key = cm_GenerateKey(vcp->vcID, pid, fd);
    {
        LARGE_INTEGER LOffset, LLength;

        LOffset.HighPart = offset.HighPart;
        LOffset.LowPart = offset.LowPart;
        LLength.HighPart = 0;
        LLength.LowPart = count;

        lock_ObtainWrite(&scp->rw);
        code = cm_LockCheckRead(scp, LOffset, LLength, key);
        lock_ReleaseWrite(&scp->rw);
    }
    cm_ReleaseSCache(scp);

    if (code) {
        smb_ReleaseFID(fidp);
        return code;
    }

    /* set inp->fid so that later read calls in same msg can find fid */
    inp->fid = fd;

    userp = smb_GetUserFromVCP(vcp, inp);

    /* 0 and 1 are reserved for request chaining, were setup by our caller,
     * and will be further filled in after we return.
     */
    smb_SetSMBParm(outp, 2, 0);	/* remaining bytes, for pipes */
    smb_SetSMBParm(outp, 3, 0);	/* resvd */
    smb_SetSMBParm(outp, 4, 0);	/* resvd */
    smb_SetSMBParm(outp, 5, count);	/* # of bytes we're going to read */
    /* fill in #6 when we have all the parameters' space reserved */
    smb_SetSMBParm(outp, 7, 0);	/* resv'd */
    smb_SetSMBParm(outp, 8, 0);	/* resv'd */
    smb_SetSMBParm(outp, 9, 0);	/* resv'd */
    smb_SetSMBParm(outp, 10, 0);	/* resv'd */
    smb_SetSMBParm(outp, 11, 0);	/* reserved */

    /* get op ptr after putting in the parms, since otherwise we don't
     * know where the data really is.
     */
    op = smb_GetSMBData(outp, NULL);

    /* now fill in offset from start of SMB header to first data byte (to op) */
    smb_SetSMBParm(outp, 6, ((int) (op - outp->data)));

    /* set the packet data length the count of the # of bytes */
    smb_SetSMBDataLength(outp, count);

    code = smb_ReadData(fidp, &offset, count, op, userp, &finalCount);

    /* fix some things up */
    smb_SetSMBParm(outp, 5, finalCount);
    smb_SetSMBDataLength(outp, finalCount);

    cm_ReleaseUser(userp);
    smb_ReleaseFID(fidp);
    return code;
}

/*
 * Values for createDisp, copied from NTDDK.H
 */
#define  FILE_SUPERSEDE	0	// (???)
#define  FILE_OPEN     	1	// (open)
#define  FILE_CREATE	2	// (exclusive)
#define  FILE_OPEN_IF	3	// (non-exclusive)
#define  FILE_OVERWRITE	4	// (open & truncate, but do not create)
#define  FILE_OVERWRITE_IF 5	// (open & truncate, or create)

/* Flags field */
#define REQUEST_OPLOCK 2
#define REQUEST_BATCH_OPLOCK 4
#define OPEN_DIRECTORY 8
#define EXTENDED_RESPONSE_REQUIRED 0x10

/* CreateOptions field. */
#define FILE_DIRECTORY_FILE       0x0001
#define FILE_WRITE_THROUGH        0x0002
#define FILE_SEQUENTIAL_ONLY      0x0004
#define FILE_NON_DIRECTORY_FILE   0x0040
#define FILE_NO_EA_KNOWLEDGE      0x0200
#define FILE_EIGHT_DOT_THREE_ONLY 0x0400
#define FILE_RANDOM_ACCESS        0x0800
#define FILE_DELETE_ON_CLOSE      0x1000
#define FILE_OPEN_BY_FILE_ID      0x2000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000
#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000

/* SMB_COM_NT_CREATE_ANDX */
long smb_ReceiveNTCreateX(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    clientchar_t *pathp, *realPathp;
    long code = 0;
    cm_space_t *spacep;
    cm_user_t *userp;
    cm_scache_t *dscp;		/* parent dir */
    cm_scache_t *scp;		/* file to create or open */
    cm_scache_t *targetScp;	/* if scp is a symlink */
    cm_attr_t setAttr;
    clientchar_t *lastNamep;
    clientchar_t *treeStartp;
    unsigned short nameLength;
    unsigned int flags;
    unsigned int requestOpLock;
    unsigned int requestBatchOpLock;
    unsigned int mustBeDir;
    unsigned int extendedRespRequired;
    unsigned int treeCreate;
    int realDirFlag;
    unsigned int desiredAccess;
    unsigned int extAttributes;
    unsigned int createDisp;
    unsigned int createOptions;
    unsigned int shareAccess;
    unsigned short baseFid;
    smb_fid_t *baseFidp;
    smb_fid_t *fidp;
    cm_scache_t *baseDirp;
    unsigned short openAction;
    int parmSlot;
    long fidflags;
    FILETIME ft;
    LARGE_INTEGER sz;
    clientchar_t *tidPathp;
    BOOL foundscp;
    cm_req_t req;
    int created = 0;
    int prefetch = 0;
    int checkDoneRequired = 0;
    cm_lock_data_t *ldp = NULL;
    BOOL is_rpc = FALSE;
    BOOL is_ipc = FALSE;

    smb_InitReq(&req);

    /* This code is very long and has a lot of if-then-else clauses
     * scp and dscp get reused frequently and we need to ensure that
     * we don't lose a reference.  Start by ensuring that they are NULL.
     */
    scp = NULL;
    dscp = NULL;
    treeCreate = FALSE;
    foundscp = FALSE;

    nameLength = smb_GetSMBOffsetParm(inp, 2, 1);
    flags = smb_GetSMBOffsetParm(inp, 3, 1)
        | (smb_GetSMBOffsetParm(inp, 4, 1) << 16);
    requestOpLock = flags & REQUEST_OPLOCK;
    requestBatchOpLock = flags & REQUEST_BATCH_OPLOCK;
    mustBeDir = flags & OPEN_DIRECTORY;
    extendedRespRequired = flags & EXTENDED_RESPONSE_REQUIRED;

    /*
     * Why all of a sudden 32-bit FID?
     * We will reject all bits higher than 16.
     */
    if (smb_GetSMBOffsetParm(inp, 6, 1) != 0)
        return CM_ERROR_INVAL;
    baseFid = smb_GetSMBOffsetParm(inp, 5, 1);
    desiredAccess = smb_GetSMBOffsetParm(inp, 7, 1)
        | (smb_GetSMBOffsetParm(inp, 8, 1) << 16);
    extAttributes = smb_GetSMBOffsetParm(inp, 13, 1)
        | (smb_GetSMBOffsetParm(inp, 14, 1) << 16);
    shareAccess = smb_GetSMBOffsetParm(inp, 15, 1)
        | (smb_GetSMBOffsetParm(inp, 16, 1) << 16);
    createDisp = smb_GetSMBOffsetParm(inp, 17, 1)
        | (smb_GetSMBOffsetParm(inp, 18, 1) << 16);
    createOptions = smb_GetSMBOffsetParm(inp, 19, 1)
        | (smb_GetSMBOffsetParm(inp, 20, 1) << 16);

    /* mustBeDir is never set; createOptions directory bit seems to be
     * more important
     */
    if (createOptions & FILE_DIRECTORY_FILE)
        realDirFlag = 1;
    else if (createOptions & FILE_NON_DIRECTORY_FILE)
        realDirFlag = 0;
    else
        realDirFlag = -1;

    pathp = smb_ParseStringCb(inp, smb_GetSMBData(inp, NULL), nameLength,
                              NULL, SMB_STRF_ANSIPATH);

    /* Sometimes path is not null-terminated, so we make a copy. */
    realPathp = malloc(nameLength+sizeof(clientchar_t));
    memcpy(realPathp, pathp, nameLength+sizeof(clientchar_t));
    realPathp[nameLength/sizeof(clientchar_t)] = 0;

    spacep = inp->spacep;
    /* smb_StripLastComponent will strip "::$DATA" if present */
    smb_StripLastComponent(spacep->wdata, &lastNamep, realPathp);

    osi_Log1(smb_logp,"NTCreateX for [%S]",osi_LogSaveClientString(smb_logp,realPathp));
    osi_Log4(smb_logp,"... da=[%x] ea=[%x] cd=[%x] co=[%x]", desiredAccess, extAttributes, createDisp, createOptions);
    osi_Log3(smb_logp,"... share=[%x] flags=[%x] lastNamep=[%S]", shareAccess, flags, osi_LogSaveClientString(smb_logp,(lastNamep?lastNamep:_C("null"))));

    if (baseFid == 0) {
	baseFidp = NULL;
        baseDirp = cm_RootSCachep(cm_rootUserp, &req);
        code = smb_LookupTIDPath(vcp, ((smb_t *)inp)->tid, &tidPathp);
        if (code == CM_ERROR_TIDIPC) {
            /* Attempt to use a TID allocated for IPC.  The client
             * is probably looking for DCE RPC end points which we
             * don't support OR it could be looking to make a DFS
             * referral request.
             */
            osi_Log0(smb_logp, "NTCreateX received IPC TID");
	    is_ipc = TRUE;
        }
    }

    osi_Log1(smb_logp, "NTCreateX tidPathp=[%S]", (tidPathp==NULL)?_C("null"): osi_LogSaveClientString(smb_logp,tidPathp));

    if (lastNamep &&

	((is_ipc && MSRPC_IsWellKnownService(lastNamep) && (is_rpc = TRUE)) ||

	 /* special case magic file name for receiving IOCTL requests
	  * (since IOCTL calls themselves aren't getting through).
	  */
	 cm_ClientStrCmpIA(lastNamep,  _C(SMB_IOCTL_FILENAME)) == 0)) {

	unsigned short file_type = 0;
	unsigned short device_state = 0;

        fidp = smb_FindFID(vcp, 0, SMB_FLAG_CREATE);

	if (is_rpc) {
	    code = smb_SetupRPCFid(fidp, lastNamep, &file_type, &device_state);
	    osi_Log1(smb_logp, "NTCreateX Setting up RPC on fid[%d]", fidp->fid);
	    if (code) {
		osi_Log1(smb_logp, "smb_SetupRPCFid() failure code [%d]", code);
		smb_ReleaseFID(fidp);
		free(realPathp);
		return code;
	    }
	} else {
	    smb_SetupIoctlFid(fidp, spacep);
	    osi_Log1(smb_logp, "NTCreateX Setting up IOCTL on fid[%d]", fidp->fid);
	}

        /* set inp->fid so that later read calls in same msg can find fid */
        inp->fid = fidp->fid;

        /* out parms */
        parmSlot = 2;
        smb_SetSMBParmByte(outp, parmSlot, 0);	/* oplock */
        smb_SetSMBParm(outp, parmSlot, fidp->fid); parmSlot++;
        smb_SetSMBParmLong(outp, parmSlot, 1); parmSlot += 2; /* Action */
        /* times */
        memset(&ft, 0, sizeof(ft));
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&ft); parmSlot += 4;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&ft); parmSlot += 4;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&ft); parmSlot += 4;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&ft); parmSlot += 4;
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2; /* attr */
        sz.HighPart = 0x7fff; sz.LowPart = 0;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&sz); parmSlot += 4; /* alen */
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&sz); parmSlot += 4; /* len */
        smb_SetSMBParm(outp, parmSlot, file_type); parmSlot++;	/* filetype */
        smb_SetSMBParm(outp, parmSlot, device_state); parmSlot++;	/* dev state */
        smb_SetSMBParmByte(outp, parmSlot, 0);	/* is a dir? */
        smb_SetSMBDataLength(outp, 0);

        /* clean up fid reference */
        smb_ReleaseFID(fidp);
        free(realPathp);
        return 0;
    }

#ifndef DFS_SUPPORT
    if (is_ipc) {
	osi_Log0(smb_logp, "NTCreateX rejecting IPC TID");
	free(realPathp);
	return CM_ERROR_BADFD;
    }
#endif

    if (!cm_IsValidClientString(realPathp)) {
#ifdef DEBUG
        clientchar_t * hexp;

        hexp = cm_GetRawCharsAlloc(realPathp, -1);
        osi_Log1(smb_logp, "NTCreateX rejecting invalid name. [%S]",
                 osi_LogSaveClientString(smb_logp, hexp));
        if (hexp)
	    free(hexp);
#else
        osi_Log0(smb_logp, "NTCreateX rejecting invalid name");
#endif
        free(realPathp);
        return CM_ERROR_BADNTFILENAME;
    }

    userp = smb_GetUserFromVCP(vcp, inp);
    if (!userp) {
    	osi_Log1(smb_logp, "NTCreateX Invalid user [%d]", ((smb_t *) inp)->uid);
    	free(realPathp);
    	return CM_ERROR_INVAL;
    }

    if (baseFidp != 0) {
        baseFidp = smb_FindFID(vcp, baseFid, 0);
        if (!baseFidp) {
            osi_Log1(smb_logp, "NTCreateX Invalid base fid [%d]", baseFid);
	    cm_ReleaseUser(userp);
            free(realPathp);
            return CM_ERROR_INVAL;
        }

        if (baseFidp->scp && (baseFidp->scp->flags & CM_SCACHEFLAG_DELETED)) {
            free(realPathp);
	    smb_CloseFID(vcp, baseFidp, NULL, 0);
            smb_ReleaseFID(baseFidp);
	    cm_ReleaseUser(userp);
            return CM_ERROR_NOSUCHPATH;
        }

        baseDirp = baseFidp->scp;
        tidPathp = NULL;
    }

    /* compute open mode */
    fidflags = 0;
    if (desiredAccess & DELETE)
        fidflags |= SMB_FID_OPENDELETE;
    if (desiredAccess & (AFS_ACCESS_READ|AFS_ACCESS_EXECUTE))
        fidflags |= SMB_FID_OPENREAD_LISTDIR;
    if (desiredAccess & AFS_ACCESS_WRITE)
        fidflags |= SMB_FID_OPENWRITE;
    if (createOptions & FILE_DELETE_ON_CLOSE)
        fidflags |= SMB_FID_DELONCLOSE;
    if (createOptions & FILE_SEQUENTIAL_ONLY && !(createOptions & FILE_RANDOM_ACCESS))
	fidflags |= SMB_FID_SEQUENTIAL;
    if (createOptions & FILE_RANDOM_ACCESS && !(createOptions & FILE_SEQUENTIAL_ONLY))
	fidflags |= SMB_FID_RANDOM;
    if (createOptions & FILE_OPEN_REPARSE_POINT)
        osi_Log0(smb_logp, "NTCreateX Open Reparse Point");
    if (smb_IsExecutableFileName(lastNamep))
        fidflags |= SMB_FID_EXECUTABLE;

    /* and the share mode */
    if (shareAccess & FILE_SHARE_READ)
        fidflags |= SMB_FID_SHARE_READ;
    if (shareAccess & FILE_SHARE_WRITE)
        fidflags |= SMB_FID_SHARE_WRITE;

    osi_Log1(smb_logp, "NTCreateX fidflags 0x%x", fidflags);
    code = 0;

    /* For an exclusive create, we want to do a case sensitive match for the last component. */
    if ( createDisp == FILE_CREATE ||
         createDisp == FILE_OVERWRITE ||
         createDisp == FILE_OVERWRITE_IF) {
        code = cm_NameI(baseDirp, spacep->wdata, CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                        userp, tidPathp, &req, &dscp);
        if (code == 0) {
#ifdef DFS_SUPPORT
            if (dscp->fileType == CM_SCACHETYPE_DFSLINK) {
                int pnc = cm_VolStatus_Notify_DFS_Mapping(dscp, tidPathp,
                                                          spacep->wdata);
                cm_ReleaseSCache(dscp);
                cm_ReleaseUser(userp);
                free(realPathp);
		if (baseFidp)
		    smb_ReleaseFID(baseFidp);
                if ( WANTS_DFS_PATHNAMES(inp) || pnc )
                    return CM_ERROR_PATH_NOT_COVERED;
                else
                    return CM_ERROR_NOSUCHPATH;
            }
#endif /* DFS_SUPPORT */
            code = cm_Lookup(dscp, (lastNamep)?(lastNamep+1):realPathp, CM_FLAG_FOLLOW,
                             userp, &req, &scp);
            if (code == CM_ERROR_NOSUCHFILE || code == CM_ERROR_BPLUS_NOMATCH) {
                code = cm_Lookup(dscp, (lastNamep)?(lastNamep+1):realPathp,
                                 CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD, userp, &req, &scp);
                if (code == 0 && realDirFlag == 1) {
                    cm_ReleaseSCache(scp);
                    cm_ReleaseSCache(dscp);
                    cm_ReleaseUser(userp);
                    free(realPathp);
		    if (baseFidp)
			smb_ReleaseFID(baseFidp);
                    return CM_ERROR_EXISTS;
                }
            }
            /* we have both scp and dscp */
        }
    } else {
        code = cm_NameI(baseDirp, realPathp, CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                        userp, tidPathp, &req, &scp);
#ifdef DFS_SUPPORT
        if (code == 0 && scp->fileType == CM_SCACHETYPE_DFSLINK) {
            int pnc = cm_VolStatus_Notify_DFS_Mapping(scp, tidPathp, realPathp);
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
            free(realPathp);
	    if (baseFidp)
		smb_ReleaseFID(baseFidp);
            if ( WANTS_DFS_PATHNAMES(inp) || pnc )
                return CM_ERROR_PATH_NOT_COVERED;
            else
                return CM_ERROR_NOSUCHPATH;
        }
#endif /* DFS_SUPPORT */
        /* we might have scp but not dscp */
    }

    if (code &&
        code != CM_ERROR_NOSUCHFILE &&
        code != CM_ERROR_NOSUCHPATH &&
        code != CM_ERROR_BPLUS_NOMATCH) {
        cm_ReleaseUser(userp);
        free(realPathp);
        if (baseFidp)
            smb_ReleaseFID(baseFidp);
        return code;
    }

    if (scp)
        foundscp = TRUE;

    if (!foundscp || (fidflags & (SMB_FID_OPENDELETE | SMB_FID_OPENWRITE))) {
        /* look up parent directory */
        /* If we are trying to create a path (i.e. multiple nested directories), then we don't *need*
         * the immediate parent.  We have to work our way up realPathp until we hit something that we
         * recognize.
         */

        /* we might or might not have scp */

        if (dscp == NULL) {
            do {
                clientchar_t *tp;

                code = cm_NameI(baseDirp, spacep->wdata,
                                CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                                userp, tidPathp, &req, &dscp);

#ifdef DFS_SUPPORT
                if (code == 0 && dscp->fileType == CM_SCACHETYPE_DFSLINK) {
                    int pnc = cm_VolStatus_Notify_DFS_Mapping(dscp, tidPathp,
                                                              spacep->wdata);
                    if (scp)
                        cm_ReleaseSCache(scp);
                    cm_ReleaseSCache(dscp);
                    cm_ReleaseUser(userp);
                    free(realPathp);
		    if (baseFidp)
			smb_ReleaseFID(baseFidp);
                    if ( WANTS_DFS_PATHNAMES(inp) || pnc )
                        return CM_ERROR_PATH_NOT_COVERED;
                    else
                        return CM_ERROR_NOSUCHPATH;
                }
#endif /* DFS_SUPPORT */

                if (code &&
                    (code == CM_ERROR_NOSUCHFILE ||
                     code == CM_ERROR_NOSUCHPATH ||
                     code == CM_ERROR_BPLUS_NOMATCH) &&
                    (tp = cm_ClientStrRChr(spacep->wdata, '\\')) &&
                    (createDisp == FILE_CREATE) &&
                    (realDirFlag == 1)) {
                    *tp++ = 0;
                    treeCreate = TRUE;
                    treeStartp = realPathp + (tp - spacep->wdata);

                    if (*tp && !smb_IsLegalFilename(tp)) {
                        cm_ReleaseUser(userp);
                        if (baseFidp)
                            smb_ReleaseFID(baseFidp);
                        free(realPathp);
                        if (scp)
                            cm_ReleaseSCache(scp);
                        return CM_ERROR_BADNTFILENAME;
                    }
                    code = 0;
                }
            } while (dscp == NULL && code == 0);
        } else
            code = 0;

        /* we might have scp and we might have dscp */

        if (baseFidp)
            smb_ReleaseFID(baseFidp);

        if (code) {
            osi_Log0(smb_logp,"NTCreateX parent not found");
            if (scp)
                cm_ReleaseSCache(scp);
            if (dscp)
                cm_ReleaseSCache(dscp);
            cm_ReleaseUser(userp);
            free(realPathp);
            return code;
        }

        if (treeCreate && dscp->fileType == CM_SCACHETYPE_FILE) {
            /* A file exists where we want a directory. */
            if (scp)
                cm_ReleaseSCache(scp);
            cm_ReleaseSCache(dscp);
            cm_ReleaseUser(userp);
            free(realPathp);
            return CM_ERROR_EXISTS;
        }

        if (!lastNamep)
            lastNamep = realPathp;
        else
            lastNamep++;

        if (!smb_IsLegalFilename(lastNamep)) {
            if (scp)
                cm_ReleaseSCache(scp);
            if (dscp)
                cm_ReleaseSCache(dscp);
            cm_ReleaseUser(userp);
            free(realPathp);
            return CM_ERROR_BADNTFILENAME;
        }

        if (!foundscp && !treeCreate) {
            if ( createDisp == FILE_CREATE ||
                 createDisp == FILE_OVERWRITE ||
                 createDisp == FILE_OVERWRITE_IF)
            {
                code = cm_Lookup(dscp, lastNamep,
                                  CM_FLAG_FOLLOW, userp, &req, &scp);
            } else {
                code = cm_Lookup(dscp, lastNamep,
                                 CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                                 userp, &req, &scp);
            }
            if (code && (code != CM_ERROR_NOSUCHFILE && code != CM_ERROR_BPLUS_NOMATCH)) {
                if (dscp)
                    cm_ReleaseSCache(dscp);
                cm_ReleaseUser(userp);
                free(realPathp);
                return code;
            }
        }
        /* we have scp and dscp */
    } else {
        /* we have scp but not dscp */
        if (baseFidp)
            smb_ReleaseFID(baseFidp);
    }

    /* if we get here, if code is 0, the file exists and is represented by
     * scp.  Otherwise, we have to create it.  The dir may be represented
     * by dscp, or we may have found the file directly.  If code is non-zero,
     * scp is NULL.
     */

    /*
     * open the file itself
     * allocate the fidp early so the smb fid can be used by cm_CheckNTOpen()
     */
    fidp = smb_FindFID(vcp, 0, SMB_FLAG_CREATE);
    osi_assertx(fidp, "null smb_fid_t");

    /* save a reference to the user */
    cm_HoldUser(userp);
    fidp->userp = userp;

    if (code == 0 && !treeCreate) {
        code = cm_CheckNTOpen(scp, desiredAccess, shareAccess, createDisp, 0, fidp->fid, userp, &req, &ldp);
        if (code) {
            cm_CheckNTOpenDone(scp, userp, &req, &ldp);
            if (dscp)
                cm_ReleaseSCache(dscp);
            if (scp)
                cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
	    smb_CloseFID(vcp, fidp, NULL, 0);
	    smb_ReleaseFID(fidp);
            free(realPathp);
            return code;
        }
        checkDoneRequired = 1;

	if (createDisp == FILE_CREATE) {
            /* oops, file shouldn't be there */
	    cm_CheckNTOpenDone(scp, userp, &req, &ldp);
            if (dscp)
                cm_ReleaseSCache(dscp);
            if (scp)
                cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
	    smb_CloseFID(vcp, fidp, NULL, 0);
	    smb_ReleaseFID(fidp);
            free(realPathp);
            return CM_ERROR_EXISTS;
        }

        if ( createDisp == FILE_OVERWRITE ||
             createDisp == FILE_OVERWRITE_IF) {

            setAttr.mask = CM_ATTRMASK_LENGTH;
            setAttr.length.LowPart = 0;
            setAttr.length.HighPart = 0;
            /* now watch for a symlink */
            code = 0;
            while (code == 0 && scp->fileType == CM_SCACHETYPE_SYMLINK) {
                targetScp = 0;
                osi_assertx(dscp != NULL, "null cm_scache_t");
                code = cm_EvaluateSymLink(dscp, scp, &targetScp, userp, &req);
                if (code == 0) {
                    /* we have a more accurate file to use (the
                     * target of the symbolic link).  Otherwise,
                     * we'll just use the symlink anyway.
                     */
                    osi_Log2(smb_logp, "symlink vp %x to vp %x",
                              scp, targetScp);
		    cm_CheckNTOpenDone(scp, userp, &req, &ldp);
                    cm_ReleaseSCache(scp);
                    scp = targetScp;
		    code = cm_CheckNTOpen(scp, desiredAccess, shareAccess, createDisp, 0, fidp->fid, userp, &req, &ldp);
		    if (code) {
                        cm_CheckNTOpenDone(scp, userp, &req, &ldp);
			if (dscp)
			    cm_ReleaseSCache(dscp);
			if (scp)
			    cm_ReleaseSCache(scp);
			cm_ReleaseUser(userp);
                        smb_CloseFID(vcp, fidp, NULL, 0);
                        smb_ReleaseFID(fidp);
			free(realPathp);
			return code;
		    }
		}
            }
            code = cm_SetAttr(scp, &setAttr, userp, &req);
            openAction = 3;	/* truncated existing file */
        }
        else
            openAction = 1;	/* found existing file */

    } else if (createDisp == FILE_OPEN || createDisp == FILE_OVERWRITE) {
        /* don't create if not found */
        if (dscp)
            cm_ReleaseSCache(dscp);
        if (scp)
            cm_ReleaseSCache(scp);
        cm_ReleaseUser(userp);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        free(realPathp);
        return CM_ERROR_NOSUCHFILE;
    } else if (realDirFlag == 0 || realDirFlag == -1) {
        osi_assertx(dscp != NULL, "null cm_scache_t");
        osi_Log1(smb_logp, "smb_ReceiveNTCreateX creating file %S",
                  osi_LogSaveClientString(smb_logp, lastNamep));
        openAction = 2;		/* created file */
        setAttr.mask = CM_ATTRMASK_CLIENTMODTIME;
        setAttr.clientModTime = time(NULL);
        smb_SetInitialModeBitsForFile(extAttributes, &setAttr);

        code = cm_Create(dscp, lastNamep, 0, &setAttr, &scp, userp, &req);
        if (code == 0) {
	    created = 1;
	    if (dscp->flags & CM_SCACHEFLAG_ANYWATCH)
		smb_NotifyChange(FILE_ACTION_ADDED,
				 FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_CREATION,
				 dscp, lastNamep, NULL, TRUE);
	} else if (code == CM_ERROR_EXISTS && createDisp != FILE_CREATE) {
            /* Not an exclusive create, and someone else tried
             * creating it already, then we open it anyway.  We
             * don't bother retrying after this, since if this next
             * fails, that means that the file was deleted after we
             * started this call.
             */
            code = cm_Lookup(dscp, lastNamep, CM_FLAG_CASEFOLD,
                              userp, &req, &scp);
            if (code == 0) {
                if (createDisp == FILE_OVERWRITE_IF) {
                    setAttr.mask = CM_ATTRMASK_LENGTH;
                    setAttr.length.LowPart = 0;
                    setAttr.length.HighPart = 0;

                    /* now watch for a symlink */
                    code = 0;
                    while (code == 0 && scp->fileType == CM_SCACHETYPE_SYMLINK) {
                        targetScp = 0;
                        code = cm_EvaluateSymLink(dscp, scp, &targetScp, userp, &req);
                        if (code == 0) {
                            /* we have a more accurate file to use (the
                             * target of the symbolic link).  Otherwise,
                             * we'll just use the symlink anyway.
                             */
                            osi_Log2(smb_logp, "symlink vp %x to vp %x",
                                      scp, targetScp);
                            cm_ReleaseSCache(scp);
                            scp = targetScp;
                        }
                    }
                    code = cm_SetAttr(scp, &setAttr, userp, &req);
                }
            }	/* lookup succeeded */
        }
    } else {
        clientchar_t *tp, *pp;
        clientchar_t *cp; /* This component */
        int clen = 0; /* length of component */
        cm_scache_t *tscp1, *tscp2;
        int isLast = 0;

        /* create directory */
        if ( !treeCreate )
            treeStartp = lastNamep;
        osi_assertx(dscp != NULL, "null cm_scache_t");
        osi_Log1(smb_logp, "smb_ReceiveNTCreateX creating directory [%S]",
                  osi_LogSaveClientString(smb_logp, treeStartp));
        openAction = 2;		/* created directory */

	/* if the request is to create the root directory
	 * it will appear as a directory name of the nul-string
	 * and a code of CM_ERROR_NOSUCHFILE
	 */
	if ( !*treeStartp && (code == CM_ERROR_NOSUCHFILE || code == CM_ERROR_BPLUS_NOMATCH))
	    code = CM_ERROR_EXISTS;

        setAttr.mask = CM_ATTRMASK_CLIENTMODTIME;
        setAttr.clientModTime = time(NULL);
        smb_SetInitialModeBitsForDir(extAttributes, &setAttr);

        pp = treeStartp;
        cp = spacep->wdata;
        tscp1 = dscp;
        cm_HoldSCache(tscp1);
        tscp2 = NULL;

        while (pp && *pp) {
            tp = cm_ClientStrChr(pp, '\\');
            if (!tp) {
                cm_ClientStrCpy(cp, lengthof(spacep->wdata) - (cp - spacep->wdata), pp);
                clen = (int)cm_ClientStrLen(cp);
                isLast = 1; /* indicate last component.  the supplied path never ends in a slash */
            } else {
                clen = (int)(tp - pp);
                cm_ClientStrCpyN(cp, lengthof(spacep->wdata) - (cp - spacep->wdata),
                                 pp, clen);
                *(cp + clen) = 0;
                tp++;
            }
            pp = tp;

            if (clen == 0)
                continue; /* the supplied path can't have consecutive slashes either , but */

            /* cp is the next component to be created. */
            code = cm_MakeDir(tscp1, cp, 0, &setAttr, userp, &req, NULL);
            if (code == 0 && (tscp1->flags & CM_SCACHEFLAG_ANYWATCH))
                smb_NotifyChange(FILE_ACTION_ADDED,
                                 FILE_NOTIFY_CHANGE_DIR_NAME,
                                 tscp1, cp, NULL, TRUE);
            if (code == 0 ||
                (code == CM_ERROR_EXISTS && createDisp != FILE_CREATE)) {
                /* Not an exclusive create, and someone else tried
                 * creating it already, then we open it anyway.  We
                 * don't bother retrying after this, since if this next
                 * fails, that means that the file was deleted after we
                 * started this call.
                 */
                code = cm_Lookup(tscp1, cp, CM_FLAG_CASEFOLD,
                                 userp, &req, &tscp2);
            }
            if (code)
                break;

            if (!isLast) { /* for anything other than dscp, release it unless it's the last one */
                cm_ReleaseSCache(tscp1);
                tscp1 = tscp2; /* Newly created directory will be next parent */
                /* the hold is transfered to tscp1 from tscp2 */
            }
        }

        if (dscp)
            cm_ReleaseSCache(dscp);
        dscp = tscp1;
        if (scp)
            cm_ReleaseSCache(scp);
        scp = tscp2;
        /*
         * if we get here and code == 0, then scp is the last directory created, and dscp is the
         * parent of scp.
         */
    }

    if (code) {
        /* something went wrong creating or truncating the file */
	if (checkDoneRequired)
	    cm_CheckNTOpenDone(scp, userp, &req, &ldp);
        if (scp)
            cm_ReleaseSCache(scp);
        if (dscp)
            cm_ReleaseSCache(dscp);
        cm_ReleaseUser(userp);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        free(realPathp);
        return code;
    }

    /* make sure we have file vs. dir right (only applies for single component case) */
    if (realDirFlag == 0 && scp->fileType != CM_SCACHETYPE_FILE) {
        /* now watch for a symlink */
        code = 0;
        while (code == 0 && scp->fileType == CM_SCACHETYPE_SYMLINK) {
            cm_scache_t * targetScp = 0;
            code = cm_EvaluateSymLink(dscp, scp, &targetScp, userp, &req);
            if (code == 0) {
                /* we have a more accurate file to use (the
                * target of the symbolic link).  Otherwise,
                * we'll just use the symlink anyway.
                */
                osi_Log2(smb_logp, "symlink vp %x to vp %x", scp, targetScp);
		if (checkDoneRequired) {
		    cm_CheckNTOpenDone(scp, userp, &req, &ldp);
                    checkDoneRequired = 0;
                }
                cm_ReleaseSCache(scp);
                scp = targetScp;
            }
        }

        if (scp->fileType != CM_SCACHETYPE_FILE) {
	    if (checkDoneRequired)
		cm_CheckNTOpenDone(scp, userp, &req, &ldp);
            if (dscp)
                cm_ReleaseSCache(dscp);
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
	    smb_CloseFID(vcp, fidp, NULL, 0);
	    smb_ReleaseFID(fidp);
            free(realPathp);
            return CM_ERROR_ISDIR;
        }
    }

    /* (only applies to single component case) */
    if (realDirFlag == 1 && scp->fileType == CM_SCACHETYPE_FILE) {
	if (checkDoneRequired)
	    cm_CheckNTOpenDone(scp, userp, &req, &ldp);
        cm_ReleaseSCache(scp);
        if (dscp)
            cm_ReleaseSCache(dscp);
        cm_ReleaseUser(userp);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        free(realPathp);
        return CM_ERROR_NOTDIR;
    }

    /* If we are restricting sharing, we should do so with a suitable
       share lock. */
    if (scp->fileType == CM_SCACHETYPE_FILE &&
        !(fidflags & SMB_FID_SHARE_WRITE)) {
        cm_key_t key;
        LARGE_INTEGER LOffset, LLength;
        int sLockType;

        LOffset.HighPart = SMB_FID_QLOCK_HIGH;
        LOffset.LowPart = SMB_FID_QLOCK_LOW;
        LLength.HighPart = 0;
        LLength.LowPart = SMB_FID_QLOCK_LENGTH;

        /* If we are not opening the file for writing, then we don't
           try to get an exclusive lock.  No one else should be able to
           get an exclusive lock on the file anyway, although someone
           else can get a shared lock. */
        if ((fidflags & SMB_FID_SHARE_READ) ||
            !(fidflags & SMB_FID_OPENWRITE)) {
            sLockType = LOCKING_ANDX_SHARED_LOCK;
        } else {
            sLockType = 0;
        }

        key = cm_GenerateKey(vcp->vcID, SMB_FID_QLOCK_PID, fidp->fid);

        lock_ObtainWrite(&scp->rw);
        code = cm_Lock(scp, sLockType, LOffset, LLength, key, 0, userp, &req, NULL);
        lock_ReleaseWrite(&scp->rw);

        if (code) {
	    if (checkDoneRequired)
		cm_CheckNTOpenDone(scp, userp, &req, &ldp);
            cm_ReleaseSCache(scp);
            if (dscp)
                cm_ReleaseSCache(dscp);
	    cm_ReleaseUser(userp);
	    smb_CloseFID(vcp, fidp, NULL, 0);
	    smb_ReleaseFID(fidp);
            free(realPathp);
            return CM_ERROR_SHARING_VIOLATION;
        }
    }

    /* Now its safe to release the file server lock obtained by cm_CheckNTOpen() */
    if (checkDoneRequired) {
	cm_CheckNTOpenDone(scp, userp, &req, &ldp);
        checkDoneRequired = 0;
    }

    lock_ObtainMutex(&fidp->mx);
    /* save a pointer to the vnode */
    fidp->scp = scp;    /* Hold transfered to fidp->scp and no longer needed */
    lock_ObtainWrite(&scp->rw);
    scp->flags |= CM_SCACHEFLAG_SMB_FID;
    lock_ReleaseWrite(&scp->rw);
    osi_Log2(smb_logp,"smb_ReceiveNTCreateX fidp 0x%p scp 0x%p", fidp, scp);

    fidp->flags = fidflags;

    /* remember if the file was newly created */
    if (created)
	fidp->flags |= SMB_FID_CREATED;

    /* save parent dir and pathname for delete or change notification */
    if (fidflags & (SMB_FID_OPENDELETE | SMB_FID_OPENWRITE)) {
	osi_Log2(smb_logp,"smb_ReceiveNTCreateX fidp 0x%p dscp 0x%p", fidp, dscp);
        fidp->flags |= SMB_FID_NTOPEN;
        fidp->NTopen_dscp = dscp;
	dscp = NULL;
        fidp->NTopen_pathp = cm_ClientStrDup(lastNamep);
    }
    fidp->NTopen_wholepathp = realPathp;
    lock_ReleaseMutex(&fidp->mx);

    /* we don't need this any longer */
    if (dscp) {
        cm_ReleaseSCache(dscp);
        dscp = NULL;
    }

    cm_Open(scp, 0, userp);

    /* set inp->fid so that later read calls in same msg can find fid */
    inp->fid = fidp->fid;

    lock_ObtainRead(&scp->rw);

    /*
     * Always send the standard response.  Sending the extended
     * response results in the Explorer Shell being unable to
     * access directories at random times.
     */
    if (1 /*!extendedRespRequired */) {
        /* out parms */
        parmSlot = 2;
        smb_SetSMBParmByte(outp, parmSlot, 0);	/* oplock */
        smb_SetSMBParm(outp, parmSlot, fidp->fid); parmSlot++;
        smb_SetSMBParmLong(outp, parmSlot, openAction); parmSlot += 2;
        cm_LargeSearchTimeFromUnixTime(&ft, scp->clientModTime);
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&ft); parmSlot += 4;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&ft); parmSlot += 4;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&ft); parmSlot += 4;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&ft); parmSlot += 4;
        smb_SetSMBParmLong(outp, parmSlot, smb_ExtAttributes(scp));
        parmSlot += 2;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&scp->length); parmSlot += 4;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&scp->length); parmSlot += 4;
        smb_SetSMBParm(outp, parmSlot, 0); parmSlot++;	/* filetype */
        smb_SetSMBParm(outp, parmSlot, NO_REPARSETAG|NO_SUBSTREAMS|NO_EAS);
        parmSlot++;	/* dev state */
        smb_SetSMBParmByte(outp, parmSlot,
                            (scp->fileType == CM_SCACHETYPE_DIRECTORY ||
                              scp->fileType == CM_SCACHETYPE_MOUNTPOINT ||
                              scp->fileType == CM_SCACHETYPE_INVALID) ? 1 : 0); /* is a dir? */
        smb_SetSMBDataLength(outp, 0);
    } else {
        /* out parms */
        parmSlot = 2;
        smb_SetSMBParmByte(outp, parmSlot, 0);	/* oplock */
        smb_SetSMBParm(outp, parmSlot, fidp->fid); parmSlot++;
        smb_SetSMBParmLong(outp, parmSlot, openAction); parmSlot += 2;
        cm_LargeSearchTimeFromUnixTime(&ft, scp->clientModTime);
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&ft); parmSlot += 4;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&ft); parmSlot += 4;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&ft); parmSlot += 4;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&ft); parmSlot += 4;
        smb_SetSMBParmLong(outp, parmSlot, smb_ExtAttributes(scp));
        parmSlot += 2;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&scp->length); parmSlot += 4;
        smb_SetSMBParmDouble(outp, parmSlot, (char *)&scp->length); parmSlot += 4;
        smb_SetSMBParm(outp, parmSlot, 0); parmSlot++;	/* filetype */
        smb_SetSMBParm(outp, parmSlot, NO_REPARSETAG|NO_SUBSTREAMS|NO_EAS);
        parmSlot++;	/* dev state */
        smb_SetSMBParmByte(outp, parmSlot,
                            (scp->fileType == CM_SCACHETYPE_DIRECTORY ||
                              scp->fileType == CM_SCACHETYPE_MOUNTPOINT ||
                              scp->fileType == CM_SCACHETYPE_INVALID) ? 1 : 0); /* is a dir? */
        /* Setting the GUID results in a failure with cygwin */
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        /* Maxmimal access rights */
        smb_SetSMBParmLong(outp, parmSlot, 0x001f01ff); parmSlot += 2;
        /* Guest access rights */
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        smb_SetSMBDataLength(outp, 0);
    }

    if ((fidp->flags & SMB_FID_EXECUTABLE) &&
        LargeIntegerGreaterThanZero(scp->length) &&
        !(scp->flags & CM_SCACHEFLAG_PREFETCHING)) {
        prefetch = 1;
    }
    lock_ReleaseRead(&scp->rw);

    if (prefetch) {
        rock_BkgFetch_t *rockp = malloc(sizeof(*rockp));

        if (rockp) {
            rockp->base.LowPart = 0;
            rockp->base.HighPart = 0;
            rockp->length = scp->length;

            cm_QueueBKGRequest(scp, cm_BkgPrefetch, rockp, userp, &req);

            /* rock is freed by cm_BkgDaemon */
        }
    }

    osi_Log2(smb_logp, "SMB NT CreateX opening fid %d path %S", fidp->fid,
              osi_LogSaveClientString(smb_logp, realPathp));

    cm_ReleaseUser(userp);
    smb_ReleaseFID(fidp);

    /* Can't free realPathp if we get here since
       fidp->NTopen_wholepathp is pointing there */

    /* leave scp held since we put it in fidp->scp */
    return 0;
}

/*
 * A lot of stuff copied verbatim from NT Create&X to NT Tran Create.
 * Instead, ultimately, would like to use a subroutine for common code.
 */

/* NT_TRANSACT_CREATE (SMB_COM_NT_TRANSACT) */
long smb_ReceiveNTTranCreate(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    clientchar_t *pathp, *realPathp;
    long code = 0;
    cm_space_t *spacep;
    cm_user_t *userp;
    cm_scache_t *dscp;		/* parent dir */
    cm_scache_t *scp;		/* file to create or open */
    cm_scache_t *targetScp;     /* if scp is a symlink */
    cm_attr_t setAttr;
    clientchar_t *lastNamep;
    unsigned long nameLength;
    unsigned int flags;
    unsigned int requestOpLock;
    unsigned int requestBatchOpLock;
    unsigned int mustBeDir;
    unsigned int extendedRespRequired;
    int realDirFlag;
    unsigned int desiredAccess;
    unsigned int allocSize;
    unsigned int shareAccess;
    unsigned int extAttributes;
    unsigned int createDisp;
    unsigned int sdLen;
    unsigned int eaLen;
    unsigned int impLevel;
    unsigned int secFlags;
    unsigned int createOptions;
    unsigned short baseFid;
    smb_fid_t *baseFidp;
    smb_fid_t *fidp;
    cm_scache_t *baseDirp;
    unsigned short openAction;
    int parmSlot;
    long fidflags;
    FILETIME ft;
    clientchar_t *tidPathp;
    BOOL foundscp;
    int parmOffset, dataOffset;
    char *parmp;
    ULONG *lparmp;
    char *outData;
    cm_req_t req;
    int created = 0;
    int prefetch = 0;
    cm_lock_data_t *ldp = NULL;
    int checkDoneRequired = 0;

    smb_InitReq(&req);

    foundscp = FALSE;
    scp = NULL;

    parmOffset = smb_GetSMBOffsetParm(inp, 11, 1)
        | (smb_GetSMBOffsetParm(inp, 12, 1) << 16);
    parmp = inp->data + parmOffset;
    lparmp = (ULONG *) parmp;

    flags = lparmp[0];
    requestOpLock = flags & REQUEST_OPLOCK;
    requestBatchOpLock = flags & REQUEST_BATCH_OPLOCK;
    mustBeDir = flags & OPEN_DIRECTORY;
    extendedRespRequired = flags & EXTENDED_RESPONSE_REQUIRED;

    /*
     * Why all of a sudden 32-bit FID?
     * We will reject all bits higher than 16.
     */
    if (lparmp[1] & 0xFFFF0000)
        return CM_ERROR_INVAL;
    baseFid = (unsigned short)lparmp[1];
    desiredAccess = lparmp[2];
    allocSize = lparmp[3];
    extAttributes = lparmp[5];
    shareAccess = lparmp[6];
    createDisp = lparmp[7];
    createOptions = lparmp[8];
    sdLen = lparmp[9];
    eaLen = lparmp[10];
    nameLength = lparmp[11];    /* spec says chars but appears to be bytes */
    impLevel = lparmp[12];
    secFlags = lparmp[13];

    /* mustBeDir is never set; createOptions directory bit seems to be
     * more important
     */
    if (createOptions & FILE_DIRECTORY_FILE)
        realDirFlag = 1;
    else if (createOptions & FILE_NON_DIRECTORY_FILE)
        realDirFlag = 0;
    else
        realDirFlag = -1;

    pathp = smb_ParseStringCb(inp, (parmp + (13 * sizeof(ULONG)) + sizeof(UCHAR)),
                               nameLength, NULL, SMB_STRF_ANSIPATH);
    /* Sometimes path is not nul-terminated, so we make a copy. */
    realPathp = malloc(nameLength+sizeof(clientchar_t));
    memcpy(realPathp, pathp, nameLength);
    realPathp[nameLength/sizeof(clientchar_t)] = 0;
    spacep = cm_GetSpace();
    /* smb_StripLastComponent will strip "::$DATA" if present */
    smb_StripLastComponent(spacep->wdata, &lastNamep, realPathp);

    osi_Log1(smb_logp,"NTTranCreate %S",osi_LogSaveStringW(smb_logp,realPathp));
    osi_Log4(smb_logp,"... da[%x],ea[%x],sa[%x],cd[%x]",desiredAccess,extAttributes,shareAccess,createDisp);
    osi_Log4(smb_logp,"... co[%x],sdl[%x],eal[%x],as[%x],flags[%x]",createOptions,sdLen,eaLen,allocSize);
    osi_Log3(smb_logp,"... imp[%x],sec[%x],flags[%x]", impLevel, secFlags, flags);

    if ( realDirFlag == 1 &&
         ( createDisp == FILE_SUPERSEDE ||
           createDisp == FILE_OVERWRITE ||
           createDisp == FILE_OVERWRITE_IF))
    {
        osi_Log0(smb_logp, "NTTranCreate rejecting invalid readDirFlag and createDisp combination");
        cm_FreeSpace(spacep);
        free(realPathp);
        return CM_ERROR_INVAL;
    }

    /*
     * Nothing here to handle SMB_IOCTL_FILENAME.
     * Will add it if necessary.
     */

    if (!cm_IsValidClientString(realPathp)) {
#ifdef DEBUG
        clientchar_t * hexp;

        hexp = cm_GetRawCharsAlloc(realPathp, -1);
        osi_Log1(smb_logp, "NTTranCreate rejecting invalid name. [%S]",
                 osi_LogSaveClientString(smb_logp, hexp));
        if (hexp)
        free(hexp);
#else
        osi_Log0(smb_logp, "NTTranCreate rejecting invalid name.");
#endif
        cm_FreeSpace(spacep);
        free(realPathp);
        return CM_ERROR_BADNTFILENAME;
    }

    userp = smb_GetUserFromVCP(vcp, inp);
    if (!userp) {
    	osi_Log1(smb_logp, "NTTranCreate invalid user [%d]", ((smb_t *) inp)->uid);
        cm_FreeSpace(spacep);
    	free(realPathp);
    	return CM_ERROR_INVAL;
    }

    if (baseFid == 0) {
	baseFidp = NULL;
        baseDirp = cm_RootSCachep(cm_rootUserp, &req);
        code = smb_LookupTIDPath(vcp, ((smb_t *)inp)->tid, &tidPathp);
        if (code == CM_ERROR_TIDIPC) {
            /* Attempt to use a TID allocated for IPC.  The client
             * is probably looking for DCE RPC end points which we
             * don't support OR it could be looking to make a DFS
             * referral request.
             */
            osi_Log0(smb_logp, "NTTranCreate received IPC TID");
#ifndef DFS_SUPPORT
            cm_FreeSpace(spacep);
            free(realPathp);
            cm_ReleaseUser(userp);
            return CM_ERROR_NOSUCHPATH;
#endif
        }
    } else {
        baseFidp = smb_FindFID(vcp, baseFid, 0);
        if (!baseFidp) {
            osi_Log2(smb_logp, "NTTranCreate Unknown SMB Fid vcp 0x%p fid %d",
                      vcp, baseFid);
            cm_FreeSpace(spacep);
            free(realPathp);
            cm_ReleaseUser(userp);
            return CM_ERROR_BADFD;
        }

        if (baseFidp->scp && (baseFidp->scp->flags & CM_SCACHEFLAG_DELETED)) {
            cm_FreeSpace(spacep);
            free(realPathp);
            cm_ReleaseUser(userp);
	    smb_CloseFID(vcp, baseFidp, NULL, 0);
            smb_ReleaseFID(baseFidp);
            return CM_ERROR_NOSUCHPATH;
        }

        baseDirp = baseFidp->scp;
        tidPathp = NULL;
    }

    /* compute open mode */
    fidflags = 0;
    if (desiredAccess & DELETE)
        fidflags |= SMB_FID_OPENDELETE;
    if (desiredAccess & (AFS_ACCESS_READ|AFS_ACCESS_EXECUTE))
        fidflags |= SMB_FID_OPENREAD_LISTDIR;
    if (desiredAccess & AFS_ACCESS_WRITE)
        fidflags |= SMB_FID_OPENWRITE;
    if (createOptions & FILE_DELETE_ON_CLOSE)
        fidflags |= SMB_FID_DELONCLOSE;
    if (createOptions & FILE_SEQUENTIAL_ONLY && !(createOptions & FILE_RANDOM_ACCESS))
	fidflags |= SMB_FID_SEQUENTIAL;
    if (createOptions & FILE_RANDOM_ACCESS && !(createOptions & FILE_SEQUENTIAL_ONLY))
	fidflags |= SMB_FID_RANDOM;
    if (createOptions & FILE_OPEN_REPARSE_POINT)
        osi_Log0(smb_logp, "NTTranCreate Open Reparse Point");
    if (smb_IsExecutableFileName(lastNamep))
        fidflags |= SMB_FID_EXECUTABLE;

    /* And the share mode */
    if (shareAccess & FILE_SHARE_READ)
        fidflags |= SMB_FID_SHARE_READ;
    if (shareAccess & FILE_SHARE_WRITE)
        fidflags |= SMB_FID_SHARE_WRITE;

    dscp = NULL;
    code = 0;

    code = cm_NameI(baseDirp, spacep->wdata, CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                    userp, tidPathp, &req, &dscp);
    if (code == 0) {
#ifdef DFS_SUPPORT
        if (dscp->fileType == CM_SCACHETYPE_DFSLINK) {
            int pnc = cm_VolStatus_Notify_DFS_Mapping(dscp, tidPathp, spacep->wdata);
            cm_ReleaseSCache(dscp);
            cm_ReleaseUser(userp);
            cm_FreeSpace(spacep);
            free(realPathp);
            if (baseFidp)
                smb_ReleaseFID(baseFidp);
            if ( WANTS_DFS_PATHNAMES(inp) || pnc )
                return CM_ERROR_PATH_NOT_COVERED;
            else
                return CM_ERROR_NOSUCHPATH;
        }
#endif /* DFS_SUPPORT */
        code = cm_Lookup(dscp, (lastNamep)?(lastNamep+1):realPathp, CM_FLAG_FOLLOW,
                         userp, &req, &scp);
        if (code == CM_ERROR_NOSUCHFILE || code == CM_ERROR_BPLUS_NOMATCH) {

            code = cm_Lookup(dscp, (lastNamep)?(lastNamep+1):realPathp,
                             CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD, userp, &req, &scp);
            if (code == 0 && realDirFlag == 1 &&
                (createDisp == FILE_OPEN ||
                 createDisp == FILE_OVERWRITE ||
                 createDisp == FILE_OVERWRITE_IF)) {
                cm_ReleaseSCache(scp);
                cm_ReleaseSCache(dscp);
                cm_ReleaseUser(userp);
                cm_FreeSpace(spacep);
                free(realPathp);
                if (baseFidp)
                    smb_ReleaseFID(baseFidp);
                return CM_ERROR_EXISTS;
            }
        }
    } else {
        cm_ReleaseUser(userp);
        if (baseFidp)
            smb_ReleaseFID(baseFidp);
        cm_FreeSpace(spacep);
        free(realPathp);
        return CM_ERROR_NOSUCHPATH;
    }

    if (code == 0)
        foundscp = TRUE;

    if (code == CM_ERROR_NOSUCHFILE ||
        code == CM_ERROR_NOSUCHPATH ||
        code == CM_ERROR_BPLUS_NOMATCH ||
        (code == 0 && (fidflags & (SMB_FID_OPENDELETE | SMB_FID_OPENWRITE)))) {
        code = 0;

        cm_FreeSpace(spacep);

        if (baseFidp)
            smb_ReleaseFID(baseFidp);

        if (code) {
            cm_ReleaseSCache(dscp);
            cm_ReleaseUser(userp);
            free(realPathp);
            return code;
        }

        if (!lastNamep)
	    lastNamep = realPathp;
        else
	    lastNamep++;

        if (!smb_IsLegalFilename(lastNamep)) {
            cm_ReleaseSCache(dscp);
            cm_ReleaseUser(userp);
            free(realPathp);
            return CM_ERROR_BADNTFILENAME;
        }

        if (!foundscp) {
            if (createDisp == FILE_CREATE || createDisp == FILE_OVERWRITE_IF || createDisp == FILE_OPEN_IF) {
                code = cm_Lookup(dscp, lastNamep,
                                  CM_FLAG_FOLLOW, userp, &req, &scp);
            } else {
                code = cm_Lookup(dscp, lastNamep,
                                 CM_FLAG_FOLLOW | CM_FLAG_CASEFOLD,
                                 userp, &req, &scp);
            }
            if (code && code != CM_ERROR_NOSUCHFILE && code != CM_ERROR_BPLUS_NOMATCH) {
                cm_ReleaseSCache(dscp);
                cm_ReleaseUser(userp);
                free(realPathp);
                return code;
            }
        }
    } else {
        if (baseFidp)
            smb_ReleaseFID(baseFidp);
        cm_FreeSpace(spacep);
    }

    /* open the file itself */
    fidp = smb_FindFID(vcp, 0, SMB_FLAG_CREATE);
    osi_assertx(fidp, "null smb_fid_t");

    /* save a reference to the user */
    cm_HoldUser(userp);
    fidp->userp = userp;

    /* if we get here, if code is 0, the file exists and is represented by
     * scp.  Otherwise, we have to create it.  The dir may be represented
     * by dscp, or we may have found the file directly.  If code is non-zero,
     * scp is NULL.
     */
    if (code == 0) {
        code = cm_CheckNTOpen(scp, desiredAccess, shareAccess, createDisp, 0, fidp->fid, userp, &req, &ldp);
        if (code) {
            cm_CheckNTOpenDone(scp, userp, &req, &ldp);
            cm_ReleaseSCache(dscp);
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
	    smb_CloseFID(vcp, fidp, NULL, 0);
	    smb_ReleaseFID(fidp);
            free(realPathp);
            return code;
        }
        checkDoneRequired = 1;

        if (createDisp == FILE_CREATE) {
            /* oops, file shouldn't be there */
	    cm_CheckNTOpenDone(scp, userp, &req, &ldp);
            cm_ReleaseSCache(dscp);
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
	    smb_CloseFID(vcp, fidp, NULL, 0);
	    smb_ReleaseFID(fidp);
            free(realPathp);
            return CM_ERROR_EXISTS;
        }

        if (createDisp == FILE_OVERWRITE ||
            createDisp == FILE_OVERWRITE_IF) {
            setAttr.mask = CM_ATTRMASK_LENGTH;
            setAttr.length.LowPart = 0;
            setAttr.length.HighPart = 0;

            /* now watch for a symlink */
            code = 0;
            while (code == 0 && scp->fileType == CM_SCACHETYPE_SYMLINK) {
                targetScp = 0;
                code = cm_EvaluateSymLink(dscp, scp, &targetScp, userp, &req);
                if (code == 0) {
                    /* we have a more accurate file to use (the
                    * target of the symbolic link).  Otherwise,
                    * we'll just use the symlink anyway.
                    */
                    osi_Log2(smb_logp, "symlink vp %x to vp %x",
                              scp, targetScp);
		    cm_CheckNTOpenDone(scp, userp, &req, &ldp);
                    cm_ReleaseSCache(scp);
                    scp = targetScp;
		    code = cm_CheckNTOpen(scp, desiredAccess, shareAccess, createDisp, 0, fidp->fid, userp, &req, &ldp);
		    if (code) {
                        cm_CheckNTOpenDone(scp, userp, &req, &ldp);
                        cm_ReleaseSCache(dscp);
			if (scp)
			    cm_ReleaseSCache(scp);
			cm_ReleaseUser(userp);
                        smb_CloseFID(vcp, fidp, NULL, 0);
                        smb_ReleaseFID(fidp);
			free(realPathp);
			return code;
		    }
                }
            }
            code = cm_SetAttr(scp, &setAttr, userp, &req);
            openAction = 3;	/* truncated existing file */
        }
        else openAction = 1;	/* found existing file */
    }
    else if (createDisp == FILE_OPEN || createDisp == FILE_OVERWRITE) {
        /* don't create if not found */
        cm_ReleaseSCache(dscp);
        cm_ReleaseUser(userp);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        free(realPathp);
        return CM_ERROR_NOSUCHFILE;
    }
    else if (realDirFlag == 0 || realDirFlag == -1) {
        /* createDisp: FILE_SUPERSEDE, FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE_IF */
        osi_Log1(smb_logp, "smb_ReceiveNTTranCreate creating file %S",
                  osi_LogSaveClientString(smb_logp, lastNamep));
        openAction = 2;		/* created file */
        setAttr.mask = CM_ATTRMASK_CLIENTMODTIME;
        setAttr.clientModTime = time(NULL);
        smb_SetInitialModeBitsForFile(extAttributes, &setAttr);

        code = cm_Create(dscp, lastNamep, 0, &setAttr, &scp, userp,
                          &req);
        if (code == 0) {
	    created = 1;
	    if (dscp->flags & CM_SCACHEFLAG_ANYWATCH)
		smb_NotifyChange(FILE_ACTION_ADDED,
				 FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_CREATION,
				 dscp, lastNamep, NULL, TRUE);
	} else if (code == CM_ERROR_EXISTS && createDisp != FILE_CREATE) {
            /* Not an exclusive create, and someone else tried
             * creating it already, then we open it anyway.  We
             * don't bother retrying after this, since if this next
             * fails, that means that the file was deleted after we
             * started this call.
             */
            code = cm_Lookup(dscp, lastNamep, CM_FLAG_CASEFOLD,
                              userp, &req, &scp);
            if (code == 0) {
                if (createDisp == FILE_OVERWRITE_IF) {
                    setAttr.mask = CM_ATTRMASK_LENGTH;
                    setAttr.length.LowPart = 0;
                    setAttr.length.HighPart = 0;

                    /* now watch for a symlink */
                    code = 0;
                    while (code == 0 && scp->fileType == CM_SCACHETYPE_SYMLINK) {
                        targetScp = 0;
                        code = cm_EvaluateSymLink(dscp, scp, &targetScp, userp, &req);
                        if (code == 0) {
                            /* we have a more accurate file to use (the
                            * target of the symbolic link).  Otherwise,
                            * we'll just use the symlink anyway.
                            */
                            osi_Log2(smb_logp, "symlink vp %x to vp %x",
                                      scp, targetScp);
                            cm_ReleaseSCache(scp);
                            scp = targetScp;
                        }
                    }
                    code = cm_SetAttr(scp, &setAttr, userp, &req);
                }
            }	/* lookup succeeded */
        }
    } else {
        /* create directory; createDisp: FILE_CREATE, FILE_OPEN_IF */
        osi_Log1(smb_logp,
                  "smb_ReceiveNTTranCreate creating directory %S",
                  osi_LogSaveClientString(smb_logp, lastNamep));
        openAction = 2;		/* created directory */
        setAttr.mask = CM_ATTRMASK_CLIENTMODTIME;
        setAttr.clientModTime = time(NULL);
        smb_SetInitialModeBitsForDir(extAttributes, &setAttr);

        code = cm_MakeDir(dscp, lastNamep, 0, &setAttr, userp, &req, NULL);
        if (code == 0 && (dscp->flags & CM_SCACHEFLAG_ANYWATCH))
            smb_NotifyChange(FILE_ACTION_ADDED,
                              FILE_NOTIFY_CHANGE_DIR_NAME,
                              dscp, lastNamep, NULL, TRUE);
        if (code == 0 ||
            (code == CM_ERROR_EXISTS && createDisp != FILE_CREATE)) {
            /* Not an exclusive create, and someone else tried
             * creating it already, then we open it anyway.  We
             * don't bother retrying after this, since if this next
             * fails, that means that the file was deleted after we
             * started this call.
             */
            code = cm_Lookup(dscp, lastNamep, CM_FLAG_CASEFOLD,
                              userp, &req, &scp);
        }
    }

    if (code) {
        /* something went wrong creating or truncating the file */
	if (checkDoneRequired)
	    cm_CheckNTOpenDone(scp, userp, &req, &ldp);
	if (scp)
            cm_ReleaseSCache(scp);
        cm_ReleaseUser(userp);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        free(realPathp);
        return code;
    }

    /* make sure we have file vs. dir right */
    if (realDirFlag == 0 && scp->fileType != CM_SCACHETYPE_FILE) {
        /* now watch for a symlink */
        code = 0;
        while (code == 0 && scp->fileType == CM_SCACHETYPE_SYMLINK) {
            targetScp = 0;
            code = cm_EvaluateSymLink(dscp, scp, &targetScp, userp, &req);
            if (code == 0) {
                /* we have a more accurate file to use (the
                * target of the symbolic link).  Otherwise,
                * we'll just use the symlink anyway.
                */
                osi_Log2(smb_logp, "symlink vp %x to vp %x",
                          scp, targetScp);
		if (checkDoneRequired) {
		    cm_CheckNTOpenDone(scp, userp, &req, &ldp);
                    checkDoneRequired = 0;
                }
                cm_ReleaseSCache(scp);
                scp = targetScp;
            }
        }

        if (scp->fileType != CM_SCACHETYPE_FILE) {
	    if (checkDoneRequired)
		cm_CheckNTOpenDone(scp, userp, &req, &ldp);
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
	    smb_CloseFID(vcp, fidp, NULL, 0);
	    smb_ReleaseFID(fidp);
            free(realPathp);
            return CM_ERROR_ISDIR;
        }
    }

    if (realDirFlag == 1 && scp->fileType == CM_SCACHETYPE_FILE) {
	if (checkDoneRequired)
	    cm_CheckNTOpenDone(scp, userp, &req, &ldp);
        cm_ReleaseSCache(scp);
        cm_ReleaseUser(userp);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        free(realPathp);
        return CM_ERROR_NOTDIR;
    }

    /* If we are restricting sharing, we should do so with a suitable
       share lock. */
    if (scp->fileType == CM_SCACHETYPE_FILE &&
        !(fidflags & SMB_FID_SHARE_WRITE)) {
        cm_key_t key;
        LARGE_INTEGER LOffset, LLength;
        int sLockType;

        LOffset.HighPart = SMB_FID_QLOCK_HIGH;
        LOffset.LowPart = SMB_FID_QLOCK_LOW;
        LLength.HighPart = 0;
        LLength.LowPart = SMB_FID_QLOCK_LENGTH;

        /* Similar to what we do in handling NTCreateX.  We get a
           shared lock if we are only opening the file for reading. */
        if ((fidflags & SMB_FID_SHARE_READ) ||
            !(fidflags & SMB_FID_OPENWRITE)) {
            sLockType = LOCKING_ANDX_SHARED_LOCK;
        } else {
            sLockType = 0;
        }

        key = cm_GenerateKey(vcp->vcID, SMB_FID_QLOCK_PID, fidp->fid);

        lock_ObtainWrite(&scp->rw);
        code = cm_Lock(scp, sLockType, LOffset, LLength, key, 0, userp, &req, NULL);
        lock_ReleaseWrite(&scp->rw);

        if (code) {
	    if (checkDoneRequired)
		cm_CheckNTOpenDone(scp, userp, &req, &ldp);
            cm_ReleaseSCache(scp);
            cm_ReleaseUser(userp);
	    /* Shouldn't this be smb_CloseFID()?  fidp->flags = SMB_FID_DELETE; */
	    smb_CloseFID(vcp, fidp, NULL, 0);
	    smb_ReleaseFID(fidp);
	    free(realPathp);
            return CM_ERROR_SHARING_VIOLATION;
        }
    }

    /* Now its safe to drop the file server lock obtained by cm_CheckNTOpen() */
    if (checkDoneRequired) {
	cm_CheckNTOpenDone(scp, userp, &req, &ldp);
        checkDoneRequired = 0;
    }

    lock_ObtainMutex(&fidp->mx);
    /* save a pointer to the vnode */
    fidp->scp = scp;
    lock_ObtainWrite(&scp->rw);
    scp->flags |= CM_SCACHEFLAG_SMB_FID;
    lock_ReleaseWrite(&scp->rw);
    osi_Log2(smb_logp,"smb_ReceiveNTTranCreate fidp 0x%p scp 0x%p", fidp, scp);

    fidp->flags = fidflags;

    /* remember if the file was newly created */
    if (created)
	fidp->flags |= SMB_FID_CREATED;

    /* save parent dir and pathname for deletion or change notification */
    if (fidflags & (SMB_FID_OPENDELETE | SMB_FID_OPENWRITE)) {
        fidp->flags |= SMB_FID_NTOPEN;
        fidp->NTopen_dscp = dscp;
	osi_Log2(smb_logp,"smb_ReceiveNTTranCreate fidp 0x%p dscp 0x%p", fidp, dscp);
	dscp = NULL;
        fidp->NTopen_pathp = cm_ClientStrDup(lastNamep);
    }
    fidp->NTopen_wholepathp = realPathp;
    lock_ReleaseMutex(&fidp->mx);

    /* we don't need this any longer */
    if (dscp)
        cm_ReleaseSCache(dscp);

    cm_Open(scp, 0, userp);

    /* set inp->fid so that later read calls in same msg can find fid */
    inp->fid = fidp->fid;

    /* check whether we are required to send an extended response */
    if (!extendedRespRequired) {
        /* out parms */
        parmOffset = 8*4 + 39;
        parmOffset += 1;	/* pad to 4 */
        dataOffset = parmOffset + 70;

        parmSlot = 1;
        outp->oddByte = 1;
        /* Total Parameter Count */
        smb_SetSMBParmLong(outp, parmSlot, 70); parmSlot += 2;
        /* Total Data Count */
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        /* Parameter Count */
        smb_SetSMBParmLong(outp, parmSlot, 70); parmSlot += 2;
        /* Parameter Offset */
        smb_SetSMBParmLong(outp, parmSlot, parmOffset); parmSlot += 2;
        /* Parameter Displacement */
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        /* Data Count */
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        /* Data Offset */
        smb_SetSMBParmLong(outp, parmSlot, dataOffset); parmSlot += 2;
        /* Data Displacement */
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        smb_SetSMBParmByte(outp, parmSlot, 0);	/* Setup Count */
        smb_SetSMBDataLength(outp, 70);

        lock_ObtainRead(&scp->rw);
        outData = smb_GetSMBData(outp, NULL);
        outData++;			/* round to get to parmOffset */
        *outData = 0; outData++;	/* oplock */
        *outData = 0; outData++;	/* reserved */
        *((USHORT *)outData) = fidp->fid; outData += 2;	/* fid */
        *((ULONG *)outData) = openAction; outData += 4;
        *((ULONG *)outData) = 0; outData += 4;	/* EA error offset */
        cm_LargeSearchTimeFromUnixTime(&ft, scp->clientModTime);
        *((FILETIME *)outData) = ft; outData += 8;	/* creation time */
        *((FILETIME *)outData) = ft; outData += 8;	/* last access time */
        *((FILETIME *)outData) = ft; outData += 8;	/* last write time */
        *((FILETIME *)outData) = ft; outData += 8;	/* change time */
        *((ULONG *)outData) = smb_ExtAttributes(scp); outData += 4;
        *((LARGE_INTEGER *)outData) = scp->length; outData += 8; /* alloc sz */
        *((LARGE_INTEGER *)outData) = scp->length; outData += 8; /* EOF */
        *((USHORT *)outData) = 0; outData += 2;	/* filetype */
        *((USHORT *)outData) = NO_REPARSETAG|NO_SUBSTREAMS|NO_EAS;
        outData += 2;	/* dev state */
        *((USHORT *)outData) = ((scp->fileType == CM_SCACHETYPE_DIRECTORY ||
				scp->fileType == CM_SCACHETYPE_MOUNTPOINT ||
				scp->fileType == CM_SCACHETYPE_INVALID) ? 1 : 0);
        outData += 2;	/* is a dir? */
    } else {
        /* out parms */
        parmOffset = 8*4 + 39;
        parmOffset += 1;	/* pad to 4 */
        dataOffset = parmOffset + 104;

        parmSlot = 1;
        outp->oddByte = 1;
        /* Total Parameter Count */
        smb_SetSMBParmLong(outp, parmSlot, 101); parmSlot += 2;
        /* Total Data Count */
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        /* Parameter Count */
        smb_SetSMBParmLong(outp, parmSlot, 101); parmSlot += 2;
        /* Parameter Offset */
        smb_SetSMBParmLong(outp, parmSlot, parmOffset); parmSlot += 2;
        /* Parameter Displacement */
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        /* Data Count */
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        /* Data Offset */
        smb_SetSMBParmLong(outp, parmSlot, dataOffset); parmSlot += 2;
        /* Data Displacement */
        smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
        smb_SetSMBParmByte(outp, parmSlot, 0);	/* Setup Count */
        smb_SetSMBDataLength(outp, 105);

        lock_ObtainRead(&scp->rw);
        outData = smb_GetSMBData(outp, NULL);
        outData++;			/* round to get to parmOffset */
        *outData = 0; outData++;	/* oplock */
        *outData = 1; outData++;	/* response type */
        *((USHORT *)outData) = fidp->fid; outData += 2;	/* fid */
        *((ULONG *)outData) = openAction; outData += 4;
        *((ULONG *)outData) = 0; outData += 4;	/* EA error offset */
        cm_LargeSearchTimeFromUnixTime(&ft, scp->clientModTime);
        *((FILETIME *)outData) = ft; outData += 8;	/* creation time */
        *((FILETIME *)outData) = ft; outData += 8;	/* last access time */
        *((FILETIME *)outData) = ft; outData += 8;	/* last write time */
        *((FILETIME *)outData) = ft; outData += 8;	/* change time */
        *((ULONG *)outData) = smb_ExtAttributes(scp); outData += 4;
        *((LARGE_INTEGER *)outData) = scp->length; outData += 8; /* alloc sz */
        *((LARGE_INTEGER *)outData) = scp->length; outData += 8; /* EOF */
        *((USHORT *)outData) = 0; outData += 2;	/* filetype */
        *((USHORT *)outData) = NO_REPARSETAG|NO_SUBSTREAMS|NO_EAS;
        outData += 2;	/* dev state */
        *((USHORT *)outData) = ((scp->fileType == CM_SCACHETYPE_DIRECTORY ||
				scp->fileType == CM_SCACHETYPE_MOUNTPOINT ||
				scp->fileType == CM_SCACHETYPE_INVALID) ? 1 : 0);
        outData += 1;	/* is a dir? */
        /* Setting the GUID results in failures with cygwin */
        memset(outData,0,24); outData += 24; /* GUID */
        *((ULONG *)outData) = 0x001f01ffL; outData += 4; /* Maxmimal access rights */
        *((ULONG *)outData) = 0; outData += 4; /* Guest Access rights */
    }

    if ((fidp->flags & SMB_FID_EXECUTABLE) &&
         LargeIntegerGreaterThanZero(scp->length) &&
         !(scp->flags & CM_SCACHEFLAG_PREFETCHING)) {
        prefetch = 1;
    }
    lock_ReleaseRead(&scp->rw);

    if (prefetch) {
        rock_BkgFetch_t *rockp = malloc(sizeof(*rockp));

        if (rockp) {
            rockp->base.LowPart = 0;
            rockp->base.HighPart = 0;
            rockp->length = scp->length;

            cm_QueueBKGRequest(scp, cm_BkgPrefetch, rockp, userp, &req);

            /* rock is freed by cm_BkgDaemon */
        }
    }

    osi_Log1(smb_logp, "SMB NTTranCreate opening fid %d", fidp->fid);

    cm_ReleaseUser(userp);
    smb_ReleaseFID(fidp);

    /* free(realPathp); Can't free realPathp here because fidp->NTopen_wholepathp points there */
    /* leave scp held since we put it in fidp->scp */
    return 0;
}

/* NT_TRANSACT_NOTIFY_CHANGE (SMB_COM_NT_TRANSACT) */
long smb_ReceiveNTTranNotifyChange(smb_vc_t *vcp, smb_packet_t *inp,
	smb_packet_t *outp)
{
    smb_packet_t *savedPacketp;
    ULONG filter;
    USHORT fid, watchtree;
    smb_fid_t *fidp;
    cm_scache_t *scp;

    filter = smb_GetSMBParm(inp, 19) |
             (smb_GetSMBParm(inp, 20) << 16);
    fid = smb_GetSMBParm(inp, 21);
    watchtree = (smb_GetSMBParm(inp, 22) & 0xff) ? 1 : 0;

    fidp = smb_FindFID(vcp, fid, 0);
    if (!fidp) {
        osi_Log2(smb_logp, "NotifyChange Unknown SMB Fid vcp 0x%p fid %d",
                 vcp, fid);
        return CM_ERROR_BADFD;
    }

    lock_ObtainMutex(&fidp->mx);
    if (fidp->scp && (fidp->scp->flags & CM_SCACHEFLAG_DELETED)) {
        lock_ReleaseMutex(&fidp->mx);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        return CM_ERROR_NOSUCHFILE;
    }
    scp = fidp->scp;
    cm_HoldSCache(scp);
    lock_ReleaseMutex(&fidp->mx);

    /* Create a copy of the Directory Watch Packet to use when sending the
     * notification if in the future a matching change is detected.
     */
    savedPacketp = smb_CopyPacket(inp);
    if (vcp != savedPacketp->vcp) {
        smb_HoldVC(vcp);
        if (savedPacketp->vcp)
            smb_ReleaseVC(savedPacketp->vcp);
        savedPacketp->vcp = vcp;
    }

    /* Add the watch to the list of events to send notifications for */
    lock_ObtainMutex(&smb_Dir_Watch_Lock);
    savedPacketp->nextp = smb_Directory_Watches;
    smb_Directory_Watches = savedPacketp;
    lock_ReleaseMutex(&smb_Dir_Watch_Lock);

    osi_Log3(smb_logp,"smb_ReceiveNTTranNotifyChange fidp 0x%p scp 0x%p file \"%S\"",
	      fidp, scp, osi_LogSaveClientString(smb_logp, fidp->NTopen_wholepathp));
    osi_Log3(smb_logp, "Request for NotifyChange filter 0x%x fid %d wtree %d",
             filter, fid, watchtree);
    if (filter & FILE_NOTIFY_CHANGE_FILE_NAME)
	osi_Log0(smb_logp, "      Notify Change File Name");
    if (filter & FILE_NOTIFY_CHANGE_DIR_NAME)
	osi_Log0(smb_logp, "      Notify Change Directory Name");
    if (filter & FILE_NOTIFY_CHANGE_ATTRIBUTES)
	osi_Log0(smb_logp, "      Notify Change Attributes");
    if (filter & FILE_NOTIFY_CHANGE_SIZE)
	osi_Log0(smb_logp, "      Notify Change Size");
    if (filter & FILE_NOTIFY_CHANGE_LAST_WRITE)
	osi_Log0(smb_logp, "      Notify Change Last Write");
    if (filter & FILE_NOTIFY_CHANGE_LAST_ACCESS)
	osi_Log0(smb_logp, "      Notify Change Last Access");
    if (filter & FILE_NOTIFY_CHANGE_CREATION)
	osi_Log0(smb_logp, "      Notify Change Creation");
    if (filter & FILE_NOTIFY_CHANGE_EA)
	osi_Log0(smb_logp, "      Notify Change Extended Attributes");
    if (filter & FILE_NOTIFY_CHANGE_SECURITY)
	osi_Log0(smb_logp, "      Notify Change Security");
    if (filter & FILE_NOTIFY_CHANGE_STREAM_NAME)
	osi_Log0(smb_logp, "      Notify Change Stream Name");
    if (filter & FILE_NOTIFY_CHANGE_STREAM_SIZE)
	osi_Log0(smb_logp, "      Notify Change Stream Size");
    if (filter & FILE_NOTIFY_CHANGE_STREAM_WRITE)
	osi_Log0(smb_logp, "      Notify Change Stream Write");

    lock_ObtainWrite(&scp->rw);
    if (watchtree)
        scp->flags |= CM_SCACHEFLAG_WATCHEDSUBTREE;
    else
        scp->flags |= CM_SCACHEFLAG_WATCHED;
    lock_ReleaseWrite(&scp->rw);
    cm_ReleaseSCache(scp);
    smb_ReleaseFID(fidp);

    outp->flags |= SMB_PACKETFLAG_NOSEND;
    return 0;
}

unsigned char nullSecurityDesc[] = {
    0x01,				/* security descriptor revision */
    0x00,				/* reserved, should be zero */
    0x04, 0x80,			        /* security descriptor control;
                                         * 0x0004 : null-DACL present - everyone has full access
                                         * 0x8000 : relative format */
    0x14, 0x00, 0x00, 0x00,		/* offset of owner SID */
    0x20, 0x00, 0x00, 0x00,		/* offset of group SID */
    0x00, 0x00, 0x00, 0x00,		/* offset of DACL would go here */
    0x00, 0x00, 0x00, 0x00,		/* offset of SACL would go here */
    0x01, 0x01, 0x00, 0x00,             /* "everyone SID" owner SID */
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x00,             /* "everyone SID" owner SID */
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00
};

/* NT_TRANSACT_QUERY_SECURITY_DESC (SMB_COM_NT_TRANSACT) */
long smb_ReceiveNTTranQuerySecurityDesc(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    int parmOffset, parmCount, dataOffset, dataCount;
    int totalParmCount, totalDataCount;
    int parmSlot;
    int maxData, maxParm;
    int inTotalParm, inTotalData;
    int inParm, inData;
    int inParmOffset, inDataOffset;
    char *outData;
    char *parmp;
    USHORT *sparmp;
    ULONG *lparmp;
    USHORT fid;
    ULONG securityInformation;
    smb_fid_t *fidp;
    long code = 0;
    DWORD dwLength;

    /*
     * For details on the meanings of the various
     * SMB_COM_TRANSACTION fields, see sections 2.2.4.33
     * of http://msdn.microsoft.com/en-us/library/ee442092%28PROT.13%29.aspx
     */

    inTotalParm = smb_GetSMBOffsetParm(inp, 1, 1)
        | (smb_GetSMBOffsetParm(inp, 2, 1) << 16);

    inTotalData = smb_GetSMBOffsetParm(inp, 3, 1)
        | (smb_GetSMBOffsetParm(inp, 4, 1) << 16);

    maxParm = smb_GetSMBOffsetParm(inp, 5, 1)
        | (smb_GetSMBOffsetParm(inp, 6, 1) << 16);

    maxData = smb_GetSMBOffsetParm(inp, 7, 1)
        | (smb_GetSMBOffsetParm(inp, 8, 1) << 16);

    inParm = smb_GetSMBOffsetParm(inp, 9, 1)
        | (smb_GetSMBOffsetParm(inp, 10, 1) << 16);

    inParmOffset = smb_GetSMBOffsetParm(inp, 11, 1)
        | (smb_GetSMBOffsetParm(inp, 12, 1) << 16);

    inData = smb_GetSMBOffsetParm(inp, 13, 1)
        | (smb_GetSMBOffsetParm(inp, 14, 1) << 16);

    inDataOffset = smb_GetSMBOffsetParm(inp, 15, 1)
        | (smb_GetSMBOffsetParm(inp, 16, 1) << 16);

    parmp = inp->data + inParmOffset;
    sparmp = (USHORT *) parmp;
    lparmp = (ULONG *) parmp;

    fid = sparmp[0];
    securityInformation = lparmp[1];

    fidp = smb_FindFID(vcp, fid, 0);
    if (!fidp) {
        osi_Log2(smb_logp, "smb_ReceiveNTTranQuerySecurityDesc Unknown SMB Fid vcp 0x%p fid %d",
                 vcp, fid);
        return CM_ERROR_BADFD;
    }

    lock_ObtainMutex(&fidp->mx);
    if (fidp->scp && (fidp->scp->flags & CM_SCACHEFLAG_DELETED)) {
        lock_ReleaseMutex(&fidp->mx);
        smb_CloseFID(vcp, fidp, NULL, 0);
        smb_ReleaseFID(fidp);
        return CM_ERROR_NOSUCHFILE;
    }
    lock_ReleaseMutex(&fidp->mx);

    osi_Log4(smb_logp,"smb_ReceiveNTTranQuerySecurityDesc fidp 0x%p scp 0x%p file \"%S\" Info=0x%x",
	      fidp, fidp->scp, osi_LogSaveClientString(smb_logp, fidp->NTopen_wholepathp),
              securityInformation);

    smb_ReleaseFID(fidp);

    if ( securityInformation & ~(OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION) )
    {
        code = CM_ERROR_BAD_LEVEL;
        goto done;
    }

    dwLength = sizeof( nullSecurityDesc);

    totalDataCount = dwLength;
    totalParmCount = 4;

    if (maxData >= totalDataCount) {
        dataCount = totalDataCount;
        parmCount = min(totalParmCount, maxParm);
    } else if (maxParm >= totalParmCount) {
        totalDataCount = dataCount = 0;
        parmCount = totalParmCount;
    } else {
        totalDataCount = dataCount = 0;
        totalParmCount = parmCount = 0;
    }

    /* out parms */
    parmOffset = 8*4 + 39;
    parmOffset += 1;	/* pad to 4 */

    dataOffset = parmOffset + parmCount;

    parmSlot = 1;
    outp->oddByte = 1;
    /* Total Parameter Count */
    smb_SetSMBParmLong(outp, parmSlot, totalParmCount); parmSlot += 2;
    /* Total Data Count */
    smb_SetSMBParmLong(outp, parmSlot, totalDataCount); parmSlot += 2;
    /* Parameter Count */
    smb_SetSMBParmLong(outp, parmSlot, parmCount); parmSlot += 2;
    /* Parameter Offset */
    smb_SetSMBParmLong(outp, parmSlot, parmCount ? parmOffset : 0); parmSlot += 2;
    /* Parameter Displacement */
    smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
    /* Data Count */
    smb_SetSMBParmLong(outp, parmSlot, dataCount); parmSlot += 2;
    /* Data Offset */
    smb_SetSMBParmLong(outp, parmSlot, dataCount ? dataOffset : 0); parmSlot += 2;
    /* Data Displacement */
    smb_SetSMBParmLong(outp, parmSlot, 0); parmSlot += 2;
    /* Setup Count */
    smb_SetSMBParmByte(outp, parmSlot, 0);

    if (parmCount == totalParmCount && dwLength == dataCount) {
        smb_SetSMBDataLength(outp, 1 + parmCount + dataCount);

        /* Data */
        outData = smb_GetSMBData(outp, NULL);
        outData++;			/* round to get to dataOffset */

        *((ULONG *)outData) = dataCount; outData += 4;	/* SD Length (4 bytes) */
        memcpy(outData, nullSecurityDesc, dataCount);
        outData += dataCount;

        code = 0;
    } else if (parmCount >= 4) {
        smb_SetSMBDataLength(outp, 1 + parmCount);

        /* Data */
        outData = smb_GetSMBData(outp, NULL);
        outData++;			/* round to get to dataOffset */

        *((ULONG *)outData) = dwLength; outData += 4;	/* SD Length (4 bytes) */
        code = CM_ERROR_BUFFERTOOSMALL;
    } else {
        smb_SetSMBDataLength(outp, 0);
        code = CM_ERROR_BUFFER_OVERFLOW;
    }

  done:
    return code;
}

/* SMB_COM_NT_TRANSACT

   SMB_COM_NT_TRANSACT_SECONDARY should also be handled here.
 */
long smb_ReceiveNTTransact(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    unsigned short function;

    function = smb_GetSMBParm(inp, 18);

    osi_Log1(smb_logp, "SMB NT Transact function %d", function);

    /* We can handle long names */
    if (vcp->flags & SMB_VCFLAG_USENT)
        ((smb_t *)outp)->flg2 |= SMB_FLAGS2_IS_LONG_NAME;

    switch (function) {
    case 1:                     /* NT_TRANSACT_CREATE */
        return smb_ReceiveNTTranCreate(vcp, inp, outp);
    case 2:                     /* NT_TRANSACT_IOCTL */
	osi_Log0(smb_logp, "SMB NT Transact Ioctl - not implemented");
	break;
    case 3:                     /* NT_TRANSACT_SET_SECURITY_DESC */
	osi_Log0(smb_logp, "SMB NT Transact SetSecurityDesc - not implemented");
	break;
    case 4:                     /* NT_TRANSACT_NOTIFY_CHANGE */
        return smb_ReceiveNTTranNotifyChange(vcp, inp, outp);
    case 5:                     /* NT_TRANSACT_RENAME */
	osi_Log0(smb_logp, "SMB NT Transact Rename - not implemented");
	break;
    case 6:                     /* NT_TRANSACT_QUERY_SECURITY_DESC */
        return smb_ReceiveNTTranQuerySecurityDesc(vcp, inp, outp);
    case 7:
        osi_Log0(smb_logp, "SMB NT Transact Query Quota - not implemented");
        break;
    case 8:
        osi_Log0(smb_logp, "SMB NT Transact Set Quota - not implemented");
        break;
    }
    return CM_ERROR_BADOP;
}

/*
 * smb_NotifyChange -- find relevant change notification messages and
 *		       reply to them
 *
 * If we don't know the file name (i.e. a callback break), filename is
 * NULL, and we return a zero-length list.
 *
 * At present there is not a single call to smb_NotifyChange that
 * has the isDirectParent parameter set to FALSE.
 */
void smb_NotifyChange(DWORD action, DWORD notifyFilter,
	cm_scache_t *dscp, clientchar_t *filename, clientchar_t *otherFilename,
	BOOL isDirectParent)
{
    smb_packet_t *watch, *lastWatch, *nextWatch;
    ULONG parmSlot, parmCount, parmOffset, dataOffset, nameLen = 0;
    char *outData, *oldOutData;
    ULONG filter;
    USHORT fid, wtree;
    ULONG maxLen;
    BOOL twoEntries = FALSE;
    ULONG otherNameLen, oldParmCount = 0;
    DWORD otherAction;
    smb_fid_t *fidp;

    /* Get ready for rename within directory */
    if (action == FILE_ACTION_RENAMED_OLD_NAME && otherFilename != NULL) {
        twoEntries = TRUE;
        otherAction = FILE_ACTION_RENAMED_NEW_NAME;
    }

    osi_Log4(smb_logp,"in smb_NotifyChange for file [%S] dscp [%p] notification 0x%x parent %d",
             osi_LogSaveClientString(smb_logp,filename),dscp, notifyFilter, isDirectParent);
    if (action == 0)
	osi_Log0(smb_logp,"      FILE_ACTION_NONE");
    if (action == FILE_ACTION_ADDED)
	osi_Log0(smb_logp,"      FILE_ACTION_ADDED");
    if (action == FILE_ACTION_REMOVED)
	osi_Log0(smb_logp,"      FILE_ACTION_REMOVED");
    if (action == FILE_ACTION_MODIFIED)
	osi_Log0(smb_logp,"      FILE_ACTION_MODIFIED");
    if (action == FILE_ACTION_RENAMED_OLD_NAME)
	osi_Log0(smb_logp,"      FILE_ACTION_RENAMED_OLD_NAME");
    if (action == FILE_ACTION_RENAMED_NEW_NAME)
	osi_Log0(smb_logp,"      FILE_ACTION_RENAMED_NEW_NAME");

    lock_ObtainMutex(&smb_Dir_Watch_Lock);
    watch = smb_Directory_Watches;
    while (watch) {
        filter = smb_GetSMBParm(watch, 19)
            | (smb_GetSMBParm(watch, 20) << 16);
        fid = smb_GetSMBParm(watch, 21);
        wtree = (smb_GetSMBParm(watch, 22) & 0xff) ? 1 : 0;

        maxLen = smb_GetSMBOffsetParm(watch, 5, 1)
            | (smb_GetSMBOffsetParm(watch, 6, 1) << 16);

        /*
         * Strange hack - bug in NT Client and NT Server that we must emulate?
         */
        if ((filter == (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME)) && wtree)
            filter |= FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_ATTRIBUTES;

        fidp = smb_FindFID(watch->vcp, fid, 0);
        if (!fidp) {
            osi_Log2(smb_logp," no fidp for fid[%d] in vcp 0x%p",fid, watch->vcp);
            lastWatch = watch;
            watch = watch->nextp;
            continue;
        }

        if (fidp->scp != dscp ||
            fidp->scp->flags & CM_SCACHEFLAG_DELETED ||
            (filter & notifyFilter) == 0 ||
            (!isDirectParent && !wtree))
        {
            osi_Log1(smb_logp," skipping fidp->scp[%x]", fidp->scp);
            lastWatch = watch;
            watch = watch->nextp;
            smb_ReleaseFID(fidp);
            continue;
        }

        osi_Log4(smb_logp,
                  "Sending Change Notification for fid %d filter 0x%x wtree %d file %S",
                  fid, filter, wtree, osi_LogSaveClientString(smb_logp, filename));
	if (filter & FILE_NOTIFY_CHANGE_FILE_NAME)
	    osi_Log0(smb_logp, "      Notify Change File Name");
	if (filter & FILE_NOTIFY_CHANGE_DIR_NAME)
	    osi_Log0(smb_logp, "      Notify Change Directory Name");
	if (filter & FILE_NOTIFY_CHANGE_ATTRIBUTES)
	    osi_Log0(smb_logp, "      Notify Change Attributes");
	if (filter & FILE_NOTIFY_CHANGE_SIZE)
	    osi_Log0(smb_logp, "      Notify Change Size");
	if (filter & FILE_NOTIFY_CHANGE_LAST_WRITE)
	    osi_Log0(smb_logp, "      Notify Change Last Write");
	if (filter & FILE_NOTIFY_CHANGE_LAST_ACCESS)
	    osi_Log0(smb_logp, "      Notify Change Last Access");
	if (filter & FILE_NOTIFY_CHANGE_CREATION)
	    osi_Log0(smb_logp, "      Notify Change Creation");
	if (filter & FILE_NOTIFY_CHANGE_EA)
	    osi_Log0(smb_logp, "      Notify Change Extended Attributes");
	if (filter & FILE_NOTIFY_CHANGE_SECURITY)
	    osi_Log0(smb_logp, "      Notify Change Security");
	if (filter & FILE_NOTIFY_CHANGE_STREAM_NAME)
	    osi_Log0(smb_logp, "      Notify Change Stream Name");
	if (filter & FILE_NOTIFY_CHANGE_STREAM_SIZE)
	    osi_Log0(smb_logp, "      Notify Change Stream Size");
	if (filter & FILE_NOTIFY_CHANGE_STREAM_WRITE)
	    osi_Log0(smb_logp, "      Notify Change Stream Write");

	/* A watch can only be notified once.  Remove it from the list */
        nextWatch = watch->nextp;
        if (watch == smb_Directory_Watches)
            smb_Directory_Watches = nextWatch;
        else
            lastWatch->nextp = nextWatch;

        /* Turn off WATCHED flag in dscp */
        lock_ObtainWrite(&dscp->rw);
        if (wtree)
            dscp->flags &= ~CM_SCACHEFLAG_WATCHEDSUBTREE;
        else
            dscp->flags &= ~CM_SCACHEFLAG_WATCHED;
        lock_ReleaseWrite(&dscp->rw);

        /* Convert to response packet */
        ((smb_t *) watch)->reb = SMB_FLAGS_SERVER_TO_CLIENT;
#ifdef SEND_CANONICAL_PATHNAMES
        ((smb_t *) watch)->reb |= SMB_FLAGS_CANONICAL_PATHNAMES;
#endif
        ((smb_t *) watch)->wct = 0;

        /* out parms */
        if (filename == NULL) {
            parmCount = 0;
        } else {
            nameLen = (ULONG)cm_ClientStrLen(filename);
            parmCount = 3*4 + nameLen*2;
            parmCount = (parmCount + 3) & ~3;	/* pad to 4 */
            if (twoEntries) {
                otherNameLen = (ULONG)cm_ClientStrLen(otherFilename);
                oldParmCount = parmCount;
                parmCount += 3*4 + otherNameLen*2;
                parmCount = (parmCount + 3) & ~3; /* pad to 4 */
            }
            if (maxLen < parmCount)
                parmCount = 0;	/* not enough room */
        }
        parmOffset = 8*4 + 39;
        parmOffset += 1;			/* pad to 4 */
        dataOffset = parmOffset + parmCount;

        parmSlot = 1;
        watch->oddByte = 1;
        /* Total Parameter Count */
        smb_SetSMBParmLong(watch, parmSlot, parmCount); parmSlot += 2;
        /* Total Data Count */
        smb_SetSMBParmLong(watch, parmSlot, 0); parmSlot += 2;
        /* Parameter Count */
        smb_SetSMBParmLong(watch, parmSlot, parmCount); parmSlot += 2;
        /* Parameter Offset */
        smb_SetSMBParmLong(watch, parmSlot, parmOffset); parmSlot += 2;
        /* Parameter Displacement */
        smb_SetSMBParmLong(watch, parmSlot, 0); parmSlot += 2;
        /* Data Count */
        smb_SetSMBParmLong(watch, parmSlot, 0); parmSlot += 2;
        /* Data Offset */
        smb_SetSMBParmLong(watch, parmSlot, dataOffset); parmSlot += 2;
        /* Data Displacement */
        smb_SetSMBParmLong(watch, parmSlot, 0); parmSlot += 2;
        smb_SetSMBParmByte(watch, parmSlot, 0);	/* Setup Count */
        smb_SetSMBDataLength(watch, parmCount + 1);

        if (parmCount != 0) {
            outData = smb_GetSMBData(watch, NULL);
            outData++;	/* round to get to parmOffset */
            oldOutData = outData;
            *((DWORD *)outData) = oldParmCount; outData += 4;
            /* Next Entry Offset */
            *((DWORD *)outData) = action; outData += 4;
            /* Action */
            *((DWORD *)outData) = nameLen*2; outData += 4;
            /* File Name Length */

            smb_UnparseString(watch, outData, filename, NULL, 0);
            /* File Name */

            if (twoEntries) {
                outData = oldOutData + oldParmCount;
                *((DWORD *)outData) = 0; outData += 4;
                /* Next Entry Offset */
                *((DWORD *)outData) = otherAction; outData += 4;
                /* Action */
                *((DWORD *)outData) = otherNameLen*2;
                outData += 4;	/* File Name Length */
                smb_UnparseString(watch, outData, otherFilename, NULL, 0);
            }
        }

        /*
         * If filename is null, we don't know the cause of the
         * change notification.  We return zero data (see above),
         * and set error code to NT_STATUS_NOTIFY_ENUM_DIR
         * (= 0x010C).  We set the error code here by hand, without
         * modifying wct and bcc.
         */
        if (filename == NULL) {
            ((smb_t *) watch)->rcls = 0x0C;
            ((smb_t *) watch)->reh = 0x01;
            ((smb_t *) watch)->errLow = 0;
            ((smb_t *) watch)->errHigh = 0;
            /* Set NT Status codes flag */
            ((smb_t *) watch)->flg2 |= SMB_FLAGS2_32BIT_STATUS;
        }

        smb_SendPacket(watch->vcp, watch);
        smb_FreePacket(watch);

        smb_ReleaseFID(fidp);
        watch = nextWatch;
    }
    lock_ReleaseMutex(&smb_Dir_Watch_Lock);
}

/* SMB_COM_NT_CANCEL */
long smb_ReceiveNTCancel(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    unsigned char *replyWctp;
    smb_packet_t *watch, *lastWatch;
    USHORT fid, watchtree;
    smb_fid_t *fidp;
    cm_scache_t *scp;

    osi_Log0(smb_logp, "SMB3 receive NT cancel");

    lock_ObtainMutex(&smb_Dir_Watch_Lock);
    watch = smb_Directory_Watches;
    while (watch) {
        if (((smb_t *)watch)->uid == ((smb_t *)inp)->uid
             && ((smb_t *)watch)->pid == ((smb_t *)inp)->pid
             && ((smb_t *)watch)->mid == ((smb_t *)inp)->mid
             && ((smb_t *)watch)->tid == ((smb_t *)inp)->tid) {
            if (watch == smb_Directory_Watches)
                smb_Directory_Watches = watch->nextp;
            else
                lastWatch->nextp = watch->nextp;
            lock_ReleaseMutex(&smb_Dir_Watch_Lock);

            /* Turn off WATCHED flag in scp */
            fid = smb_GetSMBParm(watch, 21);
            watchtree = smb_GetSMBParm(watch, 22) & 0xffff;

            if (vcp != watch->vcp)
                osi_Log2(smb_logp, "smb_ReceiveNTCancel: vcp %x not equal to watch vcp %x",
                          vcp, watch->vcp);

            fidp = smb_FindFID(vcp, fid, 0);
            if (fidp) {
                osi_Log3(smb_logp, "Cancelling change notification for fid %d wtree %d file %S",
                         fid, watchtree,
                         (fidp ? osi_LogSaveClientString(smb_logp, fidp->NTopen_wholepathp) :_C("")));

                scp = fidp->scp;
		osi_Log2(smb_logp,"smb_ReceiveNTCancel fidp 0x%p scp 0x%p", fidp, scp);
                if (scp) {
                    lock_ObtainWrite(&scp->rw);
    	            if (watchtree)
                        scp->flags &= ~CM_SCACHEFLAG_WATCHEDSUBTREE;
                    else
    	                scp->flags &= ~CM_SCACHEFLAG_WATCHED;
                    lock_ReleaseWrite(&scp->rw);
                }
                smb_ReleaseFID(fidp);
            } else {
                osi_Log2(smb_logp,"NTCancel unable to resolve fid [%d] in vcp[%x]", fid,vcp);
            }

            /* assume STATUS32; return 0xC0000120 (CANCELED) */
            replyWctp = watch->wctp;
            *replyWctp++ = 0;
            *replyWctp++ = 0;
            *replyWctp++ = 0;
            ((smb_t *)watch)->rcls = 0x20;
            ((smb_t *)watch)->reh = 0x1;
            ((smb_t *)watch)->errLow = 0;
            ((smb_t *)watch)->errHigh = 0xC0;
            ((smb_t *)watch)->flg2 |= SMB_FLAGS2_32BIT_STATUS;
            smb_SendPacket(vcp, watch);
            smb_FreePacket(watch);
            return 0;
        }
        lastWatch = watch;
        watch = watch->nextp;
    }
    lock_ReleaseMutex(&smb_Dir_Watch_Lock);

    return 0;
}

/*
 * NT rename also does hard links.
 */

#define RENAME_FLAG_MOVE_CLUSTER_INFORMATION 0x102
#define RENAME_FLAG_HARD_LINK                0x103
#define RENAME_FLAG_RENAME                   0x104
#define RENAME_FLAG_COPY                     0x105

long smb_ReceiveNTRename(smb_vc_t *vcp, smb_packet_t *inp, smb_packet_t *outp)
{
    clientchar_t *oldPathp, *newPathp;
    long code = 0;
    char * tp;
    int attrs;
    int rename_type;

    attrs = smb_GetSMBParm(inp, 0);
    rename_type = smb_GetSMBParm(inp, 1);

    if (rename_type != RENAME_FLAG_RENAME && rename_type != RENAME_FLAG_HARD_LINK) {
        osi_Log1(smb_logp, "NTRename invalid rename_type [%x]", rename_type);
        return CM_ERROR_NOACCESS;
    }

    tp = smb_GetSMBData(inp, NULL);
    oldPathp = smb_ParseASCIIBlock(inp, tp, &tp, 0);
    if (!oldPathp)
        return CM_ERROR_BADSMB;
    newPathp = smb_ParseASCIIBlock(inp, tp, &tp, 0);
    if (!newPathp)
        return CM_ERROR_BADSMB;

    osi_Log3(smb_logp, "NTRename for [%S]->[%S] type [%s]",
             osi_LogSaveClientString(smb_logp, oldPathp),
             osi_LogSaveClientString(smb_logp, newPathp),
             ((rename_type==RENAME_FLAG_RENAME)?"rename":(rename_type==RENAME_FLAG_HARD_LINK)?"hardlink":"other"));

    if (rename_type == RENAME_FLAG_RENAME) {
        code = smb_Rename(vcp,inp,oldPathp,newPathp,attrs);
    } else if (rename_type == RENAME_FLAG_HARD_LINK) { /* RENAME_FLAG_HARD_LINK */
        code = smb_Link(vcp,inp,oldPathp,newPathp);
    } else
        code = CM_ERROR_BADOP;
    return code;
}

void smb3_Init()
{
    lock_InitializeMutex(&smb_Dir_Watch_Lock, "Directory Watch List Lock", LOCK_HIERARCHY_SMB_DIRWATCH);
}

cm_user_t *smb_FindCMUserByName(clientchar_t *usern, clientchar_t *machine, afs_uint32 flags)
{
    smb_username_t *unp;
    cm_user_t *     userp;

    unp = smb_FindUserByName(usern, machine, flags);
    if (!unp->userp) {
        lock_ObtainMutex(&unp->mx);
        unp->userp = cm_NewUser();
        lock_ReleaseMutex(&unp->mx);
        osi_Log2(smb_logp,"smb_FindCMUserByName New user name[%S] machine[%S]",osi_LogSaveClientString(smb_logp,usern),osi_LogSaveClientString(smb_logp,machine));
    }  else	{
        osi_Log2(smb_logp,"smb_FindCMUserByName Found name[%S] machine[%S]",osi_LogSaveClientString(smb_logp,usern),osi_LogSaveClientString(smb_logp,machine));
    }
    userp = unp->userp;
    cm_HoldUser(userp);
    smb_ReleaseUsername(unp);
    return userp;
}

cm_user_t *smb_FindCMUserBySID(clientchar_t *usern, clientchar_t *machine, afs_uint32 flags)
{
    smb_username_t *unp;
    cm_user_t *     userp;

    unp = smb_FindUserByName(usern, machine, flags);
    if (!unp->userp) {
        lock_ObtainMutex(&unp->mx);
        unp->flags |= SMB_USERNAMEFLAG_SID;
        unp->userp = cm_NewUser();
        lock_ReleaseMutex(&unp->mx);
        osi_Log2(smb_logp,"smb_FindCMUserBySID New user name[%S] machine[%S]",osi_LogSaveClientString(smb_logp,usern),osi_LogSaveClientString(smb_logp,machine));
    }  else	{
        osi_Log2(smb_logp,"smb_FindCMUserBySID Found name[%S] machine[%S]",osi_LogSaveClientString(smb_logp,usern),osi_LogSaveClientString(smb_logp,machine));
    }
    userp = unp->userp;
    cm_HoldUser(userp);
    smb_ReleaseUsername(unp);
    return userp;
}

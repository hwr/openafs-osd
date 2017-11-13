/*
 * Copyright (c) 2008, 2009, 2010, 2011 Kernel Drivers, LLC.
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Your File System, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice,
 *   this list of conditions and the following disclaimer in the
 *   documentation
 *   and/or other materials provided with the distribution.
 * - Neither the names of Kernel Drivers, LLC and Your File System, Inc.
 *   nor the names of their contributors may be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission from Kernel Drivers, LLC and Your File System, Inc.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

//
// File: AFSWrite.cpp
//

#include "AFSCommon.h"

static
NTSTATUS
AFSCachedWrite( IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp,
                IN LARGE_INTEGER StartingByte,
                IN ULONG ByteCount,
                IN BOOLEAN ForceFlush);
static
NTSTATUS
AFSNonCachedWrite( IN PDEVICE_OBJECT DeviceObject,
                   IN PIRP Irp,
                   IN LARGE_INTEGER StartingByte,
                   IN ULONG ByteCount);

static
NTSTATUS
AFSNonCachedWriteDirect( IN PDEVICE_OBJECT DeviceObject,
                         IN PIRP Irp,
                         IN LARGE_INTEGER StartingByte,
                         IN ULONG ByteCount);

static
NTSTATUS
AFSExtendingWrite( IN AFSFcb *Fcb,
                   IN PFILE_OBJECT FileObject,
                   IN LONGLONG NewLength);

//
// Function: AFSWrite
//
// Description:
//
//      This is the dispatch handler for the IRP_MJ_WRITE request
//
// Return:
//
//      A status is returned for the function
//
NTSTATUS
AFSWrite( IN PDEVICE_OBJECT LibDeviceObject,
          IN PIRP Irp)
{

    UNREFERENCED_PARAMETER(LibDeviceObject);
    NTSTATUS ntStatus = STATUS_SUCCESS;

    __try
    {

        ntStatus = AFSCommonWrite( AFSRDRDeviceObject, Irp, NULL, FALSE);
    }
    __except( AFSExceptionFilter( __FUNCTION__, GetExceptionCode(), GetExceptionInformation()) )
    {

        ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }

    return ntStatus;
}

NTSTATUS
AFSCommonWrite( IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp,
                IN HANDLE OnBehalfOf,
                IN BOOLEAN bRetry)
{

    NTSTATUS           ntStatus = STATUS_SUCCESS;
    AFSDeviceExt      *pDeviceExt = (AFSDeviceExt *)DeviceObject->DeviceExtension;
    IO_STACK_LOCATION *pIrpSp;
    AFSFcb            *pFcb = NULL;
    AFSCcb            *pCcb = NULL;
    AFSNonPagedFcb    *pNPFcb = NULL;
    ULONG              ulByteCount = 0;
    LARGE_INTEGER      liStartingByte;
    PFILE_OBJECT       pFileObject;
    BOOLEAN            bPagingIo = FALSE;
    BOOLEAN            bNonCachedIo = FALSE;
    BOOLEAN            bReleaseMain = FALSE;
    BOOLEAN            bReleaseSectionObject = FALSE;
    BOOLEAN            bReleasePaging = FALSE;
    BOOLEAN            bExtendingWrite = FALSE;
    BOOLEAN            bSynchronousFo = FALSE;
    BOOLEAN	       bWriteToEndOfFile = FALSE;
    BOOLEAN	       bWait = FALSE;
    BOOLEAN            bCompleteIrp = TRUE;
    BOOLEAN            bForceFlush = FALSE;
    BOOLEAN            bLockOK;
    HANDLE             hCallingUser = OnBehalfOf;
    ULONGLONG          ullProcessId = (ULONGLONG)PsGetCurrentProcessId();
    AFSDeviceExt       *pRDRDevExt = (AFSDeviceExt *)AFSRDRDeviceObject->DeviceExtension;

    pIrpSp = IoGetCurrentIrpStackLocation( Irp);

    __Enter
    {

        Irp->IoStatus.Information = 0;

        pFileObject = pIrpSp->FileObject;

        //
        // Extract the fileobject references
        //

        pFcb = (AFSFcb *)pFileObject->FsContext;
        pCcb = (AFSCcb *)pFileObject->FsContext2;

        ObReferenceObject( pFileObject);

        if( pFcb == NULL)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSCommonWrite Attempted write (%p) when pFcb == NULL\n",
                          Irp));

            try_return( ntStatus = STATUS_INVALID_DEVICE_REQUEST);
        }

        pNPFcb = pFcb->NPFcb;

        //
        // If we are in shutdown mode then fail the request
        //

        if( BooleanFlagOn( pDeviceExt->DeviceFlags, AFS_DEVICE_FLAG_REDIRECTOR_SHUTDOWN))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_WARNING,
                          "AFSCommonWrite (%p) Open request after shutdown\n",
                          Irp));

            try_return( ntStatus = STATUS_TOO_LATE);
        }

        liStartingByte = pIrpSp->Parameters.Write.ByteOffset;
        bPagingIo      = BooleanFlagOn( Irp->Flags, IRP_PAGING_IO);
        bNonCachedIo   = BooleanFlagOn( Irp->Flags, IRP_NOCACHE);
	bWait	       = IoIsOperationSynchronous( Irp);
        ulByteCount    = pIrpSp->Parameters.Write.Length;
        bSynchronousFo = BooleanFlagOn( pFileObject->Flags, FO_SYNCHRONOUS_IO);

        if( pFcb->Header.NodeTypeCode != AFS_IOCTL_FCB &&
            pFcb->Header.NodeTypeCode != AFS_FILE_FCB  &&
            pFcb->Header.NodeTypeCode != AFS_SPECIAL_SHARE_FCB)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSCommonWrite Attempted write (%p) on an invalid node type %08lX\n",
                          Irp,
                          pFcb->Header.NodeTypeCode));

            try_return( ntStatus = STATUS_INVALID_DEVICE_REQUEST);
        }

        //
        // If this is a write against an IOCtl node then handle it
        // in a different pathway
        //

        if( pFcb->Header.NodeTypeCode == AFS_IOCTL_FCB)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCommonWrite (%p) Processing file (PIOCTL) Offset %0I64X Length %08lX Irp Flags %08lX\n",
                          Irp,
                          liStartingByte.QuadPart,
                          ulByteCount,
                          Irp->Flags));

            ntStatus = AFSIOCtlWrite( DeviceObject,
                                      Irp);

            try_return( ntStatus);
        }
        else if( pFcb->Header.NodeTypeCode == AFS_SPECIAL_SHARE_FCB)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCommonWrite (%p) Processing file (SHARE) Offset %0I64X Length %08lX Irp Flags %08lX\n",
                          Irp,
                          liStartingByte.QuadPart,
                          ulByteCount,
                          Irp->Flags));

            ntStatus = AFSShareWrite( DeviceObject,
                                      Irp);

            try_return( ntStatus);
        }

        //
        // Is the Cache not there yet?  Exit.
        //
        if( !BooleanFlagOn( AFSLibControlFlags, AFS_REDIR_LIB_FLAGS_NONPERSISTENT_CACHE) &&
            !BooleanFlagOn( pRDRDevExt->DeviceFlags, AFS_REDIR_INIT_PERFORM_SERVICE_IO) &&
            NULL == pDeviceExt->Specific.RDR.CacheFileObject)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSCommonWrite (%p) Request failed due to AFS cache closed\n",
                          Irp));

            try_return( ntStatus = STATUS_TOO_LATE );
        }

        if( pFcb->ObjectInformation->VolumeCB != NULL &&
            BooleanFlagOn( pFcb->ObjectInformation->VolumeCB->VolumeInformation.FileSystemAttributes, FILE_READ_ONLY_VOLUME))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSCommonWrite (%p) Request failed due to read only volume\n",
                          Irp));

            try_return( ntStatus = STATUS_MEDIA_WRITE_PROTECTED);
        }

        //
        // We need to know on whose behalf we have been called (which
        // we will eventually tell to the server - for non paging
        // writes).  If we were posted then we were told.  If this is
        // the first time we saw the irp then we grab it now.
        //
        if( NULL == OnBehalfOf )
        {

            hCallingUser = PsGetCurrentProcessId();
        }
        else
        {

            hCallingUser = OnBehalfOf;
        }

        //
        // Check for zero length write
        //

        if( ulByteCount == 0)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCommonWrite (%p) Request completed due to zero length\n",
                          Irp));

            try_return( ntStatus);
        }

        //
        // Is this Fcb valid???
        //

        if( BooleanFlagOn( pFcb->ObjectInformation->Flags, AFS_OBJECT_FLAGS_OBJECT_INVALID))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSCommonWrite (%p) Failing request due to INVALID fcb\n",
                          Irp));

            try_return( ntStatus = STATUS_FILE_DELETED);
        }

        if( BooleanFlagOn( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_DELETED) ||
            BooleanFlagOn( pFcb->ObjectInformation->Flags, AFS_OBJECT_FLAGS_DELETED))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSCommonWrite (%p) Request failed due to file deleted\n",
                          Irp));

            try_return( ntStatus = STATUS_FILE_DELETED);
        }

        if( FlagOn( pIrpSp->MinorFunction, IRP_MN_COMPLETE))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCommonWrite (%p) IRP_MN_COMPLETE being processed\n",
                          Irp));

            CcMdlWriteComplete(pFileObject, &pIrpSp->Parameters.Write.ByteOffset, Irp->MdlAddress);

            //
            // Mdl is now Deallocated
            //

            Irp->MdlAddress = NULL;

            try_return( ntStatus = STATUS_SUCCESS );
        }

        //
        // If we get a non cached IO for a cached file we should do a purge.
        // For now we will just promote to cached
        //
        if( NULL != pFileObject->SectionObjectPointer->DataSectionObject && !bPagingIo && bNonCachedIo)
        {
            bNonCachedIo = FALSE;
            bForceFlush = TRUE;
        }

        if ( !bNonCachedIo && !bPagingIo)
        {

            if( pFileObject->PrivateCacheMap == NULL)
            {

		AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING|AFS_SUBSYSTEM_SECTION_OBJECT,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCommonWrite Acquiring Fcb SectionObject lock %p EXCL %08lX\n",
                              &pNPFcb->SectionObjectResource,
                              PsGetCurrentThread()));

                AFSAcquireExcl( &pNPFcb->SectionObjectResource,
                                TRUE);

                bReleaseSectionObject = TRUE;

                __try
                {

                    AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCommonWrite Initialize caching on Fcb %p FileObject %p\n",
                                  pFcb,
                                  pFileObject));

                    CcInitializeCacheMap( pFileObject,
                                          (PCC_FILE_SIZES)&pFcb->Header.AllocationSize,
                                          FALSE,
                                          AFSLibCacheManagerCallbacks,
                                          pFcb);

                    CcSetReadAheadGranularity( pFileObject,
                                               pDeviceExt->Specific.RDR.MaximumRPCLength);

                    CcSetDirtyPageThreshold( pFileObject,
                                             AFS_DIRTY_CHUNK_THRESHOLD * pDeviceExt->Specific.RDR.MaximumRPCLength / 4096);
                }
		__except( EXCEPTION_EXECUTE_HANDLER)
                {

                    ntStatus = GetExceptionCode();

                    AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                                  AFS_TRACE_LEVEL_ERROR,
                                  "AFSCommonWrite (%p) Exception thrown while initializing cache map Status %08lX\n",
                                  Irp,
                                  ntStatus));
                }

		AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING|AFS_SUBSYSTEM_SECTION_OBJECT,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCommonWrite Releasing Fcb SectionObject lock %p EXCL %08lX\n",
                              &pNPFcb->SectionObjectResource,
                              PsGetCurrentThread()));

                AFSReleaseResource( &pNPFcb->SectionObjectResource);

                bReleaseSectionObject = FALSE;

                if( !NT_SUCCESS( ntStatus))
                {

                    try_return( ntStatus);
                }
            }

	    //
	    // On versions of Microsoft Windows older than Vista the IO Manager
	    // will issue multiple outstanding writes on a synchronous file object
	    // if one of the cached writes completes with STATUS_PENDING.  This can
	    // result in the writes being completed out of order which can corrupt
	    // the end of file marker.  On OS versions older than Vista use a spin
	    // loop instead of deferring the write.
	    //

	    if ( bSynchronousFo &&
		 AFSRtlSysVersion.dwMajorVersion < 6)
	    {

		while (!CcCanIWrite( pFileObject,
				     ulByteCount,
				     bWait && !bRetry,
				     bRetry))
		{
		    static const LONGLONG llWriteDelay = (LONGLONG)-100000;
		    bRetry = TRUE;

		    AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
				  AFS_TRACE_LEVEL_WARNING,
				  "AFSCommonWrite (FO: %p) CcCanIWrite says No room for %u bytes! Retry in 10ms\n",
				  pFileObject,
				  ulByteCount);

		    KeDelayExecutionThread(KernelMode, FALSE, (PLARGE_INTEGER)&llWriteDelay);
		}
	    }
	    else
	    {

		if (!CcCanIWrite( pFileObject,
				  ulByteCount,
				  bWait && !bRetry,
				  bRetry))
		{

		    AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
				  AFS_TRACE_LEVEL_WARNING,
				  "AFSCommonWrite (FO: %p) CcCanIWrite says No room for Offset %0I64X Length %08lX bytes! Deferring%s\n",
				  pFileObject,
				  liStartingByte.QuadPart,
				  ulByteCount,
				  bRetry ? " RETRY" : ""));

		    ntStatus = AFSDeferWrite( DeviceObject, pFileObject, hCallingUser, Irp, ulByteCount, bRetry);

		    if ( STATUS_PENDING == ntStatus)
		    {

			bCompleteIrp = FALSE;
		    }
		    else
		    {

			AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
				      AFS_TRACE_LEVEL_ERROR,
				      "AFSCommonWrite (FO: %p) AFSDeferWrite failure Status %08lX\n",
				      pFileObject,
				      ntStatus));
		    }

		    try_return( ntStatus);
		}
	    }
        }

        //
        // Save off the PID if this is not a paging IO
        //

        if( !bPagingIo &&
            ( pFcb->Specific.File.ExtentRequestProcessId == 0 ||
              ( ullProcessId != (ULONGLONG)AFSSysProcess &&
                pFcb->Specific.File.ExtentRequestProcessId != ullProcessId)))
        {

            pFcb->Specific.File.ExtentRequestProcessId = ullProcessId;

            if( ullProcessId == (ULONGLONG)AFSSysProcess)
            {
                AFSDbgTrace(( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                              AFS_TRACE_LEVEL_WARNING,
                              "%s Setting LastWriterExtentProcessId to system process for Fcb %p\n",
                              __FUNCTION__,
                              pFcb));
            }
        }

        //
        // Take locks
        //
        //   - if Paging then we need to do nothing (the precalls will
        //     have acquired the paging resource), for clarity we will collect
        //     the paging resource
        //   - If extending Write then take the fileresource EX (EOF will change, Allocation will only move out)
        //   - Otherwise we collect the file shared, check against extending and
        //

        bLockOK = FALSE;

        do
        {

            if( bPagingIo)
            {

                //ASSERT( NULL != OnBehalfOf || ExIsResourceAcquiredLite( &pNPFcb->Resource ));

                AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCommonWrite Acquiring Fcb PagingIo lock %p SHARED %08lX\n",
                              &pNPFcb->PagingResource,
                              PsGetCurrentThread()));

                AFSAcquireShared( &pNPFcb->PagingResource,
                                  TRUE);

                bReleasePaging = TRUE;

                //
                // We have the correct lock - we cannot have the wrong one
                //
                bLockOK = TRUE;
            }
            else
            {

		bWriteToEndOfFile = liStartingByte.LowPart == FILE_WRITE_TO_END_OF_FILE &&
				    liStartingByte.HighPart == -1;

		bExtendingWrite = ( bWriteToEndOfFile ||
				    ((liStartingByte.QuadPart + ulByteCount) >=
				      pFcb->Header.FileSize.QuadPart));

                if( bExtendingWrite || bNonCachedIo)
                {
                    //
                    // Check for lock inversion
                    //

		    //
		    // For bExtendingWrite the PagingResource is needed to protect
		    // the CcSetFileSizes call in AFSExtendingWrite
		    //

                    ASSERT( !ExIsResourceAcquiredLite( &pNPFcb->PagingResource ));

                    AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCommonWrite Acquiring Fcb lock %p EXCL %08lX\n",
                                  &pNPFcb->Resource,
                                  PsGetCurrentThread()));

                    AFSAcquireExcl( &pNPFcb->Resource,
                                    TRUE);

                    bReleaseMain = TRUE;

		    AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING|AFS_SUBSYSTEM_SECTION_OBJECT,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCommonWrite Acquiring Fcb SectionObject lock %p EXCL %08lX\n",
                                  &pNPFcb->SectionObjectResource,
                                  PsGetCurrentThread()));

                    AFSAcquireExcl( &pNPFcb->SectionObjectResource,
                                    TRUE);

                    bReleaseSectionObject = TRUE;

		    if ( bWriteToEndOfFile)
		    {

			if (pFcb->Header.ValidDataLength.QuadPart > pFcb->Header.FileSize.QuadPart)
			{

			    liStartingByte = pFcb->Header.ValidDataLength;
			}
			else
			{

			    liStartingByte = pFcb->Header.FileSize;
			}

			pIrpSp->Parameters.Write.ByteOffset = liStartingByte;
		    }

		    //
                    // We have the correct lock - even if we don't end up truncating
                    //
                    bLockOK = TRUE;
                }
                else
                {
                    ASSERT( !ExIsResourceAcquiredLite( &pNPFcb->PagingResource ));

                    AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCommonWrite Acquiring Fcb lock %p SHARED %08lX\n",
                                  &pNPFcb->Resource,
                                  PsGetCurrentThread()));

                    AFSAcquireShared( &pNPFcb->Resource,
                                      TRUE);

                    bReleaseMain = TRUE;

		    AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING|AFS_SUBSYSTEM_SECTION_OBJECT,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCommonWrite Acquiring Fcb SectionObject lock %p SHARED %08lX\n",
                                  &pNPFcb->SectionObjectResource,
                                  PsGetCurrentThread()));

                    AFSAcquireShared( &pNPFcb->SectionObjectResource,
                                      TRUE);

                    bReleaseSectionObject = TRUE;

                    //
                    // Have things moved?  Are we extending? If so, the the lock isn't OK
                    //
                    bLockOK = (liStartingByte.QuadPart + ulByteCount) < pFcb->Header.FileSize.QuadPart;

                    if (!bLockOK)
                    {

			AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING|AFS_SUBSYSTEM_SECTION_OBJECT,
				      AFS_TRACE_LEVEL_VERBOSE,
				      "AFSCommonWrite Releasing Fcb SectionObject lock %p SHARED %08lX\n",
				      &pNPFcb->SectionObjectResource,
				      PsGetCurrentThread()));

			AFSReleaseResource( &pNPFcb->SectionObjectResource);

			bReleaseSectionObject = FALSE;

                        AFSReleaseResource( &pNPFcb->Resource);

                        bReleaseMain = FALSE;
                    }
                }
            }
        }
        while (!bLockOK);

        if( !bPagingIo)
        {

            //
            // Check the BR locks on the file.
            //

            if ( !FsRtlCheckLockForWriteAccess( &pFcb->Specific.File.FileLock,
                                                Irp))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCommonWrite (%p) Request failed due to lock conflict\n",
                              Irp));

                try_return( ntStatus = STATUS_FILE_LOCK_CONFLICT);
            }

            if( bExtendingWrite)
            {

                ntStatus = AFSExtendingWrite( pFcb, pFileObject, (liStartingByte.QuadPart + ulByteCount));

		//
		// Fcb->NPFcb->Resource is now held SHARED
		//

                if( !NT_SUCCESS(ntStatus))
                {

                    AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                                  AFS_TRACE_LEVEL_ERROR,
                                  "AFSCommonWrite (%p) Failed extending write request Status %08lX\n",
                                  Irp,
                                  ntStatus));

                    try_return( ntStatus );
                }
            }
        }

        //
        // Fire off the request as appropriate
        //
        bCompleteIrp = FALSE;

        if( !bPagingIo &&
            !bNonCachedIo)
        {

            //
	    // Main resource held Shared
	    // SectionObject resource held exclusive if extending write
            //

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCommonWrite (%p) Processing CACHED request Offset %0I64X Len %08lX%s\n",
                          Irp,
                          liStartingByte.QuadPart,
                          ulByteCount,
                          bRetry ? " RETRY" : ""));

            ntStatus = AFSCachedWrite( DeviceObject, Irp, liStartingByte, ulByteCount, bForceFlush);
        }
        else
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCommonWrite (%p) Processing NON-CACHED request Offset %0I64X Len %08lX%s\n",
                          Irp,
                          liStartingByte.QuadPart,
                          ulByteCount,
                          bRetry ? " RETRY" : ""));

            if( BooleanFlagOn( pRDRDevExt->DeviceFlags, AFS_DEVICE_FLAG_DIRECT_SERVICE_IO))
            {

                ntStatus = AFSNonCachedWriteDirect( DeviceObject, Irp,  liStartingByte, ulByteCount);
            }
            else
            {
                ntStatus = AFSNonCachedWrite( DeviceObject, Irp,  liStartingByte, ulByteCount);
            }
        }

try_exit:

        AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSCommonWrite (%p) Process complete Status %08lX\n",
                      Irp,
                      ntStatus));

	if ( NT_SUCCESS( ntStatus) &&
	     ntStatus != STATUS_PENDING)
        {
            if ( !bPagingIo)
            {

		if( bSynchronousFo)
                {

                    pFileObject->CurrentByteOffset.QuadPart = liStartingByte.QuadPart + ulByteCount;
                }

                //
                // If this extended the VDL, then update it accordingly.
                // Increasing the VDL does not require a call to CcSetFileSizes.
                //

                if( liStartingByte.QuadPart + ulByteCount > pFcb->Header.ValidDataLength.QuadPart)
                {

                    pFcb->Header.ValidDataLength.QuadPart = liStartingByte.QuadPart + ulByteCount;
                }

		//
		// Register the File Object as having modified the file.
		//
		SetFlag( pFileObject->Flags, FO_FILE_MODIFIED);
            }
        }

	if ( ntStatus != STATUS_PENDING &&
	     !bPagingIo && bNonCachedIo && CcIsFileCached( pFileObject) &&
             pNPFcb->SectionObjectPointers.DataSectionObject != NULL &&
             bReleaseSectionObject)
        {
            //
            // Regardless of whether or not the a non-paging non-cached write
            // succeeds or fails, if the file is cached the contents of the
            // cache are no longer up to date.  A CcPurgeCacheSection must be
            // performed to force subsequent cached reads to obtain the data
            // from the service.
            //
            // The Fcb Resource is dropped in order to permit filters that perform
            // an open via a worker thread in response to a purge to do so without
            // deadlocking.  The SectionObjectResource is held across the purge to
            // prevent racing with other cache operations.
            //

            if( bReleaseMain)
            {

                AFSReleaseResource( &pNPFcb->Resource);

                bReleaseMain = FALSE;
            }

	    __try
            {

		if ( !CcPurgeCacheSection( &pNPFcb->SectionObjectPointers,
					   &liStartingByte,
					   ulByteCount,
					   FALSE))
		{

		    AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
				  AFS_TRACE_LEVEL_WARNING,
				  "AFSCommonWrite CcPurgeCacheSection failure FID %08lX-%08lX-%08lX-%08lX\n",
				  pFcb->ObjectInformation->FileId.Cell,
				  pFcb->ObjectInformation->FileId.Volume,
				  pFcb->ObjectInformation->FileId.Vnode,
				  pFcb->ObjectInformation->FileId.Unique));

		    SetFlag( pFcb->Flags, AFS_FCB_FLAG_PURGE_ON_CLOSE);
		}
	    }
	    __except( EXCEPTION_EXECUTE_HANDLER)
	    {

		DWORD ntStatus2 = GetExceptionCode();

		AFSDbgTrace(( 0,
			      0,
			      "EXCEPTION - AFSCommonWrite CcPurgeCacheSection failed FID %08lX-%08lX-%08lX-%08lX Status 0x%08lX\n",
                              pFcb->ObjectInformation->FileId.Cell,
                              pFcb->ObjectInformation->FileId.Volume,
                              pFcb->ObjectInformation->FileId.Vnode,
			      pFcb->ObjectInformation->FileId.Unique,
			      ntStatus2));

                SetFlag( pFcb->Flags, AFS_FCB_FLAG_PURGE_ON_CLOSE);
            }
        }

        ObDereferenceObject(pFileObject);

        if( bReleaseSectionObject)
        {

	    AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING|AFS_SUBSYSTEM_SECTION_OBJECT,
			  AFS_TRACE_LEVEL_VERBOSE,
			  "AFSCommonWrite Releasing Fcb SectionObject lock %p EXCL/SHARED %08lX\n",
			  &pNPFcb->SectionObjectResource,
			  PsGetCurrentThread()));

            AFSReleaseResource( &pNPFcb->SectionObjectResource);
        }

        if( bReleasePaging)
        {

            AFSReleaseResource( &pNPFcb->PagingResource);
        }

        if( bReleaseMain)
        {

            AFSReleaseResource( &pNPFcb->Resource);
        }

        if( bCompleteIrp)
        {

            AFSCompleteRequest( Irp,
                                ntStatus);
        }
    }

    return ntStatus;
}

NTSTATUS
AFSIOCtlWrite( IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp)
{

    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS ntStatus = STATUS_SUCCESS;
    AFSPIOCtlIORequestCB stIORequestCB;
    PIO_STACK_LOCATION pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    AFSFcb *pFcb = NULL;
    AFSCcb *pCcb = NULL;
    AFSPIOCtlIOResultCB stIOResultCB;
    ULONG ulBytesReturned = 0;
    AFSFileID stParentFID;

    __Enter
    {

        Irp->IoStatus.Information = 0;

        RtlZeroMemory( &stIORequestCB,
                       sizeof( AFSPIOCtlIORequestCB));

        if( pIrpSp->Parameters.Write.Length == 0)
        {

            //
            // Nothing to do in this case
            //

            try_return( ntStatus);
        }

        pFcb = (AFSFcb *)pIrpSp->FileObject->FsContext;

        pCcb = (AFSCcb *)pIrpSp->FileObject->FsContext2;

        AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSIOCtlWrite Acquiring Fcb lock %p SHARED %08lX\n",
                      &pFcb->NPFcb->Resource,
                      PsGetCurrentThread()));

        AFSAcquireShared( &pFcb->NPFcb->Resource,
                          TRUE);

        //
        // Get the parent fid to pass to the cm
        //

        RtlZeroMemory( &stParentFID,
                       sizeof( AFSFileID));

        if( BooleanFlagOn( pFcb->ObjectInformation->Flags, AFS_OBJECT_FLAGS_PARENT_FID))
        {

            //
            // The parent directory FID of the node
            //

            stParentFID = pFcb->ObjectInformation->ParentFileId;
        }

        //
        // Set the control block up
        //

        stIORequestCB.RequestId = pCcb->RequestID;

        if( pFcb->ObjectInformation->VolumeCB != NULL)
        {
            stIORequestCB.RootId = pFcb->ObjectInformation->VolumeCB->ObjectInformation.FileId;
        }

        //
        // Lock down the buffer
        //

        stIORequestCB.MappedBuffer = AFSMapToService( Irp,
                                                      pIrpSp->Parameters.Write.Length);

        if( stIORequestCB.MappedBuffer == NULL)
        {

            try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
        }

        stIORequestCB.BufferLength = pIrpSp->Parameters.Write.Length;

        stIOResultCB.BytesProcessed = 0;

        ulBytesReturned = sizeof( AFSPIOCtlIOResultCB);

        //
        // Issue the request to the service
        //

        ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_PIOCTL_WRITE,
                                      AFS_REQUEST_FLAG_SYNCHRONOUS,
                                      &pCcb->AuthGroup,
                                      NULL,
                                      &stParentFID,
                                      NULL,
                                      0,
                                      (void *)&stIORequestCB,
                                      sizeof( AFSPIOCtlIORequestCB),
                                      &stIOResultCB,
                                      &ulBytesReturned);

        if( !NT_SUCCESS( ntStatus))
        {

            try_return( ntStatus);
        }

        //
        // Update the length written
        //

        Irp->IoStatus.Information = stIOResultCB.BytesProcessed;

try_exit:

        if( stIORequestCB.MappedBuffer != NULL)
        {

            AFSUnmapServiceMappedBuffer( stIORequestCB.MappedBuffer,
                                         Irp->MdlAddress);
        }

        if( pFcb != NULL)
        {

            AFSReleaseResource( &pFcb->NPFcb->Resource);
        }
    }

    return ntStatus;
}

//
// This function is called when we know we have to read from the AFS Cache.
//
// It ensures that we have exents for the entirety of the write and
// then pins the extents into memory (meaning that although we may
// add we will not remove).  Then it creates a scatter gather write
// and fires off the IRPs
//
static
NTSTATUS
AFSNonCachedWrite( IN PDEVICE_OBJECT DeviceObject,
                   IN PIRP Irp,
                   IN LARGE_INTEGER StartingByte,
                   IN ULONG ByteCount)
{
    NTSTATUS           ntStatus = STATUS_UNSUCCESSFUL;
    VOID              *pSystemBuffer = NULL;
    BOOLEAN            bPagingIo = BooleanFlagOn( Irp->Flags, IRP_PAGING_IO);
    BOOLEAN            bLocked = FALSE;
    BOOLEAN            bCompleteIrp = TRUE;
    AFSGatherIo       *pGatherIo = NULL;
    AFSIoRun          *pIoRuns = NULL;
    AFSIoRun           stIoRuns[AFS_MAX_STACK_IO_RUNS];
    ULONG              extentsCount = 0, runCount = 0;
    AFSExtent         *pStartExtent = NULL;
    AFSExtent         *pIgnoreExtent = NULL;
    IO_STACK_LOCATION *pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    PFILE_OBJECT       pFileObject = pIrpSp->FileObject;
    AFSFcb            *pFcb = (AFSFcb *)pFileObject->FsContext;
    AFSCcb            *pCcb = (AFSCcb *)pFileObject->FsContext2;
    BOOLEAN            bSynchronousFo = BooleanFlagOn( pFileObject->Flags, FO_SYNCHRONOUS_IO);
    AFSDeviceExt      *pDevExt = (AFSDeviceExt *)DeviceObject->DeviceExtension;
    LARGE_INTEGER      liCurrentTime, liLastRequestTime;
    AFSDeviceExt      *pControlDevExt = (AFSDeviceExt *)AFSControlDeviceObject->DeviceExtension;
    PFILE_OBJECT       pCacheFileObject = NULL;
    BOOLEAN            bDerefExtents = FALSE;

    __Enter
    {

        AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSNonCachedWrite (FO: %p) StartingByte %08lX:%08lX Length %08lX\n",
                      pFileObject,
                      StartingByte.HighPart,
                      StartingByte.LowPart,
                      ByteCount));

        if (ByteCount > pDevExt->Specific.RDR.MaxIo.QuadPart)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSNonCachedWrite (%p) Request %08lX Actual %08lX larger than MaxIO %I64X\n",
                          Irp,
                          ByteCount,
                          pIrpSp->Parameters.Write.Length,
                          pDevExt->Specific.RDR.MaxIo.QuadPart));

            try_return( ntStatus = STATUS_UNSUCCESSFUL);
        }

        //
        // Get the mapping for the buffer
        //
        pSystemBuffer = AFSLockSystemBuffer( Irp,
                                             ByteCount);

        if( pSystemBuffer == NULL)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSNonCachedWrite (%p) Failed to map system buffer\n",
                          Irp));

            try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
        }


        //
        // Provoke a get of the extents - if we need to.
        //

        AFSDbgTrace(( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSNonCachedWrite Requesting extents for fid %08lX-%08lX-%08lX-%08lX Offset %0I64X Length %08lX\n",
                      pFcb->ObjectInformation->FileId.Cell,
                      pFcb->ObjectInformation->FileId.Volume,
                      pFcb->ObjectInformation->FileId.Vnode,
                      pFcb->ObjectInformation->FileId.Unique,
                      StartingByte.QuadPart,
                      ByteCount));

        ntStatus = AFSRequestExtentsAsync( pFcb,
                                           pCcb,
                                           &StartingByte,
                                           ByteCount);

        if (!NT_SUCCESS(ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSNonCachedWrite (%p) Failed to request extents Status %08lX\n",
                          Irp,
                          ntStatus));

            try_return( ntStatus);
        }

        KeQueryTickCount( &liLastRequestTime);

        while (TRUE)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSNonCachedWrite Acquiring Fcb extents lock %p SHARED %08lX\n",
                          &pFcb->NPFcb->Specific.File.ExtentsResource,
                          PsGetCurrentThread()));

            ASSERT( !ExIsResourceAcquiredLite( &pFcb->NPFcb->Specific.File.ExtentsResource ));

            AFSAcquireShared( &pFcb->NPFcb->Specific.File.ExtentsResource, TRUE );
            bLocked = TRUE;

            pStartExtent = NULL;
            pIgnoreExtent = NULL;

            if ( AFSDoExtentsMapRegion( pFcb, &StartingByte, ByteCount, &pStartExtent, &pIgnoreExtent ))
            {
                break;
            }

            KeClearEvent( &pFcb->NPFcb->Specific.File.ExtentsRequestComplete );

            AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSNonCachedWrite Releasing(1) Fcb extents lock %p SHARED %08lX\n",
                          &pFcb->NPFcb->Specific.File.ExtentsResource,
                          PsGetCurrentThread()));

            AFSReleaseResource( &pFcb->NPFcb->Specific.File.ExtentsResource );
            bLocked= FALSE;

            //
            // We will re-request the extents after waiting for them
            //

            KeQueryTickCount( &liCurrentTime);

            if( liCurrentTime.QuadPart - liLastRequestTime.QuadPart >= pControlDevExt->Specific.Control.ExtentRequestTimeCount.QuadPart)
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSNonCachedWrite Requesting extents, again, for fid %08lX-%08lX-%08lX-%08lX Offset %0I64X Length %08lX\n",
                              pFcb->ObjectInformation->FileId.Cell,
                              pFcb->ObjectInformation->FileId.Volume,
                              pFcb->ObjectInformation->FileId.Vnode,
                              pFcb->ObjectInformation->FileId.Unique,
                              StartingByte.QuadPart,
                              ByteCount));

                ntStatus = AFSRequestExtentsAsync( pFcb,
                                                   pCcb,
                                                   &StartingByte,
                                                   ByteCount);

                if (!NT_SUCCESS(ntStatus))
                {

                    AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                                  AFS_TRACE_LEVEL_ERROR,
                                  "AFSNonCachedWrite (%p) Failed to request extents Status %08lX\n",
                                  Irp,
                                  ntStatus));

                    try_return( ntStatus);
                }

                KeQueryTickCount( &liLastRequestTime);
            }


            AFSDbgTrace(( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSNonCachedWrite Waiting for extents for fid %08lX-%08lX-%08lX-%08lX Offset %0I64X Length %08lX\n",
                          pFcb->ObjectInformation->FileId.Cell,
                          pFcb->ObjectInformation->FileId.Volume,
                          pFcb->ObjectInformation->FileId.Vnode,
                          pFcb->ObjectInformation->FileId.Unique,
                          StartingByte.QuadPart,
                          ByteCount));

            //
            // Wait for it
            //

            ntStatus =  AFSWaitForExtentMapping ( pFcb, pCcb);

            if (!NT_SUCCESS(ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSNonCachedWrite Failed wait for extents for fid %08lX-%08lX-%08lX-%08lX Offset %0I64X Length %08lX Status %08lX\n",
                              pFcb->ObjectInformation->FileId.Cell,
                              pFcb->ObjectInformation->FileId.Volume,
                              pFcb->ObjectInformation->FileId.Vnode,
                              pFcb->ObjectInformation->FileId.Unique,
                              StartingByte.QuadPart,
                              ByteCount,
                              ntStatus));

                try_return( ntStatus);
            }
        }

        //
        // As per the read path -
        //

        AFSDbgTrace(( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSNonCachedWrite Extents located for fid %08lX-%08lX-%08lX-%08lX Offset %0I64X Length %08lX\n",
                      pFcb->ObjectInformation->FileId.Cell,
                      pFcb->ObjectInformation->FileId.Volume,
                      pFcb->ObjectInformation->FileId.Vnode,
                      pFcb->ObjectInformation->FileId.Unique,
                      StartingByte.QuadPart,
                      ByteCount));

        ntStatus = AFSGetExtents( pFcb,
                                  &StartingByte,
                                  ByteCount,
                                  pStartExtent,
                                  &extentsCount,
                                  &runCount);

        if (!NT_SUCCESS(ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSNonCachedWrite (%p) Failed to retrieve mapped extents Status %08lX\n",
                          Irp,
                          ntStatus));

            try_return( ntStatus );
        }

        AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSNonCachedWrite (%p) Successfully retrieved map extents count %d run count %d\n",
                      Irp,
                      extentsCount,
                      runCount));

        if( BooleanFlagOn( AFSLibControlFlags, AFS_REDIR_LIB_FLAGS_NONPERSISTENT_CACHE))
        {

            Irp->IoStatus.Information = ByteCount;

#if GEN_MD5
            //
            // Setup the MD5 for each extent
            //

            AFSSetupMD5Hash( pFcb,
                             pStartExtent,
                             extentsCount,
                             pSystemBuffer,
                             &StartingByte,
                             ByteCount);
#endif

            ntStatus = AFSProcessExtentRun( pSystemBuffer,
                                            &StartingByte,
                                            ByteCount,
                                            pStartExtent,
                                            TRUE);

            if (!NT_SUCCESS(ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSNonCachedWrite (%p) Failed to process extent run for non-persistent cache Status %08lX\n",
                              Irp,
                              ntStatus));
            }

            try_return( ntStatus);
        }

        //
        // Retrieve the cache file object
        //

        pCacheFileObject = AFSReferenceCacheFileObject();

        if( pCacheFileObject == NULL)
        {

            ntStatus = STATUS_DEVICE_NOT_READY;

            AFSDbgTrace(( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSNonCachedWrite Failed to retrieve cache fileobject for fid %08lX-%08lX-%08lX-%08lX Offset %0I64X Length %08lX Status %08lX\n",
                          pFcb->ObjectInformation->FileId.Cell,
                          pFcb->ObjectInformation->FileId.Volume,
                          pFcb->ObjectInformation->FileId.Vnode,
                          pFcb->ObjectInformation->FileId.Unique,
                          StartingByte.QuadPart,
                          ByteCount,
                          ntStatus));

            try_return( ntStatus);
        }

        if (runCount > AFS_MAX_STACK_IO_RUNS)
        {

            pIoRuns = (AFSIoRun*) AFSExAllocatePoolWithTag( PagedPool,
                                                            runCount * sizeof( AFSIoRun ),
                                                            AFS_IO_RUN_TAG );
            if (NULL == pIoRuns)
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSNonCachedWrite (%p) Failed to allocate IO run block\n",
                              Irp));

                try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES );
            }
        }
        else
        {

            pIoRuns = stIoRuns;
        }

        RtlZeroMemory( pIoRuns, runCount * sizeof( AFSIoRun ));

        ntStatus = AFSSetupIoRun( IoGetRelatedDeviceObject( pCacheFileObject),
                                  Irp,
                                  pSystemBuffer,
                                  pIoRuns,
                                  &StartingByte,
                                  ByteCount,
                                  pStartExtent,
                                  &runCount );

        if (!NT_SUCCESS(ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSNonCachedWrite (%p) Failed to initialize IO run block Status %08lX\n",
                          Irp,
                          ntStatus));

            try_return( ntStatus );
        }

        AFSReferenceActiveExtents( pStartExtent,
                                   extentsCount);

        bDerefExtents = TRUE;

        AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSNonCachedWrite Releasing(2) Fcb extents lock %p SHARED %08lX\n",
                      &pFcb->NPFcb->Specific.File.ExtentsResource,
                      PsGetCurrentThread()));

        AFSReleaseResource( &pFcb->NPFcb->Specific.File.ExtentsResource );
        bLocked = FALSE;

        pGatherIo = (AFSGatherIo*) AFSExAllocatePoolWithTag( NonPagedPool,
                                                             sizeof( AFSGatherIo),
                                                             AFS_GATHER_TAG);

        if (NULL == pGatherIo)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSNonCachedWrite (%p) Failed to allocate IO gather block\n",
                          Irp));

            AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSNonCachedWrite Acquiring(1) Fcb extents lock %p SHARED %08lX\n",
                          &pFcb->NPFcb->Specific.File.ExtentsResource,
                          PsGetCurrentThread()));

            AFSAcquireShared( &pFcb->NPFcb->Specific.File.ExtentsResource,
                              TRUE);
            bLocked = TRUE;

            AFSDereferenceActiveExtents( pStartExtent,
                                         extentsCount);

            try_return (ntStatus = STATUS_INSUFFICIENT_RESOURCES );
        }

        RtlZeroMemory( pGatherIo, sizeof( AFSGatherIo ));

        //
        // Initialize count to 1, that was we won't get an early
        // completion if the first irp completes before the second is
        // queued.
        //
        pGatherIo->Count = 1;
        pGatherIo->Status = STATUS_SUCCESS;
        pGatherIo->MasterIrp = Irp;
        pGatherIo->Synchronous = TRUE;
        pGatherIo->CompleteMasterIrp = FALSE;

        bCompleteIrp = TRUE;

        if( pGatherIo->Synchronous)
        {
            KeInitializeEvent( &pGatherIo->Event, NotificationEvent, FALSE );
        }

#if GEN_MD5
        //
        // Setup the MD5 for each extent
        //

        AFSSetupMD5Hash( pFcb,
                         pStartExtent,
                         extentsCount,
                         pSystemBuffer,
                         &StartingByte,
                         ByteCount);
#endif

        //
        // Pre-emptively set up the count
        //

        Irp->IoStatus.Information = ByteCount;

        ntStatus = AFSQueueStartIos( pCacheFileObject,
                                     IRP_MJ_WRITE,
                                     IRP_WRITE_OPERATION | IRP_SYNCHRONOUS_API,
                                     pIoRuns,
                                     runCount,
                                     pGatherIo);

        AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSNonCachedWrite (%p) AFSStartIos completed Status %08lX\n",
                      Irp,
                      ntStatus));

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSNonCachedWrite Acquiring(2) Fcb extents lock %p SHARED %08lX\n",
                          &pFcb->NPFcb->Specific.File.ExtentsResource,
                          PsGetCurrentThread()));

            AFSAcquireShared( &pFcb->NPFcb->Specific.File.ExtentsResource,
                              TRUE);
            bLocked = TRUE;

            AFSDereferenceActiveExtents( pStartExtent,
                                         extentsCount);

            try_return( ntStatus);
        }

        //
        // Wait for completion of All IOs we started.
        //

        ntStatus = KeWaitForSingleObject( &pGatherIo->Event,
                                          Executive,
                                          KernelMode,
                                          FALSE,
                                          NULL);

        if( NT_SUCCESS( ntStatus))
        {

            ntStatus = pGatherIo->Status;
        }

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSNonCachedWrite Acquiring(3) Fcb extents lock %p SHARED %08lX\n",
                          &pFcb->NPFcb->Specific.File.ExtentsResource,
                          PsGetCurrentThread()));

            AFSAcquireShared( &pFcb->NPFcb->Specific.File.ExtentsResource,
                              TRUE);
            bLocked = TRUE;

            AFSDereferenceActiveExtents( pStartExtent,
                                         extentsCount);

            try_return( ntStatus);
        }

try_exit:

        if( NT_SUCCESS( ntStatus) &&
            pStartExtent != NULL &&
            Irp->IoStatus.Information > 0)
        {

            if ( !bLocked)
            {

                AFSAcquireShared( &pFcb->NPFcb->Specific.File.ExtentsResource,
                                  TRUE);
                bLocked = TRUE;
            }

            //
            // Since this is dirty we can mark the extents dirty now.
            // AFSMarkDirty will dereference the extents.  Do not call
            // AFSDereferenceActiveExtents() in this code path.
            //

            AFSMarkDirty( pFcb,
                          pStartExtent,
                          extentsCount,
                          &StartingByte,
                          bDerefExtents);

            if (!bPagingIo)
            {
                //
                // This was an uncached user write - tell the server to do
                // the flush when the worker thread next wakes up
                //
                pFcb->Specific.File.LastServerFlush.QuadPart = 0;
            }
        }

        if( pCacheFileObject != NULL)
        {
            AFSReleaseCacheFileObject( pCacheFileObject);
        }

        AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSNonCachedWrite (FO: %p) StartingByte %08lX:%08lX Length %08lX Status %08lX\n",
                      pFileObject,
                      StartingByte.HighPart,
                      StartingByte.LowPart,
                      ByteCount,
                      ntStatus));

        if (NT_SUCCESS(ntStatus) &&
            !bPagingIo &&
            bSynchronousFo)
        {

            pFileObject->CurrentByteOffset.QuadPart = StartingByte.QuadPart + ByteCount;
        }

        if( bLocked)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSNonCachedWrite Releasing Fcb extents lock %p SHARED %08lX\n",
                          &pFcb->NPFcb->Specific.File.ExtentsResource,
                          PsGetCurrentThread()));

            AFSReleaseResource( &pFcb->NPFcb->Specific.File.ExtentsResource );
        }

        if( pGatherIo)
        {
            AFSExFreePoolWithTag(pGatherIo, AFS_GATHER_TAG);
        }

        if( NULL != pIoRuns &&
            stIoRuns != pIoRuns)
        {
            AFSExFreePoolWithTag(pIoRuns, AFS_IO_RUN_TAG);
        }

        if( bCompleteIrp)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSNonCachedWrite Completing Irp %p Status %08lX Info %08lX\n",
                          Irp,
                          ntStatus,
                          Irp->IoStatus.Information));

            AFSCompleteRequest( Irp, ntStatus);
        }
    }

    return ntStatus;
}

static
NTSTATUS
AFSNonCachedWriteDirect( IN PDEVICE_OBJECT DeviceObject,
                         IN PIRP Irp,
                         IN LARGE_INTEGER StartingByte,
                         IN ULONG ByteCount)
{
    NTSTATUS           ntStatus = STATUS_UNSUCCESSFUL;
    VOID              *pSystemBuffer = NULL;
    BOOLEAN            bPagingIo = BooleanFlagOn( Irp->Flags, IRP_PAGING_IO);
    IO_STACK_LOCATION *pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    PFILE_OBJECT       pFileObject = pIrpSp->FileObject;
    AFSFcb            *pFcb = (AFSFcb *)pFileObject->FsContext;
    AFSCcb            *pCcb = (AFSCcb *)pFileObject->FsContext2;
    BOOLEAN            bSynchronousFo = BooleanFlagOn( pFileObject->Flags, FO_SYNCHRONOUS_IO);
    BOOLEAN            bNoIntermediateBuffering = BooleanFlagOn( pFileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING);
    AFSDeviceExt      *pDevExt = (AFSDeviceExt *)DeviceObject->DeviceExtension;
    AFSFileIOCB        stFileIORequest;
    AFSFileIOResultCB  stFileIOResult;
    ULONG              ulResultLen = 0;
    ULONG              ulFlags;

    __Enter
    {
        Irp->IoStatus.Information = 0;

        AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSNonCachedWriteDirect (FO: %p) StartingByte %08lX:%08lX Length %08lX\n",
                      pFileObject,
                      StartingByte.HighPart,
                      StartingByte.LowPart,
                      ByteCount));

        if (ByteCount > pDevExt->Specific.RDR.MaxIo.QuadPart)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSNonCachedWriteDirect (%p) Request %08lX Actual %08lX larger than MaxIO %I64X\n",
                          Irp,
                          ByteCount,
                          pIrpSp->Parameters.Write.Length,
                          pDevExt->Specific.RDR.MaxIo.QuadPart));

            try_return( ntStatus = STATUS_UNSUCCESSFUL);
        }

        //
        // Get the mapping for the buffer
        //
        pSystemBuffer = AFSLockSystemBuffer( Irp,
                                             ByteCount);

        if( pSystemBuffer == NULL)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSNonCachedWriteDirect (%p) Failed to map system buffer\n",
                          Irp));

            try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
        }

        //
        // Issue the request at the service for processing
        //

        ulResultLen = sizeof( AFSFileIOResultCB);

        RtlZeroMemory( &stFileIORequest,
                       sizeof( AFSFileIOCB));

        RtlZeroMemory( &stFileIOResult,
                       sizeof( AFSFileIOResultCB));

        stFileIORequest.SystemIOBuffer = pSystemBuffer;

        stFileIORequest.SystemIOBufferMdl = Irp->MdlAddress;

        stFileIORequest.IOLength = ByteCount;

        stFileIORequest.IOOffset = StartingByte;

        ulFlags = AFS_REQUEST_FLAG_SYNCHRONOUS;

        if ( bNoIntermediateBuffering)
        {

            ulFlags |= AFS_REQUEST_FLAG_CACHE_BYPASS;
        }

        //
        // Update file metadata
        //

        stFileIORequest.EndOfFile = pFcb->ObjectInformation->EndOfFile;

        stFileIORequest.CreateTime = pFcb->ObjectInformation->CreationTime;

        stFileIORequest.ChangeTime = pFcb->ObjectInformation->ChangeTime;

        stFileIORequest.LastAccessTime = pFcb->ObjectInformation->LastAccessTime;

        stFileIORequest.LastWriteTime = pFcb->ObjectInformation->LastWriteTime;

        //
        // Write the data to the service
        //

        ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_PROCESS_WRITE_FILE,
                                      ulFlags,
                                      &pCcb->AuthGroup,
                                      &pCcb->DirectoryCB->NameInformation.FileName,
                                      &pFcb->ObjectInformation->FileId,
                                      pFcb->ObjectInformation->VolumeCB->VolumeInformation.Cell,
                                      pFcb->ObjectInformation->VolumeCB->VolumeInformation.CellLength,
                                      &stFileIORequest,
                                      sizeof( AFSFileIOCB),
                                      &stFileIOResult,
                                      &ulResultLen);

        if( NT_SUCCESS( ntStatus))
        {

            Irp->IoStatus.Information = (ULONG_PTR)stFileIOResult.Length;
        }
        else
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSNonCachedWriteDirect (%p) Failed to send write to service Status %08lX\n",
                          Irp,
                          ntStatus));
        }

try_exit:

        AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSNonCachedWriteDirect (FO: %p) StartingByte %08lX:%08lX Length %08lX Status %08lX\n",
                      pFileObject,
                      StartingByte.HighPart,
                      StartingByte.LowPart,
                      ByteCount,
                      ntStatus));

        if (NT_SUCCESS(ntStatus) &&
            !bPagingIo &&
            bSynchronousFo)
        {

            pFileObject->CurrentByteOffset.QuadPart = StartingByte.QuadPart + ByteCount;
        }

        AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSNonCachedWriteDirect Completing Irp %p Status %08lX Info %08lX\n",
                      Irp,
                      ntStatus,
                      Irp->IoStatus.Information));

        AFSCompleteRequest( Irp, ntStatus);
    }

    return ntStatus;
}

static
NTSTATUS
AFSCachedWrite( IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp,
                IN LARGE_INTEGER StartingByte,
                IN ULONG ByteCount,
                IN BOOLEAN ForceFlush)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PVOID              pSystemBuffer = NULL;
    NTSTATUS           ntStatus = STATUS_SUCCESS;
    IO_STATUS_BLOCK    iosbFlush;
    IO_STACK_LOCATION *pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    PFILE_OBJECT       pFileObject = pIrpSp->FileObject;
    AFSFcb            *pFcb = (AFSFcb *)pFileObject->FsContext;
    BOOLEAN            bSynchronousFo = BooleanFlagOn( pFileObject->Flags, FO_SYNCHRONOUS_IO);
    ULONG              ulCurrentIO = 0, ulTotalLen = ByteCount;
    PMDL               pCurrentMdl = Irp->MdlAddress;
    LARGE_INTEGER      liCurrentOffset;

    __Enter
    {

        Irp->IoStatus.Information = 0;

        if( BooleanFlagOn( pIrpSp->MinorFunction, IRP_MN_MDL))
        {

            __try
            {

                CcPrepareMdlWrite( pFileObject,
                                   &StartingByte,
                                   ByteCount,
                                   &Irp->MdlAddress,
                                   &Irp->IoStatus);

                ntStatus = Irp->IoStatus.Status;
            }
	    __except( EXCEPTION_EXECUTE_HANDLER)
            {
                ntStatus = GetExceptionCode();

                AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCachedWrite (%p) Exception thrown while preparing mdl write Status %08lX\n",
                              Irp,
                              ntStatus));
            }

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCachedWrite (%p) Failed to process MDL write Status %08lX\n",
                              Irp,
                              ntStatus));

		if ( Irp->IoStatus.Information > 0)
		{

		    CcMdlWriteComplete( pFileObject,
					&StartingByte,
					Irp->MdlAddress);

		    //
		    // Mdl is now Deallocated
		    //

		    Irp->MdlAddress = NULL;
		}
            }

            try_return( ntStatus);
        }

        liCurrentOffset.QuadPart = StartingByte.QuadPart;

        while( ulTotalLen > 0)
        {

            ntStatus = STATUS_SUCCESS;

            if( pCurrentMdl != NULL)
            {

                pSystemBuffer = MmGetSystemAddressForMdlSafe( pCurrentMdl,
                                                              NormalPagePriority);

                ulCurrentIO = MmGetMdlByteCount( pCurrentMdl);

                if( ulCurrentIO > ulTotalLen)
                {
                    ulCurrentIO = ulTotalLen;
                }
            }
            else
            {

                pSystemBuffer = AFSLockSystemBuffer( Irp,
                                                     ulTotalLen);

                ulCurrentIO = ulTotalLen;
            }

            if( pSystemBuffer == NULL)
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCachedWrite (%p) Failed to lock system buffer\n",
                              Irp));

                try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
            }

            __try
            {

                if( !CcCopyWrite( pFileObject,
                                  &liCurrentOffset,
                                  ulCurrentIO,
                                  TRUE,
                                  pSystemBuffer))
                {
                    //
                    // Failed to process request.
                    //

                    AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                  AFS_TRACE_LEVEL_ERROR,
                                  "AFSCachedWrite (%p) Failed to issue CcCopyWrite %wZ @ %0I64X Status %08lX\n",
                                  Irp,
                                  &pFileObject->FileName,
                                  liCurrentOffset.QuadPart,
                                  Irp->IoStatus.Status));

                    try_return( ntStatus = STATUS_UNSUCCESSFUL);
                }
            }
	    __except( EXCEPTION_EXECUTE_HANDLER)
            {

                ntStatus = GetExceptionCode();

                AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCachedWrite (%p) CcCopyWrite Threw exception %wZ @ %0I64X Status %08lX\n",
                              Irp,
                              &pFileObject->FileName,
                              liCurrentOffset.QuadPart,
                              ntStatus));
            }

            if( !NT_SUCCESS( ntStatus))
            {
                try_return( ntStatus);
            }

            if( ForceFlush ||
                BooleanFlagOn(pFileObject->Flags, (FO_NO_INTERMEDIATE_BUFFERING + FO_WRITE_THROUGH)))
            {

		__try
		{
		    //
		    // We have detected a file we do a write through with.
		    //

		    CcFlushCache(&pFcb->NPFcb->SectionObjectPointers,
				  &liCurrentOffset,
				  ulCurrentIO,
				  &iosbFlush);

		    if( !NT_SUCCESS( iosbFlush.Status))
		    {

			AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
				      AFS_TRACE_LEVEL_ERROR,
				      "AFSCachedWrite (%p) CcFlushCache failure %wZ FID %08lX-%08lX-%08lX-%08lX Status 0x%08lX Bytes 0x%08lX\n",
				      Irp,
				      &pFileObject->FileName,
				      pFcb->ObjectInformation->FileId.Cell,
				      pFcb->ObjectInformation->FileId.Volume,
				      pFcb->ObjectInformation->FileId.Vnode,
				      pFcb->ObjectInformation->FileId.Unique,
				      iosbFlush.Status,
				      iosbFlush.Information));

			try_return( ntStatus = iosbFlush.Status);
		    }
		}
		__except( EXCEPTION_EXECUTE_HANDLER)
                {

		    ntStatus = GetExceptionCode();

                    AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                                  AFS_TRACE_LEVEL_ERROR,
				  "AFSCachedWrite (%p) CcFlushCache Threw exception %wZ @ %0I64X Status %08lX\n",
                                  Irp,
                                  &pFileObject->FileName,
				  liCurrentOffset.QuadPart,
				  ntStatus));

		    try_return( ntStatus);
                }
            }

            if( ulTotalLen <= ulCurrentIO)
            {
                break;
            }

            liCurrentOffset.QuadPart += ulCurrentIO;

            ulTotalLen -= ulCurrentIO;

            pCurrentMdl = pCurrentMdl->Next;
        }

try_exit:

        if( NT_SUCCESS( ntStatus))
        {

            Irp->IoStatus.Information = ByteCount;

            if ( ForceFlush ||
                 BooleanFlagOn(pFileObject->Flags, (FO_NO_INTERMEDIATE_BUFFERING + FO_WRITE_THROUGH)))
            {
                //
                // Write through asked for... Set things so that we get
                // flush when the worker thread next wakes up
                //
                pFcb->Specific.File.LastServerFlush.QuadPart = 0;
            }
        }

        AFSCompleteRequest( Irp,
                            ntStatus);
    }

    return ntStatus;
}

//
// Called with Fcb->NPFcb->SectionObjectResource and Fcb->NPFcb->Resource held
//

static
NTSTATUS
AFSExtendingWrite( IN AFSFcb *Fcb,
                   IN PFILE_OBJECT FileObject,
                   IN LONGLONG NewLength)
{
    LARGE_INTEGER liSaveFileSize = Fcb->Header.FileSize;
    LARGE_INTEGER liSaveAllocation = Fcb->Header.AllocationSize;
    NTSTATUS      ntStatus = STATUS_SUCCESS;
    AFSCcb       *pCcb = (AFSCcb *)FileObject->FsContext2;

    if( NewLength > Fcb->Header.AllocationSize.QuadPart)
    {

        Fcb->Header.AllocationSize.QuadPart = NewLength;

        Fcb->ObjectInformation->AllocationSize = Fcb->Header.AllocationSize;
    }

    if( NewLength > Fcb->Header.FileSize.QuadPart)
    {

        Fcb->Header.FileSize.QuadPart = NewLength;

        Fcb->ObjectInformation->EndOfFile = Fcb->Header.FileSize;
    }

    //
    // Tell the server
    //

    ntStatus = AFSUpdateFileInformation( &Fcb->ObjectInformation->ParentFileId,
                                         Fcb->ObjectInformation,
                                         &pCcb->AuthGroup);

    if (NT_SUCCESS(ntStatus))
    {

        KeQuerySystemTime( &Fcb->ObjectInformation->ChangeTime);

        SetFlag( Fcb->Flags, AFS_FCB_FLAG_FILE_MODIFIED | AFS_FCB_FLAG_UPDATE_CHANGE_TIME);

        //
        // If the file is currently cached, then let the MM know about the extension
        //
	// The CcSetFileSizes call should be made with only the PagingResource held
	// which we are currently not holding.
	//

        if( CcIsFileCached( FileObject))
        {
            CcSetFileSizes( FileObject,
                            (PCC_FILE_SIZES)&Fcb->Header.AllocationSize);
        }
    }
    else
    {
        Fcb->Header.FileSize = liSaveFileSize;
        Fcb->Header.AllocationSize = liSaveAllocation;
    }

    //
    // DownConvert file resource to shared
    //
    ExConvertExclusiveToSharedLite( &Fcb->NPFcb->Resource);

    return ntStatus;
}

NTSTATUS
AFSShareWrite( IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp)
{

    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    AFSFcb *pFcb = NULL;
    AFSCcb *pCcb = NULL;
    AFSPipeIORequestCB *pIoRequest = NULL;
    void *pBuffer = NULL;
    AFSPipeIOResultCB stIoResult;
    ULONG ulBytesReturned = 0;

    __Enter
    {

        pCcb = (AFSCcb *)pIrpSp->FileObject->FsContext2;

        AFSDbgTrace(( AFS_SUBSYSTEM_PIPE_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSShareWrite On pipe %wZ Length %08lX\n",
                      &pCcb->DirectoryCB->NameInformation.FileName,
                      pIrpSp->Parameters.Write.Length));

        if( pIrpSp->Parameters.Write.Length == 0)
        {

            //
            // Nothing to do in this case
            //

            try_return( ntStatus);
        }

        //
        // Retrieve the buffer for the read request
        //

        pBuffer = AFSLockSystemBuffer( Irp,
                                       pIrpSp->Parameters.Write.Length);

        if( pBuffer == NULL)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_PIPE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSShareWrite Failed to map buffer on pipe %wZ\n",
                          &pCcb->DirectoryCB->NameInformation.FileName));

            try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
        }

	pFcb = (AFSFcb *)pIrpSp->FileObject->FsContext;

        AFSAcquireShared( &pFcb->NPFcb->Resource,
                          TRUE);

        pIoRequest = (AFSPipeIORequestCB *)AFSExAllocatePoolWithTag( PagedPool,
                                                                     sizeof( AFSPipeIORequestCB) +
                                                                                pIrpSp->Parameters.Write.Length,
                                                                     AFS_GENERIC_MEMORY_14_TAG);

        if( pIoRequest == NULL)
        {

            try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
        }

        RtlZeroMemory( pIoRequest,
                       sizeof( AFSPipeIORequestCB) + pIrpSp->Parameters.Write.Length);

        pIoRequest->RequestId = pCcb->RequestID;

        pIoRequest->RootId = pFcb->ObjectInformation->VolumeCB->ObjectInformation.FileId;

        pIoRequest->BufferLength = pIrpSp->Parameters.Write.Length;

        RtlCopyMemory( (void *)((char *)pIoRequest + sizeof( AFSPipeIORequestCB)),
                       pBuffer,
                       pIrpSp->Parameters.Write.Length);

        stIoResult.BytesProcessed = 0;

        ulBytesReturned = sizeof( AFSPipeIOResultCB);

        //
        // Issue the open request to the service
        //

        ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_PIPE_WRITE,
                                      AFS_REQUEST_FLAG_SYNCHRONOUS,
                                      &pCcb->AuthGroup,
                                      &pCcb->DirectoryCB->NameInformation.FileName,
                                      NULL,
                                      NULL,
                                      0,
                                      pIoRequest,
                                      sizeof( AFSPipeIORequestCB) +
                                                pIrpSp->Parameters.Write.Length,
                                      &stIoResult,
                                      &ulBytesReturned);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSShareWrite (%p) Failed service write Status %08lX\n",
                          Irp,
                          ntStatus));

            try_return( ntStatus);
        }

        AFSDbgTrace(( AFS_SUBSYSTEM_PIPE_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSShareWrite Completed on pipe %wZ Length read %08lX\n",
                      &pCcb->DirectoryCB->NameInformation.FileName,
                      stIoResult.BytesProcessed));

        Irp->IoStatus.Information = stIoResult.BytesProcessed;

try_exit:

        if( pFcb != NULL)
        {

            AFSReleaseResource( &pFcb->NPFcb->Resource);
        }

        if( pIoRequest != NULL)
        {

            AFSExFreePoolWithTag( pIoRequest, AFS_GENERIC_MEMORY_14_TAG);
        }
    }

    return ntStatus;
}

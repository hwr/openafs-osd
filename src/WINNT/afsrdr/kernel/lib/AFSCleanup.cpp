/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Kernel Drivers, LLC.
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
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
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
// File: AFSCleanup.cpp
//

#include "AFSCommon.h"

//
// Function: AFSCleanup
//
// Description:
//
//      This function is the IRP_MJ_CLEANUP dispatch handler
//
// Return:
//
//       A status is returned for the handling of this request
//

NTSTATUS
AFSCleanup( IN PDEVICE_OBJECT LibDeviceObject,
            IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(LibDeviceObject);
    NTSTATUS ntStatus = STATUS_SUCCESS;
    AFSDeviceExt *pDeviceExt = NULL;
    IO_STACK_LOCATION *pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    AFSFcb *pFcb = NULL;
    AFSCcb *pCcb = NULL;
    PFILE_OBJECT pFileObject = NULL;
    AFSFcb *pRootFcb = NULL;
    AFSDeviceExt *pControlDeviceExt = NULL;
    IO_STATUS_BLOCK stIoSB;
    AFSObjectInfoCB *pObjectInfo = NULL;
    AFSObjectInfoCB *pParentObjectInfo = NULL;
    AFSFileCleanupCB stFileCleanup;
    AFSFileCleanupResultCB *pResultCB = NULL;
    ULONG ulResultLen = 0;
    ULONG   ulNotificationFlags = 0;
    LONG    lCount;

    __try
    {

        if( AFSRDRDeviceObject == NULL)
        {

            //
            // Let this through, it's a cleanup on the library control device
            //

            try_return( ntStatus);
        }

        pDeviceExt = (AFSDeviceExt *)AFSRDRDeviceObject->DeviceExtension;

        pControlDeviceExt = (AFSDeviceExt *)AFSControlDeviceObject->DeviceExtension;

        //
        // Set some initial variables to make processing easier
        //

        pFileObject = pIrpSp->FileObject;

        pFcb = (AFSFcb *)pIrpSp->FileObject->FsContext;

        pCcb = (AFSCcb *)pIrpSp->FileObject->FsContext2;

        if( pFcb == NULL)
        {
            try_return( ntStatus);
        }

        pObjectInfo = pFcb->ObjectInformation;

        if ( BooleanFlagOn( pObjectInfo->Flags, AFS_OBJECT_FLAGS_PARENT_FID))
        {

            pParentObjectInfo = AFSFindObjectInfo( pObjectInfo->VolumeCB,
                                                   &pObjectInfo->ParentFileId,
                                                   FALSE);
        }

        pRootFcb = pObjectInfo->VolumeCB->RootFcb;

        RtlZeroMemory( &stFileCleanup,
                       sizeof( AFSFileCleanupCB));

        stFileCleanup.ProcessId = (ULONGLONG)PsGetCurrentProcessId();

        stFileCleanup.Identifier = (ULONGLONG)pFileObject;

        //
        // Allocate our return buffer
        //

        pResultCB = (AFSFileCleanupResultCB *)AFSExAllocatePoolWithTag( PagedPool,
                                                                        PAGE_SIZE,
                                                                        AFS_GENERIC_MEMORY_32_TAG);

        if( pResultCB == NULL)
        {

            try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
        }

        RtlZeroMemory( pResultCB,
                       PAGE_SIZE);

        ulResultLen = PAGE_SIZE;


        //
        // Perform the cleanup functionality depending on the type of node it is
        //

        switch( pFcb->Header.NodeTypeCode)
        {

            case AFS_ROOT_ALL:
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup Acquiring GlobalRoot lock %p EXCL %08lX\n",
                              &pFcb->NPFcb->Resource,
                              PsGetCurrentThread()));

                AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                  TRUE);

                FsRtlNotifyCleanup( pControlDeviceExt->Specific.Control.NotifySync,
                                    &pControlDeviceExt->Specific.Control.DirNotifyList,
                                    pCcb);

                ASSERT( pFcb->OpenHandleCount != 0);

                lCount = InterlockedDecrement( &pFcb->OpenHandleCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup (RootAll) Decrement handle count on Fcb %p Cnt %d\n",
                              pFcb,
                              lCount));

                AFSReleaseResource( &pFcb->NPFcb->Resource);

                break;
            }

            case AFS_IOCTL_FCB:
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup Acquiring PIOCtl lock %p EXCL %08lX\n",
                              &pFcb->NPFcb->Resource,
                              PsGetCurrentThread()));

                AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                  TRUE);

                ASSERT( pFcb->OpenHandleCount != 0);

                //
                // Decrement the open child handle count
                //

                if( pParentObjectInfo != NULL &&
                    pParentObjectInfo->Specific.Directory.ChildOpenHandleCount > 0)
                {

                    lCount = InterlockedDecrement( &pParentObjectInfo->Specific.Directory.ChildOpenHandleCount);

                    AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCleanup (IOCtl) Decrement child open handle count on Parent object %p Cnt %d\n",
                                  pParentObjectInfo,
                                  lCount));
                }

                AFSReleaseResource( &pFcb->NPFcb->Resource);

                lCount = InterlockedDecrement( &pFcb->OpenHandleCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup (IOCtl) Decrement handle count on Fcb %p Cnt %d\n",
                              pFcb,
                              lCount));

                break;
            }

            //
            // This Fcb represents a file
            //

            case AFS_FILE_FCB:
            {

                //
                // We may be performing some cleanup on the Fcb so grab it exclusive to ensure no collisions
                //


		AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
			      AFS_TRACE_LEVEL_VERBOSE,
			      "AFSCleanup Acquiring Fcb lock %p EXCL %08lX\n",
			      &pFcb->NPFcb->Resource,
			      PsGetCurrentThread()));

		AFSAcquireExcl( &pFcb->NPFcb->Resource,
				TRUE);

		AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING|AFS_SUBSYSTEM_SECTION_OBJECT,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup Acquiring Fcb SectionObject lock %p EXCL %08lX\n",
                              &pFcb->NPFcb->SectionObjectResource,
                              PsGetCurrentThread()));

                AFSAcquireExcl( &pFcb->NPFcb->SectionObjectResource,
                                TRUE);

		__try
                {

		    //
		    // If the handle has write permission ...
		    //

		    if( ((pCcb->GrantedAccess & FILE_WRITE_DATA) || pFcb->OpenHandleCount == 1) &&
			CcIsFileCached( pIrpSp->FileObject))
                    {

                        CcFlushCache( &pFcb->NPFcb->SectionObjectPointers,
                                      NULL,
                                      0,
                                      &stIoSB);

                        if( !NT_SUCCESS( stIoSB.Status))
                        {

                            AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                                          AFS_TRACE_LEVEL_ERROR,
                                          "AFSCleanup CcFlushCache failure %wZ FID %08lX-%08lX-%08lX-%08lX Status 0x%08lX Bytes 0x%08lX\n",
                                          &pCcb->FullFileName,
                                          pObjectInfo->FileId.Cell,
                                          pObjectInfo->FileId.Volume,
                                          pObjectInfo->FileId.Vnode,
                                          pObjectInfo->FileId.Unique,
                                          stIoSB.Status,
                                          stIoSB.Information));

                            ntStatus = stIoSB.Status;
                        }

                        if ( ( pFcb->OpenHandleCount == 1 ||
                               BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_PURGE_ON_CLOSE)) &&
                             pFcb->NPFcb->SectionObjectPointers.DataSectionObject != NULL)
                        {

                            if ( !CcPurgeCacheSection( &pFcb->NPFcb->SectionObjectPointers,
                                                       NULL,
                                                       0,
                                                       FALSE))
                            {

                                AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
                                              AFS_TRACE_LEVEL_WARNING,
                                              "AFSCleanup CcPurgeCacheSection failure FID %08lX-%08lX-%08lX-%08lX\n",
                                              pObjectInfo->FileId.Cell,
                                              pObjectInfo->FileId.Volume,
                                              pObjectInfo->FileId.Vnode,
                                              pObjectInfo->FileId.Unique));

                                SetFlag( pObjectInfo->Fcb->Flags, AFS_FCB_FLAG_PURGE_ON_CLOSE);
                            }
                            else
                            {
                                ClearFlag( pObjectInfo->Fcb->Flags, AFS_FCB_FLAG_PURGE_ON_CLOSE);
                            }
                        }
                    }

		    //
		    // Uninitialize the cache map. This call is unconditional.
		    //

		    AFSDbgTrace(( AFS_SUBSYSTEM_IO_PROCESSING,
				  AFS_TRACE_LEVEL_VERBOSE,
				  "AFSCleanup Tearing down cache map for Fcb %p FileObject %p\n",
				  pFcb,
				  pFileObject));

		    CcUninitializeCacheMap( pFileObject,
					    NULL,
					    NULL);
		}
		__except( EXCEPTION_EXECUTE_HANDLER)
		{

		    ntStatus = GetExceptionCode();

		    AFSDbgTrace(( 0,
				  0,
				  "EXCEPTION - AFSCleanup Cc FID %08lX-%08lX-%08lX-%08lX Status 0x%08lX\n",
				  pObjectInfo->FileId.Cell,
				  pObjectInfo->FileId.Volume,
				  pObjectInfo->FileId.Vnode,
				  pObjectInfo->FileId.Unique,
				  ntStatus));

		    SetFlag( pObjectInfo->Fcb->Flags, AFS_FCB_FLAG_PURGE_ON_CLOSE);
                }

		AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING|AFS_SUBSYSTEM_SECTION_OBJECT,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup Releasing Fcb SectionObject lock %p EXCL %08lX\n",
                              &pFcb->NPFcb->SectionObjectResource,
                              PsGetCurrentThread()));

                AFSReleaseResource( &pFcb->NPFcb->SectionObjectResource);

                //
                // Unlock all outstanding locks on the file, again, unconditionally
                //

                (VOID) FsRtlFastUnlockAll( &pFcb->Specific.File.FileLock,
                                           pFileObject,
                                           IoGetRequestorProcess( Irp),
                                           NULL);

                //
                // Tell the service to unlock all on the file
                //

                ulNotificationFlags |= AFS_REQUEST_FLAG_BYTE_RANGE_UNLOCK_ALL;

                //
                // Perform some final common processing
                //

                ASSERT( pFcb->OpenHandleCount != 0);

                if( pParentObjectInfo != NULL)
                {

                    stFileCleanup.ParentId = pParentObjectInfo->FileId;
                }

                stFileCleanup.LastAccessTime = pObjectInfo->LastAccessTime;

		//
		// If the file has been modified set the last write time in ObjectInfo to 'now'
		// unless the last write time was set via this File Object.  Then tell the
		// following code to write the time.
		//
		if ( BooleanFlagOn( pFileObject->Flags, FO_FILE_MODIFIED) &&
		     !BooleanFlagOn( pCcb->Flags, CCB_FLAG_LAST_WRITE_TIME_SET)) {

		    SetFlag( pFcb->Flags, AFS_FCB_FLAG_FILE_MODIFIED);

		    SetFlag( pFcb->Flags, AFS_FCB_FLAG_UPDATE_LAST_WRITE_TIME);

		    KeQuerySystemTime(&pFcb->ObjectInformation->LastWriteTime);
		}

                if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_FILE_MODIFIED))
                {

                    stFileCleanup.AllocationSize = pObjectInfo->EndOfFile;

                    stFileCleanup.FileAttributes = pObjectInfo->FileAttributes;

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_UPDATE_CREATE_TIME))
                    {

                        stFileCleanup.CreateTime = pObjectInfo->CreationTime;

                        ClearFlag( pFcb->Flags, AFS_FCB_FLAG_UPDATE_CREATE_TIME);
                    }

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_UPDATE_CHANGE_TIME))
                    {

                        stFileCleanup.ChangeTime = pObjectInfo->ChangeTime;

                        ClearFlag( pFcb->Flags, AFS_FCB_FLAG_UPDATE_CHANGE_TIME);
                    }

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_UPDATE_ACCESS_TIME))
                    {

                        stFileCleanup.LastAccessTime = pObjectInfo->LastAccessTime;

                        ClearFlag( pFcb->Flags, AFS_FCB_FLAG_UPDATE_ACCESS_TIME);
                    }

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_UPDATE_LAST_WRITE_TIME))
                    {

                        stFileCleanup.LastWriteTime = pObjectInfo->LastWriteTime;

			ClearFlag( pFcb->Flags, AFS_FCB_FLAG_UPDATE_LAST_WRITE_TIME);
                    }
                }

                //
                // If the count has dropped to one and there is a pending delete
                // then delete the node.  The final count will be decremented just
                // before the Fcb->NPFcb->Resource is released.
                //

                if( pFcb->OpenHandleCount == 1 &&
                    BooleanFlagOn( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_PENDING_DELETE))
                {

		    //
		    // Release the Fcb Resource while processing the pending delete
		    // to avoid an out of order lock acquisition
		    //

		    ClearFlag( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_PENDING_DELETE);

		    AFSReleaseResource( &pFcb->NPFcb->Resource);

                    ntStatus = STATUS_SUCCESS;

                    ulNotificationFlags |= AFS_REQUEST_FLAG_FILE_DELETED;

                    //
                    // Indicate the file access mode that is being released
                    //

                    stFileCleanup.FileAccess = pCcb->FileAccess;

                    //
                    // Push the request to the service
                    //

                    ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_CLEANUP_PROCESSING,
                                                  ulNotificationFlags | AFS_REQUEST_FLAG_SYNCHRONOUS,
                                                  &pCcb->AuthGroup,
                                                  &pCcb->DirectoryCB->NameInformation.FileName,
                                                  &pObjectInfo->FileId,
                                                  pObjectInfo->VolumeCB->VolumeInformation.Cell,
                                                  pObjectInfo->VolumeCB->VolumeInformation.CellLength,
                                                  &stFileCleanup,
                                                  sizeof( AFSFileCleanupCB),
                                                  pResultCB,
                                                  &ulResultLen);

                    if( !NT_SUCCESS( ntStatus) &&
                        ntStatus != STATUS_OBJECT_NAME_NOT_FOUND)
                    {

                        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                      AFS_TRACE_LEVEL_ERROR,
                                      "AFSCleanup Failed to notify service of deleted file %wZ Status %08lX\n",
                                      &pCcb->FullFileName,
                                      ntStatus));

                        ntStatus = STATUS_SUCCESS;
                    }
                    else
                    {

                        ntStatus = STATUS_SUCCESS;

                        if ( --pObjectInfo->Links < 1)
                        {

                            //
                            // Stop anything possibly in process
                            //

                            AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                                          AFS_TRACE_LEVEL_VERBOSE,
                                          "AFSCleanup Acquiring Fcb extents lock %p EXCL %08lX\n",
                                          &pFcb->NPFcb->Specific.File.ExtentsResource,
                                          PsGetCurrentThread()));

                            AFSAcquireExcl( &pFcb->NPFcb->Specific.File.ExtentsResource,
                                            TRUE);

                            pFcb->NPFcb->Specific.File.ExtentsRequestStatus = STATUS_FILE_DELETED;

                            KeSetEvent( &pFcb->NPFcb->Specific.File.ExtentsRequestComplete,
                                        0,
                                        FALSE);

                            //
                            // The file has been deleted since the Link count is zero
                            //

                            AFSDeleteFcbExtents( pFcb);

                            AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                                          AFS_TRACE_LEVEL_VERBOSE,
                                          "AFSCleanup Releasing Fcb extents lock %p EXCL %08lX\n",
                                          &pFcb->NPFcb->Specific.File.ExtentsResource,
                                          PsGetCurrentThread()));

                            AFSReleaseResource( &pFcb->NPFcb->Specific.File.ExtentsResource);
                        }

                        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                      AFS_TRACE_LEVEL_VERBOSE,
                                      "AFSCleanup Setting DELETE flag in file %wZ Dir Entry %p\n",
                                      &pCcb->FullFileName,
                                      pCcb->DirectoryCB));

                        SetFlag( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_DELETED);

                        ASSERT( pParentObjectInfo != NULL);

                        if ( pParentObjectInfo != NULL)
                        {

                            AFSAcquireExcl( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock,
                                            TRUE);

                            if ( pParentObjectInfo->DataVersion.QuadPart != pResultCB->ParentDataVersion.QuadPart - 1)
                            {

                                SetFlag( pParentObjectInfo->Flags, AFS_OBJECT_FLAGS_VERIFY);

                                pParentObjectInfo->DataVersion.QuadPart = (ULONGLONG)-1;
                            }
                            else
                            {

                                pParentObjectInfo->DataVersion.QuadPart = pResultCB->ParentDataVersion.QuadPart;
                            }

                            //
                            // Now that the service has the entry has deleted we need to remove it from the parent
                            // tree so another lookup on the node will fail
                            //

                            if( !BooleanFlagOn( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_NOT_IN_PARENT_TREE))
                            {

                                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                              AFS_TRACE_LEVEL_VERBOSE,
                                              "AFSCleanup DE %p for %wZ removing entry\n",
                                              pCcb->DirectoryCB,
                                              &pCcb->DirectoryCB->NameInformation.FileName));

                                AFSRemoveNameEntry( pParentObjectInfo,
                                                    pCcb->DirectoryCB);
                            }
                            else
                            {

                                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                              AFS_TRACE_LEVEL_VERBOSE,
                                              "AFSCleanup DE %p for %wZ NOT removing entry due to flag set\n",
                                              pCcb->DirectoryCB,
                                              &pCcb->DirectoryCB->NameInformation.FileName));
                            }

                            AFSReleaseResource( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock);

                            AFSFsRtlNotifyFullReportChange( pParentObjectInfo,
                                                            pCcb,
                                                            (ULONG)FILE_NOTIFY_CHANGE_FILE_NAME,
                                                            (ULONG)FILE_ACTION_REMOVED);
                        }
                        else
                        {
                            if( !BooleanFlagOn( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_NOT_IN_PARENT_TREE))
                            {

                                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                              AFS_TRACE_LEVEL_VERBOSE,
                                              "AFSCleanup DE %p for %wZ NOT removing entry due to pParentObjectInfo == NULL\n",
                                              pCcb->DirectoryCB,
                                              &pCcb->DirectoryCB->NameInformation.FileName));
                            }
                        }
                    }

		    //
		    // Regain exclusive access to the Fcb
		    //

		    AFSAcquireExcl( &pFcb->NPFcb->Resource,
				    TRUE);
                }
                else
                {

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_FILE_MODIFIED) &&
                        pParentObjectInfo != NULL)
                    {

                        ULONG ulNotifyFilter = 0;

                        ClearFlag( pFcb->Flags, AFS_FCB_FLAG_FILE_MODIFIED);

                        ulNotifyFilter |= (FILE_NOTIFY_CHANGE_ATTRIBUTES);

                        AFSFsRtlNotifyFullReportChange( pParentObjectInfo,
                                                        pCcb,
                                                        (ULONG)ulNotifyFilter,
                                                        (ULONG)FILE_ACTION_MODIFIED);
                    }


                    //
                    // Whenever a handle with write access or the last handle is closed
                    // notify the service to FSync the file.  If the redirector is holding
                    // dirty extents, flush them to the service.  This is a bit aggressive
                    // but it ensures cache coherency.
                    //

                    if( (pCcb->GrantedAccess & FILE_WRITE_DATA) || (pFcb->OpenHandleCount == 1))
                    {

                        if ( pFcb->Specific.File.ExtentsDirtyCount != 0)
                        {

                            AFSFlushExtents( pFcb,
                                             &pCcb->AuthGroup);
                        }

                        ulNotificationFlags |= AFS_REQUEST_FLAG_FLUSH_FILE;
                    }

                    if( pFcb->OpenHandleCount == 1)
                    {

                        //
                        // Wait for any outstanding queued flushes to complete
                        //

                        AFSWaitOnQueuedFlushes( pFcb);

                        AFSTearDownFcbExtents( pFcb,
                                               &pCcb->AuthGroup);
                    }

                    //
                    // Indicate the file access mode that is being released
                    //

                    stFileCleanup.FileAccess = pCcb->FileAccess;

                    //
                    // Remove the share access at this time since we may not get the close for sometime on this FO.
                    //

                    IoRemoveShareAccess( pFileObject,
                                         &pFcb->ShareAccess);


                    //
                    // We don't need the name array after the user closes the handle on the file
                    //

                    if( pCcb->NameArray != NULL)
                    {

                        AFSFreeNameArray( pCcb->NameArray);

                        pCcb->NameArray = NULL;
                    }

                    //
                    // Release the Fcb Resource across the call to the service
                    // which may block for quite a while if flushing of the
                    // data is required.
                    //

                    AFSReleaseResource( &pFcb->NPFcb->Resource);

                    //
                    // Push the request to the service
                    //

                    ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_CLEANUP_PROCESSING,
                                                  ulNotificationFlags | AFS_REQUEST_FLAG_SYNCHRONOUS,
                                                  &pCcb->AuthGroup,
                                                  &pCcb->DirectoryCB->NameInformation.FileName,
                                                  &pObjectInfo->FileId,
                                                  pObjectInfo->VolumeCB->VolumeInformation.Cell,
                                                  pObjectInfo->VolumeCB->VolumeInformation.CellLength,
                                                  &stFileCleanup,
                                                  sizeof( AFSFileCleanupCB),
                                                  pResultCB,
                                                  &ulResultLen);

                    //
                    // Regain exclusive access to the Fcb
                    //

                    AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                    TRUE);

                    if ( NT_SUCCESS( ntStatus))
                    {

                        if ( pParentObjectInfo != NULL)
                        {

                            AFSAcquireExcl( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock,
                                            TRUE);

                            if ( pParentObjectInfo->DataVersion.QuadPart != pResultCB->ParentDataVersion.QuadPart)
                            {

                                SetFlag( pParentObjectInfo->Flags, AFS_OBJECT_FLAGS_VERIFY);

                                pParentObjectInfo->DataVersion.QuadPart = (ULONGLONG)-1;
                            }

                            AFSReleaseResource( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock);
                        }
                    }

                    ntStatus = STATUS_SUCCESS;
                }

                //
                // Decrement the open child handle count
                //

                if( pParentObjectInfo != NULL)
                {

                    ASSERT( pParentObjectInfo->Specific.Directory.ChildOpenHandleCount > 0);

                    lCount = InterlockedDecrement( &pParentObjectInfo->Specific.Directory.ChildOpenHandleCount);

                    AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCleanup (File) Decrement child open handle count on Parent object %p Cnt %d\n",
                                  pParentObjectInfo,
                                  lCount));
                }


                lCount = InterlockedDecrement( &pFcb->OpenHandleCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup (File) Decrement handle count on Fcb %p Cnt %d\n",
                              pFcb,
                              lCount));

                if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_PURGE_ON_CLOSE))
                {
                    //
                    // The ObjectReferenceCount will be freed by AFSPerformObjectInvalidate
                    //

                    lCount = AFSObjectInfoIncrement( pObjectInfo,
                                                     AFS_OBJECT_REFERENCE_INVALIDATION);

                    AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCleanup Setting Purge on Close Increment count on object %p Cnt %d\n",
                                  pObjectInfo,
                                  lCount));

                    ClearFlag( pFcb->Flags, AFS_FCB_FLAG_PURGE_ON_CLOSE);

                    AFSReleaseResource( &pFcb->NPFcb->Resource);

                    AFSPerformObjectInvalidate( pObjectInfo,
                                                AFS_INVALIDATE_DATA_VERSION);
                }
                else
                {

                    AFSReleaseResource( &pFcb->NPFcb->Resource);
                }

                break;
            }

            //
            // Root or directory node
            //

            case AFS_ROOT_FCB:
            {

                //
                // Set the root Fcb to this node
                //

                pRootFcb = pFcb;

                //
                // Fall through to below
                //
            }

            case AFS_DIRECTORY_FCB:
            {

                //
                // We may be performing some cleanup on the Fcb so grab it exclusive to ensure no collisions
                //

                AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup Acquiring Dcb lock %p EXCL %08lX\n",
                              &pFcb->NPFcb->Resource,
                              PsGetCurrentThread()));

                AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                  TRUE);

                //
                // Perform some final common processing
                //

                ASSERT( pFcb->OpenHandleCount != 0);

                if( pParentObjectInfo != NULL)
                {

                    stFileCleanup.ParentId = pParentObjectInfo->FileId;
                }

                stFileCleanup.LastAccessTime = pObjectInfo->LastAccessTime;

                if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_FILE_MODIFIED))
                {

                    stFileCleanup.FileAttributes = pObjectInfo->FileAttributes;

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_UPDATE_CREATE_TIME))
                    {

                        stFileCleanup.CreateTime = pObjectInfo->CreationTime;

                        ClearFlag( pFcb->Flags, AFS_FCB_FLAG_UPDATE_CREATE_TIME);
                    }

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_UPDATE_CHANGE_TIME))
                    {

                        stFileCleanup.ChangeTime = pObjectInfo->ChangeTime;

                        ClearFlag( pFcb->Flags, AFS_FCB_FLAG_UPDATE_CHANGE_TIME);
                    }

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_UPDATE_ACCESS_TIME))
                    {

                        stFileCleanup.LastAccessTime = pObjectInfo->LastAccessTime;

                        ClearFlag( pFcb->Flags, AFS_FCB_FLAG_UPDATE_ACCESS_TIME);
                    }
                }

                //
                // If the count has dropped to one and there is a pending delete
                // then delete the node.  The final count will be decremented just
                // before the Fcb->NPFcb->Resource is released.
                //

                if( pFcb->OpenHandleCount == 1 &&
                    BooleanFlagOn( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_PENDING_DELETE))
                {

		    //
		    // Release the Fcb Resource while processing the pending delete
		    // to avoid an out of order lock acquisition
		    //

		    ClearFlag( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_PENDING_DELETE);

		    AFSReleaseResource( &pFcb->NPFcb->Resource);

                    //
                    // Try to notify the service about the delete
                    //

                    ulNotificationFlags |= AFS_REQUEST_FLAG_FILE_DELETED;

                    //
                    // Indicate the file access mode that is being released
                    //

                    stFileCleanup.FileAccess = pCcb->FileAccess;

                    //
                    // Push the request to the service
                    //

                    ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_CLEANUP_PROCESSING,
                                                  ulNotificationFlags | AFS_REQUEST_FLAG_SYNCHRONOUS,
                                                  &pCcb->AuthGroup,
                                                  &pCcb->DirectoryCB->NameInformation.FileName,
                                                  &pObjectInfo->FileId,
                                                  pObjectInfo->VolumeCB->VolumeInformation.Cell,
                                                  pObjectInfo->VolumeCB->VolumeInformation.CellLength,
                                                  &stFileCleanup,
                                                  sizeof( AFSFileCleanupCB),
                                                  pResultCB,
                                                  &ulResultLen);

                    if( !NT_SUCCESS( ntStatus) &&
                        ntStatus != STATUS_OBJECT_NAME_NOT_FOUND)
                    {

                        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                      AFS_TRACE_LEVEL_ERROR,
                                      "AFSCleanup Failed to notify service of deleted directory %wZ Status %08lX\n",
                                      &pCcb->FullFileName,
                                      ntStatus));

                        ntStatus = STATUS_SUCCESS;
                    }
                    else
                    {

                        ntStatus = STATUS_SUCCESS;

                        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                      AFS_TRACE_LEVEL_VERBOSE,
                                      "AFSCleanup Setting DELETE flag in directory %wZ Dir Entry %p\n",
                                      &pCcb->FullFileName,
                                      pCcb->DirectoryCB));

                        SetFlag( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_DELETED);

                        ASSERT( pParentObjectInfo != NULL);

                        if ( pParentObjectInfo != NULL)
                        {

                            AFSAcquireExcl( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock,
                                            TRUE);

                            if ( pParentObjectInfo->DataVersion.QuadPart != pResultCB->ParentDataVersion.QuadPart - 1)
                            {

                                SetFlag( pParentObjectInfo->Flags, AFS_OBJECT_FLAGS_VERIFY);

                                pParentObjectInfo->DataVersion.QuadPart = (ULONGLONG)-1;
                            }
                            else
                            {

                                pParentObjectInfo->DataVersion.QuadPart = pResultCB->ParentDataVersion.QuadPart;
                            }

                            //
                            // Now that the service has the entry has deleted we need to remove it from the parent
                            // tree so another lookup on the node will fail
                            //

                            if( !BooleanFlagOn( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_NOT_IN_PARENT_TREE))
                            {

                                AFSRemoveNameEntry( pParentObjectInfo,
                                                    pCcb->DirectoryCB);
                            }
                            else
                            {

                                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                              AFS_TRACE_LEVEL_VERBOSE,
                                              "AFSCleanup DE %p for %wZ NOT removing entry due to flag set\n",
                                              pCcb->DirectoryCB,
                                              &pCcb->DirectoryCB->NameInformation.FileName));
                            }

                            AFSReleaseResource( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock);

                            AFSFsRtlNotifyFullReportChange( pParentObjectInfo,
                                                            pCcb,
                                                            (ULONG)FILE_NOTIFY_CHANGE_FILE_NAME,
                                                            (ULONG)FILE_ACTION_REMOVED);
                        }
                        else
                        {
                            if( !BooleanFlagOn( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_NOT_IN_PARENT_TREE))
                            {

                                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                              AFS_TRACE_LEVEL_VERBOSE,
                                              "AFSCleanup DE %p for %wZ NOT removing entry due to pParentObjectInfo == NULL\n",
                                              pCcb->DirectoryCB,
                                              &pCcb->DirectoryCB->NameInformation.FileName));
                            }
                        }
                    }

		    //
		    // Regain exclusive access to the Fcb
		    //

		    AFSAcquireExcl( &pFcb->NPFcb->Resource,
				    TRUE);
                }

                //
                // If there have been any updates to the node then push it to
                // the service
                //

                else
                {

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_FILE_MODIFIED) &&
                        pParentObjectInfo != NULL)
                    {

                        ULONG ulNotifyFilter = 0;

                        ClearFlag( pFcb->Flags, AFS_FCB_FLAG_FILE_MODIFIED);

                        ulNotifyFilter |= (FILE_NOTIFY_CHANGE_ATTRIBUTES);

                        AFSFsRtlNotifyFullReportChange( pParentObjectInfo,
                                                        pCcb,
                                                        (ULONG)ulNotifyFilter,
                                                        (ULONG)FILE_ACTION_MODIFIED);
                    }

                    //
                    // Indicate the file access mode that is being released
                    //

                    stFileCleanup.FileAccess = pCcb->FileAccess;

                    ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_CLEANUP_PROCESSING,
                                                  ulNotificationFlags | AFS_REQUEST_FLAG_SYNCHRONOUS,
                                                  &pCcb->AuthGroup,
                                                  &pCcb->DirectoryCB->NameInformation.FileName,
                                                  &pObjectInfo->FileId,
                                                  pObjectInfo->VolumeCB->VolumeInformation.Cell,
                                                  pObjectInfo->VolumeCB->VolumeInformation.CellLength,
                                                  &stFileCleanup,
                                                  sizeof( AFSFileCleanupCB),
                                                  pResultCB,
                                                  &ulResultLen);

                    if ( NT_SUCCESS( ntStatus))
                    {

                        if ( pParentObjectInfo != NULL)
                        {

                            AFSAcquireExcl( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock,
                                              TRUE);

                            if ( pParentObjectInfo->DataVersion.QuadPart != pResultCB->ParentDataVersion.QuadPart)
                            {

                                SetFlag( pParentObjectInfo->Flags, AFS_OBJECT_FLAGS_VERIFY);

                                pParentObjectInfo->DataVersion.QuadPart = (ULONGLONG)-1;
                            }

                            AFSReleaseResource( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock);
                        }
                    }

                    ntStatus = STATUS_SUCCESS;
                }

                //
                // Release the notification for this directory if there is one
                //

                FsRtlNotifyCleanup( pControlDeviceExt->Specific.Control.NotifySync,
                                    &pControlDeviceExt->Specific.Control.DirNotifyList,
                                    pCcb);

                //
                // Remove the share access at this time since we may not get the close for sometime on this FO.
                //

                IoRemoveShareAccess( pFileObject,
                                     &pFcb->ShareAccess);

                //
                // We don't need the name array after the user closes the handle on the file
                //

                if( pCcb->NameArray != NULL)
                {

                    AFSFreeNameArray( pCcb->NameArray);

                    pCcb->NameArray = NULL;
                }

                //
                // Decrement the open child handle count
                //

                if( pParentObjectInfo != NULL)
                {

                    ASSERT( pParentObjectInfo->Specific.Directory.ChildOpenHandleCount > 0);

                    lCount = InterlockedDecrement( &pParentObjectInfo->Specific.Directory.ChildOpenHandleCount);

                    AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCleanup (Dir) Decrement child open handle count on Parent object %p Cnt %d\n",
                                  pParentObjectInfo,
                                  lCount));
                }

                lCount = InterlockedDecrement( &pFcb->OpenHandleCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup (Dir) Decrement handle count on Fcb %p Cnt %d\n",
                              pFcb,
                              lCount));

                AFSReleaseResource( &pFcb->NPFcb->Resource);

                break;
            }

            case AFS_SYMBOLIC_LINK_FCB:
            case AFS_MOUNT_POINT_FCB:
            case AFS_DFS_LINK_FCB:
            case AFS_INVALID_FCB:
            {

                //
                // We may be performing some cleanup on the Fcb so grab it exclusive to ensure no collisions
                //

                AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup (MP/SL) Acquiring Dcb lock %p EXCL %08lX\n",
                              &pFcb->NPFcb->Resource,
                              PsGetCurrentThread()));

                AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                  TRUE);

                //
                // Perform some final common processing
                //

                ASSERT( pFcb->OpenHandleCount != 0);

                if( pParentObjectInfo != NULL)
                {

                    stFileCleanup.ParentId = pParentObjectInfo->FileId;
                }

                stFileCleanup.LastAccessTime = pObjectInfo->LastAccessTime;

                if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_FILE_MODIFIED))
                {

                    stFileCleanup.FileAttributes = pObjectInfo->FileAttributes;

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_UPDATE_CREATE_TIME))
                    {

                        stFileCleanup.CreateTime = pObjectInfo->CreationTime;

                        ClearFlag( pFcb->Flags, AFS_FCB_FLAG_UPDATE_CREATE_TIME);
                    }

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_UPDATE_CHANGE_TIME))
                    {

                        stFileCleanup.ChangeTime = pObjectInfo->ChangeTime;

                        ClearFlag( pFcb->Flags, AFS_FCB_FLAG_UPDATE_CHANGE_TIME);
                    }

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_UPDATE_ACCESS_TIME))
                    {

                        stFileCleanup.LastAccessTime = pObjectInfo->LastAccessTime;

                        ClearFlag( pFcb->Flags, AFS_FCB_FLAG_UPDATE_ACCESS_TIME);
                    }
                }

                //
                // If the count has dropped to one and there is a pending delete
                // then delete the node.  The final count will be decremented just
                // before the Fcb->NPFcb->Resource is released.
                //

                if( pFcb->OpenHandleCount == 1 &&
                    BooleanFlagOn( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_PENDING_DELETE))
                {

		    //
		    // Release the Fcb Resource while processing the pending delete
		    // to avoid an out of order lock acquisition
		    //

		    ClearFlag( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_PENDING_DELETE);

		    AFSReleaseResource( &pFcb->NPFcb->Resource);

                    //
                    // Try to notify the service about the delete
                    //

                    ulNotificationFlags |= AFS_REQUEST_FLAG_FILE_DELETED;

                    //
                    // Indicate the file access mode that is being released
                    //

                    stFileCleanup.FileAccess = pCcb->FileAccess;

                    //
                    // Push the request to the service
                    //

                    ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_CLEANUP_PROCESSING,
                                                  ulNotificationFlags | AFS_REQUEST_FLAG_SYNCHRONOUS,
                                                  &pCcb->AuthGroup,
                                                  &pCcb->DirectoryCB->NameInformation.FileName,
                                                  &pObjectInfo->FileId,
                                                  pObjectInfo->VolumeCB->VolumeInformation.Cell,
                                                  pObjectInfo->VolumeCB->VolumeInformation.CellLength,
                                                  &stFileCleanup,
                                                  sizeof( AFSFileCleanupCB),
                                                  pResultCB,
                                                  &ulResultLen);

                    if( !NT_SUCCESS( ntStatus) &&
                        ntStatus != STATUS_OBJECT_NAME_NOT_FOUND)
                    {

                        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                      AFS_TRACE_LEVEL_ERROR,
                                      "AFSCleanup Failed to notify service of deleted MP/SL %wZ Status %08lX\n",
                                      &pCcb->FullFileName,
                                      ntStatus));

                        ntStatus = STATUS_SUCCESS;
                    }
                    else
                    {

                        ntStatus = STATUS_SUCCESS;

                        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                      AFS_TRACE_LEVEL_VERBOSE,
                                      "AFSCleanup Setting DELETE flag in MP/SL %wZ Dir Entry %p\n",
                                      &pCcb->FullFileName,
                                      pCcb->DirectoryCB));

                        SetFlag( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_DELETED);

                        ASSERT( pParentObjectInfo != NULL);

                        if ( pParentObjectInfo != NULL)
                        {

                            AFSAcquireExcl( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock,
                                            TRUE);

                            if ( pParentObjectInfo->DataVersion.QuadPart != pResultCB->ParentDataVersion.QuadPart - 1)
                            {

                                SetFlag( pParentObjectInfo->Flags, AFS_OBJECT_FLAGS_VERIFY);

                                pParentObjectInfo->DataVersion.QuadPart = (ULONGLONG)-1;
                            }
                            else
                            {
                                pParentObjectInfo->DataVersion.QuadPart = pResultCB->ParentDataVersion.QuadPart;
                            }

                            //
                            // Now that the service has the entry has deleted we need to remove it from the parent
                            // tree so another lookup on the node will fail
                            //

                            if( !BooleanFlagOn( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_NOT_IN_PARENT_TREE))
                            {

                                AFSRemoveNameEntry( pParentObjectInfo,
                                                    pCcb->DirectoryCB);
                            }
                            else
                            {

                                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                              AFS_TRACE_LEVEL_VERBOSE,
                                              "AFSCleanup DE %p for %wZ NOT removing entry due to flag set\n",
                                              pCcb->DirectoryCB,
                                              &pCcb->DirectoryCB->NameInformation.FileName));
                            }

                            AFSReleaseResource( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock);

                            AFSFsRtlNotifyFullReportChange( pParentObjectInfo,
                                                            pCcb,
                                                            (ULONG)FILE_NOTIFY_CHANGE_FILE_NAME,
                                                            (ULONG)FILE_ACTION_REMOVED);
                        }
                        else
                        {

                            if( !BooleanFlagOn( pCcb->DirectoryCB->Flags, AFS_DIR_ENTRY_NOT_IN_PARENT_TREE))
                            {

                                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                              AFS_TRACE_LEVEL_VERBOSE,
                                              "AFSCleanup DE %p for %wZ NOT removing entry due to pParentObjectInfo == NULL\n",
                                              pCcb->DirectoryCB,
                                              &pCcb->DirectoryCB->NameInformation.FileName));
                            }
                        }
                    }

		    //
		    // Regain exclusive access to the Fcb
		    //

		    AFSAcquireExcl( &pFcb->NPFcb->Resource,
				    TRUE);
		}

                //
                // If there have been any updates to the node then push it to
                // the service
                //

                else
                {

                    if( BooleanFlagOn( pFcb->Flags, AFS_FCB_FLAG_FILE_MODIFIED) &&
                        pParentObjectInfo != NULL)
                    {

                        ULONG ulNotifyFilter = 0;

                        ClearFlag( pFcb->Flags, AFS_FCB_FLAG_FILE_MODIFIED);

                        ulNotifyFilter |= (FILE_NOTIFY_CHANGE_ATTRIBUTES);

                        AFSFsRtlNotifyFullReportChange( pParentObjectInfo,
                                                        pCcb,
                                                        (ULONG)ulNotifyFilter,
                                                        (ULONG)FILE_ACTION_MODIFIED);
                    }

                    //
                    // Indicate the file access mode that is being released
                    //

                    stFileCleanup.FileAccess = pCcb->FileAccess;

                    ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_CLEANUP_PROCESSING,
                                                  ulNotificationFlags | AFS_REQUEST_FLAG_SYNCHRONOUS,
                                                  &pCcb->AuthGroup,
                                                  &pCcb->DirectoryCB->NameInformation.FileName,
                                                  &pObjectInfo->FileId,
                                                  pObjectInfo->VolumeCB->VolumeInformation.Cell,
                                                  pObjectInfo->VolumeCB->VolumeInformation.CellLength,
                                                  &stFileCleanup,
                                                  sizeof( AFSFileCleanupCB),
                                                  pResultCB,
                                                  &ulResultLen);

                    if ( NT_SUCCESS( ntStatus))
                    {

                        if ( pParentObjectInfo != NULL)
                        {

                            AFSAcquireExcl( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock,
                                              TRUE);

                            if ( pParentObjectInfo->DataVersion.QuadPart != pResultCB->ParentDataVersion.QuadPart)
                            {

                                SetFlag( pParentObjectInfo->Flags, AFS_OBJECT_FLAGS_VERIFY);

                                pParentObjectInfo->DataVersion.QuadPart = (ULONGLONG)-1;
                            }

                            AFSReleaseResource( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock);
                        }
                    }

                    ntStatus = STATUS_SUCCESS;
                }

                //
                // Remove the share access at this time since we may not get the close for sometime on this FO.
                //

                IoRemoveShareAccess( pFileObject,
                                     &pFcb->ShareAccess);

                //
                // We don't need the name array after the user closes the handle on the file
                //

                if( pCcb->NameArray != NULL)
                {

                    AFSFreeNameArray( pCcb->NameArray);

                    pCcb->NameArray = NULL;
                }

                //
                // Decrement the open child handle count
                //

                if( pParentObjectInfo != NULL)
                {

                    ASSERT( pParentObjectInfo->Specific.Directory.ChildOpenHandleCount > 0);

                    lCount = InterlockedDecrement( &pParentObjectInfo->Specific.Directory.ChildOpenHandleCount);

                    AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCleanup (MP/SL) Decrement child open handle count on Parent object %p Cnt %d\n",
                                  pParentObjectInfo,
                                  lCount));
                }

                lCount = InterlockedDecrement( &pFcb->OpenHandleCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup (MP/SL) Decrement handle count on Fcb %p Cnt %d\n",
                              pFcb,
                              lCount));

                AFSReleaseResource( &pFcb->NPFcb->Resource);

                break;
            }

            case AFS_SPECIAL_SHARE_FCB:
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup Acquiring SPECIAL SHARE lock %p EXCL %08lX\n",
                              &pFcb->NPFcb->Resource,
                              PsGetCurrentThread()));

                AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                TRUE);

                ASSERT( pFcb->OpenHandleCount != 0);

                //
                // Decrement the open child handle count
                //

                if( pParentObjectInfo != NULL &&
                    pParentObjectInfo->Specific.Directory.ChildOpenHandleCount > 0)
                {

                    lCount = InterlockedDecrement( &pParentObjectInfo->Specific.Directory.ChildOpenHandleCount);

                    AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCleanup (Share) Decrement child open handle count on Parent object %p Cnt %d\n",
                                  pParentObjectInfo,
                                  lCount));
                }

                lCount = InterlockedDecrement( &pFcb->OpenHandleCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCleanup (Share) Decrement handle count on Fcb %p Cnt %d\n",
                              pFcb,
                              lCount));

                AFSReleaseResource( &pFcb->NPFcb->Resource);

                break;
            }

            default:

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCleanup Processing unknown node type %d\n",
                              pFcb->Header.NodeTypeCode));

                break;
        }


try_exit:

        if ( pParentObjectInfo != NULL)
        {

            AFSReleaseObjectInfo( &pParentObjectInfo);
        }

        if( pResultCB != NULL)
        {

            AFSExFreePoolWithTag( pResultCB, AFS_GENERIC_MEMORY_32_TAG);
        }

        if( pFileObject != NULL)
        {

            //
            // Setup the fileobject flags to indicate cleanup is complete.
            //

            SetFlag( pFileObject->Flags, FO_CLEANUP_COMPLETE);
        }

        //
        // Complete the request
        //

        AFSCompleteRequest( Irp, ntStatus);
    }
    __except( AFSExceptionFilter( __FUNCTION__, GetExceptionCode(), GetExceptionInformation()) )
    {

        AFSDbgTrace(( 0,
                      0,
                      "EXCEPTION - AFSCleanup\n"));

        AFSDumpTraceFilesFnc();
    }

    return ntStatus;
}

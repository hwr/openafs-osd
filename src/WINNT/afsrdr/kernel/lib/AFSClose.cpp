/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Kernel Drivers, LLC.
 * Copyright (c) 2009, 2010, 2011, 2012, 2013 Your File System, Inc.
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
// File: AFSClose.cpp
//

#include "AFSCommon.h"

//
// Function: AFSClose
//
// Description:
//
//      This function is the IRP_MJ_CLOSE dispatch handler
//
// Return:
//
//       A status is returned for the handling of this request
//

NTSTATUS
AFSClose( IN PDEVICE_OBJECT LibDeviceObject,
          IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(LibDeviceObject);
    NTSTATUS ntStatus = STATUS_SUCCESS;
    IO_STACK_LOCATION *pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    AFSFcb *pFcb = NULL;
    AFSDeviceExt *pDeviceExt = NULL;
    AFSCcb *pCcb = NULL;
    AFSObjectInfoCB *pObjectInfo = NULL;
    AFSObjectInfoCB *pParentObjectInfo = NULL;
    AFSDirectoryCB *pDirCB = NULL;
    LONG lCount;

    __try
    {

        if( AFSRDRDeviceObject == NULL)
        {

            //
            // Let this through, it's an close on the library control device
            //

            try_return( ntStatus);
        }

        pDeviceExt = (AFSDeviceExt *)AFSRDRDeviceObject->DeviceExtension;

        pIrpSp = IoGetCurrentIrpStackLocation( Irp);

        pFcb = (AFSFcb *)pIrpSp->FileObject->FsContext;

        if( pFcb == NULL)
        {
            try_return( ntStatus);
        }

        pObjectInfo = pFcb->ObjectInformation;

        //
        // Perform the close functionality depending on the type of node it is
        //

        switch( pFcb->Header.NodeTypeCode)
        {

            case AFS_IOCTL_FCB:
            {

                AFSPIOCtlOpenCloseRequestCB stPIOCtlClose;
                AFSFileID stParentFileId;

                AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSClose Acquiring GlobalRoot lock %p EXCL %08lX\n",
                              &pFcb->NPFcb->Resource,
                              PsGetCurrentThread()));

                AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                  TRUE);

                pCcb = (AFSCcb *)pIrpSp->FileObject->FsContext2;

		pIrpSp->FileObject->FsContext2 = NULL;

                //
                // Send the close to the CM
                //

                RtlZeroMemory( &stPIOCtlClose,
                               sizeof( AFSPIOCtlOpenCloseRequestCB));

                stPIOCtlClose.RequestId = pCcb->RequestID;

                stPIOCtlClose.RootId = pObjectInfo->VolumeCB->ObjectInformation.FileId;

                RtlZeroMemory( &stParentFileId,
                               sizeof( AFSFileID));

                stParentFileId = pObjectInfo->ParentFileId;

                //
                // Issue the close request to the service
                //

                AFSProcessRequest( AFS_REQUEST_TYPE_PIOCTL_CLOSE,
                                   AFS_REQUEST_FLAG_SYNCHRONOUS,
                                   &pCcb->AuthGroup,
                                   NULL,
                                   &stParentFileId,
                                   NULL,
                                   0,
                                   (void *)&stPIOCtlClose,
                                   sizeof( AFSPIOCtlOpenCloseRequestCB),
                                   NULL,
                                   NULL);

                //
                // Remove the Ccb and de-allocate it
                //

                AFSRemoveCcb( pFcb,
                              pCcb);

                //
                // If this is not the root then decrement the open child reference count
                //

                if ( BooleanFlagOn( pObjectInfo->Flags, AFS_OBJECT_FLAGS_PARENT_FID))
                {

                    pParentObjectInfo = AFSFindObjectInfo( pObjectInfo->VolumeCB,
                                                           &pObjectInfo->ParentFileId,
                                                           FALSE);
                }

                if( pParentObjectInfo != NULL &&
                    pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount > 0)
                {

                    InterlockedDecrement( &pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount);

                    AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSClose (IOCtl) Decrement child open ref count on Parent object %p Cnt %d\n",
                                  pParentObjectInfo,
                                  pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount));
                }

                AFSReleaseResource( &pFcb->NPFcb->Resource);

		pIrpSp->FileObject->FsContext = NULL;

                lCount = InterlockedDecrement( &pFcb->OpenReferenceCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSClose (IOCtl) Decrement count on Fcb %p Cnt %d\n",
                              pFcb,
                              lCount));

                ASSERT( lCount >= 0);

                break;
            }

            case AFS_ROOT_ALL:
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSClose Acquiring Special Root ALL lock %p EXCL %08lX\n",
                              &pFcb->NPFcb->Resource,
                              PsGetCurrentThread()));

                AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                TRUE);

                pCcb = (AFSCcb *)pIrpSp->FileObject->FsContext2;

		pIrpSp->FileObject->FsContext2;

                //
                // Remove the Ccb and de-allocate it
                //

                AFSRemoveCcb( pFcb,
                              pCcb);

                AFSReleaseResource( &pFcb->NPFcb->Resource);

		pIrpSp->FileObject->FsContext = NULL;

                lCount = InterlockedDecrement( &pFcb->OpenReferenceCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSClose (RootAll) Decrement count on Fcb %p Cnt %d\n",
                              pFcb,
                              lCount));

                ASSERT( lCount >= 0);

                break;
            }

            //
            // Root, file or directory node
            //

            case AFS_FILE_FCB:
            case AFS_ROOT_FCB:
            case AFS_DIRECTORY_FCB:
            case AFS_SYMBOLIC_LINK_FCB:
            case AFS_MOUNT_POINT_FCB:
            case AFS_DFS_LINK_FCB:
            case AFS_INVALID_FCB:
            {

                pCcb = (AFSCcb *)pIrpSp->FileObject->FsContext2;

		pIrpSp->FileObject->FsContext2 = NULL;

                //
                // We may be performing some cleanup on the Fcb so grab it exclusive to ensure no collisions
                //

                AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSClose Acquiring Dcb lock %p EXCL %08lX\n",
                              &pFcb->NPFcb->Resource,
                              PsGetCurrentThread()));

                AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                TRUE);

                KeQueryTickCount( &pFcb->ObjectInformation->LastAccessCount);

                if( pFcb->OpenReferenceCount == 1 &&
                    pFcb->Header.NodeTypeCode == AFS_FILE_FCB)
                {

                    SetFlag( pFcb->Flags, AFS_FCB_FILE_CLOSED);

		    if( !BooleanFlagOn( pDeviceExt->DeviceFlags, AFS_DEVICE_FLAG_DIRECT_SERVICE_IO))
		    {

			//
			// Attempt to tear down our extent list for the file
			// If there are remaining dirty extents then attempt to
			// flush them as well
			//

			if( pFcb->Specific.File.ExtentsDirtyCount)
			{

			    AFSFlushExtents( pFcb,
					     &pCcb->AuthGroup);
			}

			//
			// Wait for any outstanding queued flushes to complete
			//

			AFSWaitOnQueuedFlushes( pFcb);

			ASSERT( pFcb->Specific.File.ExtentsDirtyCount == 0 &&
				pFcb->Specific.File.QueuedFlushCount == 0);

			AFSReleaseResource( &pFcb->NPFcb->Resource);

			//
			// Tear 'em down, we'll not be needing them again
			//

			AFSTearDownFcbExtents( pFcb,
					       &pCcb->AuthGroup);
		    }
		    else
		    {

			if( pFcb->Header.NodeTypeCode == AFS_FILE_FCB &&
			    pFcb->Specific.File.ExtentsDirtyCount &&
			    (pCcb->GrantedAccess & FILE_WRITE_DATA))
			{

			    AFSFlushExtents( pFcb,
					     &pCcb->AuthGroup);
			}

			AFSReleaseResource( &pFcb->NPFcb->Resource);
		    }
		}
		else
		{

		    AFSReleaseResource( &pFcb->NPFcb->Resource);
		}

                pDirCB = pCcb->DirectoryCB;

                //
                // Steal the DirOpenReferenceCount from the Ccb
                //

                pCcb->DirectoryCB = NULL;

                //
                // Object the Parent ObjectInformationCB
                //

                if( BooleanFlagOn( pObjectInfo->Flags, AFS_OBJECT_FLAGS_PARENT_FID))
                {

                    pParentObjectInfo = AFSFindObjectInfo( pObjectInfo->VolumeCB,
                                                           &pObjectInfo->ParentFileId,
                                                           FALSE);
                }

                //
                // Remove the Ccb and de-allocate it
                //

                AFSRemoveCcb( pFcb,
                              pCcb);

                //
                // If this entry is deleted then remove the object from the volume tree
                //

                if( BooleanFlagOn( pDirCB->Flags, AFS_DIR_ENTRY_DELETED))
                {

                    if( pFcb->Header.NodeTypeCode == AFS_FILE_FCB &&
                        pObjectInfo->Links == 0)
                    {

                        //
                        // Stop anything possibly in process
                        //

                        AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                                      AFS_TRACE_LEVEL_VERBOSE,
                                      "AFSClose Acquiring Fcb extents lock %p EXCL %08lX\n",
                                      &pFcb->NPFcb->Specific.File.ExtentsResource,
                                      PsGetCurrentThread()));

                        AFSAcquireExcl( &pObjectInfo->Fcb->NPFcb->Specific.File.ExtentsResource,
                                        TRUE);

                        pObjectInfo->Fcb->NPFcb->Specific.File.ExtentsRequestStatus = STATUS_FILE_DELETED;

                        KeSetEvent( &pObjectInfo->Fcb->NPFcb->Specific.File.ExtentsRequestComplete,
                                    0,
                                    FALSE);

                        AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                                      AFS_TRACE_LEVEL_VERBOSE,
                                      "AFSClose Releasing Fcb extents lock %p EXCL %08lX\n",
                                      &pFcb->NPFcb->Specific.File.ExtentsResource,
                                      PsGetCurrentThread()));

                        AFSReleaseResource( &pObjectInfo->Fcb->NPFcb->Specific.File.ExtentsResource);
                    }

                    ASSERT( pParentObjectInfo != NULL);

                    if ( pParentObjectInfo != NULL)
                    {
                        AFSAcquireExcl( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock,
                                        TRUE);

                        AFSAcquireExcl( pObjectInfo->VolumeCB->ObjectInfoTree.TreeLock,
                                        TRUE);

                        lCount = InterlockedDecrement( &pDirCB->DirOpenReferenceCount);

                        AFSDbgTrace(( AFS_SUBSYSTEM_DIRENTRY_REF_COUNTING,
                                      AFS_TRACE_LEVEL_VERBOSE,
                                      "AFSClose (Other) Decrement count on %wZ DE %p Ccb %p Cnt %d\n",
                                      &pDirCB->NameInformation.FileName,
                                      pDirCB,
                                      pCcb,
                                      lCount));

                        ASSERT( lCount >= 0);

                        if( lCount == 0 &&
                            pDirCB->NameArrayReferenceCount <= 0)
                        {

                            AFSDbgTrace(( AFS_SUBSYSTEM_CLEANUP_PROCESSING,
                                          AFS_TRACE_LEVEL_VERBOSE,
                                          "AFSClose Deleting dir entry %p (%p) for %wZ  FID %08lX-%08lX-%08lX-%08lX\n",
                                          pDirCB,
                                          pObjectInfo,
                                          &pDirCB->NameInformation.FileName,
                                          pObjectInfo->FileId.Cell,
                                          pObjectInfo->FileId.Volume,
                                          pObjectInfo->FileId.Vnode,
                                          pObjectInfo->FileId.Unique));

                            //
                            // Remove and delete the directory entry from the parent list
                            //

                            AFSDeleteDirEntry( pParentObjectInfo,
                                               &pDirCB);

                            AFSAcquireShared( &pObjectInfo->NonPagedInfo->ObjectInfoLock,
                                              TRUE);

                            if( pObjectInfo->ObjectReferenceCount <= 0)
                            {

                                if( BooleanFlagOn( pObjectInfo->Flags, AFS_OBJECT_INSERTED_HASH_TREE))
                                {

                                    AFSDbgTrace(( AFS_SUBSYSTEM_CLEANUP_PROCESSING,
                                                  AFS_TRACE_LEVEL_VERBOSE,
                                                  "AFSClose Removing object %p from volume tree\n",
                                                  pObjectInfo));

                                    AFSRemoveHashEntry( &pObjectInfo->VolumeCB->ObjectInfoTree.TreeHead,
                                                        &pObjectInfo->TreeEntry);

                                    ClearFlag( pObjectInfo->Flags, AFS_OBJECT_INSERTED_HASH_TREE);
                                }
                            }

                            AFSReleaseResource( &pObjectInfo->NonPagedInfo->ObjectInfoLock);
                        }

                        AFSReleaseResource( pObjectInfo->VolumeCB->ObjectInfoTree.TreeLock);

                        AFSReleaseResource( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock);
                    }
                }
                else
                {

                    lCount = InterlockedDecrement( &pDirCB->DirOpenReferenceCount);

                    AFSDbgTrace(( AFS_SUBSYSTEM_DIRENTRY_REF_COUNTING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSClose (Other2) Decrement count on %wZ DE %p Ccb %p Cnt %d\n",
                                  &pDirCB->NameInformation.FileName,
                                  pDirCB,
                                  pCcb,
                                  lCount));

                    ASSERT( lCount >= 0);
                }

                //
                // If this is not the root then decrement the open child reference count
                //

                if( pObjectInfo != NULL &&
                    pParentObjectInfo != NULL &&
                    pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount > 0)
                {

                    InterlockedDecrement( &pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount);

                    AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSClose Decrement child open ref count on Parent object %p Cnt %d\n",
                                  pParentObjectInfo,
                                  pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount));
                }

		pIrpSp->FileObject->FsContext = NULL;

                //
                // Decrement the reference count on the Fcb. this is protecting it from teardown.
                //

                lCount = InterlockedDecrement( &pFcb->OpenReferenceCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSClose Decrement count on Fcb %p Cnt %d\n",
                              pFcb,
                              lCount));

                ASSERT( lCount >= 0);

                break;
            }

            case AFS_SPECIAL_SHARE_FCB:
            {

                AFSPipeOpenCloseRequestCB stPipeClose;

                pCcb = (AFSCcb *)pIrpSp->FileObject->FsContext2;

		pIrpSp->FileObject->FsContext2 = NULL;

                //
                // Object the Parent ObjectInformationCB
                //

                if( BooleanFlagOn( pObjectInfo->Flags, AFS_OBJECT_FLAGS_PARENT_FID))
                {

                    pParentObjectInfo = AFSFindObjectInfo( pObjectInfo->VolumeCB,
                                                           &pObjectInfo->ParentFileId,
                                                           FALSE);
                }

                AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSClose Acquiring Special Share lock %p EXCL %08lX\n",
                              &pFcb->NPFcb->Resource,
                              PsGetCurrentThread()));

                AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                TRUE);

                RtlZeroMemory( &stPipeClose,
                               sizeof( AFSPipeOpenCloseRequestCB));

                stPipeClose.RequestId = pCcb->RequestID;

                stPipeClose.RootId = pObjectInfo->VolumeCB->ObjectInformation.FileId;

                //
                // Remove the Ccb and de-allocate it
                //

                AFSRemoveCcb( pFcb,
                              pCcb);

                //
                // If this is not the root then decrement the open child reference count
                //

                if( pParentObjectInfo != NULL &&
                    pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount > 0)
                {

                    lCount = InterlockedDecrement( &pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount);

                    AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSClose (Share) Decrement child open ref count on Parent object %p Cnt %d\n",
                                  pParentObjectInfo,
                                  lCount));
                }

                AFSReleaseResource( &pFcb->NPFcb->Resource);

		pIrpSp->FileObject->FsContext = NULL;

                lCount = InterlockedDecrement( &pFcb->OpenReferenceCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSClose (Share) Decrement count on Fcb %p Cnt %d\n",
                              pFcb,
                              lCount));

                ASSERT( lCount >= 0);

                break;
            }

            default:
	    {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSClose Processing unknown node type %d\n",
                              pFcb->Header.NodeTypeCode));

                break;
	    }
        }

try_exit:

        //
        // Complete the request
        //

        AFSCompleteRequest( Irp,
                            ntStatus);
    }
    __except( AFSExceptionFilter( __FUNCTION__, GetExceptionCode(), GetExceptionInformation()) )
    {

        AFSDbgTrace(( 0,
                      0,
                      "EXCEPTION - AFSClose\n"));

        AFSDumpTraceFilesFnc();
    }

    if ( pParentObjectInfo != NULL)
    {

        AFSReleaseObjectInfo( &pParentObjectInfo);
    }

    return ntStatus;
}

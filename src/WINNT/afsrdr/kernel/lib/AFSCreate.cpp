/*
 * Copyright (c) 2008, 2009, 2010, 2011 Kernel Drivers, LLC.
 * Copyright (c) 2009, 2010, 2011 Your File System, Inc.
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
// File: AFSCreate.cpp
//

#include "AFSCommon.h"

//
// Function: AFSCreate
//
// Description:
//
//      This function is the dispatch handler for the IRP_MJ_CREATE requests. It makes the determination to
//      which interface this request is destined.
//
// Return:
//
//      A status is returned for the function. The Irp completion processing is handled in the specific
//      interface handler.
//

NTSTATUS
AFSCreate( IN PDEVICE_OBJECT LibDeviceObject,
           IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(LibDeviceObject);
    NTSTATUS ntStatus = STATUS_SUCCESS;
    IO_STACK_LOCATION  *pIrpSp;
    FILE_OBJECT        *pFileObject = NULL;

    __try
    {

        pIrpSp = IoGetCurrentIrpStackLocation( Irp);
        pFileObject = pIrpSp->FileObject;

        if( pFileObject == NULL ||
            pFileObject->FileName.Buffer == NULL)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCreate (%p) Processing control device open request\n",
                          Irp));

            ntStatus = AFSControlDeviceCreate( Irp);

            try_return( ntStatus);
        }

        if( AFSRDRDeviceObject == NULL)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCreate (%p) Invalid request to open before library is initialized\n",
                          Irp));

            try_return( ntStatus = STATUS_DEVICE_NOT_READY);
        }

        ntStatus = AFSCommonCreate( AFSRDRDeviceObject,
                                    Irp);

try_exit:

        NOTHING;
    }
    __except( AFSExceptionFilter( __FUNCTION__, GetExceptionCode(), GetExceptionInformation()) )
    {

        AFSDbgTrace(( 0,
                      0,
                      "EXCEPTION - AFSCreate\n"));

        ntStatus = STATUS_ACCESS_DENIED;

        AFSDumpTraceFilesFnc();
    }

    //
    // Complete the request
    //

    AFSCompleteRequest( Irp,
                          ntStatus);

    return ntStatus;
}

NTSTATUS
AFSCommonCreate( IN PDEVICE_OBJECT DeviceObject,
                 IN PIRP Irp)
{

    NTSTATUS            ntStatus = STATUS_SUCCESS;
    UNICODE_STRING      uniFileName;
    ULONG               ulCreateDisposition = 0;
    ULONG               ulOptions = 0;
    BOOLEAN             bNoIntermediateBuffering = FALSE;
    FILE_OBJECT        *pFileObject = NULL;
    IO_STACK_LOCATION  *pIrpSp;
    AFSFcb             *pFcb = NULL;
    AFSCcb             *pCcb = NULL;
    AFSDeviceExt       *pDeviceExt = NULL;
    BOOLEAN             bOpenTargetDirectory = FALSE, bReleaseVolume = FALSE;
    PACCESS_MASK        pDesiredAccess = NULL;
    UNICODE_STRING      uniComponentName, uniRootFileName, uniParsedFileName;
    UNICODE_STRING      uniSubstitutedPathName;
    UNICODE_STRING      uniRelativeName;
    AFSNameArrayHdr    *pNameArray = NULL;
    AFSVolumeCB        *pVolumeCB = NULL;
    LONG                VolumeReferenceReason = AFS_VOLUME_REFERENCE_INVALID;
    AFSVolumeCB        *pNewVolumeCB = NULL;
    LONG                NewVolumeReferenceReason = AFS_VOLUME_REFERENCE_INVALID;
    AFSDirectoryCB     *pParentDirectoryCB = NULL, *pDirectoryCB = NULL;
    AFSDirectoryCB     *pNewParentDirectoryCB = NULL;
    BOOLEAN             bReleaseParentDir = FALSE, bReleaseDir = FALSE;
    ULONG               ulParseFlags = 0;
    GUID                stAuthGroup = {0};
    ULONG               ulNameProcessingFlags = 0;
    BOOLEAN             bOpenedReparsePoint = FALSE;
    LONG                lCount;

    __Enter
    {

        pIrpSp = IoGetCurrentIrpStackLocation( Irp);
        pDeviceExt = (AFSDeviceExt *)DeviceObject->DeviceExtension;
        ulCreateDisposition = (pIrpSp->Parameters.Create.Options >> 24) & 0x000000ff;
        ulOptions = pIrpSp->Parameters.Create.Options;
        bNoIntermediateBuffering = BooleanFlagOn( ulOptions, FILE_NO_INTERMEDIATE_BUFFERING);
        bOpenTargetDirectory = BooleanFlagOn( pIrpSp->Flags, SL_OPEN_TARGET_DIRECTORY);
        pFileObject = pIrpSp->FileObject;
        pDesiredAccess = &pIrpSp->Parameters.Create.SecurityContext->DesiredAccess;

        uniFileName.Length = uniFileName.MaximumLength = 0;
        uniFileName.Buffer = NULL;

        uniRootFileName.Length = uniRootFileName.MaximumLength = 0;
        uniRootFileName.Buffer = NULL;

        uniParsedFileName.Length = uniParsedFileName.MaximumLength = 0;
        uniParsedFileName.Buffer = NULL;

        uniSubstitutedPathName.Buffer = NULL;
        uniSubstitutedPathName.Length = 0;

        uniRelativeName.Buffer = NULL;
        uniRelativeName.Length = 0;

        if( AFSGlobalRoot == NULL)
        {
            try_return( ntStatus = STATUS_DEVICE_NOT_READY);
        }

        RtlZeroMemory( &stAuthGroup,
                       sizeof( GUID));

        AFSRetrieveAuthGroupFnc( (ULONGLONG)PsGetCurrentProcessId(),
                                 (ULONGLONG)PsGetCurrentThreadId(),
                                  &stAuthGroup);

        //
        // If we are in shutdown mode then fail the request
        //

        if( BooleanFlagOn( pDeviceExt->DeviceFlags, AFS_DEVICE_FLAG_REDIRECTOR_SHUTDOWN))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_WARNING,
                          "AFSCommonCreate (%p) Open request after shutdown\n",
                          Irp));

            try_return( ntStatus = STATUS_TOO_LATE);
        }

        if( !BooleanFlagOn( AFSGlobalRoot->ObjectInformation.Flags, AFS_OBJECT_FLAGS_DIRECTORY_ENUMERATED))
        {

            ntStatus = AFSEnumerateGlobalRoot( &stAuthGroup);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCommonCreate Failed to enumerate global root Status %08lX\n",
                              ntStatus));

                try_return( ntStatus);
            }
        }

        //
        // Go and parse the name for processing.
        // If ulParseFlags is returned with AFS_PARSE_FLAG_FREE_FILE_BUFFER set,
        // then we are responsible for releasing the uniRootFileName.Buffer.
        //

        ntStatus = AFSParseName( Irp,
                                 &stAuthGroup,
                                 &uniFileName,
                                 &uniParsedFileName,
                                 &uniRootFileName,
                                 &ulParseFlags,
                                 &pVolumeCB,
                                 &pParentDirectoryCB,
                                 &pNameArray);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          uniFileName.Length > 0 ? AFS_TRACE_LEVEL_ERROR : AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCommonCreate (%p) Failed to parse name \"%wZ\" Status %08lX\n",
                          Irp,
                          &uniFileName,
                          ntStatus));

            try_return( ntStatus);
        }

        //
        // Check for STATUS_REPARSE
        //

        if( ntStatus == STATUS_REPARSE)
        {

            //
            // Update the information and return
            //

            Irp->IoStatus.Information = IO_REPARSE;

            try_return( ntStatus);
        }

        if ( pParentDirectoryCB != NULL)
        {

            bReleaseParentDir = TRUE;
        }

        //
        // If the returned volume cb is NULL then we are dealing with the \\Server\GlobalRoot
        // name
        //

        if( pVolumeCB == NULL)
        {

            //
            // Remove any leading or trailing slashes
            //

            if( uniFileName.Length >= sizeof( WCHAR) &&
                uniFileName.Buffer[ (uniFileName.Length/sizeof( WCHAR)) - 1] == L'\\')
            {

                uniFileName.Length -= sizeof( WCHAR);
            }

            if( uniFileName.Length >= sizeof( WCHAR) &&
                uniFileName.Buffer[ 0] == L'\\')
            {

                uniFileName.Buffer = &uniFileName.Buffer[ 1];

                uniFileName.Length -= sizeof( WCHAR);
            }

            //
            // If there is a remaining portion returned for this request then
            // check if it is for the PIOCtl interface
            //

            if( uniFileName.Length > 0)
            {

                //
                // We don't accept any other opens off of the AFS Root
                //

                ntStatus = STATUS_OBJECT_NAME_NOT_FOUND;

                //
                // If this is an open on "_._AFS_IOCTL_._" then perform handling on it accordingly
                //

                if( RtlCompareUnicodeString( &AFSPIOCtlName,
                                             &uniFileName,
                                             TRUE) == 0)
                {

                    //
                    // AFSOpenIOCtlFcb does not free a DirOpenReferenceCount for
                    // AFSGlobalRoot->DirectoryCB.
                    //

                    ntStatus = AFSOpenIOCtlFcb( Irp,
                                                &stAuthGroup,
                                                AFSGlobalRoot->DirectoryCB,
                                                &pFcb,
                                                &pCcb);

                    if( !NT_SUCCESS( ntStatus))
                    {

                        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                      AFS_TRACE_LEVEL_ERROR,
                                      "AFSCommonCreate Failed to open root IOCtl Fcb Status %08lX\n",
                                      ntStatus));
                    }
                }
                else if( pParentDirectoryCB != NULL)
                {

                    if( pParentDirectoryCB->ObjectInformation->FileType == AFS_FILE_TYPE_SPECIAL_SHARE_NAME)
                    {

                        ntStatus = AFSOpenSpecialShareFcb( Irp,
                                                           &stAuthGroup,
                                                           pParentDirectoryCB,
                                                           &pFcb,
                                                           &pCcb);

                        if( !NT_SUCCESS( ntStatus))
                        {

                            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                          AFS_TRACE_LEVEL_ERROR,
                                          "AFSCommonCreate Failed to open special share Fcb Status %08lX\n",
                                          ntStatus));
                        }
                    }
                }

                try_return( ntStatus);
            }

            ntStatus = AFSOpenAFSRoot( Irp,
                                       &pFcb,
                                       &pCcb);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCommonCreate Failed to open root Status %08lX\n",
                              ntStatus));
            }

            try_return( ntStatus);
        }

        //
        // We have a reference on the root volume
        //

        VolumeReferenceReason = AFS_VOLUME_REFERENCE_PARSE_NAME;

        bReleaseVolume = TRUE;

        //
        // Attempt to locate the node in the name tree if this is not a target
        // open and the target is not the root
        //

        uniComponentName.Length = 0;
        uniComponentName.Buffer = NULL;

        if( uniFileName.Length > sizeof( WCHAR) ||
            uniFileName.Buffer[ 0] != L'\\')
        {

            if( !AFSValidNameFormat( &uniFileName))
            {

                ntStatus = STATUS_OBJECT_NAME_NOT_FOUND;

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCommonCreate (%p) Invalid name %wZ Status %08lX\n",
                              Irp,
                              &uniFileName,
                              ntStatus));

                try_return( ntStatus);
            }


	    if ( !AFSIgnoreReparsePointToFile() ||
		 !BooleanFlagOn( ulOptions, FILE_OPEN_REPARSE_POINT))
            {
		//
		// If there is no ReparsePointPolicy then the FILE_OPEN_REPARSE_POINT
		// flag is applied if it is set.
		//
		// If the FILE_OPEN_REPARSE_POINT flag is not set, then there is
		// no extra work to be done in any case.  Use a single pass evaluation.
		//

		ulNameProcessingFlags = AFS_LOCATE_FLAGS_SUBSTITUTE_NAME;

		//
		// Opening a reparse point directly?
		//

		if( BooleanFlagOn( ulOptions, FILE_OPEN_REPARSE_POINT))
		{
		    ulNameProcessingFlags |= (AFS_LOCATE_FLAGS_NO_MP_TARGET_EVAL |
					       AFS_LOCATE_FLAGS_NO_SL_TARGET_EVAL |
					       AFS_LOCATE_FLAGS_NO_DFS_LINK_EVAL);
		}

		uniSubstitutedPathName = uniRootFileName;

		ntStatus = AFSLocateNameEntry( &stAuthGroup,
					       pFileObject,
					       &uniRootFileName,
					       &uniParsedFileName,
					       pNameArray,
					       ulNameProcessingFlags,
					       pVolumeCB,
					       pParentDirectoryCB,
					       &pNewVolumeCB,
					       &NewVolumeReferenceReason,
					       &pNewParentDirectoryCB,
					       &pDirectoryCB,
					       &uniComponentName,
					       NULL);

		if ( pNewVolumeCB != NULL)
		{

		    //
		    // AFSLocateNameEntry returns pNewVolumeCB with a reference held
		    // even if pVolumeCB == pNewVolumeCB.  It is always safe to release
		    // the reference on pVolumeCB that was held prior to the call.
		    // If pVolumeCB == pNewVolumeCB, the reference from AFSLocateNameEntry
		    // will be released second.
		    //

		    lCount = AFSVolumeDecrement( pVolumeCB,
						 VolumeReferenceReason);

		    AFSDbgTrace(( AFS_SUBSYSTEM_VOLUME_REF_COUNTING,
				  AFS_TRACE_LEVEL_VERBOSE,
				  "AFSCommonCreate Decrement count on volume %p Reason %u Cnt %d\n",
				  pVolumeCB,
				  VolumeReferenceReason,
				  lCount));

		    pVolumeCB = pNewVolumeCB;

		    pNewVolumeCB = NULL;

		    VolumeReferenceReason = NewVolumeReferenceReason;

		    NewVolumeReferenceReason = AFS_VOLUME_REFERENCE_INVALID;

		    bReleaseVolume = (pVolumeCB != NULL);
		}

		//
		// AFSLocateNameEntry does not alter the reference count of
		// pParentDirectoryCB and it returns pNewParentDirectoryCB with
		// a reference held.
		//

		if ( bReleaseParentDir)
		{

		    lCount = InterlockedDecrement( &pParentDirectoryCB->DirOpenReferenceCount);

		    AFSDbgTrace(( AFS_SUBSYSTEM_DIRENTRY_REF_COUNTING,
				  AFS_TRACE_LEVEL_VERBOSE,
				  "AFSCommonCreate DecrementX count on %wZ DE %p Ccb %p Cnt %d\n",
				  &pParentDirectoryCB->NameInformation.FileName,
				  pParentDirectoryCB,
				  pCcb,
				  lCount));
		}

		pParentDirectoryCB = pNewParentDirectoryCB;

		pNewParentDirectoryCB = NULL;

		bReleaseParentDir = (pParentDirectoryCB != NULL);

		if ( pDirectoryCB)
		{

		    bReleaseDir = TRUE;
		}

		if( !NT_SUCCESS( ntStatus) &&
		    ntStatus != STATUS_OBJECT_NAME_NOT_FOUND)
		{

		    if ( uniSubstitutedPathName.Buffer == uniRootFileName.Buffer)
		    {
			uniSubstitutedPathName.Buffer = NULL;
		    }

		    //
		    // AFSLocateNameEntry released the Parent while walking the
		    // branch
		    //

		    AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
				  AFS_TRACE_LEVEL_VERBOSE,
				  "AFSCommonCreate (%p) Failed to locate name entry for %wZ Status %08lX\n",
				  Irp,
				  &uniFileName,
				  ntStatus));

		    try_return( ntStatus);
		}

		//
		// Check for STATUS_REPARSE
		//

		if( ntStatus == STATUS_REPARSE)
		{

		    uniSubstitutedPathName.Buffer = NULL;

		    //
		    // Update the information and return
		    //

		    Irp->IoStatus.Information = IO_REPARSE;

		    try_return( ntStatus);
		}

		//
		// If we re-allocated the name, then update our substitute name
		//

		if( uniSubstitutedPathName.Buffer != uniRootFileName.Buffer)
                {

		    uniSubstitutedPathName = uniRootFileName;
		}
		else
		{

                    uniSubstitutedPathName.Buffer = NULL;
                }

                //
		// Check for a symlink access
                //

		if( ntStatus == STATUS_OBJECT_NAME_NOT_FOUND &&
		    pParentDirectoryCB != NULL)
		{

		    //
		    // pParentDirectoryCB DirOpenReferenceCount is still held
		    //

		    UNICODE_STRING uniFinalComponent;

		    uniFinalComponent.Length = 0;
		    uniFinalComponent.MaximumLength = 0;
		    uniFinalComponent.Buffer = NULL;

		    AFSRetrieveFinalComponent( &uniFileName,
					       &uniFinalComponent);

		    ntStatus = AFSCheckSymlinkAccess( pParentDirectoryCB,
						      &uniFinalComponent);

		    if( !NT_SUCCESS( ntStatus) &&
			ntStatus != STATUS_OBJECT_NAME_NOT_FOUND)
		    {

			AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
				      AFS_TRACE_LEVEL_VERBOSE,
				      "AFSCommonCreate (%p) Failing access to symlink %wZ Status %08lX\n",
				      Irp,
				      &uniFileName,
				      ntStatus));

			try_return( ntStatus);
		    }
		}
	    }
	    else
            {
		AFSNameArrayHdr    *pNameArrayClone = NULL;

		//
		// The FILE_OPEN_REPARSE_POINT flag has been specified and a ReparsePointPolicy
		// is in effect which conditionally applies depending on the type of the target
		// object.  Therefore, two lookup passes must be performed.
		//   1. Evaluate the path as if the FILE_OPEN_REPARSE_POINT flag had
		//      not been specified.
		//   2. If the target object type matches the policy, use it and ignore
		//      the FILE_OPEN_REPARSE_POINT flag.
		//   3. If the target object type does not match the policy, perform
		//      a second pass that opens the reparse point.
		//   4. If the target object cannot be evaluated, perform the second pass
		//      that opens the reparse point.


		ulNameProcessingFlags = AFS_LOCATE_FLAGS_SUBSTITUTE_NAME;

		uniSubstitutedPathName = uniRootFileName;

                //
		// Since we may need to replay the call with different options
		// the values that might be altered need to be cloned:
		//   1. uniRootFileName
		//   2. pNameArray
                //

		pNameArrayClone = AFSInitNameArray( NULL, 0);

		if ( pNameArrayClone == NULL)
		{

		    AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
				  AFS_TRACE_LEVEL_VERBOSE,
				  "AFSCommonCreate (%p) Failed to initialize name array clone\n",
				  Irp));

		    try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
		}

		ntStatus = AFSPopulateNameArrayFromRelatedArray( pNameArrayClone,
								 pNameArray,
								 NULL);

		if ( !NT_SUCCESS(ntStatus))
		{

		    AFSFreeNameArray( pNameArrayClone);

		    try_return( ntStatus);
		}

                //
		// Now that the data is saved perform the lookup to determine
		// what the target resolves to.
                //

		ntStatus = AFSLocateNameEntry( &stAuthGroup,
					       pFileObject,
					       &uniRootFileName,
					       &uniParsedFileName,
					       pNameArray,
					       ulNameProcessingFlags,
					       pVolumeCB,
					       pParentDirectoryCB,
					       &pNewVolumeCB,
					       &NewVolumeReferenceReason,
					       &pNewParentDirectoryCB,
					       &pDirectoryCB,
					       &uniComponentName,
					       NULL);

		if ( ntStatus == STATUS_SUCCESS ||
		     ntStatus == STATUS_OBJECT_NAME_NOT_FOUND ||
		     ntStatus == STATUS_ACCESS_DENIED)
		{
		    //
		    // Decide what to do based upon the ReparsePointPolicy
		    // and the type of the target object.
		    //

		    if ( ntStatus == STATUS_SUCCESS &&
			 AFSIgnoreReparsePointToFile() &&
			 pDirectoryCB->ObjectInformation->FileType == AFS_FILE_TYPE_FILE)
		    {

			//
			// We found an entity that matches the policy.
			// Therefore, we are done.  Cleanup the cloned data
			// and clear the FILE_OPEN_REPARSE_FLAG so we do not
			// later mark the CCB with CCB_FLAG_MASK_OPENED_REPARSE_POINT.
			//

			AFSFreeNameArray( pNameArrayClone);

			pNameArrayClone = NULL;

			ClearFlag( ulOptions, FILE_OPEN_REPARSE_POINT);
		    }
		    else
		    {
			//
			//  There is no matching policy, so we need to cleanup the
			//  output values from AFSLocateNameEntry(), restore the
			//  cloned information, and re-issue the request attempting
			//  to open the reparse point (if any).
			//

			if ( pNewVolumeCB != NULL)
			{

			    lCount = AFSVolumeDecrement( pNewVolumeCB,
							 NewVolumeReferenceReason);

			    pNewVolumeCB = NULL;

			    NewVolumeReferenceReason = AFS_VOLUME_REFERENCE_INVALID;
			}

			if ( pNewParentDirectoryCB)
			{

			    lCount = InterlockedDecrement( &pNewParentDirectoryCB->DirOpenReferenceCount);

			    AFSDbgTrace(( AFS_SUBSYSTEM_DIRENTRY_REF_COUNTING,
					  AFS_TRACE_LEVEL_VERBOSE,
					  "AFSCommonCreate DecrementY count on %wZ DE %p Ccb %p Cnt %d\n",
					  &pNewParentDirectoryCB->NameInformation.FileName,
					  pNewParentDirectoryCB,
					  pCcb,
					  lCount));

			    pNewParentDirectoryCB = NULL;
			}

			if ( pDirectoryCB)
			{

			    lCount = InterlockedDecrement( &pDirectoryCB->DirOpenReferenceCount);

			    AFSDbgTrace(( AFS_SUBSYSTEM_DIRENTRY_REF_COUNTING,
					  AFS_TRACE_LEVEL_VERBOSE,
					  "AFSCommonCreate DecrementZ count on %wZ DE %p Ccb %p Cnt %d\n",
					  &pDirectoryCB->NameInformation.FileName,
					  pDirectoryCB,
					  pCcb,
					  lCount));

			    pDirectoryCB = NULL;
			}

			RtlZeroMemory( &uniComponentName,
				       sizeof( UNICODE_STRING));

			if ( uniSubstitutedPathName.Buffer != uniRootFileName.Buffer)
			{

			    AFSExFreePoolWithTag( uniRootFileName.Buffer, 0);

			    uniRootFileName = uniSubstitutedPathName;
			}

			AFSFreeNameArray( pNameArray);

			pNameArray = pNameArrayClone;

			pNameArrayClone = NULL;

			//
			// Retry the lookup
			//

			ulNameProcessingFlags |= (AFS_LOCATE_FLAGS_NO_MP_TARGET_EVAL |
						   AFS_LOCATE_FLAGS_NO_SL_TARGET_EVAL |
						   AFS_LOCATE_FLAGS_NO_DFS_LINK_EVAL);

			ntStatus = AFSLocateNameEntry( &stAuthGroup,
						       pFileObject,
						       &uniRootFileName,
						       &uniParsedFileName,
						       pNameArray,
						       ulNameProcessingFlags,
						       pVolumeCB,
						       pParentDirectoryCB,
						       &pNewVolumeCB,
						       &NewVolumeReferenceReason,
						       &pNewParentDirectoryCB,
						       &pDirectoryCB,
						       &uniComponentName,
						       NULL);
		    }
		}
		else
		{

		    AFSFreeNameArray( pNameArrayClone);

		    pNameArrayClone = NULL;
		}

		if ( pNewVolumeCB != NULL)
		{

		    //
		    // AFSLocateNameEntry returns pNewVolumeCB with a reference held
		    // even if pVolumeCB == pNewVolumeCB.  It is always safe to release
		    // the reference on pVolumeCB that was held prior to the call.
		    // If pVolumeCB == pNewVolumeCB, the reference from AFSLocateNameEntry
		    // will be released second.
		    //

		    lCount = AFSVolumeDecrement( pVolumeCB,
						 VolumeReferenceReason);

		    AFSDbgTrace(( AFS_SUBSYSTEM_VOLUME_REF_COUNTING,
				  AFS_TRACE_LEVEL_VERBOSE,
				  "AFSCommonCreate Decrement count on volume %p Reason %u Cnt %d\n",
				  pVolumeCB,
				  VolumeReferenceReason,
				  lCount));

		    pVolumeCB = pNewVolumeCB;

		    pNewVolumeCB = NULL;

		    VolumeReferenceReason = NewVolumeReferenceReason;

		    NewVolumeReferenceReason = AFS_VOLUME_REFERENCE_INVALID;

		    bReleaseVolume = (pVolumeCB != NULL);
		}

		//
		// AFSLocateNameEntry does not alter the reference count of
		// pParentDirectoryCB and it returns pNewParentDirectoryCB with
		// a reference held.
		//

		if ( bReleaseParentDir)
		{

		    lCount = InterlockedDecrement( &pParentDirectoryCB->DirOpenReferenceCount);

		    AFSDbgTrace(( AFS_SUBSYSTEM_DIRENTRY_REF_COUNTING,
				  AFS_TRACE_LEVEL_VERBOSE,
				  "AFSCommonCreate DecrementX count on %wZ DE %p Ccb %p Cnt %d\n",
				  &pParentDirectoryCB->NameInformation.FileName,
				  pParentDirectoryCB,
				  pCcb,
				  lCount));
		}

		pParentDirectoryCB = pNewParentDirectoryCB;

		pNewParentDirectoryCB = NULL;

		bReleaseParentDir = (pParentDirectoryCB != NULL);

		if ( pDirectoryCB)
		{

		    bReleaseDir = TRUE;
		}

                if( !NT_SUCCESS( ntStatus) &&
                    ntStatus != STATUS_OBJECT_NAME_NOT_FOUND)
                {

		    if ( uniSubstitutedPathName.Buffer == uniRootFileName.Buffer)
		    {
			uniSubstitutedPathName.Buffer = NULL;
		    }

		    //
		    // AFSLocateNameEntry released the Parent while walking the
		    // branch
		    //

                    AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                  AFS_TRACE_LEVEL_VERBOSE,
				  "AFSCommonCreate (%p) Failed to locate name entry for %wZ Status %08lX\n",
                                  Irp,
                                  &uniFileName,
                                  ntStatus));

                    try_return( ntStatus);
                }

		//
		// Check for STATUS_REPARSE
		//

		if( ntStatus == STATUS_REPARSE)
		{

		    uniSubstitutedPathName.Buffer = NULL;

		    //
		    // Update the information and return
		    //

		    Irp->IoStatus.Information = IO_REPARSE;

		    try_return( ntStatus);
		}

		//
		// If we re-allocated the name, then update our substitute name
		//

		if( uniSubstitutedPathName.Buffer != uniRootFileName.Buffer)
		{

		    uniSubstitutedPathName = uniRootFileName;
		}
		else
		{

		    uniSubstitutedPathName.Buffer = NULL;
		}

		//
		// Check for a symlink access
		//

		if( ntStatus == STATUS_OBJECT_NAME_NOT_FOUND &&
		    pParentDirectoryCB != NULL)
		{

		    //
		    // pParentDirectoryCB DirOpenReferenceCount is still held
		    //

		    UNICODE_STRING uniFinalComponent;

		    uniFinalComponent.Length = 0;
		    uniFinalComponent.MaximumLength = 0;
		    uniFinalComponent.Buffer = NULL;

		    AFSRetrieveFinalComponent( &uniFileName,
					       &uniFinalComponent);

		    ntStatus = AFSCheckSymlinkAccess( pParentDirectoryCB,
						      &uniFinalComponent);

		    if( !NT_SUCCESS( ntStatus) &&
			ntStatus != STATUS_OBJECT_NAME_NOT_FOUND)
		    {

			AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
				      AFS_TRACE_LEVEL_VERBOSE,
				      "AFSCommonCreate (%p) Failing access to symlink %wZ Status %08lX\n",
				      Irp,
				      &uniFileName,
				      ntStatus));

			try_return( ntStatus);
		    }
		}
            }
        }

        //
        // If we have no parent then this is a root open, be sure there is a directory entry
        // for the root
        //

        else if( pParentDirectoryCB == NULL &&
                 pDirectoryCB == NULL)
        {

            pDirectoryCB = pVolumeCB->DirectoryCB;

            lCount = InterlockedIncrement( &pDirectoryCB->DirOpenReferenceCount);

            AFSDbgTrace(( AFS_SUBSYSTEM_DIRENTRY_REF_COUNTING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCommonCreate Increment0 count on %wZ DE %p Ccb %p Cnt %d\n",
                          &pDirectoryCB->NameInformation.FileName,
                          pDirectoryCB,
                          pCcb,
                          lCount));

            bReleaseDir = TRUE;
        }

        if( bOpenTargetDirectory)
        {

            //
            // If we have a directory cb for the entry then dereference it and reference the parent
            //

            if( pDirectoryCB != NULL)
            {

                if ( !bReleaseParentDir)
                {

                    //
                    // Perform in this order to prevent thrashing
                    //

                    lCount = InterlockedIncrement( &pParentDirectoryCB->DirOpenReferenceCount);

                    AFSDbgTrace(( AFS_SUBSYSTEM_DIRENTRY_REF_COUNTING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCommonCreate Increment1 count on %wZ DE %p Ccb %p Cnt %d\n",
                                  &pParentDirectoryCB->NameInformation.FileName,
                                  pParentDirectoryCB,
                                  pCcb,
                                  lCount));

                    bReleaseParentDir = TRUE;
                }

                //
                // Do NOT decrement the reference count on the pDirectoryCB yet.
                // The BackupEntry below might drop the count to zero leaving
                // the entry subject to being deleted and we need some of the
                // contents during later processing
                //

                AFSBackupEntry( pNameArray);
            }

            //
            // OK, open the target directory
            //

            if( uniComponentName.Length == 0)
            {
                AFSRetrieveFinalComponent( &uniFileName,
                                           &uniComponentName);
            }

            ntStatus = AFSOpenTargetDirectory( Irp,
                                               pVolumeCB,
                                               pParentDirectoryCB,
                                               pDirectoryCB,
                                               &uniComponentName,
                                               &pFcb,
                                               &pCcb);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCommonCreate Failed to open target directory %wZ Status %08lX\n",
                              &pParentDirectoryCB->NameInformation.FileName,
                              ntStatus));
            }

            try_return( ntStatus);
        }

        if ( BooleanFlagOn( ulOptions, FILE_OPEN_REPARSE_POINT))
        {

            if( pDirectoryCB == NULL ||
                !BooleanFlagOn( pDirectoryCB->ObjectInformation->FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT))
            {
                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCommonCreate (%p) Reparse open request but attribute not set for %wZ DirCB %p Type %08lX\n",
                              Irp,
                              &uniFileName,
                              pDirectoryCB,
                              pDirectoryCB ? pDirectoryCB->ObjectInformation->FileType : 0));
            }
            else
            {
                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCommonCreate (%p) Opening as reparse point %wZ Type %08lX\n",
                              Irp,
                              &uniFileName,
                              pDirectoryCB->ObjectInformation->FileType));

                bOpenedReparsePoint = TRUE;
            }
        }

        //
        // Based on the options passed in, process the file accordingly.
        //

        if( ulCreateDisposition == FILE_CREATE ||
            ( ( ulCreateDisposition == FILE_OPEN_IF ||
                ulCreateDisposition == FILE_OVERWRITE_IF) &&
              pDirectoryCB == NULL))
        {

            if( uniComponentName.Length == 0 ||
                pDirectoryCB != NULL)
            {

                //
                // We traversed the entire path so we found each entry,
                // fail with collision
                //

                if( pDirectoryCB != NULL)
                {

                    AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCommonCreate Object name collision on create of %wZ Status %08lX\n",
                                  &pDirectoryCB->NameInformation.FileName,
                                  ntStatus));
                }
                else
                {

                    AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSCommonCreate Object name collision on create Status %08lX\n",
                                  ntStatus));
                }

                try_return( ntStatus = STATUS_OBJECT_NAME_COLLISION);
            }

            //
            // OK, go and create the node
            //

            ntStatus = AFSProcessCreate( Irp,
                                         &stAuthGroup,
                                         pVolumeCB,
                                         pParentDirectoryCB,
                                         &uniFileName,
                                         &uniComponentName,
                                         &uniRootFileName,
                                         &pFcb,
                                         &pCcb);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCommonCreate Failed to create of %wZ in directory %wZ Status %08lX\n",
                              &uniComponentName,
                              &pParentDirectoryCB->NameInformation.FileName,
                              ntStatus));
            }

            try_return( ntStatus);
        }

        //
        // We should not have an extra component except for PIOCtl opens
        //

        if( uniComponentName.Length > 0)
        {

            //
            // If this is an open on "_._AFS_IOCTL_._" then perform handling on it accordingly
            //

            if( RtlCompareUnicodeString( &AFSPIOCtlName,
                                         &uniComponentName,
                                         TRUE) == 0)
            {

                //
                // AFSOpenIOCtlFcb does not free a DirOpenReferenceCount for
                // pParentDirectoryCB.
                //

                ntStatus = AFSOpenIOCtlFcb( Irp,
                                            &stAuthGroup,
                                            pParentDirectoryCB,
                                            &pFcb,
                                            &pCcb);

                if( !NT_SUCCESS( ntStatus))
                {

                    AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                  AFS_TRACE_LEVEL_ERROR,
                                  "AFSCommonCreate Failed to IOCtl open on %wZ Status %08lX\n",
                                  &uniComponentName,
                                  ntStatus));
                }
            }
            else
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCommonCreate (%p) File %wZ name not found\n",
                              Irp,
                              &uniFileName));

                ntStatus = STATUS_OBJECT_NAME_NOT_FOUND;
            }

            try_return( ntStatus);
        }

        //
        // For root opens the parent will be NULL
        //

        if( pParentDirectoryCB == NULL)
        {

            //
            // Check for the delete on close flag for the root
            //

            if( BooleanFlagOn( ulOptions, FILE_DELETE_ON_CLOSE ))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCommonCreate (%p) Attempt to open root as delete on close\n",
                              Irp));

                try_return( ntStatus = STATUS_CANNOT_DELETE);
            }

            //
            // If this is the target directory, then bail
            //

            if( bOpenTargetDirectory)
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCommonCreate (%p) Attempt to open root as target directory\n",
                              Irp));

                try_return( ntStatus = STATUS_INVALID_PARAMETER);
            }

            //
            // Go and open the root of the volume
            //

            ntStatus = AFSOpenRoot( Irp,
                                    pVolumeCB,
                                    &stAuthGroup,
                                    &pFcb,
                                    &pCcb);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCommonCreate Failed to open volume root %08lX-%08lX Status %08lX\n",
                              pVolumeCB->ObjectInformation.FileId.Cell,
                              pVolumeCB->ObjectInformation.FileId.Volume,
                              ntStatus));
            }

            try_return( ntStatus);
        }

        //
        // At this point if we have no pDirectoryCB it was not found.
        //

        if( pDirectoryCB == NULL)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSCommonCreate Failing access to %wZ Name not found\n",
                          &uniFileName));

            try_return( ntStatus = STATUS_OBJECT_NAME_NOT_FOUND);
        }

        if( ulCreateDisposition == FILE_OVERWRITE ||
            ulCreateDisposition == FILE_SUPERSEDE ||
            ulCreateDisposition == FILE_OVERWRITE_IF)
        {

            //
            // Go process a file for overwrite or supersede.
            //

            ntStatus = AFSProcessOverwriteSupersede( DeviceObject,
                                                     Irp,
                                                     pVolumeCB,
                                                     &stAuthGroup,
                                                     pParentDirectoryCB,
                                                     pDirectoryCB,
                                                     &pFcb,
                                                     &pCcb);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCommonCreate Failed overwrite/supersede on %wZ Status %08lX\n",
                              &pDirectoryCB->NameInformation.FileName,
                              ntStatus));
            }

            try_return( ntStatus);
        }

        //
        // Trying to open the file
        //

        ntStatus = AFSProcessOpen( Irp,
                                   &stAuthGroup,
                                   pVolumeCB,
                                   pParentDirectoryCB,
                                   pDirectoryCB,
				   bOpenedReparsePoint,
                                   &pFcb,
                                   &pCcb);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSCommonCreate Failed open on %wZ Status %08lX\n",
                          &pDirectoryCB->NameInformation.FileName,
                          ntStatus));
        }

try_exit:

        if( NT_SUCCESS( ntStatus) &&
            ntStatus != STATUS_REPARSE)
        {

            if( pCcb != NULL)
            {

                AFSAcquireExcl( &pCcb->NPCcb->CcbLock,
                                TRUE);

                RtlCopyMemory( &pCcb->AuthGroup,
                               &stAuthGroup,
                               sizeof( GUID));

                //
                // If we have a substitute name, then use it
                //

                if( uniSubstitutedPathName.Buffer != NULL)
                {

                    pCcb->FullFileName = uniSubstitutedPathName;

                    SetFlag( pCcb->Flags, CCB_FLAG_FREE_FULL_PATHNAME);

                    ClearFlag( ulParseFlags, AFS_PARSE_FLAG_FREE_FILE_BUFFER);
                }
                else
                {

                    pCcb->FullFileName = uniRootFileName;

                    if( BooleanFlagOn( ulParseFlags, AFS_PARSE_FLAG_FREE_FILE_BUFFER))
                    {

                        SetFlag( pCcb->Flags, CCB_FLAG_FREE_FULL_PATHNAME);

                        ClearFlag( ulParseFlags, AFS_PARSE_FLAG_FREE_FILE_BUFFER);
                    }
                }

                if( bOpenedReparsePoint)
                {
                    SetFlag( pCcb->Flags, CCB_FLAG_MASK_OPENED_REPARSE_POINT);
                }

                lCount = pCcb->DirectoryCB->DirOpenReferenceCount;

                AFSDbgTrace(( AFS_SUBSYSTEM_DIRENTRY_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSCommonCreate Count on %wZ DE %p Ccb %p Cnt %d\n",
                              &pCcb->DirectoryCB->NameInformation.FileName,
                              pCcb->DirectoryCB,
                              pCcb,
                              lCount));

                ASSERT( lCount >= 0);

                pCcb->CurrentDirIndex = 0;

                if( !BooleanFlagOn( ulParseFlags, AFS_PARSE_FLAG_ROOT_ACCESS))
                {

                    SetFlag( pCcb->Flags, CCB_FLAG_RETURN_RELATIVE_ENTRIES);
                }

                //
                // Save off the name array for this instance
                //

                pCcb->NameArray = pNameArray;

                pNameArray = NULL;

                AFSReleaseResource( &pCcb->NPCcb->CcbLock);
            }

            //
            // If we make it here then init the FO for the request.
            //

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE_2,
                          "AFSCommonCreate (%p) FileObject %p FsContext %p FsContext2 %p\n",
                          Irp,
                          pFileObject,
                          pFcb,
                          pCcb));

            pFileObject->FsContext = (void *)pFcb;

            pFileObject->FsContext2 = (void *)pCcb;

            if( pFcb != NULL)
            {

                ASSERT( pFcb->OpenHandleCount > 0);

                ClearFlag( pFcb->Flags, AFS_FCB_FILE_CLOSED);

                //
                // For files perform additional processing
                //

                switch( pFcb->Header.NodeTypeCode)
                {

                    case AFS_FILE_FCB:
                    case AFS_IOCTL_FCB:
                    {

                        pFileObject->SectionObjectPointer = &pFcb->NPFcb->SectionObjectPointers;
                    }
                }

                //
                // If the user did not request nobuffering then mark the FO as cacheable
                //

                if( bNoIntermediateBuffering)
                {

                    pFileObject->Flags |= FO_NO_INTERMEDIATE_BUFFERING;
                }
                else
                {

                    pFileObject->Flags |= FO_CACHE_SUPPORTED;
                }

                //
                // If the file was opened for execution then we need to set the bit in the FO
                //

                if( BooleanFlagOn( *pDesiredAccess,
                                   FILE_EXECUTE))
                {

                    SetFlag( pFileObject->Flags, FO_FILE_FAST_IO_READ);
                }

                //
                // Update the last access time
                //

                KeQuerySystemTime( &pFcb->ObjectInformation->LastAccessTime);

                if( pCcb != NULL)
                {
                    AFSInsertCcb( pFcb,
                                  pCcb);
                }
            }
            else
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCommonCreate (%p) Returning with NULL Fcb FileObject %p FsContext %p FsContext2 %p\n",
                              Irp,
                              pFileObject,
                              pFcb,
                              pCcb));
            }
        }
        else
        {
            if( NT_SUCCESS( ntStatus) &&
                ntStatus == STATUS_REPARSE)
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSCommonCreate (%p) STATUS_REPARSE FileObject %p FsContext %p FsContext2 %p\n",
                              Irp,
                              pFileObject,
                              pFcb,
                              pCcb));
            }

            //
            // Free up the sub name if we have one
            //

            if( uniSubstitutedPathName.Buffer != NULL)
            {

                AFSExFreePoolWithTag( uniSubstitutedPathName.Buffer, 0);

                ClearFlag( ulParseFlags, AFS_PARSE_FLAG_FREE_FILE_BUFFER);
            }
        }

        //
        // Free up the name array ...
        //

        if( pNameArray != NULL)
        {

            AFSFreeNameArray( pNameArray);
        }

        if( BooleanFlagOn( ulParseFlags, AFS_PARSE_FLAG_FREE_FILE_BUFFER))
        {

            AFSExFreePoolWithTag( uniRootFileName.Buffer, 0);
        }

        if( bReleaseVolume)
        {

            lCount = AFSVolumeDecrement( pVolumeCB,
                                         VolumeReferenceReason);

            AFSDbgTrace(( AFS_SUBSYSTEM_VOLUME_REF_COUNTING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCommonCreate Decrement count on Volume %08lX Reason %u Cnt %d\n",
                          pVolumeCB,
                          VolumeReferenceReason,
                          lCount));
        }

        if ( bReleaseDir)
        {

            //
            // Release the reference from AFSLocateNameEntry
            //

            lCount = InterlockedDecrement( &pDirectoryCB->DirOpenReferenceCount);

            AFSDbgTrace(( AFS_SUBSYSTEM_DIRENTRY_REF_COUNTING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCommonCreate Decrement count on %wZ DE %p Ccb %p Cnt %d\n",
                          &pDirectoryCB->NameInformation.FileName,
                          pDirectoryCB,
                          pCcb,
                          lCount));

            ASSERT( lCount >= 0);
        }

        if ( bReleaseParentDir)
        {

            //
            // Release the reference from AFSLocateNameEntry
            //

            lCount = InterlockedDecrement( &pParentDirectoryCB->DirOpenReferenceCount);

            AFSDbgTrace(( AFS_SUBSYSTEM_DIRENTRY_REF_COUNTING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSCommonCreate Decrement count on %wZ DE %p Ccb %p Cnt %d\n",
                          &pParentDirectoryCB->NameInformation.FileName,
                          pParentDirectoryCB,
                          pCcb,
                          lCount));

            ASSERT( lCount >= 0);
        }

        //
        // Setup the Irp for completion, the Information has been set previously
        //

        Irp->IoStatus.Status = ntStatus;
    }

    return ntStatus;
}

NTSTATUS
AFSOpenAFSRoot( IN PIRP Irp,
                IN AFSFcb **Fcb,
                IN AFSCcb **Ccb)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    LONG lCount;

    __Enter
    {

        //
        // Initialize the Ccb for the file.
        //

        ntStatus = AFSInitCcb( Ccb,
                               AFSGlobalRoot->DirectoryCB,
                               0,
                               0);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSOpenAFSRoot (%p) Failed to allocate Ccb\n",
                          Irp));

            try_return( ntStatus);
        }

        //
        // Increment the open count on this Fcb
        //

        lCount = InterlockedIncrement( &AFSGlobalRoot->RootFcb->OpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenAFSRoot Increment count on Fcb %p Cnt %d\n",
                      AFSGlobalRoot->RootFcb,
                      lCount));

        lCount = InterlockedIncrement( &AFSGlobalRoot->RootFcb->OpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenAFSRoot Increment handle count on Fcb %p Cnt %d\n",
                      AFSGlobalRoot->RootFcb,
                      lCount));

        *Fcb = AFSGlobalRoot->RootFcb;

        //
        // Return the open result for this file
        //

        Irp->IoStatus.Information = FILE_OPENED;

try_exit:

        NOTHING;
    }

    return ntStatus;
}

NTSTATUS
AFSOpenRoot( IN PIRP Irp,
             IN AFSVolumeCB *VolumeCB,
             IN GUID *AuthGroup,
             OUT AFSFcb **RootFcb,
             OUT AFSCcb **Ccb)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    PFILE_OBJECT pFileObject = NULL;
    PIO_STACK_LOCATION pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    PACCESS_MASK pDesiredAccess = NULL;
    USHORT usShareAccess;
    ULONG ulOptions;
    BOOLEAN bAllocatedCcb = FALSE;
    BOOLEAN bReleaseFcb = FALSE;
    AFSFileOpenCB   stOpenCB;
    AFSFileOpenResultCB stOpenResultCB;
    ULONG       ulResultLen = 0;
    LONG        lCount;

    __Enter
    {

        pDesiredAccess = &pIrpSp->Parameters.Create.SecurityContext->DesiredAccess;
        usShareAccess = pIrpSp->Parameters.Create.ShareAccess;
        ulOptions = pIrpSp->Parameters.Create.Options;

        pFileObject = pIrpSp->FileObject;

        if( BooleanFlagOn( ulOptions, FILE_NON_DIRECTORY_FILE))
        {

            ntStatus = STATUS_FILE_IS_A_DIRECTORY;

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSOpenRoot (%p) Attempt to open root as file Status %08lX\n",
                          Irp,
                          ntStatus));

            try_return( ntStatus);
        }

        //
        // Check if we should go and retrieve updated information for the node
        //

        ntStatus = AFSValidateEntry( VolumeCB->DirectoryCB,
                                     AuthGroup,
                                     FALSE,
                                     TRUE);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSOpenRoot (%p) Failed to validate root entry Status %08lX\n",
                          Irp,
                          ntStatus));

            try_return( ntStatus);
        }

        //
        // Check with the service that we can open the file
        //

        RtlZeroMemory( &stOpenCB,
                       sizeof( AFSFileOpenCB));

        stOpenCB.DesiredAccess = *pDesiredAccess;

        stOpenCB.ShareAccess = usShareAccess;

        stOpenResultCB.GrantedAccess = 0;

        ulResultLen = sizeof( AFSFileOpenResultCB);

        ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_OPEN_FILE,
                                      AFS_REQUEST_FLAG_SYNCHRONOUS | AFS_REQUEST_FLAG_HOLD_FID,
                                      AuthGroup,
                                      NULL,
                                      &VolumeCB->ObjectInformation.FileId,
                                      VolumeCB->VolumeInformation.Cell,
                                      VolumeCB->VolumeInformation.CellLength,
                                      (void *)&stOpenCB,
                                      sizeof( AFSFileOpenCB),
                                      (void *)&stOpenResultCB,
                                      &ulResultLen);

        if( !NT_SUCCESS( ntStatus))
        {

            UNICODE_STRING uniGUID;

            uniGUID.Length = 0;
            uniGUID.MaximumLength = 0;
            uniGUID.Buffer = NULL;

            if( AuthGroup != NULL)
            {
                RtlStringFromGUID( *AuthGroup,
                                   &uniGUID);
            }

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSOpenRoot (%p) Failed open in service volume %08lX-%08lX AuthGroup %wZ Status %08lX\n",
                          Irp,
                          VolumeCB->ObjectInformation.FileId.Cell,
                          VolumeCB->ObjectInformation.FileId.Volume,
                          &uniGUID,
                          ntStatus));

            if( AuthGroup != NULL)
            {
                RtlFreeUnicodeString( &uniGUID);
            }

            try_return( ntStatus);
        }

        //
        // If the entry is not initialized then do it now
        //

        if( !BooleanFlagOn( VolumeCB->ObjectInformation.Flags, AFS_OBJECT_FLAGS_DIRECTORY_ENUMERATED))
        {

            AFSAcquireExcl( VolumeCB->ObjectInformation.Specific.Directory.DirectoryNodeHdr.TreeLock,
                            TRUE);

            ntStatus = AFSEnumerateDirectory( AuthGroup,
                                              &VolumeCB->ObjectInformation,
                                              TRUE);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSReleaseResource( VolumeCB->ObjectInformation.Specific.Directory.DirectoryNodeHdr.TreeLock);

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSOpenRoot (%p) Failed to enumerate directory Status %08lX\n",
                              Irp,
                              ntStatus));

                try_return( ntStatus);
            }

            AFSReleaseResource( VolumeCB->ObjectInformation.Specific.Directory.DirectoryNodeHdr.TreeLock);
        }

        //
        // If the root fcb has been initialized then check access otherwise
        // init the volume fcb
        //

        ntStatus = AFSInitRootFcb( (ULONGLONG)PsGetCurrentProcessId(),
                                   VolumeCB);

        if( !NT_SUCCESS( ntStatus))
        {

            try_return( ntStatus);
        }

        lCount = InterlockedIncrement( &VolumeCB->RootFcb->OpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenRoot Increment count on Fcb %p Cnt %d\n",
                      VolumeCB->RootFcb,
                      lCount));

        bReleaseFcb = TRUE;

        //
        // If there are current opens on the Fcb, check the access.
        //

        if( VolumeCB->RootFcb->OpenHandleCount > 0)
        {

            ntStatus = IoCheckShareAccess( *pDesiredAccess,
                                           usShareAccess,
                                           pFileObject,
                                           &VolumeCB->RootFcb->ShareAccess,
                                           FALSE);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSOpenRoot (%p) Access check failure Status %08lX\n",
                              Irp,
                              ntStatus));

                try_return( ntStatus);
            }
        }

        //
        // Initialize the Ccb for the file.
        //

        ntStatus = AFSInitCcb( Ccb,
                               VolumeCB->DirectoryCB,
                               *pDesiredAccess,
                               0);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSOpenRoot (%p) Failed to allocate Ccb Status %08lX\n",
                          Irp,
                          ntStatus));

            try_return( ntStatus);
        }

        bAllocatedCcb = TRUE;

        //
        // OK, update the share access on the fileobject
        //

        if( VolumeCB->RootFcb->OpenHandleCount > 0)
        {

            IoUpdateShareAccess( pFileObject,
                                 &VolumeCB->RootFcb->ShareAccess);
        }
        else
        {

            //
            // Set the access
            //

            IoSetShareAccess( *pDesiredAccess,
                              usShareAccess,
                              pFileObject,
                              &VolumeCB->RootFcb->ShareAccess);
        }

        //
        // Increment the open count on this Fcb
        //

        lCount = InterlockedIncrement( &VolumeCB->RootFcb->OpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenRoot Increment handle count on Fcb %p Cnt %d\n",
                      VolumeCB->RootFcb,
                      lCount));

        //
        // Indicate the object is held
        //

        SetFlag( VolumeCB->ObjectInformation.Flags, AFS_OBJECT_HELD_IN_SERVICE);

        //
        // Return the open result for this file
        //

        Irp->IoStatus.Information = FILE_OPENED;

        *RootFcb = VolumeCB->RootFcb;

try_exit:

        if( bReleaseFcb)
        {
            if ( !NT_SUCCESS( ntStatus))
            {

                lCount = InterlockedDecrement( &VolumeCB->RootFcb->OpenReferenceCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSOpenRoot Decrement count on Fcb %p Cnt %d\n",
                              VolumeCB->RootFcb,
                              lCount));
            }

            AFSReleaseResource( VolumeCB->RootFcb->Header.Resource);
        }

        if( !NT_SUCCESS( ntStatus))
        {

            if( bAllocatedCcb)
            {

                AFSRemoveCcb( NULL,
                              *Ccb);

                *Ccb = NULL;
            }

            Irp->IoStatus.Information = 0;
        }
    }

    return ntStatus;
}

NTSTATUS
AFSProcessCreate( IN PIRP               Irp,
                  IN GUID              *AuthGroup,
                  IN AFSVolumeCB       *VolumeCB,
                  IN AFSDirectoryCB    *ParentDirCB,
                  IN PUNICODE_STRING    FileName,
                  IN PUNICODE_STRING    ComponentName,
                  IN PUNICODE_STRING    FullFileName,
                  OUT AFSFcb          **Fcb,
                  OUT AFSCcb          **Ccb)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    PFILE_OBJECT pFileObject = NULL;
    PIO_STACK_LOCATION pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    ULONG ulOptions = 0;
    ULONG ulAttributes = 0;
    BOOLEAN bFileCreated = FALSE, bReleaseFcb = FALSE, bAllocatedCcb = FALSE;
    PACCESS_MASK pDesiredAccess = NULL;
    USHORT usShareAccess;
    AFSDirectoryCB *pDirEntry = NULL;
    AFSObjectInfoCB *pParentObjectInfo = NULL;
    AFSObjectInfoCB *pObjectInfo = NULL;
    LONG lCount;

    __Enter
    {

        pDesiredAccess = &pIrpSp->Parameters.Create.SecurityContext->DesiredAccess;
        usShareAccess = pIrpSp->Parameters.Create.ShareAccess;

        pFileObject = pIrpSp->FileObject;

        //
        // Extract out the options
        //

        ulOptions = pIrpSp->Parameters.Create.Options;

        //
        // We pass all attributes they want to apply to the file to the create
        //

        ulAttributes = pIrpSp->Parameters.Create.FileAttributes;

        //
        // If this is a directory create then set the attribute correctly
        //

        if( ulOptions & FILE_DIRECTORY_FILE)
        {

            ulAttributes |= FILE_ATTRIBUTE_DIRECTORY;
        }

        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessCreate (%p) Creating file %wZ Attributes %08lX\n",
                      Irp,
                      FullFileName,
                      ulAttributes));

        if( BooleanFlagOn( VolumeCB->VolumeInformation.FileSystemAttributes, FILE_READ_ONLY_VOLUME))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessCreate Request failed due to read only volume %wZ\n",
                          FullFileName));

            try_return( ntStatus = STATUS_MEDIA_WRITE_PROTECTED);
        }

        pParentObjectInfo = ParentDirCB->ObjectInformation;

        //
        // Allocate and insert the direntry into the parent node
        //

        ntStatus = AFSCreateDirEntry( AuthGroup,
                                      pParentObjectInfo,
                                      ParentDirCB,
                                      FileName,
                                      ComponentName,
                                      ulAttributes,
                                      &pDirEntry);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessCreate (%p) Failed to create directory entry %wZ Status %08lX\n",
                          Irp,
                          FullFileName,
                          ntStatus));

            try_return( ntStatus);
        }

        bFileCreated = TRUE;

        pObjectInfo = pDirEntry->ObjectInformation;

        if( BooleanFlagOn( pObjectInfo->Flags, AFS_OBJECT_FLAGS_NOT_EVALUATED) ||
            pObjectInfo->FileType == AFS_FILE_TYPE_UNKNOWN)
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSProcessCreate (%p) Evaluating object %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                          Irp,
                          &pDirEntry->NameInformation.FileName,
                          pObjectInfo->FileId.Cell,
                          pObjectInfo->FileId.Volume,
                          pObjectInfo->FileId.Vnode,
                          pObjectInfo->FileId.Unique));

            ntStatus = AFSEvaluateNode( AuthGroup,
                                        pDirEntry);

            if( !NT_SUCCESS( ntStatus))
            {

                if ( ntStatus == STATUS_NOT_A_DIRECTORY)
                {

                    if ( !BooleanFlagOn( pObjectInfo->Flags, AFS_OBJECT_FLAGS_PARENT_FID))
                    {

                        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                      AFS_TRACE_LEVEL_ERROR,
                                      "AFSProcessCreate (%p) Failed to evaluate object %wZ FID %08lX-%08lX-%08lX-%08lX PARENT %08lX-%08lX-%08lX-%08lX != NULL Status %08lX\n",
                                      Irp,
                                      &pDirEntry->NameInformation.FileName,
                                      pObjectInfo->FileId.Cell,
                                      pObjectInfo->FileId.Volume,
                                      pObjectInfo->FileId.Vnode,
                                      pObjectInfo->FileId.Unique,
                                      pParentObjectInfo->FileId.Cell,
                                      pParentObjectInfo->FileId.Volume,
                                      pParentObjectInfo->FileId.Vnode,
                                      pParentObjectInfo->FileId.Unique,
                                      ntStatus));
                    }
                    else if ( AFSIsEqualFID( &pParentObjectInfo->FileId, &pObjectInfo->ParentFileId))
                    {

                        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                      AFS_TRACE_LEVEL_ERROR,
                                      "AFSProcessCreate (%p) Failed to evaluate object %wZ FID %08lX-%08lX-%08lX-%08lX PARENT %08lX-%08lX-%08lX-%08lX Status %08lX\n",
                                      Irp,
                                      &pDirEntry->NameInformation.FileName,
                                      pObjectInfo->FileId.Cell,
                                      pObjectInfo->FileId.Volume,
                                      pObjectInfo->FileId.Vnode,
                                      pObjectInfo->FileId.Unique,
                                      pParentObjectInfo->FileId.Cell,
                                      pParentObjectInfo->FileId.Volume,
                                      pParentObjectInfo->FileId.Vnode,
                                      pParentObjectInfo->FileId.Unique,
                                      ntStatus));
                    }
                    else
                    {

                        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                      AFS_TRACE_LEVEL_ERROR,
                                      "AFSProcessCreate (%p) Failed to evaluate object %wZ FID %08lX-%08lX-%08lX-%08lX PARENT %08lX-%08lX-%08lX-%08lX != %08lX-%08lX-%08lX-%08lX Status %08lX\n",
                                      Irp,
                                      &pDirEntry->NameInformation.FileName,
                                      pObjectInfo->FileId.Cell,
                                      pObjectInfo->FileId.Volume,
                                      pObjectInfo->FileId.Vnode,
                                      pObjectInfo->FileId.Unique,
                                      pParentObjectInfo->FileId.Cell,
                                      pParentObjectInfo->FileId.Volume,
                                      pParentObjectInfo->FileId.Vnode,
                                      pParentObjectInfo->FileId.Unique,
                                      pObjectInfo->ParentFileId.Cell,
                                      pObjectInfo->ParentFileId.Volume,
                                      pObjectInfo->ParentFileId.Vnode,
                                      pObjectInfo->ParentFileId.Unique,
                                      ntStatus));
                    }
                }
                else
                {

                    AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                  AFS_TRACE_LEVEL_ERROR,
                                  "AFSProcessCreate (%p) Failed to evaluate object %wZ FID %08lX-%08lX-%08lX-%08lX Status %08lX\n",
                                  Irp,
                                  &pDirEntry->NameInformation.FileName,
                                  pObjectInfo->FileId.Cell,
                                  pObjectInfo->FileId.Volume,
                                  pObjectInfo->FileId.Vnode,
                                  pObjectInfo->FileId.Unique,
                                  ntStatus));
                }

                try_return( ntStatus);
            }

            ClearFlag( pObjectInfo->Flags, AFS_OBJECT_FLAGS_NOT_EVALUATED);
        }

        ASSERT( BooleanFlagOn( pObjectInfo->Flags, AFS_OBJECT_FLAGS_PARENT_FID) &&
                AFSIsEqualFID( &pParentObjectInfo->FileId, &pObjectInfo->ParentFileId));

        //
        // We may have raced and the Fcb is already created
        //

        //
        // Allocate and initialize the Fcb for the file.
        //

        ntStatus = AFSInitFcb( pDirEntry);

        *Fcb = pObjectInfo->Fcb;

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessCreate (%p) Failed to initialize fcb %wZ Status %08lX\n",
                          Irp,
                          FullFileName,
                          ntStatus));

            try_return( ntStatus);
        }

        ntStatus = STATUS_SUCCESS;

        //
        // Increment the open count on this Fcb
        //

        lCount = InterlockedIncrement( &(*Fcb)->OpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessCreate Increment count on Fcb %p Cnt %d\n",
                      *Fcb,
                      lCount));

        bReleaseFcb = TRUE;

        //
        // Initialize the Ccb for the file.
        //

        ntStatus = AFSInitCcb( Ccb,
                               pDirEntry,
                               *pDesiredAccess,
                               0);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessCreate (%p) Failed to initialize ccb %wZ Status %08lX\n",
                          Irp,
                          FullFileName,
                          ntStatus));

            try_return( ntStatus);
        }

        bAllocatedCcb = TRUE;

        //
        // If this is a file, update the headers filesizes.
        //

        if( (*Fcb)->Header.NodeTypeCode == AFS_FILE_FCB)
        {

            //
            // Update the sizes with the information passed in
            //

            (*Fcb)->Header.AllocationSize.QuadPart  = pObjectInfo->AllocationSize.QuadPart;
            (*Fcb)->Header.FileSize.QuadPart        = pObjectInfo->EndOfFile.QuadPart;
            (*Fcb)->Header.ValidDataLength.QuadPart = pObjectInfo->EndOfFile.QuadPart;

            //
            // Notify the system of the addition
            //

            AFSFsRtlNotifyFullReportChange( pParentObjectInfo,
                                            *Ccb,
                                            (ULONG)FILE_NOTIFY_CHANGE_FILE_NAME,
                                            (ULONG)FILE_ACTION_ADDED);

            (*Fcb)->NPFcb->Specific.File.ExtentsRequestStatus = STATUS_SUCCESS;
        }
        else if( (*Fcb)->Header.NodeTypeCode == AFS_DIRECTORY_FCB)
        {

            //
            // This is a new directory node so indicate it has been enumerated
            //

            SetFlag( pObjectInfo->Flags, AFS_OBJECT_FLAGS_DIRECTORY_ENUMERATED);

            //
            // And the parent directory entry
            //

            KeQuerySystemTime( &pParentObjectInfo->ChangeTime);

            //
            // Notify the system of the addition
            //

            AFSFsRtlNotifyFullReportChange( pParentObjectInfo,
                                            *Ccb,
                                            (ULONG)FILE_NOTIFY_CHANGE_DIR_NAME,
                                            (ULONG)FILE_ACTION_ADDED);
        }
        else if( (*Fcb)->Header.NodeTypeCode == AFS_MOUNT_POINT_FCB ||
                 (*Fcb)->Header.NodeTypeCode == AFS_SYMBOLIC_LINK_FCB ||
                 (*Fcb)->Header.NodeTypeCode == AFS_DFS_LINK_FCB ||
                 (*Fcb)->Header.NodeTypeCode == AFS_INVALID_FCB)
        {

            //
            // And the parent directory entry
            //

            KeQuerySystemTime( &pParentObjectInfo->ChangeTime);

            //
            // Notify the system of the addition
            //

            AFSFsRtlNotifyFullReportChange( pParentObjectInfo,
                                            *Ccb,
                                            (ULONG)FILE_NOTIFY_CHANGE_DIR_NAME,
                                            (ULONG)FILE_ACTION_ADDED);
        }

        //
        // Save off the access for the open
        //

        IoSetShareAccess( *pDesiredAccess,
                          usShareAccess,
                          pFileObject,
                          &(*Fcb)->ShareAccess);

        lCount = InterlockedIncrement( &(*Fcb)->OpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessCreate Increment handle count on Fcb %p Cnt %d\n",
                      (*Fcb),
                      lCount));

        //
        // Increment the open reference and handle on the parent node
        //

        lCount = InterlockedIncrement( &pParentObjectInfo->Specific.Directory.ChildOpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessCreate Increment child open handle count on Parent object %p Cnt %d\n",
                      pParentObjectInfo,
                      lCount));

        lCount = InterlockedIncrement( &pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessCreate Increment child open ref count on Parent object %p Cnt %d\n",
                      pParentObjectInfo,
                      lCount));

        if( ulOptions & FILE_DELETE_ON_CLOSE)
        {

            //
            // Mark it for delete on close
            //

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSProcessCreate (%p) Setting PENDING_DELETE flag in DirEntry %p Name %wZ\n",
                          Irp,
                          pDirEntry,
                          FullFileName));

            SetFlag( pDirEntry->Flags, AFS_DIR_ENTRY_PENDING_DELETE);
        }

        //
        // Indicate the object is locked in the service
        //

        SetFlag( pObjectInfo->Flags, AFS_OBJECT_HELD_IN_SERVICE);

        //
        // Return the open result for this file
        //

        Irp->IoStatus.Information = FILE_CREATED;

try_exit:

        //
        // If we created the Fcb we need to release the resources
        //

        if( bReleaseFcb)
        {

            if( !NT_SUCCESS( ntStatus))
            {
                //
                // Decrement the open count on this Fcb
                //

                lCount = InterlockedDecrement( &(*Fcb)->OpenReferenceCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSProcessCreate Decrement count on Fcb %p Cnt %d\n",
                              *Fcb,
                              lCount));
            }

            AFSReleaseResource( &(*Fcb)->NPFcb->Resource);
        }

        if ( bFileCreated)
        {

            //
            // Decrement the reference added during initialization of the DE
            // AFSInitCcb allocates its own reference count.
            //

            lCount = InterlockedDecrement( &pDirEntry->DirOpenReferenceCount);

            AFSDbgTrace(( AFS_SUBSYSTEM_DIRENTRY_REF_COUNTING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSProcessCreate Decrement count on %wZ DE %p Cnt %d\n",
                          &pDirEntry->NameInformation.FileName,
                          pDirEntry,
                          lCount));

            ASSERT( lCount >= 0);
        }

        if( !NT_SUCCESS( ntStatus))
        {

            if( bFileCreated)
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSProcessCreate Create failed, removing DE %p from parent object %p Status %08lX\n",
                              pDirEntry,
                              pParentObjectInfo,
                              ntStatus));

                //
                // Remove the dir entry from the parent
                //

                AFSAcquireExcl( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock,
                                TRUE);

                SetFlag( pDirEntry->Flags, AFS_DIR_ENTRY_DELETED);

                AFSNotifyDelete( pDirEntry,
                                 AuthGroup,
                                 FALSE);

                //
                // Pull the directory entry from the parent
                //

                AFSRemoveDirNodeFromParent( pParentObjectInfo,
                                            pDirEntry,
                                            FALSE); // Leave it in the enum list so the worker cleans it up

                //
                // Tag the parent as needing verification
                //

                SetFlag( pParentObjectInfo->Flags, AFS_OBJECT_FLAGS_VERIFY);

                pParentObjectInfo->DataVersion.QuadPart = (ULONGLONG)-1;

                AFSReleaseResource( pParentObjectInfo->Specific.Directory.DirectoryNodeHdr.TreeLock);
            }

            if( bAllocatedCcb)
            {

                AFSRemoveCcb( NULL,
                              *Ccb);
            }

            //
            // Fcb will be freed by AFSPrimaryVolumeWorker thread
            //

            *Fcb = NULL;

            *Ccb = NULL;
        }
    }

    return ntStatus;
}

NTSTATUS
AFSOpenTargetDirectory( IN PIRP Irp,
                        IN AFSVolumeCB *VolumeCB,
                        IN AFSDirectoryCB *ParentDirectoryCB,
                        IN AFSDirectoryCB *TargetDirectoryCB,
                        IN UNICODE_STRING *TargetName,
                        OUT AFSFcb **Fcb,
                        OUT AFSCcb **Ccb)
{
    UNREFERENCED_PARAMETER(VolumeCB);
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PFILE_OBJECT pFileObject = NULL;
    PIO_STACK_LOCATION pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    PACCESS_MASK pDesiredAccess = NULL;
    USHORT usShareAccess;
    BOOLEAN bAllocatedCcb = FALSE;
    BOOLEAN bReleaseFcb = FALSE;
    AFSObjectInfoCB *pParentObject = NULL;
    AFSObjectInfoCB *pGrandParentObject = NULL;
    UNICODE_STRING uniTargetName;
    LONG lCount;

    __Enter
    {

        pDesiredAccess = &pIrpSp->Parameters.Create.SecurityContext->DesiredAccess;
        usShareAccess = pIrpSp->Parameters.Create.ShareAccess;

        pFileObject = pIrpSp->FileObject;

        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenTargetDirectory (%p) Processing file %wZ\n",
                      Irp,
                      TargetName));

        pParentObject = ParentDirectoryCB->ObjectInformation;

        if( pParentObject->FileType != AFS_FILE_TYPE_DIRECTORY)
        {

            try_return( ntStatus = STATUS_INVALID_PARAMETER);
        }

        //
        // Make sure we have an Fcb for the access

        //
        // Allocate and initialize the Fcb for the file.
        //

        ntStatus = AFSInitFcb( ParentDirectoryCB);

        *Fcb = pParentObject->Fcb;

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSOpenTargetDirectory (%p) Failed to initialize fcb %wZ Status %08lX\n",
                          Irp,
                          &ParentDirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

        ntStatus = STATUS_SUCCESS;

        //
        // Increment the open count on this Fcb
        //

        lCount = InterlockedIncrement( &pParentObject->Fcb->OpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenTargetDirectory Increment count on Fcb %p Cnt %d\n",
                      pParentObject->Fcb,
                      lCount));

        bReleaseFcb = TRUE;

        //
        // If there are current opens on the Fcb, check the access.
        //

        if( pParentObject->Fcb->OpenHandleCount > 0)
        {

            ntStatus = IoCheckShareAccess( *pDesiredAccess,
                                           usShareAccess,
                                           pFileObject,
                                           &pParentObject->Fcb->ShareAccess,
                                           FALSE);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSOpenTargetDirectory (%p) Access check failure %wZ Status %08lX\n",
                              Irp,
                              &ParentDirectoryCB->NameInformation.FileName,
                              ntStatus));

                try_return( ntStatus);
            }
        }

        //
        // Initialize the Ccb for the file.
        //

        ntStatus = AFSInitCcb( Ccb,
                               ParentDirectoryCB,
                               *pDesiredAccess,
                               0);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSOpenTargetDirectory (%p) Failed to initialize ccb %wZ Status %08lX\n",
                          Irp,
                          &ParentDirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

        bAllocatedCcb = TRUE;

        if( TargetDirectoryCB != NULL &&
            FsRtlAreNamesEqual( &TargetDirectoryCB->NameInformation.FileName,
                                TargetName,
                                FALSE,
                                NULL))
        {

            Irp->IoStatus.Information = FILE_EXISTS;

            uniTargetName = TargetDirectoryCB->NameInformation.FileName;
        }
        else
        {

            Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;

            uniTargetName = *TargetName;
        }

        //
        // Update the filename in the fileobject for rename processing
        //

        RtlCopyMemory( pFileObject->FileName.Buffer,
                       uniTargetName.Buffer,
                       uniTargetName.Length);

        pFileObject->FileName.Length = uniTargetName.Length;

        //
        // OK, update the share access on the fileobject
        //

        if( pParentObject->Fcb->OpenHandleCount > 0)
        {

            IoUpdateShareAccess( pFileObject,
                                 &pParentObject->Fcb->ShareAccess);
        }
        else
        {

            //
            // Set the access
            //

            IoSetShareAccess( *pDesiredAccess,
                              usShareAccess,
                              pFileObject,
                              &pParentObject->Fcb->ShareAccess);
        }

        lCount = InterlockedIncrement( &pParentObject->Fcb->OpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenTargetDirectory Increment handle count on Fcb %p Cnt %d\n",
                      pParentObject->Fcb,
                      lCount));

        //
        // Increment the open reference and handle on the parent node
        //

        if( BooleanFlagOn( pParentObject->Flags, AFS_OBJECT_FLAGS_PARENT_FID))
        {

            pGrandParentObject = AFSFindObjectInfo( pParentObject->VolumeCB,
                                                    &pParentObject->ParentFileId,
                                                    TRUE);

            if ( pGrandParentObject)
            {

                lCount = InterlockedIncrement( &pGrandParentObject->Specific.Directory.ChildOpenHandleCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSOpenTargetDirectory Increment child open handle count on Parent object %p Cnt %d\n",
                              pGrandParentObject,
                              lCount));

                lCount = InterlockedIncrement( &pGrandParentObject->Specific.Directory.ChildOpenReferenceCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSOpenTargetDirectory Increment child open ref count on Parent object %p Cnt %d\n",
                              pGrandParentObject,
                              lCount));

                AFSReleaseObjectInfo( &pGrandParentObject);
            }
        }

try_exit:

        if( bReleaseFcb)
        {

            if( !NT_SUCCESS( ntStatus))
            {
                //
                // Decrement the open count on this Fcb
                //

                lCount = InterlockedDecrement( &pParentObject->Fcb->OpenReferenceCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSOpenTargetDirectory Decrement count on Fcb %p Cnt %d\n",
                              pParentObject->Fcb,
                              lCount));
            }

            AFSReleaseResource( &pParentObject->Fcb->NPFcb->Resource);
        }

        if( !NT_SUCCESS( ntStatus))
        {

            if( bAllocatedCcb)
            {

                AFSRemoveCcb( NULL,
                              *Ccb);
            }

            *Ccb = NULL;

            //
            // Fcb will be freed by AFSPrimaryVolumeWorker thread
            //

            *Fcb = NULL;
        }
    }

    return ntStatus;
}

NTSTATUS
AFSProcessOpen( IN PIRP Irp,
                IN GUID *AuthGroup,
                IN AFSVolumeCB *VolumeCB,
                IN AFSDirectoryCB *ParentDirCB,
                IN AFSDirectoryCB *DirectoryCB,
		IN BOOLEAN bOpenedReparsePoint,
                OUT AFSFcb **Fcb,
                OUT AFSCcb **Ccb)
{
    UNREFERENCED_PARAMETER(VolumeCB);
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PFILE_OBJECT pFileObject = NULL;
    PIO_STACK_LOCATION pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    PACCESS_MASK pDesiredAccess = NULL;
    USHORT usShareAccess;
    BOOLEAN bAllocatedCcb = FALSE, bReleaseFcb = FALSE;
    ULONG ulOptions = 0;
    AFSFileOpenCB   stOpenCB;
    AFSFileOpenResultCB stOpenResultCB;
    ULONG       ulResultLen = 0;
    AFSObjectInfoCB *pParentObjectInfo = NULL;
    AFSObjectInfoCB *pObjectInfo = NULL;
    ULONG       ulFileAccess = 0;
    AFSFileAccessReleaseCB stReleaseFileAccess;
    LONG lCount;

    __Enter
    {

        pDesiredAccess = &pIrpSp->Parameters.Create.SecurityContext->DesiredAccess;
        usShareAccess = pIrpSp->Parameters.Create.ShareAccess;

        pFileObject = pIrpSp->FileObject;

        pParentObjectInfo = ParentDirCB->ObjectInformation;

        pObjectInfo = DirectoryCB->ObjectInformation;

        ASSERT( BooleanFlagOn( pObjectInfo->Flags, AFS_OBJECT_FLAGS_PARENT_FID) &&
                AFSIsEqualFID( &pParentObjectInfo->FileId, &pObjectInfo->ParentFileId));

        //
        // Check if the entry is pending a deletion
        //

        if( BooleanFlagOn( DirectoryCB->Flags, AFS_DIR_ENTRY_PENDING_DELETE))
        {

            ntStatus = STATUS_DELETE_PENDING;

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessOpen (%p) Entry pending delete %wZ Status %08lX\n",
                          Irp,
                          &DirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

        //
        // Extract out the options
        //

        ulOptions = pIrpSp->Parameters.Create.Options;

        //
        // Check if we should go and retrieve updated information for the node
        //

        ntStatus = AFSValidateEntry( DirectoryCB,
                                     AuthGroup,
				     bOpenedReparsePoint,
                                     TRUE);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessOpen (%p) Failed to validate entry %wZ Status %08lX\n",
                          Irp,
                          &DirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

        //
        // If this is marked for delete on close then be sure we can delete the entry
        //

        if( BooleanFlagOn( ulOptions, FILE_DELETE_ON_CLOSE))
        {

            ntStatus = AFSNotifyDelete( DirectoryCB,
                                        AuthGroup,
                                        TRUE);

            if( !NT_SUCCESS( ntStatus))
            {

                ntStatus = STATUS_CANNOT_DELETE;

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSProcessOpen (%p) Cannot delete entry %wZ marked for delete on close Status %08lX\n",
                              Irp,
                              &DirectoryCB->NameInformation.FileName,
                              ntStatus));

                try_return( ntStatus);
            }
        }

        //
        // Be sure we have an Fcb for the current object
        //

        ntStatus = AFSInitFcb( DirectoryCB);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessOpen (%p) Failed to init fcb on %wZ Status %08lX\n",
                          Irp,
                          &DirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

        ntStatus = STATUS_SUCCESS;

        //
        // AFSInitFcb returns the Fcb resource held
        //

        bReleaseFcb = TRUE;

        //
        // Increment the open count on this Fcb
        //

        lCount = InterlockedIncrement( &pObjectInfo->Fcb->OpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessOpen Increment2 count on Fcb %p Cnt %d\n",
                      pObjectInfo->Fcb,
                      lCount));

        //
        // Check access on the entry
        //

        if( pObjectInfo->Fcb->OpenHandleCount > 0)
        {

            ntStatus = IoCheckShareAccess( *pDesiredAccess,
                                           usShareAccess,
                                           pFileObject,
                                           &pObjectInfo->Fcb->ShareAccess,
                                           FALSE);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSProcessOpen (%p) Failed to check share access on %wZ Status %08lX\n",
                              Irp,
                              &DirectoryCB->NameInformation.FileName,
                              ntStatus));

                try_return( ntStatus);
            }
        }

        //
        // Additional checks
        //

        if( pObjectInfo->Fcb->Header.NodeTypeCode == AFS_FILE_FCB)
        {

            //
            // If the caller is asking for write access then try to flush the image section
            //

            if( FlagOn( *pDesiredAccess, FILE_WRITE_DATA) ||
                BooleanFlagOn(ulOptions, FILE_DELETE_ON_CLOSE))
            {

                BOOLEAN bMmFlushed;

		AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING|AFS_SUBSYSTEM_SECTION_OBJECT,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSProcessOpen Acquiring Fcb SectionObject lock %p EXCL %08lX\n",
                              &pObjectInfo->Fcb->NPFcb->SectionObjectResource,
                              PsGetCurrentThread()));

                AFSAcquireExcl( &pObjectInfo->Fcb->NPFcb->SectionObjectResource,
                                TRUE);

		__try
		{

		    bMmFlushed = MmFlushImageSection( &pObjectInfo->Fcb->NPFcb->SectionObjectPointers,
						      MmFlushForWrite);
		}
		__except( AFSExceptionFilter( __FUNCTION__, GetExceptionCode(), GetExceptionInformation()))
		{

		    bMmFlushed = FALSE;

		    ntStatus = GetExceptionCode();

		    AFSDbgTrace(( 0,
				  0,
				  "EXCEPTION - AFSProcessOpen MmFlushImageSection failed FID %08lX-%08lX-%08lX-%08lX Status 0x%08lX\n",
				  pObjectInfo->FileId.Cell,
				  pObjectInfo->FileId.Volume,
				  pObjectInfo->FileId.Vnode,
				  pObjectInfo->FileId.Unique,
				  ntStatus));
		}

		AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING|AFS_SUBSYSTEM_SECTION_OBJECT,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSProcessOpen Releasing Fcb SectionObject lock %p EXCL %08lX\n",
                              &pObjectInfo->Fcb->NPFcb->SectionObjectResource,
                              PsGetCurrentThread()));

                AFSReleaseResource( &pObjectInfo->Fcb->NPFcb->SectionObjectResource);

                if ( !bMmFlushed)
                {

                    ntStatus = BooleanFlagOn(ulOptions, FILE_DELETE_ON_CLOSE) ? STATUS_CANNOT_DELETE :
                                                                            STATUS_SHARING_VIOLATION;

                    AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                                  AFS_TRACE_LEVEL_ERROR,
                                  "AFSProcessOpen (%p) Failed to flush image section %wZ Status %08lX\n",
                                  Irp,
                                  &DirectoryCB->NameInformation.FileName,
                                  ntStatus));

                    try_return( ntStatus);
                }
            }

            if( BooleanFlagOn( ulOptions, FILE_DIRECTORY_FILE))
            {

                ntStatus = STATUS_NOT_A_DIRECTORY;

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSProcessOpen (%p) Attempt to open file as directory %wZ Status %08lX\n",
                              Irp,
                              &DirectoryCB->NameInformation.FileName,
                              ntStatus));

                try_return( ntStatus);
            }

            pObjectInfo->Fcb->NPFcb->Specific.File.ExtentsRequestStatus = STATUS_SUCCESS;
        }
        else if( pObjectInfo->Fcb->Header.NodeTypeCode == AFS_DIRECTORY_FCB ||
                 pObjectInfo->Fcb->Header.NodeTypeCode == AFS_ROOT_FCB)
        {

            if( BooleanFlagOn( ulOptions, FILE_NON_DIRECTORY_FILE))
            {

                ntStatus = STATUS_FILE_IS_A_DIRECTORY;

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSProcessOpen (%p) Attempt to open directory as file %wZ Status %08lX\n",
                              Irp,
                              &DirectoryCB->NameInformation.FileName,
                              ntStatus));

                try_return( ntStatus);
            }
        }
        else if( pObjectInfo->Fcb->Header.NodeTypeCode == AFS_MOUNT_POINT_FCB ||
                 pObjectInfo->Fcb->Header.NodeTypeCode == AFS_SYMBOLIC_LINK_FCB ||
                 pObjectInfo->Fcb->Header.NodeTypeCode == AFS_DFS_LINK_FCB ||
                 pObjectInfo->Fcb->Header.NodeTypeCode == AFS_INVALID_FCB)
        {

        }
        else
        {
            ASSERT( FALSE);
            try_return( ntStatus = STATUS_UNSUCCESSFUL);
        }

        //
        // Check with the service that we can open the file
        //

        stOpenCB.ParentId = pParentObjectInfo->FileId;

        stOpenCB.DesiredAccess = *pDesiredAccess;

        stOpenCB.ShareAccess = usShareAccess;

        stOpenCB.ProcessId = (ULONGLONG)PsGetCurrentProcessId();

        stOpenCB.Identifier = (ULONGLONG)pFileObject;

        stOpenResultCB.GrantedAccess = 0;

        ulResultLen = sizeof( AFSFileOpenResultCB);

        ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_OPEN_FILE,
                                      AFS_REQUEST_FLAG_SYNCHRONOUS | AFS_REQUEST_FLAG_HOLD_FID,
                                      AuthGroup,
                                      &DirectoryCB->NameInformation.FileName,
                                      &pObjectInfo->FileId,
                                      pObjectInfo->VolumeCB->VolumeInformation.Cell,
                                      pObjectInfo->VolumeCB->VolumeInformation.CellLength,
                                      (void *)&stOpenCB,
                                      sizeof( AFSFileOpenCB),
                                      (void *)&stOpenResultCB,
                                      &ulResultLen);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessOpen (%p) Failed open in service %wZ Status %08lX\n",
                          Irp,
                          &DirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

        //
        // Save the granted access in case we need to release it below
        //

        ulFileAccess = stOpenResultCB.FileAccess;

        //
        // Check if there is a conflict
        //

        if( !AFSCheckAccess( *pDesiredAccess,
                             stOpenResultCB.GrantedAccess,
                             BooleanFlagOn( DirectoryCB->ObjectInformation->FileAttributes, FILE_ATTRIBUTE_DIRECTORY)))
        {

            ntStatus = STATUS_ACCESS_DENIED;

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessOpen (%p) Failed to check access from service Desired %08lX Granted %08lX Entry %wZ Status %08lX\n",
                          Irp,
                          *pDesiredAccess,
                          stOpenResultCB.GrantedAccess,
                          &DirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

        //
        // Initialize the Ccb for the file.
        //

        ntStatus = AFSInitCcb( Ccb,
                               DirectoryCB,
                               *pDesiredAccess,
                               ulFileAccess);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessOpen (%p) Failed to initialize ccb %wZ Status %08lX\n",
                          Irp,
                          &DirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

        bAllocatedCcb = TRUE;

        //
        // Perform the access check on the target if this is a mount point or symlink
        //

        if( pObjectInfo->Fcb->OpenHandleCount > 0)
        {

            IoUpdateShareAccess( pFileObject,
                                 &pObjectInfo->Fcb->ShareAccess);
        }
        else
        {

            //
            // Set the access
            //

            IoSetShareAccess( *pDesiredAccess,
                              usShareAccess,
                              pFileObject,
                              &pObjectInfo->Fcb->ShareAccess);
        }

        lCount = InterlockedIncrement( &pObjectInfo->Fcb->OpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessOpen Increment handle count on Fcb %p Cnt %d\n",
                      pObjectInfo->Fcb,
                      lCount));

        //
        // Increment the open reference and handle on the parent node
        //

        lCount = InterlockedIncrement( &pParentObjectInfo->Specific.Directory.ChildOpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessOpen Increment child open handle count on Parent object %p Cnt %d\n",
                      pParentObjectInfo,
                      lCount));

        lCount = InterlockedIncrement( &pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessOpen Increment child open ref count on Parent object %p Cnt %d\n",
                      pParentObjectInfo,
                      lCount));

        if( BooleanFlagOn( ulOptions, FILE_DELETE_ON_CLOSE))
        {

            //
            // Mark it for delete on close
            //

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSProcessOpen (%p) Setting PENDING_DELETE flag in DirEntry %p Name %wZ\n",
                          Irp,
                          DirectoryCB,
                          &DirectoryCB->NameInformation.FileName));

            SetFlag( DirectoryCB->Flags, AFS_DIR_ENTRY_PENDING_DELETE);
        }

        //
        // Indicate the object is held
        //

        SetFlag( pObjectInfo->Flags, AFS_OBJECT_HELD_IN_SERVICE);

        //
        // Return the open result for this file
        //

        Irp->IoStatus.Information = FILE_OPENED;

        *Fcb = pObjectInfo->Fcb;

try_exit:

        if( bReleaseFcb)
        {

            if( !NT_SUCCESS( ntStatus))
            {
                //
                // Decrement the open count on this Fcb
                //

                lCount = InterlockedDecrement( &pObjectInfo->Fcb->OpenReferenceCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSProcessOpen Decrement2 count on Fcb %p Cnt %d\n",
                              pObjectInfo->Fcb,
                              lCount));
            }

            AFSReleaseResource( pObjectInfo->Fcb->Header.Resource);
        }

        if( !NT_SUCCESS( ntStatus))
        {

            if ( ulFileAccess > 0)
            {

                stReleaseFileAccess.ProcessId = (ULONGLONG)PsGetCurrentProcessId();

                stReleaseFileAccess.FileAccess = ulFileAccess;

                stReleaseFileAccess.Identifier = (ULONGLONG)pFileObject;

                AFSProcessRequest( AFS_REQUEST_TYPE_RELEASE_FILE_ACCESS,
                                   AFS_REQUEST_FLAG_SYNCHRONOUS,
                                   AuthGroup,
                                   &DirectoryCB->NameInformation.FileName,
                                   &pObjectInfo->FileId,
                                   pObjectInfo->VolumeCB->VolumeInformation.Cell,
                                   pObjectInfo->VolumeCB->VolumeInformation.CellLength,
                                   (void *)&stReleaseFileAccess,
                                   sizeof( AFSFileAccessReleaseCB),
                                   NULL,
                                   NULL);
            }

            if( bAllocatedCcb)
            {

                AFSRemoveCcb( NULL,
                              *Ccb);
            }

            *Ccb = NULL;

            //
            // Fcb will be freed by AFSPrimaryVolumeWorker thread
            //

            *Fcb = NULL;
        }
    }

    return ntStatus;
}

NTSTATUS
AFSProcessOverwriteSupersede( IN PDEVICE_OBJECT DeviceObject,
                              IN PIRP           Irp,
                              IN AFSVolumeCB   *VolumeCB,
                              IN GUID          *AuthGroup,
                              IN AFSDirectoryCB *ParentDirCB,
                              IN AFSDirectoryCB *DirectoryCB,
                              OUT AFSFcb       **Fcb,
                              OUT AFSCcb       **Ccb)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    PFILE_OBJECT pFileObject = NULL;
    LARGE_INTEGER liZero = {0,0};
    BOOLEAN bReleasePaging = FALSE, bReleaseFcb = FALSE;
    ULONG   ulAttributes = 0;
    ULONG ulCreateDisposition = 0;
    BOOLEAN bAllocatedCcb = FALSE;
    BOOLEAN bUserMapped = FALSE;
    PACCESS_MASK pDesiredAccess = NULL;
    USHORT usShareAccess;
    AFSObjectInfoCB *pParentObjectInfo = NULL;
    AFSObjectInfoCB *pObjectInfo = NULL;
    LONG lCount;
    LARGE_INTEGER liSaveSize;
    LARGE_INTEGER liSaveVDL;
    LARGE_INTEGER liSaveAlloc;

    __Enter
    {

        pDesiredAccess = &pIrpSp->Parameters.Create.SecurityContext->DesiredAccess;

        usShareAccess = pIrpSp->Parameters.Create.ShareAccess;

        pFileObject = pIrpSp->FileObject;

        ulAttributes = pIrpSp->Parameters.Create.FileAttributes;

        ulCreateDisposition = (pIrpSp->Parameters.Create.Options >> 24) & 0x000000ff;

        if( BooleanFlagOn( VolumeCB->VolumeInformation.FileSystemAttributes, FILE_READ_ONLY_VOLUME))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessOverwriteSupersede Request failed on %wZ due to read only volume\n",
                          Irp,
                          &DirectoryCB->NameInformation.FileName));

            try_return( ntStatus = STATUS_MEDIA_WRITE_PROTECTED);
        }

        pParentObjectInfo = ParentDirCB->ObjectInformation;

        pObjectInfo = DirectoryCB->ObjectInformation;

        ASSERT( BooleanFlagOn( pObjectInfo->Flags, AFS_OBJECT_FLAGS_PARENT_FID) &&
                AFSIsEqualFID( &pParentObjectInfo->FileId, &pObjectInfo->ParentFileId));

        //
        // Check if we should go and retrieve updated information for the node
        //

        ntStatus = AFSValidateEntry( DirectoryCB,
                                     AuthGroup,
                                     FALSE,
                                     TRUE);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessOverwriteSupersede (%p) Failed to validate entry %wZ Status %08lX\n",
                          Irp,
                          &DirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

	if ( BooleanFlagOn( pObjectInfo->FileAttributes, FILE_ATTRIBUTE_READONLY))
	{

	    AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
			  AFS_TRACE_LEVEL_WARNING,
			  "AFSProcessOverwriteSupersede Request failed on %wZ due to read only file attribute\n",
			  Irp,
			  &DirectoryCB->NameInformation.FileName));

	    try_return( ntStatus = STATUS_ACCESS_DENIED);
	}

        //
        // Be sure we have an Fcb for the object block
        //

        ntStatus = AFSInitFcb( DirectoryCB);

        *Fcb = pObjectInfo->Fcb;

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessOverwriteSupersede (%p) Failed to initialize fcb %wZ Status %08lX\n",
                          Irp,
                          &DirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

        ntStatus = STATUS_SUCCESS;

        //
        // Increment the open count on this Fcb.
        //

        lCount = InterlockedIncrement( &pObjectInfo->Fcb->OpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessOverwriteSupersede Increment2 count on Fcb %p Cnt %d\n",
                      pObjectInfo->Fcb,
                      lCount));

        bReleaseFcb = TRUE;

        //
        // Check access on the entry
        //

        if( pObjectInfo->Fcb->OpenHandleCount > 0)
        {

            ntStatus = IoCheckShareAccess( *pDesiredAccess,
                                           usShareAccess,
                                           pFileObject,
                                           &pObjectInfo->Fcb->ShareAccess,
                                           FALSE);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSProcessOverwriteSupersede (%p) Access check failure %wZ Status %08lX\n",
                              Irp,
                              &DirectoryCB->NameInformation.FileName,
                              ntStatus));

                try_return( ntStatus);
            }
        }

	AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING|AFS_SUBSYSTEM_SECTION_OBJECT,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessOverwriteSupercede Acquiring Fcb SectionObject lock %p EXCL %08lX\n",
                      &pObjectInfo->Fcb->NPFcb->SectionObjectResource,
                      PsGetCurrentThread()));

        AFSAcquireExcl( &pObjectInfo->Fcb->NPFcb->SectionObjectResource,
                        TRUE);

	__try
	{

	    //
	    //  Before we actually truncate, check to see if the purge
	    //  is going to fail.
	    //

	    bUserMapped = !MmCanFileBeTruncated( &pObjectInfo->Fcb->NPFcb->SectionObjectPointers,
						 &liZero);
	}
	__except( AFSExceptionFilter( __FUNCTION__, GetExceptionCode(), GetExceptionInformation()))
	{

	    bUserMapped = FALSE;

	    ntStatus = GetExceptionCode();

	    AFSDbgTrace(( 0,
			  0,
			  "EXCEPTION - AFSProcessOverwriteSupercede MmCanFileBeTruncated failed FID %08lX-%08lX-%08lX-%08lX Status 0x%08lX\n",
			  pObjectInfo->FileId.Cell,
			  pObjectInfo->FileId.Volume,
			  pObjectInfo->FileId.Vnode,
			  pObjectInfo->FileId.Unique,
			  ntStatus));
	}

	AFSDbgTrace(( AFS_SUBSYSTEM_LOCK_PROCESSING|AFS_SUBSYSTEM_SECTION_OBJECT,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessOverwriteSupercede Releasing Fcb SectionObject lock %p EXCL %08lX\n",
                      &pObjectInfo->Fcb->NPFcb->SectionObjectResource,
                      PsGetCurrentThread()));

        AFSReleaseResource( &pObjectInfo->Fcb->NPFcb->SectionObjectResource);

        if( bUserMapped)
        {

            ntStatus = STATUS_USER_MAPPED_FILE;

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessOverwriteSupersede (%p) File user mapped %wZ Status %08lX\n",
                          Irp,
                          &DirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

        //
        // Initialize the Ccb for the file.
        //

        ntStatus = AFSInitCcb( Ccb,
                               DirectoryCB,
                               *pDesiredAccess,
                               0);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessOverwriteSupersede (%p) Failed to initialize ccb %wZ Status %08lX\n",
                          Irp,
                          &DirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

        bAllocatedCcb = TRUE;

        //
        // Set the file length to zero
        //

        AFSAcquireExcl( pObjectInfo->Fcb->Header.PagingIoResource,
                        TRUE);

        bReleasePaging = TRUE;

        liSaveSize = pObjectInfo->Fcb->Header.FileSize;
        liSaveAlloc = pObjectInfo->Fcb->Header.AllocationSize;
        liSaveVDL = pObjectInfo->Fcb->Header.ValidDataLength;

        pObjectInfo->Fcb->Header.FileSize.QuadPart = 0;
        pObjectInfo->Fcb->Header.ValidDataLength.QuadPart = 0;
        pObjectInfo->Fcb->Header.AllocationSize.QuadPart = 0;

        pObjectInfo->EndOfFile.QuadPart = 0;
        pObjectInfo->AllocationSize.QuadPart = 0;

        //
        // Trim down the extents. We do this BEFORE telling the service
        // the file is truncated since there is a potential race between
        // a worker thread releasing extents and us trimming
        //

        AFSTrimExtents( pObjectInfo->Fcb,
                        &pObjectInfo->Fcb->Header.FileSize);

        KeQuerySystemTime( &pObjectInfo->ChangeTime);

        KeQuerySystemTime( &pObjectInfo->LastAccessTime);

        KeQuerySystemTime( &pObjectInfo->LastWriteTime);

        //
        // Set the update flag accordingly
        //

        SetFlag( pObjectInfo->Fcb->Flags, AFS_FCB_FLAG_FILE_MODIFIED |
                                          AFS_FCB_FLAG_UPDATE_CREATE_TIME |
                                          AFS_FCB_FLAG_UPDATE_CHANGE_TIME |
                                          AFS_FCB_FLAG_UPDATE_ACCESS_TIME |
                                          AFS_FCB_FLAG_UPDATE_LAST_WRITE_TIME);

        ntStatus = AFSUpdateFileInformation( &pParentObjectInfo->FileId,
                                             pObjectInfo,
                                             AuthGroup);

        if( !NT_SUCCESS( ntStatus))
        {

            pObjectInfo->Fcb->Header.ValidDataLength = liSaveVDL;
            pObjectInfo->Fcb->Header.FileSize = liSaveSize;
            pObjectInfo->Fcb->Header.AllocationSize = liSaveAlloc;
            pObjectInfo->Fcb->ObjectInformation->EndOfFile = liSaveSize;
            pObjectInfo->Fcb->ObjectInformation->AllocationSize = liSaveAlloc;

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessOverwriteSupersede (%p) Failed to update file information %wZ Status %08lX\n",
                          Irp,
                          &DirectoryCB->NameInformation.FileName,
                          ntStatus));

            try_return( ntStatus);
        }

        ulAttributes |= FILE_ATTRIBUTE_ARCHIVE;

        if( ulCreateDisposition == FILE_SUPERSEDE)
        {

            pObjectInfo->FileAttributes = ulAttributes;

        }
        else
        {

            pObjectInfo->FileAttributes |= ulAttributes;
        }

        //
        // Save off the access for the open
        //

        if( pObjectInfo->Fcb->OpenHandleCount > 0)
        {

            IoUpdateShareAccess( pFileObject,
                                 &pObjectInfo->Fcb->ShareAccess);
        }
        else
        {

            //
            // Set the access
            //

            IoSetShareAccess( *pDesiredAccess,
                              usShareAccess,
                              pFileObject,
                              &pObjectInfo->Fcb->ShareAccess);
        }

        //
        // Return the correct action
        //

        if( ulCreateDisposition == FILE_SUPERSEDE)
        {

            Irp->IoStatus.Information = FILE_SUPERSEDED;
        }
        else
        {

            Irp->IoStatus.Information = FILE_OVERWRITTEN;
        }

        lCount = InterlockedIncrement( &pObjectInfo->Fcb->OpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessOverwriteSupersede Increment handle count on Fcb %p Cnt %d\n",
                      pObjectInfo->Fcb,
                      lCount));

        //
        // Increment the open reference and handle on the parent node
        //

        lCount = InterlockedIncrement( &pParentObjectInfo->Specific.Directory.ChildOpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessOverwriteSupersede Increment child open handle count on Parent object %p Cnt %d\n",
                      pParentObjectInfo,
                      lCount));

        lCount = InterlockedIncrement( &pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessOverwriteSupersede Increment child open ref count on Parent object %p Cnt %d\n",
                      pParentObjectInfo,
                      lCount));

        AFSReleaseResource( pObjectInfo->Fcb->Header.Resource);

        bReleaseFcb = FALSE;

        *Fcb = pObjectInfo->Fcb;

        //
        // Now that the Fcb->Resource has been dropped
        // we can call CcSetFileSizes.  We are still holding
        // the PagingIoResource
        //

        pFileObject->SectionObjectPointer = &pObjectInfo->Fcb->NPFcb->SectionObjectPointers;

        pFileObject->FsContext = (void *)pObjectInfo->Fcb;

        pFileObject->FsContext2 = (void *)*Ccb;

        CcSetFileSizes( pFileObject,
                        (PCC_FILE_SIZES)&pObjectInfo->Fcb->Header.AllocationSize);

try_exit:

        if( bReleasePaging)
        {

            AFSReleaseResource( pObjectInfo->Fcb->Header.PagingIoResource);
        }

        if( bReleaseFcb)
        {

            if( !NT_SUCCESS( ntStatus))
            {
                //
                // Decrement the open count on this Fcb.
                //

                lCount = InterlockedDecrement( &pObjectInfo->Fcb->OpenReferenceCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSProcessOverwriteSupersede Decrement2 count on Fcb %p Cnt %d\n",
                              pObjectInfo->Fcb,
                              lCount));
            }

            AFSReleaseResource( pObjectInfo->Fcb->Header.Resource);
        }

        if( !NT_SUCCESS( ntStatus))
        {

            if( bAllocatedCcb)
            {

                AFSRemoveCcb( NULL,
                              *Ccb);
            }

            *Ccb = NULL;

            //
            // Fcb will be freed by AFSPrimaryVolumeWorker thread
            //

            *Fcb = NULL;
        }
    }

    return ntStatus;
}

NTSTATUS
AFSControlDeviceCreate( IN PIRP Irp)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;

    __Enter
    {

        if ( KernelMode == Irp->RequestorMode) {
            //
            // For now, just let the open happen
            //
            Irp->IoStatus.Information = FILE_OPENED;
        }
        else
        {
            //
            // Not from usermode, All access must be via
            // the FS component (which will do the
            // security check)
            //
            ntStatus = STATUS_ACCESS_DENIED;
        }
    }

    return ntStatus;
}

//
// AFSOpenIOCtlFcb does not release a DirOpenReferenceCount on
// the ParentDirCB.
//

NTSTATUS
AFSOpenIOCtlFcb( IN PIRP Irp,
                 IN GUID *AuthGroup,
                 IN AFSDirectoryCB *ParentDirCB,
                 OUT AFSFcb **Fcb,
                 OUT AFSCcb **Ccb)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    PFILE_OBJECT pFileObject = NULL;
    PIO_STACK_LOCATION pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    BOOLEAN bReleaseFcb = FALSE, bAllocatedCcb = FALSE;
    AFSPIOCtlOpenCloseRequestCB stPIOCtlOpen;
    AFSFileID stFileID;
    AFSObjectInfoCB *pParentObjectInfo = NULL;
    LONG lCount;

    __Enter
    {

        pFileObject = pIrpSp->FileObject;

        pParentObjectInfo = ParentDirCB->ObjectInformation;

        //
        // If we haven't initialized the PIOCtl DirectoryCB for this directory then do it now
        //

        if( pParentObjectInfo->Specific.Directory.PIOCtlDirectoryCB == NULL)
        {

            ntStatus = AFSInitPIOCtlDirectoryCB( pParentObjectInfo);

            if( !NT_SUCCESS( ntStatus))
            {

                try_return( ntStatus);
            }
        }

        //
        // Allocate and initialize the Fcb for the file.
        //

        ntStatus = AFSInitFcb( pParentObjectInfo->Specific.Directory.PIOCtlDirectoryCB);

        *Fcb = pParentObjectInfo->Specific.Directory.PIOCtlDirectoryCB->ObjectInformation->Fcb;

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSOpenIOCtlFcb (%p) Failed to initialize fcb Status %08lX\n",
                          Irp,
                          ntStatus));

            try_return( ntStatus);
        }

        ntStatus = STATUS_SUCCESS;

        //
        // Increment the open reference and handle on the node
        //

        lCount = InterlockedIncrement( &(*Fcb)->OpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenIOCtlFcb Increment count on Fcb %p Cnt %d\n",
                      (*Fcb),
                      lCount));

        bReleaseFcb = TRUE;

        //
        // Initialize the Ccb for the file.
        //

        ntStatus = AFSInitCcb( Ccb,
                               pParentObjectInfo->Specific.Directory.PIOCtlDirectoryCB,
                               0,
                               0);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSOpenIOCtlFcb (%p) Failed to initialize ccb Status %08lX\n",
                          Irp,
                          ntStatus));

            try_return( ntStatus);
        }

        bAllocatedCcb = TRUE;

        //
        // Set the PIOCtl index
        //

        (*Ccb)->RequestID = InterlockedIncrement( &pParentObjectInfo->Specific.Directory.OpenRequestIndex);

        RtlZeroMemory( &stPIOCtlOpen,
                       sizeof( AFSPIOCtlOpenCloseRequestCB));

        stPIOCtlOpen.RequestId = (*Ccb)->RequestID;

        stPIOCtlOpen.RootId = pParentObjectInfo->VolumeCB->ObjectInformation.FileId;

        RtlZeroMemory( &stFileID,
                       sizeof( AFSFileID));

        //
        // The parent directory FID of the node
        //

        stFileID = pParentObjectInfo->FileId;

        //
        // Issue the open request to the service
        //

        ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_PIOCTL_OPEN,
                                      AFS_REQUEST_FLAG_SYNCHRONOUS,
                                      AuthGroup,
                                      NULL,
                                      &stFileID,
                                      NULL,
                                      0,
                                      (void *)&stPIOCtlOpen,
                                      sizeof( AFSPIOCtlOpenCloseRequestCB),
                                      NULL,
                                      NULL);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSOpenIOCtlFcb (%p) Failed service open Status %08lX\n",
                          Irp,
                          ntStatus));

            try_return( ntStatus);
        }

        //
        // Increment the handle on the node
        //

        lCount = InterlockedIncrement( &(*Fcb)->OpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenIOCtlFcb Increment handle count on Fcb %p Cnt %d\n",
                      (*Fcb),
                      lCount));

        //
        // Increment the open reference and handle on the parent node
        //

        lCount = InterlockedIncrement( &pParentObjectInfo->Specific.Directory.ChildOpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenIOCtlFcb Increment child open handle count on Parent object %p Cnt %d\n",
                      pParentObjectInfo,
                      lCount));

        lCount = InterlockedIncrement( &pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenIOCtlFcb Increment child open ref count on Parent object %p Cnt %d\n",
                      pParentObjectInfo,
                      lCount));

        //
        // Return the open result for this file
        //

        Irp->IoStatus.Information = FILE_OPENED;

try_exit:

        //
        // If we created the Fcb we need to release the resources
        //

        if( bReleaseFcb)
        {

            if( !NT_SUCCESS( ntStatus))
            {
                //
                // Decrement the open reference and handle on the node
                //

                lCount = InterlockedDecrement( &(*Fcb)->OpenReferenceCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSOpenIOCtlFcb Decrement count on Fcb %p Cnt %d\n",
                              (*Fcb),
                              lCount));
            }

            AFSReleaseResource( &(*Fcb)->NPFcb->Resource);
        }

        if( !NT_SUCCESS( ntStatus))
        {

            if( bAllocatedCcb)
            {

                AFSRemoveCcb( NULL,
                              *Ccb);
            }

            *Ccb = NULL;

            //
            // Fcb will be freed by AFSPrimaryVolumeWorker thread
            //

            *Fcb = NULL;
        }
    }

    return ntStatus;
}

NTSTATUS
AFSOpenSpecialShareFcb( IN PIRP Irp,
                        IN GUID *AuthGroup,
                        IN AFSDirectoryCB *DirectoryCB,
                        OUT AFSFcb **Fcb,
                        OUT AFSCcb **Ccb)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    PFILE_OBJECT pFileObject = NULL;
    PIO_STACK_LOCATION pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    BOOLEAN bReleaseFcb = FALSE, bAllocatedCcb = FALSE, bAllocateFcb = FALSE;
    AFSObjectInfoCB *pObjectInfo = NULL;
    AFSObjectInfoCB *pParentObjectInfo = NULL;
    AFSPipeOpenCloseRequestCB stPipeOpen;
    LONG lCount;

    __Enter
    {

        pFileObject = pIrpSp->FileObject;

        AFSDbgTrace(( AFS_SUBSYSTEM_PIPE_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE_2,
                      "AFSOpenSpecialShareFcb (%p) Processing Share %wZ open\n",
                      Irp,
                      &DirectoryCB->NameInformation.FileName));

        pObjectInfo = DirectoryCB->ObjectInformation;

        if ( BooleanFlagOn( pObjectInfo->Flags, AFS_OBJECT_FLAGS_PARENT_FID))
        {

            pParentObjectInfo = AFSFindObjectInfo( pObjectInfo->VolumeCB,
                                                   &pObjectInfo->ParentFileId,
						   TRUE);
	}

	*Fcb = pObjectInfo->Fcb;

	if( *Fcb == NULL)
	{

	    //
            // Allocate and initialize the Fcb for the file.
            //

            ntStatus = AFSInitFcb( DirectoryCB);

            *Fcb = pObjectInfo->Fcb;

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgTrace(( AFS_SUBSYSTEM_PIPE_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSOpenSpecialShareFcb (%p) Failed to initialize fcb Status %08lX\n",
                              Irp,
                              ntStatus));

                try_return( ntStatus);
            }

            if ( ntStatus != STATUS_REPARSE)
            {

                bAllocateFcb = TRUE;
            }

            ntStatus = STATUS_SUCCESS;
        }
        else
        {

            AFSAcquireExcl( &(*Fcb)->NPFcb->Resource,
                            TRUE);
        }

        //
        // Increment the open count on this Fcb
        //

        lCount = InterlockedIncrement( &(*Fcb)->OpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenSpecialShareFcb Increment count on Fcb %p Cnt %d\n",
                      (*Fcb),
                      lCount));

        bReleaseFcb = TRUE;

        //
        // Initialize the Ccb for the file.
        //

        ntStatus = AFSInitCcb( Ccb,
                               DirectoryCB,
                               0,
                               0);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_PIPE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSOpenSpecialShareFcb (%p) Failed to initialize ccb Status %08lX\n",
                          Irp,
                          ntStatus));

            try_return( ntStatus);
        }

        bAllocatedCcb = TRUE;

        //
        // Call the service to open the share
        //

        (*Ccb)->RequestID = InterlockedIncrement( &pParentObjectInfo->Specific.Directory.OpenRequestIndex);

        RtlZeroMemory( &stPipeOpen,
                       sizeof( AFSPipeOpenCloseRequestCB));

        stPipeOpen.RequestId = (*Ccb)->RequestID;

        stPipeOpen.RootId = pParentObjectInfo->VolumeCB->ObjectInformation.FileId;

        //
        // Issue the open request to the service
        //

        ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_PIPE_OPEN,
                                      AFS_REQUEST_FLAG_SYNCHRONOUS,
                                      AuthGroup,
                                      &DirectoryCB->NameInformation.FileName,
                                      NULL,
                                      NULL,
                                      0,
                                      (void *)&stPipeOpen,
                                      sizeof( AFSPipeOpenCloseRequestCB),
                                      NULL,
                                      NULL);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSDbgTrace(( AFS_SUBSYSTEM_PIPE_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSOpenSpecialShareFcb (%p) Failed service open Status %08lX\n",
                          Irp,
                          ntStatus));

            try_return( ntStatus);
        }

        lCount = InterlockedIncrement( &(*Fcb)->OpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenSpecialShareFcb Increment handle count on Fcb %p Cnt %d\n",
                      (*Fcb),
                      lCount));

        //
        // Increment the open reference and handle on the parent node
        //

        lCount = InterlockedIncrement( &pParentObjectInfo->Specific.Directory.ChildOpenHandleCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenSpecialShareFcb Increment child open handle count on Parent object %p Cnt %d\n",
                      pParentObjectInfo,
                      lCount));

        lCount = InterlockedIncrement( &pParentObjectInfo->Specific.Directory.ChildOpenReferenceCount);

        AFSDbgTrace(( AFS_SUBSYSTEM_OBJECT_REF_COUNTING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSOpenSpecialShareFcb Increment child open ref count on Parent object %p Cnt %d\n",
                      pParentObjectInfo,
                      lCount));

        //
        // Return the open result for this file
        //

        Irp->IoStatus.Information = FILE_OPENED;

try_exit:

        if( bReleaseFcb)
        {

            if( !NT_SUCCESS( ntStatus))
            {
                //
                // Decrement the open count on this Fcb
                //

                lCount = InterlockedDecrement( &(*Fcb)->OpenReferenceCount);

                AFSDbgTrace(( AFS_SUBSYSTEM_FCB_REF_COUNTING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSOpenSpecialShareFcb Decrement count on Fcb %p Cnt %d\n",
                              (*Fcb),
                              lCount));
            }

            AFSReleaseResource( &(*Fcb)->NPFcb->Resource);
        }

        if( !NT_SUCCESS( ntStatus))
        {

            if( bAllocatedCcb)
            {

                AFSRemoveCcb( NULL,
                              *Ccb);
            }

            *Ccb = NULL;

            if( bAllocateFcb)
            {

                //
                // Need to tear down this Fcb since it is not in the tree for the worker thread
                //

                AFSAcquireExcl( &DirectoryCB->ObjectInformation->NonPagedInfo->ObjectInfoLock,
                                TRUE);

                AFSRemoveFcb( &DirectoryCB->ObjectInformation->Fcb);

                AFSReleaseResource( &DirectoryCB->ObjectInformation->NonPagedInfo->ObjectInfoLock);
            }

            *Fcb = NULL;
        }
    }

    return ntStatus;
}

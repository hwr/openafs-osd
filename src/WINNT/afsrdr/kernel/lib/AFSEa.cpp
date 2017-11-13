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
// File: AFSEa.cpp
//

#include "AFSCommon.h"

//
// Function: AFSQueryEA
//
// Description:
//
//      This function is the dipatch handler for the IRP_MJ_QUERY_EA request
//
// Return:
//
//      A status is returned for the function
//

NTSTATUS
AFSQueryEA( IN PDEVICE_OBJECT LibDeviceObject,
            IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(LibDeviceObject);
    NTSTATUS ntStatus = STATUS_EAS_NOT_SUPPORTED;
    IO_STACK_LOCATION *pIrpSp;

    pIrpSp = IoGetCurrentIrpStackLocation( Irp);

    __try
    {

        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                      AFS_TRACE_LEVEL_ERROR,
                      "AFSQueryEa Entry for FO %p\n",
                      pIrpSp->FileObject));

        AFSCompleteRequest( Irp,
                            ntStatus);

    }
    __except( AFSExceptionFilter( __FUNCTION__, GetExceptionCode(), GetExceptionInformation()) )
    {

        AFSDbgTrace(( 0,
                      0,
                      "EXCEPTION - AFSQueryEA\n"));

        AFSDumpTraceFilesFnc();
    }

    return ntStatus;
}

//
// Function: AFSSetEA
//
// Description:
//
//      This function is the dipatch handler for the IRP_MJ_SET_EA request
//
// Return:
//
//      A status is returned for the function
//

NTSTATUS
AFSSetEA( IN PDEVICE_OBJECT LibDeviceObject,
          IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(LibDeviceObject);
    NTSTATUS ntStatus = STATUS_EAS_NOT_SUPPORTED;
    IO_STACK_LOCATION *pIrpSp;

    pIrpSp = IoGetCurrentIrpStackLocation( Irp);

    __try
    {

        AFSDbgTrace(( AFS_SUBSYSTEM_FILE_PROCESSING,
                      AFS_TRACE_LEVEL_ERROR,
                      "AFSSetEa Entry for FO %p\n", pIrpSp->FileObject));

        AFSCompleteRequest( Irp,
                            ntStatus);

    }
    __except( AFSExceptionFilter( __FUNCTION__, GetExceptionCode(), GetExceptionInformation()) )
    {

        AFSDbgTrace(( 0,
                      0,
                      "EXCEPTION - AFSSetEA\n"));

        AFSDumpTraceFilesFnc();
    }

    return ntStatus;
}

/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <winsock2.h>
#include <ws2tcpip.h>

extern "C" {
#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>
#include <roken.h>
}

#include "TaAfsAdmSvrClientInternal.h"


/*
 * ROUTINES ___________________________________________________________________
 *
 */

BOOL ADMINAPI asc_CellChange (UINT_PTR idClient, ASID idCell, LPAFSADMSVR_CHANGECELL_PARAMS pChange, ULONG *pStatus)
{
   BOOL rc = TRUE;
   ULONG status = 0;

   RpcTryExcept
      {
      if ((rc = AfsAdmSvr_ChangeCell (idClient, idCell, pChange, &status)) != FALSE)
         {
         // If we succeeded in changing this cell's properties, get the
         // newest values for our cache.
         //
         ASOBJPROP Properties;
         rc = asc_ObjectPropertiesGet (idClient, GET_ALL_DATA, idCell, idCell, &Properties, &status);
         }
      }
   RpcExcept(1)
      {
      rc = FALSE;
      status = RPC_S_CALL_FAILED_DNE;
      }
   RpcEndExcept

   if (!rc && pStatus)
      *pStatus = status;
   return rc;
}


BOOL ADMINAPI asc_CellRefreshRateSet (UINT_PTR idClient, ASID idCell, ULONG cminRefreshRate, ULONG *pStatus)
{
   BOOL rc = TRUE;
   ULONG status = 0;

   RpcTryExcept
      {
      rc = AfsAdmSvr_SetRefreshRate (idClient, idCell, cminRefreshRate, &status);
      }
   RpcExcept(1)
      {
      rc = FALSE;
      status = RPC_S_CALL_FAILED_DNE;
      }
   RpcEndExcept

   if (!rc && pStatus)
      *pStatus = status;
   return rc;
}


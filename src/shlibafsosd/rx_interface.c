#include <afsconfig.h>
#ifdef  KERNEL
#include "afs/param.h"
#else
#include <afs/param.h>
#endif

#define BUILDING_RX_INTERFACE 1

#include <sys/types.h>
#include <rx/rx.h>
#include <rx/xdr.h>
#include <afs/afsosd.h>

int rx_enable_stats = 0;

int
rx_EndCall(struct rx_call *call, afs_int32 rc)
{
    return (rxops->op_EndCall)(call, rc);
}

void *
rx_GetSpecific(struct rx_connection *conn, int key)
{
    return (rxops->op_GetSpecific)(conn, key);
}

void
rx_IncrementTimeAndCount(struct rx_peer *peer, afs_uint32 rxInterface,
                         afs_uint32 currentFunc, afs_uint32 totalFunc,
                         struct clock *queueTime, struct clock *execTime,
                         afs_hyper_t * bytesSent, afs_hyper_t * bytesRcvd,
			 int isServer)
{
    (rxops->op_IncrementTimeAndCount) (peer, rxInterface, currentFunc, 
					totalFunc, queueTime, execTime,
					bytesSent, bytesRcvd, isServer);
}

struct rx_call *
rx_NewCall(struct rx_connection *conn)
{
    return (rxops->op_NewCall)(conn);
}

struct rx_connection *
rx_NewConnection(afs_uint32 shost, u_short sport, u_short sservice,
                 struct rx_securityClass *securityObject,
                 int serviceSecurityIndex)
{
   return (rxops->op_NewConnection) (shost, sport, sservice, securityObject,
				     serviceSecurityIndex);
}

int
rx_ReadProc(struct rx_call *call, char *buf, int nbytes)
{
    return (rxops->op_Read)(call, buf, nbytes);
}

int
rx_ReadProc32(struct rx_call *call, afs_int32 * value)
{
    return (rxops->op_Read32)(call, value);
}

int
rx_WriteProc(struct rx_call *call, char *buf, int nbytes)
{
    return (rxops->op_Write)(call, buf, nbytes);
}

int
rx_WriteProc32(struct rx_call *call, afs_int32 * value)
{
    return (rxops->op_Write32)(call, value);
}

char *osi_alloc(afs_int32 x)
{
    return (rxops->op_osi_alloc)(x);
}

int osi_free(char * x, afs_int32 size)
{
    return (rxops->op_osi_free)(x, size);
}

bool_t xdr_async(XDR *xdrs, struct async *objp)
{
    return (rxops->op_xdr_async)(xdrs, objp);
}

bool_t xdr_asyncError(XDR *xdrs, struct asyncError *objp)
{
    return (rxops->op_xdr_asyncError)(xdrs, objp);
}

bool_t xdr_osd_file2List(XDR *xdrs, struct osd_file2List *objp)
{
    return (rxops->op_xdr_osd_file2List)(xdrs, objp);
}

bool_t xdr_FsCmdInputs(XDR *xdrs, struct FsCmdInputs *objp)
{
    return (rxops->op_xdr_FsCmdInputs)(xdrs, objp);
}

bool_t xdr_FsCmdOutputs(XDR *xdrs, struct FsCmdOutputs *objp)
{
    return (rxops->op_xdr_FsCmdOutputs)(xdrs, objp);
}

bool_t xdr_AFSFetchStatus(XDR *xdrs, struct AFSFetchStatus *objp)
{
    return (rxops->op_xdr_AFSFetchStatus)(xdrs, objp);
}

bool_t xdr_AFSFid(XDR *xdrs, struct AFSFid *objp)
{
    return (rxops->op_xdr_AFSFid)(xdrs, objp);
}

size_t strlcpy(char *dst, const char *src, size_t siz)
{
    return (rxops->op_strlcpy)(dst, src, siz);
}

void
osi_AssertFailU(const char *expr, const char *file, int line)
{
    (rxops->op_osi_AssertFailU)(expr, file, line);
}

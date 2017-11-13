/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
 * All Rights Reserved
 */
#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <roken.h>

#include <afs/cmd.h>
#include <afs/afs_args.h>
#include <afs/icl.h>
#include <afs/afsutil.h>
#include <rx/rx.h>
#include <afs/vice.h>
#include <afs/sys_prototypes.h>

#if defined(AFS_OSF_ENV) || defined(AFS_SGI61_ENV) || (defined(AFS_AIX51_ENV) && defined(AFS_64BIT_KERNEL))
/* For SGI 6.2, this is changed to 1 if it's a 32 bit kernel. */
int afs_icl_sizeofLong = 2;
#else
int afs_icl_sizeofLong = 1;
#endif

#if defined(AFS_SGI61_ENV) || (defined(AFS_AIX51_ENV) && defined(AFS_64BIT_KERNEL))
int afs_64bit_kernel = 1;	/* Default for 6.2+, and always for 6.1 */
extern int afs_icl_sizeofLong;	/* Used in ICL_SIZEHACK() */
#ifdef AFS_SGI62_ENV

/* If _SC_KERN_POINTERS not in sysconf, then we can assume a 32 bit abi. */
void
set_kernel_sizeof_long(void)
{
    int retval;


    retval = sysconf(_SC_KERN_POINTERS);
    if (retval == 64) {
	afs_64bit_kernel = 1;
	afs_icl_sizeofLong = 2;
    } else {
	afs_64bit_kernel = 0;
	afs_icl_sizeofLong = 1;
    }
}

#endif /* AFS_SGI62_ENV */
#endif /* AFS_SGI61_ENV */

int afs_syscall(long call, long parm0, long parm1, long parm2, long parm3,
		long parm4, long parm5, long parm6);
void dce1_error_inq_text(afs_uint32 status_to_convert,
		         char *error_text, int *status);
int icl_CreateSetWithFlags(char *name, struct afs_icl_log *baseLogp,
		           struct afs_icl_log *fatalLogp, afs_uint32 flags,
		           struct afs_icl_set **outSetpp);
int icl_LogHold(struct afs_icl_log *logp);
int icl_LogUse(struct afs_icl_log *logp);
int icl_LogReleNL(struct afs_icl_log *logp);
int icl_LogRele(struct afs_icl_log *logp);
int icl_ZeroLog(struct afs_icl_log *logp);
int icl_LogFreeUse(struct afs_icl_log *logp);

#define BUFFER_MULTIPLIER     1024

/* make it big enough to snapshot everything at once, since
 * decoding takes so long.
 */
#define IBSIZE		100000	/* default size */

struct logInfo {
    struct logInfo *nextp;
    char *name;
} *allInfo = 0;

char dumpFileName[256] = "";
void
RegisterIclDumpFileName(char *name)
{
    (void)sprintf(dumpFileName, "icl.%.250s", name);
}

/* define globals to use for bulk info */
afs_icl_bulkSetinfo_t *setInfo = (afs_icl_bulkSetinfo_t *) 0;
afs_icl_bulkLoginfo_t *logInfo = (afs_icl_bulkLoginfo_t *) 0;

struct afs_icl_set *icl_allSets = 0;


char *name;
/* given a type and an address, get the size of the thing
 * in words.
 */
static int
icl_GetSize(afs_int32 type, char *addr)
{
    int rsize;
    int tsize;

    rsize = 0;
    ICL_SIZEHACK(type, addr, tsize, rsize);
    return rsize;
}

/* Check types in printf string "bufferp", making sure that each
 * is compatible with the corresponding parameter type described
 * by typesp.  Also watch for prematurely running out of parameters
 * before the string is gone.
 */
#if defined(AFS_SGI61_ENV) || (defined(AFS_AIX51_ENV) && defined(AFS_64BIT_KERNEL))
static int
CheckTypes(char *bufferp, int *typesp, int typeCount, char *outMsgBuffer)
{
    char tc;
    int inPercent;
    int tix;

    inPercent = 0;
    tix = 0;
    for (tc = *bufferp;; outMsgBuffer++, tc = *(++bufferp)) {
	*outMsgBuffer = tc;
	if (tc == 0) {
	    /* hit end of string.  We win as long as we aren't
	     * in a '%'.
	     */
	    if (inPercent)
		return 0;
	    else
		return 1;
	}
	if (tc == '%') {
	    inPercent = 1 - inPercent;
	    continue;
	}
	if (inPercent) {
	    if (tc >= '0' && tc <= '9') {
		/* skip digits in % string */
		outMsgBuffer--;
		continue;
	    }
	    if (tc == 'l') {
		/* 'l' is a type modifier. */
		outMsgBuffer--;
		continue;
	    }
	    /* otherwise, we've finally gotten to the type-describing
	     * character.  Make sure there's a type descriptor, and then
	     * check the type descriptor.
	     */
	    inPercent = 0;
	    if (tix >= typeCount)
		return 0;	/* no more type descriptors left */
	    if (tc == 's') {
		if (typesp[tix] != 1)	/* not a string descriptor */
		    return 0;
		outMsgBuffer--;
		*outMsgBuffer = (char)1;
	    }
	    if (tc == 'u' || tc == 'x' || tc == 'd' || tc == 'o') {
		if (typesp[tix] != 0)
		    return 0;	/* not an integer descriptor */
		outMsgBuffer--;
		switch (tc) {
		case 'd':
		    *outMsgBuffer = (char)2;
		    break;
		case 'u':
		    *outMsgBuffer = (char)3;
		    break;
		case 'o':
		    *outMsgBuffer = (char)4;
		    break;
		case 'x':
		default:
		    *outMsgBuffer = (char)5;
		    break;
		}
	    }
	    /* otherwise we're fine, so eat this descriptor */
	    tix++;
	}
    }
    /* not reached */
}
#else /* AFS_SGI61_ENV */
static int
CheckTypes(char *bufferp, int *typesp, int typeCount)
{
    char tc;
    int inPercent;
    int tix;

    inPercent = 0;
    tix = 0;
    for (tc = *bufferp;; tc = *(++bufferp)) {
	if (tc == 0) {
	    /* hit end of string.  We win as long as we aren't
	     * in a '%'.
	     */
	    if (inPercent)
		return 0;
	    else
		return 1;
	}
	if (tc == '%') {
	    inPercent = 1 - inPercent;
	    continue;
	}
	if (inPercent) {
	    if (tc >= '0' && tc <= '9')
		continue;	/* skip digits in % string */
	    /* otherwise, we've finally gotten to the type-describing
	     * character.  Make sure there's a type descriptor, and then
	     * check the type descriptor.
	     */
	    inPercent = 0;
	    if (tix >= typeCount)
		return 0;	/* no more type descriptors left */
	    if (tc == 's' && typesp[tix] != 1)	/* not a string descriptor */
		return 0;
	    if ((tc == 'u' || tc == 'l' || tc == 'x' || tc == 'd')
		&& (typesp[tix] != 0))
		return 0;	/* not an integer descriptor */
	    /* otherwise we're fine, so eat this descriptor */
	    tix++;
	}
    }
    /* not reached */
}
#endif /* AFS_SGI61_ENV */

/* display a single record.
 * alp points at the first word in the array to be interpreted
 * rsize gives the # of words in the array
 */
#if defined(AFS_SGI61_ENV) && !defined(AFS_SGI62_ENV)
#define uint64_t long long
#endif
static void
DisplayRecord(FILE *outFilep, afs_int32 *alp, afs_int32 rsize)
{
    char msgBuffer[1024];
#if defined(AFS_SGI61_ENV) || (defined(AFS_AIX51_ENV) && defined(AFS_64BIT_KERNEL))
    char outMsgBuffer[1024];
    uint64_t tempParam;
    uint64_t printfParms[ICL_MAXEXPANSION * /* max parms */ 4];
    char *printfStrings[ICL_MAXEXPANSION * /* max parms */ 4];
#else /* AFS_SGI61_ENV */
    long printfParms[ICL_MAXEXPANSION * /* max parms */ 4];
#endif /* AFS_SGI61_ENV */
    int printfTypes[ICL_MAXEXPANSION * 4];
    int i;
    afs_int32 done = 0;
    afs_int32 temp;
    int j;
    int type;
    int pix;			/* index in alp */
    int pfpix;			/* index in printfParms */
    int pftix;			/* index in printfTypes */
    int status;
    int printed;		/* did we print the string yet? */
    time_t tmv;

    /* decode parameters */
    temp = alp[0];		/* type encoded in low-order 24 bits, t0 high */
    pix = 4;
    pfpix = 0;
    pftix = 0;
    /* init things */

    for (i = 0; i < 4 * ICL_MAXEXPANSION; i++)
	printfParms[i] = 0;
    /* decode each parameter, getting addrs for afs_hyper_t and strings */
    for (i = 0; !done && i < 4; i++) {
	type = (temp >> (18 - i * 6)) & 0x3f;
	switch (type) {
	case ICL_TYPE_NONE:
	    done = 1;
	    break;
	case ICL_TYPE_LONG:
	case ICL_TYPE_POINTER:
	    printfTypes[pftix++] = 0;
#if defined(AFS_SGI61_ENV) || (defined(AFS_AIX51_ENV) && defined(AFS_64BIT_KERNEL))
	    printfParms[pfpix] = alp[pix];
	    printfParms[pfpix] &= 0xffffffff;
	    if (afs_64bit_kernel) {
		printfParms[pfpix] <<= 32;
		printfParms[pfpix] |= alp[pix + 1];
	    }
#elif defined(AFS_OSF_ENV)
	    printfParms[pfpix] = alp[pix + 1];
	    printfParms[pfpix] |= (alp[pix] <<= 32);
#else /* !AFS_OSF_ENV && !AFS_SGI61_ENV */
	    printfParms[pfpix] = alp[pix];
#endif
	    pfpix++;
	    break;
	case ICL_TYPE_INT32:
	    printfTypes[pftix++] = 0;
	    printfParms[pfpix++] = alp[pix];
	    break;
	case ICL_TYPE_HYPER:
	case ICL_TYPE_INT64:
	    printfTypes[pftix++] = 0;
	    printfParms[pfpix++] = alp[pix];
	    printfTypes[pftix++] = 0;
	    printfParms[pfpix++] = alp[pix + 1];
	    break;
	case ICL_TYPE_FID:
	    printfTypes[pftix++] = 0;
	    printfParms[pfpix++] = alp[pix];
	    printfTypes[pftix++] = 0;
	    printfParms[pfpix++] = alp[pix + 1];
	    printfTypes[pftix++] = 0;
	    printfParms[pfpix++] = alp[pix + 2];
	    printfTypes[pftix++] = 0;
	    printfParms[pfpix++] = alp[pix + 3];
	    break;
	case ICL_TYPE_STRING:
	    printfTypes[pftix++] = 1;
#ifdef AFS_SGI64_ENV
	    printfStrings[pfpix++] = (char *)&alp[pix];
#else /* AFS_SGI64_ENV */
#if defined(AFS_SGI61_ENV) || (defined(AFS_AIX51_ENV) && defined(AFS_64BIT_KERNEL))
	    printfStrings[pfpix++] = (char *)&alp[pix];
#else /* AFS_SGI61_ENV */
	    printfParms[pfpix++] = (long)&alp[pix];
#endif /* AFS_SGI61_ENV */
#endif /* AFS_SGI64_ENV */
	    break;
	case ICL_TYPE_UNIXDATE:
	    tmv = alp[pix];
	    printfParms[pfpix++] = (long)ctime(&tmv);
	    break;
	default:
	    printf("DisplayRecord: Bad type %d in decode switch.\n", type);
	    done = 1;
	    break;
	}
	if (done)
	    break;

	pix += icl_GetSize(type, (char *)&alp[pix]);
    }

    /* next, try to decode the opcode into a printf string */
    dce1_error_inq_text(alp[1], msgBuffer, &status);

    /* if we got a string back, and it is compatible with the
     * parms we've got, then print it.
     */
    printed = 0;
    if (status == 0) {
#if defined(AFS_SGI61_ENV) || (defined(AFS_AIX51_ENV) && defined(AFS_64BIT_KERNEL))
	if (CheckTypes(msgBuffer, printfTypes, pftix, outMsgBuffer)) {
	    /* we have a string to use, but it ends "(dfs / zcm)",
	     * so we remove the extra gunk.
	     */
	    j = strlen(outMsgBuffer);
	    if (j > 12) {
		outMsgBuffer[j - 11] = 0;
		j -= 11;
	    }
	    pfpix = 0;
	    fprintf(outFilep, "time %d.%06d, pid %u: ", alp[3] / 1000000,
		    alp[3] % 1000000, alp[2]);
	    for (i = 0; i < j; i++) {
		if ((int)outMsgBuffer[i] > 5)
		    fputc(outMsgBuffer[i], outFilep);
		else {
		    switch (outMsgBuffer[i]) {
		    case 0:	/* done */
			break;
		    case 1:	/* string */
			fprintf(outFilep, "%s", printfStrings[pfpix++]);
			break;
		    case 2:	/* signed integer */
			fprintf(outFilep, "%" AFS_INT64_FMT, printfParms[pfpix++]);
			break;
		    case 3:	/* unsigned integer */
			fprintf(outFilep, "%llu", printfParms[pfpix++]);
			break;
		    case 4:	/* octal integer */
			fprintf(outFilep, "%llo", printfParms[pfpix++]);
			break;
		    case 5:	/* hex integer */
			fprintf(outFilep, "%llx", printfParms[pfpix++]);
			break;
		    default:
			fprintf(outFilep,
				"fstrace: Bad char %d in outMsgBuffer for parm %d\n",
				outMsgBuffer[i], pfpix);
			fprintf(outFilep, "fstrace: msgBuffer='%s'\n",
				msgBuffer);
			break;
		    }
		}
	    }
	    fprintf(outFilep, "\n");
	    printed = 1;
	}
#else /* AFS_SGI61_ENV */
	if (CheckTypes(msgBuffer, printfTypes, pftix)) {
	    /* we have a string to use, but it ends "(dfs / zcm)",
	     * so we remove the extra gunk.
	     */
	    j = strlen(msgBuffer);
	    if (j > 12)
		msgBuffer[j - 11] = 0;
	    fprintf(outFilep, "time %d.%06d, pid %u: ", alp[3] / 1000000,
		    alp[3] % 1000000, alp[2]);
	    fprintf(outFilep, msgBuffer, printfParms[0], printfParms[1],
		    printfParms[2], printfParms[3], printfParms[4],
		    printfParms[5], printfParms[6], printfParms[7],
		    printfParms[8], printfParms[9], printfParms[10],
		    printfParms[11], printfParms[12], printfParms[13],
		    printfParms[14], printfParms[15]);
	    fprintf(outFilep, "\n");
	    printed = 1;
	}
#endif /* AFS_SGI61_ENV */
	else {
	    fprintf(outFilep, "Type mismatch, using raw print.\n");
	    fprintf(outFilep, "%s", msgBuffer);
	}
    }
    if (!printed) {
	if (alp[1] == ICL_INFO_TIMESTAMP) {
	    tmv = alp[4];
	    fprintf(outFilep, "time %d.%06d, pid %u: %s\n", alp[3] / 1000000,
		    alp[3] % 1000000, alp[2], ctime(&tmv));
	} else {
	    fprintf(outFilep, "raw op %d, time %d.%06d, pid %u\n", alp[1],
		    alp[3] / 1000000, alp[3] % 1000000, alp[2]);
	    /* now decode each parameter and print it */
	    pix = 4;
	    done = 0;
	    for (i = 0; !done && i < 4; i++) {
		type = (temp >> (18 - i * 6)) & 0x3f;
		switch (type) {
		case ICL_TYPE_NONE:
		    done = 1;
		    break;
		case ICL_TYPE_INT32:
		    fprintf(outFilep, "p%d:%d ", i, alp[pix]);
		    break;
		case ICL_TYPE_LONG:
#ifdef AFS_SGI61_ENV
		    tempParam = alp[pix];
		    tempParam <<= 32;
		    tempParam |= alp[pix + 1];
		    fprintf(outFilep, "p%d:%" AFS_INT64_FMT " ", i, tempParam);
#else /* AFS_SGI61_ENV */
		    fprintf(outFilep, "p%d:%d ", i, alp[pix]);
#endif /* AFS_SGI61_ENV */
		    break;
		case ICL_TYPE_POINTER:
#ifdef AFS_SGI61_ENV
		    tempParam = alp[pix];
		    tempParam <<= 32;
		    tempParam |= alp[pix + 1];
		    fprintf(outFilep, "p%d:0x%llx ", i, tempParam);
#else /* AFS_SGI61_ENV */
		    fprintf(outFilep, "p%d:0x%x ", i, alp[pix]);
#endif /* AFS_SGI61_ENV */
		    break;
		case ICL_TYPE_HYPER:
		case ICL_TYPE_INT64:
		    fprintf(outFilep, "p%d:%x.%x ", i, alp[pix],
			    alp[pix + 1]);
		    break;
		case ICL_TYPE_FID:
		    fprintf(outFilep, "p%d:%d.%d.%d.%d ", i, alp[pix],
			    alp[pix + 1], alp[pix + 2], alp[pix + 3]);
		    break;
		case ICL_TYPE_STRING:
		    fprintf(outFilep, "p%d:%s ", i, (char *)&alp[pix]);
		    break;
		case ICL_TYPE_UNIXDATE:
		    tmv = alp[pix];
		    fprintf(outFilep, "p%d:%s ", i,
			    ctime(&tmv));
		    break;
		default:
		    printf
			("DisplayRecord: Bad type %d in raw print switch.\n",
			 type);
		    done = 1;
		    break;
		}
		if (done)
		    break;

		pix += icl_GetSize(type, (char *)&alp[pix]);
	    }
	}
	fprintf(outFilep, "\n");	/* done with line */
    }
}



#include <locale.h>
#ifdef	AFS_OSF_ENV
#include <limits.h>
#endif
#include <nl_types.h>

#define FACILITY_CODE_MASK          0xF0000000
#define FACILITY_CODE_SHIFT         28

#define COMPONENT_CODE_MASK         0x0FFFF000
#define COMPONENT_CODE_SHIFT        12

#define STATUS_CODE_MASK            0x00000FFF
#define STATUS_CODE_SHIFT           0

#define NO_MESSAGE                  "THIS IS NOT A MESSAGE"

/*
 * We use NLS message catalog functions to convert numbers to human-readable
 * strings.  The message catalog will be in AFSDIR_DATA_DIR, which is
 * ${datadir}/openafs with normal paths and /usr/vice/etc (for historical
 * compatibility) for Transarc paths.
 */

void
dce1_error_inq_text(afs_uint32 status_to_convert,
		   char *error_text, int *status)
{
    unsigned short facility_code;
    unsigned short component_code;
    unsigned short status_code;
    unsigned short i;
    nl_catd catd;
    char component_name[4];
    char *facility_name;
    char filename_prefix[7];
    char nls_filename[80];
    char *message;
    static char *facility_names[] = {
	"xxx",
	"afs"
    };

    /*
     * set up output status for future error returns
     */
    if (status != NULL) {
	*status = -1;
    }
    /*
     * check for ok input status
     */
    if (status_to_convert == 0) {
	if (status != NULL) {
	    *status = 0;
	}
	strcpy((char *)error_text, "successful completion");
	return;
    }

    /*
     * extract the component, facility and status codes
     */
    facility_code =
	(status_to_convert & FACILITY_CODE_MASK) >> FACILITY_CODE_SHIFT;
    component_code =
	(status_to_convert & COMPONENT_CODE_MASK) >> COMPONENT_CODE_SHIFT;
    status_code = (status_to_convert & STATUS_CODE_MASK) >> STATUS_CODE_SHIFT;

    /*
     * see if this is a recognized facility
     */
    if (facility_code == 0
	|| facility_code > sizeof(facility_names) / sizeof(char *)) {
	sprintf((char *)error_text, "status %08x (unknown facility)",
		status_to_convert);
	return;
    }
    facility_name = facility_names[facility_code - 1];
    /*
     * Convert component name from RAD-50 component code.  (Mapping is:
     * 0 => 'a', ..., 25 => 'z', 26 => '{', 27 => '0', ..., 36 => '9'.)
     */
    component_name[3] = 0;
    component_name[2] = component_code % 40;
    component_code /= 40;
    component_name[1] = component_code % 40;
    component_name[0] = component_code / 40;
    for (i = 0; i < 3; i++) {
	component_name[i] += (component_name[i] <= 26) ? 'a' : ('0' - 27);
    }
    sprintf(filename_prefix, "%3s%3s", facility_name, component_name);

    /*
     * We do not use the normal NLS message catalog search path since our use
     * message catalogs isn't a typical use.  It wouldn't make sense to
     * install this special message catalog in with internationalization
     * catalogs.
     */
    snprintf(nls_filename, sizeof(nls_filename), "%s/C/%s.cat",
	     AFSDIR_CLIENT_DATA_DIRPATH, filename_prefix);

    catd = catopen(nls_filename, 0);
    if (catd == (nl_catd) -1) {
	sprintf((char *)error_text, "status %08x (%s / %s)",
		status_to_convert, facility_name, component_name);
	return;
    }
    /*
     * try to get the specified message from the file
     */
    message = (char *)catgets(catd, 1, status_code, NO_MESSAGE);
    /*
     * if everything went well, return the resulting message
     */
    if (strcmp(message, NO_MESSAGE) != 0) {
	sprintf((char *)error_text, "%s (%s / %s)", message, facility_name,
		component_name);
	if (status != NULL) {
	    *status = 0;
	}
    } else {
	sprintf((char *)error_text, "status %08x (%s / %s)",
		status_to_convert, facility_name, component_name);
    }
    catclose(catd);
}

int
icl_DumpKernel(FILE *outFilep, char *setname)
{
    afs_int32 bufferSize = 0;
    afs_int32 *bufferp;
    afs_int32 i;
    afs_int32 code, retVal = 0;
    char tname[64];
    afs_int32 nwords;
    afs_int32 ix;
    afs_int32 rlength;
    afs_int32 dummy, dummy2;
    struct logInfo *lip;

    /* first, enumerate the logs we're interested in */
    if (setname) {
	int found = 0;
	/* dump logs for a particular set */
	for (i = 0; i < ICL_LOGSPERSET; i++) {
	    code =
		afs_syscall(AFSCALL_ICL, ICL_OP_ENUMLOGSBYSET, (long)setname,
			    i, (long)tname, sizeof(tname), 0, 0);
	    if (code) {
		if (errno == EBADF) {
		    continue;	/* missing slot, nothing to worry about */
		}
		break;
	    }
	    code =
		afs_syscall(AFSCALL_ICL, ICL_OP_GETLOGINFO, (long)tname,
			    (long)&dummy, (long)&dummy2, 0, 0, 0);
	    if (code)
		break;
	    found++;
	    if (dummy > bufferSize)	/* find biggest log */
		bufferSize = dummy;
	    lip = calloc(1, sizeof(struct logInfo));
	    lip->nextp = allInfo;
	    allInfo = lip;
	    lip->name = strdup(tname);
	}
	i = found;
    } else {
	/* dump all logs */
	for (i = 0; i < 1000; i++) {
	    code =
		afs_syscall(AFSCALL_ICL, ICL_OP_ENUMLOGS, i, (long)tname,
			    sizeof(tname), (long)&dummy, 0, 0);
	    if (code)
		break;
	    if (dummy > bufferSize)	/* find biggest log */
		bufferSize = dummy;
	    lip = calloc(1, sizeof(struct logInfo));
	    lip->nextp = allInfo;
	    allInfo = lip;
	    lip->name = strdup(tname);
	}
    }

    if (bufferSize == 0)
	return -1;
    bufferp = malloc(sizeof(afs_int32) * bufferSize);
    if (!bufferp)
	return -1;

    fprintf(outFilep, "Found %d logs.\n", i);

    /* now print out the contents of each log */
    for (lip = allInfo; lip; lip = lip->nextp) {
	fprintf(outFilep, "\nContents of log %s:\n", lip->name);
	/* read out everything first; gets a more consistent
	 * snapshot.
	 */
	nwords = 0;		/* total words copied out */
	for (i = 0;;) {
	    /* display all the entries in the log */
	    if (bufferSize - nwords <= 0)
		break;		/* filled whole buffer */
	    code =
		afs_syscall(AFSCALL_ICL, ICL_OP_COPYOUT, (long)lip->name,
			    (long)(bufferp + nwords), bufferSize - nwords,
			    (long)&i, 0, 0);
	    if (code < 0) {
		/* otherwise we've got an error */
		fprintf(outFilep, "Returned error %d dumping log.\n", errno);
		break;
	    }
	    /* otherwise, we have flags in the high order byte, and
	     * a length (in words) in the remainder.
	     */
	    if ((code >> 24) & ICL_COPYOUTF_MISSEDSOME)
		fprintf(outFilep, "Log wrapped; data missing.\n");
	    code &= 0xffffff;
	    if (code == 0) {
		/* we're done */
		break;
	    }
	    nwords += code;
	    i += code;
	}			/* for loop over all cookies */

	/* otherwise we should display all of the log entries here.
	 * Note that a record may end in the middle, in which case
	 * we should start over with the cookie value of the start
	 * of that record.
	 */
	for (ix = 0; ix < nwords;) {
	    /* start of a record */
	    rlength = (bufferp[ix] >> 24) & 0xff;
	    if (rlength <= 0) {
		fprintf(outFilep, "Internal error: 0 length record\n");
		retVal = -1;
		goto done;
	    }
	    /* ensure that entire record fits */
	    if (ix + rlength > nwords) {
		/* doesn't fit, adjust cookie and break */
		break;
	    }
	    /* print the record */
	    DisplayRecord(outFilep, &bufferp[ix], rlength);
	    ix += rlength;
#ifdef notdef
	    /* obsolete: read entire buffer first */
	    i += rlength;	/* update cookie value, too */
#endif
	}			/* for loop displaying buffer */
    }				/* for loop over all logs */

  done:
    free(bufferp);
    return (retVal);
}

/* clear out log 'name' */
int
icl_ClearLog(char *name)
{
    afs_int32 code;

    code = afs_syscall(AFSCALL_ICL, ICL_OP_CLRLOG, (long)name, 0, 0, 0, 0, 0);
    return code;
}

/* clear out set 'name' */
int
icl_ClearSet(char *name)
{
    afs_int32 code;

    code = afs_syscall(AFSCALL_ICL, ICL_OP_CLRSET, (long)name, 0, 0, 0, 0, 0);
    return code;
}

/* clear out all logs */
int
icl_ClearAll(void)
{
    afs_int32 code;

    code = afs_syscall(AFSCALL_ICL, ICL_OP_CLRALL, 0, 0, 0, 0, 0, 0);
    return code;
}

/* list out all available sets to outFileP */
int
icl_ListSets(FILE *outFileP)
{
    int i;
    afs_int32 code = 0;
    afs_int32 states;
    char tname[64];

    for (i = 0; i < 1000; i++) {
	code =
	    afs_syscall(AFSCALL_ICL, ICL_OP_ENUMSETS, i, (long)tname,
			sizeof(tname), (long)&states, 0, 0);
	if (code)
	    break;
	(void)fprintf(outFileP, "%s %s%s%s\n", tname,
		      (states & ICL_SETF_ACTIVE) ? "active" : "inactive",
		      (states & ICL_SETF_FREED) ? " (dormant)" : "",
		      (states & ICL_SETF_PERSISTENT) ? " persistent" : "");
    }

    return 0;
}

/* list out all available logs to outFileP */
int
icl_ListLogs(FILE *outFileP, int int32flg)
{
    int i;
    int allocated;
    afs_int32 code = 0;
    afs_int32 logSize;
    char tname[64];

    for (i = 0; i < 1000; i++) {
	code =
	    afs_syscall(AFSCALL_ICL, ICL_OP_ENUMLOGS, i, (long)tname,
			sizeof(tname), (long)&logSize, 0, 0);
	if (code)
	    break;
	if (int32flg) {
	    /* get more information on the log */
	    code =
		afs_syscall(AFSCALL_ICL, ICL_OP_GETLOGINFO, (long)tname,
			    (long)&logSize, (long)&allocated, 0, 0, 0);
	    if (code)
		break;
	    (void)fprintf(outFileP, "%s : %d kbytes (%s)\n", tname,
			  logSize / 1024,
			  allocated ? "allocated" : "unallocated");
	} else
	    (void)fprintf(outFileP, "%s\n", tname);
    }

    return 0;
}

/* list out all available logs to outFileP */
int
icl_ListLogsBySet(FILE *outFileP, char *setname, int int32flg)
{
    int i;
    afs_int32 code = 0;
    afs_int32 logSize;
    int allocated;
    char tname[64];

    for (i = 0; i < ICL_LOGSPERSET; i++) {
	code =
	    afs_syscall(AFSCALL_ICL, ICL_OP_ENUMLOGSBYSET, (long)setname, i,
			(long)tname, sizeof(tname), 0, 0);
	if (code) {
	    if (errno == EBADF) {
		code = 0;
		continue;	/* missing */
	    }
	    break;
	}
	if (int32flg) {
	    /* get more information on the log */
	    code =
		afs_syscall(AFSCALL_ICL, ICL_OP_GETLOGINFO, (long)tname,
			    (long)&logSize, (long)&allocated, 0, 0, 0);
	    if (code)
		break;
	    (void)fprintf(outFileP, "%s : %d kbytes (%s)\n", tname,
			  logSize / 1024,
			  allocated ? "allocated" : "unallocated");
	} else
	    (void)fprintf(outFileP, "%s\n", tname);
    }

    return code;
}

/* activate/deactivate/free specified set */
int
icl_ChangeSetState(char *name, afs_int32 op)
{
    afs_int32 code;

    code = afs_syscall(AFSCALL_ICL, ICL_OP_SETSTAT, (long)name, op, 0, 0, 0, 0);
    return code;
}

/* activate/deactivate/free all sets */
int
icl_ChangeAllSetState(afs_int32 op)
{
    afs_int32 code;

    code = afs_syscall(AFSCALL_ICL, ICL_OP_SETSTATALL, op, 0, 0, 0, 0, 0);
    return code;
}

/* set size if log */
int
icl_ChangeLogSize(char *name, afs_int32 logSize)
{
    afs_int32 code;

    code =
	afs_syscall(AFSCALL_ICL, ICL_OP_SETLOGSIZE, (long)name, logSize, 0,
		    0, 0, 0);
    return code;
}

/* get logsize of specified log */
int
icl_GetLogsize(char *logname, afs_int32 *logSizeP, int *allocatedP)
{
    afs_int32 code;
    code =
	afs_syscall(AFSCALL_ICL, ICL_OP_GETLOGINFO, (long)logname,
		    (long)logSizeP, (long)allocatedP, 0, 0, 0);
    return code;
}

/* get state of specified set */
int
icl_GetSetState(char *setname, afs_int32 *stateP)
{
    afs_int32 code;
    code =
	afs_syscall(AFSCALL_ICL, ICL_OP_GETSETINFO, (long)setname,
		    (long)stateP, 0, 0, 0, 0);
    return code;
}

int
icl_TailKernel(FILE *outFilep, char *logname, afs_int32 waitTime)
{
    afs_int32 bufferSize = 0;
    afs_int32 newBufferSize;
    afs_int32 *bufferp;
    afs_int32 i;
    afs_int32 code, retVal = 0;
    afs_int32 nwords;
    afs_int32 ix;
    afs_int32 rlength;
    int allocated;

    /* get information about the specified log */
    code =
	afs_syscall(AFSCALL_ICL, ICL_OP_GETLOGINFO, (long)logname,
		    (long)&bufferSize, (long)&allocated, 0, 0, 0);
    if (code) {
	if (errno == ENOENT)
	    (void)fprintf(stderr, "'%s' not found\n", logname);
	else
	    (void)fprintf(stderr,
			  "cannot get information on log '%s' (errno = %d)\n",
			  logname, errno);
	return -1;
    }

    if (!allocated) {
	(void)fprintf(stderr, "'%s' not allocated\n", logname);
	return 0;
    }

    if (bufferSize == 0)
	return -1;
    bufferp = malloc(sizeof(afs_int32) * bufferSize);
    if (!bufferp) {
	(void)fprintf(stderr, "cannot allocate %d words for buffer\n",
		      bufferSize);
	return -1;
    }

    /* start "infinite" loop */
    for (;;) {
	/* read out all that's currently there */
	nwords = 0;		/* total words copied out */
	i = 0;			/* initialize cookie */
	for (;;) {
	    /* display all the entries in the log */
	    if (bufferSize - nwords <= 0)
		break;		/* filled whole buffer, clear when done */
	    code =
		afs_syscall(AFSCALL_ICL, ICL_OP_COPYOUTCLR, (long)logname,
			    (long)(bufferp + nwords), bufferSize - nwords,
			    (long)&i, 0, 0);
	    if (code < 0) {
		/* otherwise we've got an error */
		fprintf(stderr, "returned error %d dumping log.\n", errno);
		retVal = -1;
		goto tail_done;
	    }
	    /* otherwise, we have flags in the high order byte, and
	     * a length (in words) in the remainder.
	     */
	    code &= 0xffffff;
	    if (code == 0) {
		/* we're done */
		break;
	    }
	    nwords += code;
	    i += code;
	}			/* for loop over all cookies */

	/* otherwise we should display all of the log entries here.
	 * Note that a record may end in the middle, in which case
	 * we should start over with the cookie value of the start
	 * of that record.
	 */
	for (ix = 0; ix < nwords;) {
	    /* start of a record */
	    rlength = (bufferp[ix] >> 24) & 0xff;
	    /* ensure that entire record fits */
	    if (ix + rlength > nwords) {
		/* doesn't fit, adjust cookie and break */
		if (rlength <= 0) {
		    fprintf(stderr, "BOGUS: 0 length record\n");
		    retVal = -1;
		    goto tail_done;
		}
		break;
	    }
	    /* print the record */
	    DisplayRecord(outFilep, &bufferp[ix], rlength);
	    ix += rlength;
	}			/* for loop displaying buffer */

	if (waitTime)
	    sleep(waitTime);

	/* see if things have changed */
	code =
	    afs_syscall(AFSCALL_ICL, ICL_OP_GETLOGINFO, (long)logname,
			(long)&newBufferSize, (long)&allocated, 0, 0, 0);
	if (code) {
	    if (errno == ENOENT)
		(void)fprintf(stderr, "'%s' not found\n", logname);
	    else
		(void)fprintf(stderr,
			      "cannot get information on log '%s' (errno = %d)\n",
			      logname, errno);
	    retVal = -1;
	    goto tail_done;
	}

	if (!allocated) {
	    (void)fprintf(stderr, "'%s' no int32er allocated\n", logname);
	    retVal = -1;
	    goto tail_done;
	}

	if (bufferSize == 0) {
	    (void)fprintf(stderr, "buffer size has become 0\n");
	    retVal = -1;
	    goto tail_done;
	}
	if (bufferSize != newBufferSize) {
	    /* have to reallocate a buffer */
	    bufferSize = newBufferSize;
	    free(bufferp);
	    bufferp = malloc(sizeof(afs_int32) * bufferSize);
	    if (!bufferp) {
		(void)fprintf(stderr, "cannot allocate %d words for buffer\n",
			      bufferSize);
		retVal = -1;
		goto tail_done;
	    }
	}
    }				/* infinite loop */

  tail_done:
    free(bufferp);
    return (retVal);
}

#if !defined(AFS_SGI_ENV)
int
afs_syscall(long call, long parm0, long parm1, long parm2, long parm3,
	    long parm4, long parm5, long parm6)
{
    int code;
#if defined(AFS_DARWIN80_ENV) || defined(AFS_LINUX20_ENV)
    int rval;
#endif
#ifdef AFS_LINUX20_ENV
#if defined AFS_LINUX_64BIT_KERNEL
    long long eparm[4];
    /* don't want to sign extend it to 64bit, so using ulong */
    eparm[0] = (unsigned long)parm3;
    eparm[1] = (unsigned long)parm4;
    eparm[2] = (unsigned long)parm5;
    eparm[3] = (unsigned long)parm6;
#else
    int eparm[4];
    eparm[0] = parm3;
    eparm[1] = parm4;
    eparm[2] = parm5;
    eparm[3] = parm6;
#endif
    /* Linux can only handle 5 arguments in the actual syscall. */
    if (call == AFSCALL_ICL) {
	rval = proc_afs_syscall(call, parm0, parm1, parm2, (long)eparm, &code);
	if (rval)
	    code = syscall(AFS_SYSCALL, call, parm0, parm1, parm2, eparm);
    } else {
	rval = proc_afs_syscall(call, parm0, parm1, parm2, parm3, &code);
	if (rval)
	    code = syscall(AFS_SYSCALL, call, parm0, parm1, parm2, parm3);
    }
#if defined(AFS_SPARC64_LINUX20_ENV) || defined(AFS_SPARC_LINUX20_ENV)
    /* on sparc this function returns none value, so do it myself */
    __asm__ __volatile__("mov	%o0, %i0; ret; restore");
#endif
#else
#ifdef AFS_DARWIN80_ENV
    code = ioctl_afs_syscall(call, parm0, parm1, parm2, parm3, parm4, parm5, &rval);
    if (!code) code = rval;
#else
#if !defined(AFS_SGI_ENV) && !defined(AFS_AIX32_ENV)
    code = syscall(AFS_SYSCALL, call, parm0, parm1, parm2, parm3, parm4);
#else
#if defined(AFS_SGI_ENV)
    code = syscall(AFS_ICL, call, parm0, parm1, parm2, parm3, parm4);	/* XXX */
#else
    code = syscall(AFSCALL_ICL, parm0, parm1, parm2, parm3, parm4);
#endif
#endif
#endif
#endif /* AFS_LINUX20_ENV */
    return code;
}
#endif


int icl_inited = 0;

/* init function, called once, under icl_lock */
int
icl_Init(void)
{
    icl_inited = 1;

#ifndef KERNEL
    /* setup signal handler, in user space */
#endif /* KERNEL */

    return 0;
}

int
icl_CreateSet(char *name, struct afs_icl_log *baseLogp,
	      struct afs_icl_log *fatalLogp, struct afs_icl_set **outSetpp)
{
    return icl_CreateSetWithFlags(name, baseLogp, fatalLogp, /*flags */ 0,
				  outSetpp);
}

/* create a set, given pointers to base and fatal logs, if any.
 * Logs are unlocked, but referenced, and *outSetpp is returned
 * referenced.  Function bumps reference count on logs, since it
 * addds references from the new icl_set.  When the set is destroyed,
 * those references will be released.
 */
int
icl_CreateSetWithFlags(char *name, struct afs_icl_log *baseLogp,
		       struct afs_icl_log *fatalLogp, afs_uint32 flags,
		       struct afs_icl_set **outSetpp)
{
    struct afs_icl_set *setp;
    int i;
    afs_int32 states = ICL_DEFAULT_SET_STATES;

    if (!icl_inited)
	icl_Init();

    for (setp = icl_allSets; setp; setp = setp->nextp) {
	if (strcmp(setp->name, name) == 0) {
	    setp->refCount++;
	    *outSetpp = setp;
	    if (flags & ICL_CRSET_FLAG_PERSISTENT) {
		setp->states |= ICL_SETF_PERSISTENT;
	    }
	    return 0;
	}
    }

    /* determine initial state */
    if (flags & ICL_CRSET_FLAG_DEFAULT_ON)
	states = ICL_SETF_ACTIVE;
    else if (flags & ICL_CRSET_FLAG_DEFAULT_OFF)
	states = ICL_SETF_FREED;
    if (flags & ICL_CRSET_FLAG_PERSISTENT)
	states |= ICL_SETF_PERSISTENT;

    setp = osi_Alloc(sizeof(struct afs_icl_set));
    memset((caddr_t) setp, 0, sizeof(*setp));
    setp->refCount = 1;
    if (states & ICL_SETF_FREED)
	states &= ~ICL_SETF_ACTIVE;	/* if freed, can't be active */
    setp->states = states;

    setp->name = osi_Alloc(strlen(name) + 1);
    strcpy(setp->name, name);
    setp->nevents = ICL_DEFAULTEVENTS;
    setp->eventFlags = osi_Alloc(ICL_DEFAULTEVENTS);
    for (i = 0; i < ICL_DEFAULTEVENTS; i++)
	setp->eventFlags[i] = 0xff;	/* default to enabled */

    /* update this global info under the icl_lock */
    setp->nextp = icl_allSets;
    icl_allSets = setp;

    /* set's basic lock is still held, so we can finish init */
    if (baseLogp) {
	setp->logs[0] = baseLogp;
	icl_LogHold(baseLogp);
	if (!(setp->states & ICL_SETF_FREED))
	    icl_LogUse(baseLogp);	/* log is actually being used */
    }
    if (fatalLogp) {
	setp->logs[1] = fatalLogp;
	icl_LogHold(fatalLogp);
	if (!(setp->states & ICL_SETF_FREED))
	    icl_LogUse(fatalLogp);	/* log is actually being used */
    }

    *outSetpp = setp;
    return 0;
}

/* function to change event enabling information for a particular set */
int
icl_SetEnable(struct afs_icl_set *setp, afs_int32 eventID, int setValue)
{
    char *tp;

    if (!ICL_EVENTOK(setp, eventID)) {
	return -1;
    }
    tp = &setp->eventFlags[ICL_EVENTBYTE(eventID)];
    if (setValue)
	*tp |= ICL_EVENTMASK(eventID);
    else
	*tp &= ~(ICL_EVENTMASK(eventID));
    return 0;
}

/* return indication of whether a particular event ID is enabled
 * for tracing.  If *getValuep is set to 0, the event is disabled,
 * otherwise it is enabled.  All events start out enabled by default.
 */
int
icl_GetEnable(struct afs_icl_set *setp, afs_int32 eventID, int *getValuep)
{
    if (!ICL_EVENTOK(setp, eventID)) {
	return -1;
    }
    if (setp->eventFlags[ICL_EVENTBYTE(eventID)] & ICL_EVENTMASK(eventID))
	*getValuep = 1;
    else
	*getValuep = 0;
    return 0;
}

/* hold and release event sets */
int
icl_SetHold(struct afs_icl_set *setp)
{
    setp->refCount++;
    return 0;
}

/* free a set.  Called with icl_lock locked */
int
icl_ZapSet(struct afs_icl_set *setp)
{
    struct afs_icl_set **lpp, *tp;
    int i;
    struct afs_icl_log *tlp;

    for (lpp = &icl_allSets, tp = *lpp; tp; lpp = &tp->nextp, tp = *lpp) {
	if (tp == setp) {
	    /* found the dude we want to remove */
	    *lpp = setp->nextp;
	    osi_Free(setp->name, 1 + strlen(setp->name));
	    osi_Free(setp->eventFlags, ICL_EVENTBYTES(setp->nevents));
	    for (i = 0; i < ICL_LOGSPERSET; i++) {
		if ((tlp = setp->logs[i]))
		    icl_LogReleNL(tlp);
	    }
	    osi_Free(setp, sizeof(struct afs_icl_set));
	    break;		/* won't find it twice */
	}
    }
    return 0;
}

/* do the release, watching for deleted entries */
int
icl_SetRele(struct afs_icl_set *setp)
{
    if (--setp->refCount == 0 && (setp->states & ICL_SETF_DELETED)) {
	icl_ZapSet(setp);	/* destroys setp's lock! */
    }
    return 0;
}

/* free a set entry, dropping its reference count */
int
icl_SetFree(struct afs_icl_set *setp)
{
    setp->states |= ICL_SETF_DELETED;
    icl_SetRele(setp);
    return 0;
}

/* find a set by name, returning it held */
struct afs_icl_set *
icl_FindSet(char *name)
{
    struct afs_icl_set *tp;

    for (tp = icl_allSets; tp; tp = tp->nextp) {
	if (strcmp(tp->name, name) == 0) {
	    /* this is the dude we want */
	    tp->refCount++;
	    break;
	}
    }
    return tp;
}

/* zero out all the logs in the set */
int
icl_ZeroSet(struct afs_icl_set *setp)
{
    int i;
    int code = 0;
    int tcode;
    struct afs_icl_log *logp;

    for (i = 0; i < ICL_LOGSPERSET; i++) {
	logp = setp->logs[i];
	if (logp) {
	    icl_LogHold(logp);
	    tcode = icl_ZeroLog(logp);
	    if (tcode != 0)
		code = tcode;	/* save the last bad one */
	    icl_LogRele(logp);
	}
    }
    return code;
}

int
icl_EnumerateSets(int (*aproc) (char *, void *, struct afs_icl_set *),
		  void *arock)
{
    struct afs_icl_set *tp, *np;
    afs_int32 code;

    code = 0;
    for (tp = icl_allSets; tp; tp = np) {
	tp->refCount++;		/* hold this guy */
	code = (*aproc) (tp->name, arock, tp);
	np = tp->nextp;		/* tp may disappear next, but not np */
	if (--tp->refCount == 0 && (tp->states & ICL_SETF_DELETED))
	    icl_ZapSet(tp);
	if (code)
	    break;
    }
    return code;
}

int
icl_AddLogToSet(struct afs_icl_set *setp, struct afs_icl_log *newlogp)
{
    int i;
    int code = -1;

    for (i = 0; i < ICL_LOGSPERSET; i++) {
	if (!setp->logs[i]) {
	    setp->logs[i] = newlogp;
	    code = i;
	    icl_LogHold(newlogp);
	    if (!(setp->states & ICL_SETF_FREED)) {
		/* bump up the number of sets using the log */
		icl_LogUse(newlogp);
	    }
	    break;
	}
    }
    return code;
}

int
icl_SetSetStat(struct afs_icl_set *setp, int op)
{
    int i;
    afs_int32 code;
    struct afs_icl_log *logp;

    switch (op) {
    case ICL_OP_SS_ACTIVATE:	/* activate a log */
	/*
	 * If we are not already active, see if we have released
	 * our demand that the log be allocated (FREED set).  If
	 * we have, reassert our desire.
	 */
	if (!(setp->states & ICL_SETF_ACTIVE)) {
	    if (setp->states & ICL_SETF_FREED) {
		/* have to reassert desire for logs */
		for (i = 0; i < ICL_LOGSPERSET; i++) {
		    logp = setp->logs[i];
		    if (logp) {
			icl_LogHold(logp);
			icl_LogUse(logp);
			icl_LogRele(logp);
		    }
		}
		setp->states &= ~ICL_SETF_FREED;
	    }
	    setp->states |= ICL_SETF_ACTIVE;
	}
	code = 0;
	break;

    case ICL_OP_SS_DEACTIVATE:	/* deactivate a log */
	/* this doesn't require anything beyond clearing the ACTIVE flag */
	setp->states &= ~ICL_SETF_ACTIVE;
	code = 0;
	break;

    case ICL_OP_SS_FREE:	/* deassert design for log */
	/*
	 * if we are already in this state, do nothing; otherwise
	 * deassert desire for log
	 */
	if (setp->states & ICL_SETF_ACTIVE)
	    code = EINVAL;
	else {
	    if (!(setp->states & ICL_SETF_FREED)) {
		for (i = 0; i < ICL_LOGSPERSET; i++) {
		    logp = setp->logs[i];
		    if (logp) {
			icl_LogHold(logp);
			icl_LogFreeUse(logp);
			icl_LogRele(logp);
		    }
		}
		setp->states |= ICL_SETF_FREED;
	    }
	    code = 0;
	}
	break;

    default:
	code = EINVAL;
    }

    return code;
}

struct afs_icl_log *afs_icl_allLogs = 0;

/* hold and release logs */
int
icl_LogHold(struct afs_icl_log *logp)
{
    logp->refCount++;
    return 0;
}

/* hold and release logs, called with lock already held */
int
icl_LogHoldNL(struct afs_icl_log *logp)
{
    logp->refCount++;
    return 0;
}

/* keep track of how many sets believe the log itself is allocated */
int
icl_LogUse(struct afs_icl_log *logp)
{
    if (logp->setCount == 0) {
	/* this is the first set actually using the log -- allocate it */
	if (logp->logSize == 0) {
	    /* we weren't passed in a hint and it wasn't set */
	    logp->logSize = ICL_DEFAULT_LOGSIZE;
	}
	logp->datap = osi_Alloc(sizeof(afs_int32) * logp->logSize);
    }
    logp->setCount++;
    return 0;
}

/* decrement the number of real users of the log, free if possible */
int
icl_LogFreeUse(struct afs_icl_log *logp)
{
    if (--logp->setCount == 0) {
	/* no more users -- free it (but keep log structure around) */
	osi_Free(logp->datap, sizeof(afs_int32) * logp->logSize);
	logp->firstUsed = logp->firstFree = 0;
	logp->logElements = 0;
	logp->datap = NULL;
    }
    return 0;
}

/* set the size of the log to 'logSize' */
int
icl_LogSetSize(struct afs_icl_log *logp, afs_int32 logSize)
{
    if (!logp->datap) {
	/* nothing to worry about since it's not allocated */
	logp->logSize = logSize;
    } else {
	/* reset log */
	logp->firstUsed = logp->firstFree = 0;
	logp->logElements = 0;

	/* free and allocate a new one */
	osi_Free(logp->datap, sizeof(afs_int32) * logp->logSize);
	logp->datap = osi_Alloc(sizeof(afs_int32) * logSize);
	logp->logSize = logSize;
    }

    return 0;
}

/* free a log.  Called with icl_lock locked. */
int
icl_ZapLog(struct afs_icl_log *logp)
{
    struct afs_icl_log **lpp, *tp;

    for (lpp = &afs_icl_allLogs, tp = *lpp; tp; lpp = &tp->nextp, tp = *lpp) {
	if (tp == logp) {
	    /* found the dude we want to remove */
	    *lpp = logp->nextp;
	    osi_Free(logp->name, 1 + strlen(logp->name));
	    osi_Free(logp->datap, logp->logSize * sizeof(afs_int32));
	    osi_Free(logp, sizeof(struct icl_log));
	    break;		/* won't find it twice */
	}
    }
    return 0;
}

/* do the release, watching for deleted entries */
int
icl_LogRele(struct afs_icl_log *logp)
{
    if (--logp->refCount == 0 && (logp->states & ICL_LOGF_DELETED)) {
	icl_ZapLog(logp);	/* destroys logp's lock! */
    }
    return 0;
}

/* do the release, watching for deleted entries, log already held */
int
icl_LogReleNL(struct afs_icl_log *logp)
{
    if (--logp->refCount == 0 && (logp->states & ICL_LOGF_DELETED)) {
	icl_ZapLog(logp);	/* destroys logp's lock! */
    }
    return 0;
}

/* zero out the log */
int
icl_ZeroLog(struct afs_icl_log *logp)
{
    logp->firstUsed = logp->firstFree = 0;
    logp->logElements = 0;
    return 0;
}

/* free a log entry, and drop its reference count */
int
icl_LogFree(struct afs_icl_log *logp)
{
    logp->states |= ICL_LOGF_DELETED;
    icl_LogRele(logp);
    return 0;
}


int
icl_EnumerateLogs(int (*aproc)
		    (char *name, void *arock, struct afs_icl_log * tp),
		  void *arock)
{
    struct afs_icl_log *tp, *np;
    afs_int32 code;

    code = 0;
    for (tp = afs_icl_allLogs; tp; tp = np) {
	tp->refCount++;		/* hold this guy */
	np = tp->nextp;
	code = (*aproc) (tp->name, arock, tp);
	if (--tp->refCount == 0)
	    icl_ZapLog(tp);
	if (code)
	    break;
    }
    return code;
}


afs_icl_bulkSetinfo_t *
GetBulkSetInfo(void)
{
    unsigned int infoSize;

    infoSize =
	sizeof(afs_icl_bulkSetinfo_t) + (ICL_RPC_MAX_SETS -
					 1) * sizeof(afs_icl_setinfo_t);
    if (!setInfo) {
	setInfo = calloc(1, infoSize);
	if (!setInfo) {
	    (void)fprintf(stderr,
			  "Could not allocate the memory for bulk set info structure\n");
	    exit(1);
	}
    }

    return setInfo;
}

afs_icl_bulkLoginfo_t *
GetBulkLogInfo(void)
{
    unsigned int infoSize;

    infoSize =
	sizeof(afs_icl_bulkLoginfo_t) + (ICL_RPC_MAX_LOGS -
					 1) * sizeof(afs_icl_loginfo_t);
    if (!logInfo) {
	logInfo = calloc(1, infoSize);
	if (!logInfo) {
	    (void)fprintf(stderr,
			  "Could not allocate the memory for bulk log info structure\n");
	    exit(1);
	}
    }

    return logInfo;
}


static int
DoDump(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code = 0;
    afs_int32 tcode;
    afs_int32 waitTime = 10 /* seconds */ ;
    char *logname;
    FILE *outfp = stdout;
    time_t startTime;
    struct cmd_item *itemp;

    if (geteuid() != 0) {
	printf("fstrace must be run as root\n");
	exit(1);
    }

    if (as->parms[3].items) {
	if (!as->parms[1].items) {
	    (void)fprintf(stderr, "-sleep can only be used with -follow\n");
	    return 1;
	}
	waitTime = strtol(as->parms[3].items->data, NULL, 0);
    }

    if (as->parms[2].items) {
	/* try to open the specified output file */
	if ((outfp = fopen(as->parms[2].items->data, "w")) == NULL) {
	    (void)fprintf(stderr, "Cannot open file '%s' for writing\n",
			  as->parms[2].items->data);
	    return 1;
	}
    }
#ifdef AFS_SGI64_ENV
    startTime = time((time_t *) 0);
#else
    startTime = time(0);
#endif
    (void)fprintf(outfp, "AFS Trace Dump -\n\n   Date: %s\n",
		  ctime(&startTime));

    if (as->parms[0].items) {
	for (itemp = as->parms[0].items; itemp; itemp = itemp->next) {
	    tcode = icl_DumpKernel(outfp, itemp->data);
	    if (tcode) {
		(void)fprintf(stderr, "Unable to dump set %s (errno = %d)\n",
			      itemp->data, errno);
		code = tcode;
	    }
	}
    } else if (as->parms[1].items) {
	logname = as->parms[1].items->data;
	code = icl_TailKernel(outfp, logname, waitTime);
	if (code) {
	    (void)fprintf(stderr,
			  "Error tailing kernel log '%s' (errno = %d)\n",
			  logname, errno);
	}
    } else
	code = icl_DumpKernel(outfp, NULL);

    (void)fprintf(outfp, "\nAFS Trace Dump - %s\n",
		  code ? "FAILED" : "Completed");

    if (outfp != stdout)
	(void)fclose(outfp);

    return code;
}

static void
SetUpDump(void)
{
    struct cmd_syndesc *dumpSyntax;

    dumpSyntax =
	cmd_CreateSyntax("dump", DoDump, NULL, 0, "dump AFS trace logs");
    (void)cmd_AddParm(dumpSyntax, "-set", CMD_LIST, CMD_OPTIONAL,
		      "event set name");
    (void)cmd_AddParm(dumpSyntax, "-follow", CMD_SINGLE, CMD_OPTIONAL,
		      "trace log name");
    (void)cmd_AddParm(dumpSyntax, "-file", CMD_SINGLE, CMD_OPTIONAL,
		      "path to trace log file for writing");
    (void)cmd_AddParm(dumpSyntax, "-sleep", CMD_SINGLE, CMD_OPTIONAL,
		      "interval (secs) for writes when using -follow");
}


static int
DoShowLog(struct cmd_syndesc *as, void *arock)
{
    afs_int32 retVal = 0;
    afs_int32 code = 0;
    afs_int32 logSize;
    int allocated;
    int int32flg = 0;
    struct cmd_item *itemp;

    if (geteuid() != 0) {
	printf("fstrace must be run as root\n");
	exit(1);
    }
    if (as->parms[2].items)
	int32flg = 1;

    if (as->parms[0].items) {
	/* enumerate logs for the specified sets */
	for (itemp = as->parms[0].items; itemp; itemp = itemp->next) {
	    (void)fprintf(stdout, "Logs for set '%s':\n", itemp->data);
	    code = icl_ListLogsBySet(stdout, itemp->data, int32flg);
	    if (code) {
		(void)fprintf(stderr,
			      "Error in enumerating set %s (errno = %d)\n",
			      itemp->data, errno);
		retVal = code;
	    }
	}
    } else if (as->parms[1].items) {
	/* print out log information */
	for (itemp = as->parms[1].items; itemp; itemp = itemp->next) {
	    code = icl_GetLogsize(itemp->data, &logSize, &allocated);
	    if (!code)
		(void)fprintf(stdout, "%s : %d kbytes (%s)\n", itemp->data,
			      logSize / 1024,
			      allocated ? "allocated" : "unallocated");
	    else {
		(void)fprintf(stderr,
			      "Could not find log '%s' (errno = %d)\n",
			      itemp->data, errno);
		retVal = code;
	    }
	}
    } else {
	/* show all logs */
	(void)fprintf(stdout, "Available logs:\n");
	code = icl_ListLogs(stdout, int32flg);
	if (code) {
	    (void)fprintf(stderr, "Error in listing logs (errno = %d)\n",
			  errno);
	    retVal = code;
	}
    }

    return retVal;
}

static void
SetUpShowLog(void)
{
    struct cmd_syndesc *showSyntax;

    showSyntax =
	cmd_CreateSyntax("lslog", DoShowLog, NULL, 0,
			 "list available logs");
    (void)cmd_AddParm(showSyntax, "-set", CMD_LIST, CMD_OPTIONAL,
		      "event set name");
    (void)cmd_AddParm(showSyntax, "-log", CMD_LIST, CMD_OPTIONAL,
		      "trace log name");
    (void)cmd_AddParm(showSyntax, "-long", CMD_FLAG, CMD_OPTIONAL,
		      "show defined log size in kbytes & if it is allocated in kernel mem");
}

static int
DoShowSet(struct cmd_syndesc *as, void *arock)
{
    afs_int32 retVal = 0;
    afs_int32 code = 0;
    afs_int32 state;
    struct cmd_item *itemp;

    if (geteuid() != 0) {
	printf("fstrace must be run as root\n");
	exit(1);
    }
    if (as->parms[0].items) {
	/* print information on the specified sets */
	for (itemp = as->parms[0].items; itemp; itemp = itemp->next) {
	    code = icl_GetSetState(itemp->data, &state);
	    if (code) {
		(void)fprintf(stderr,
			      "Error getting status on set %s (errno = %d)\n",
			      itemp->data, errno);
		retVal = code;
	    } else
		(void)fprintf(stdout, "Set %s: %s%s%s\n", itemp->data,
			      (state & ICL_SETF_ACTIVE) ? "active" :
			      "inactive",
			      (state & ICL_SETF_FREED) ? " (dormant)" : "",
			      (state & ICL_SETF_PERSISTENT) ? " persistent" :
			      "");
	}
    } else {
	/* show all sets */
	(void)fprintf(stdout, "Available sets:\n");
	code = icl_ListSets(stdout);
	if (code) {
	    (void)fprintf(stderr, "Error in listing sets (errno = %d)\n",
			  errno);
	    retVal = code;
	}
    }

    return retVal;
}

static void
SetUpShowSet(void)
{
    struct cmd_syndesc *showSyntax;

    showSyntax =
	cmd_CreateSyntax("lsset", DoShowSet, NULL, 0,
			 "list available event sets");
    (void)cmd_AddParm(showSyntax, "-set", CMD_LIST, CMD_OPTIONAL,
		      "event set name");
}

static int
DoClear(struct cmd_syndesc *as, void *arock)
{
    afs_int32 retVal = 0;
    afs_int32 code = 0;
    struct cmd_item *itemp;

    if (geteuid() != 0) {
	printf("fstrace must be run as root\n");
	exit(1);
    }
    if (as->parms[0].items) {
	/* clear logs for the specified sets */
	for (itemp = as->parms[0].items; itemp; itemp = itemp->next) {
	    code = icl_ClearSet(itemp->data);
	    if (code) {
		(void)fprintf(stderr,
			      "Error in clearing set %s (errno = %d)\n",
			      itemp->data, errno);
		retVal = code;
	    }
	}
    } else if (as->parms[1].items) {
	/* clear specified log */
	for (itemp = as->parms[0].items; itemp; itemp = itemp->next) {
	    code = icl_ClearLog(itemp->data);
	    if (code) {
		(void)fprintf(stderr,
			      "Error in clearing log %s (errno = %d)\n",
			      itemp->data, errno);
		retVal = code;
	    }
	}
    } else {
	/* clear all logs */
	code = icl_ClearAll();
	if (code) {
	    (void)fprintf(stderr, "Error in clearing logs (errno = %d)\n",
			  errno);
	    retVal = code;
	}
    }

    return retVal;
}

static void
SetUpClear(void)
{
    struct cmd_syndesc *clearSyntax;

    clearSyntax =
	cmd_CreateSyntax("clear", DoClear, NULL, 0,
			 "clear logs by logname or by event set");
    (void)cmd_AddParm(clearSyntax, "-set", CMD_LIST, CMD_OPTIONAL,
		      "event set name");
    (void)cmd_AddParm(clearSyntax, "-log", CMD_LIST, CMD_OPTIONAL,
		      "trace log name");
}

static int
DoSet(struct cmd_syndesc *as, void *arock)
{
    afs_int32 retVal = 0;
    afs_int32 code = 0;
    int op;
    int doFree = 0;
    char *operation;
    struct cmd_item *itemp;

    if (geteuid() != 0) {
	printf("fstrace must be run as root\n");
	exit(1);
    }
    if (as->parms[1].items) {
	op = ICL_OP_SS_ACTIVATE;
	operation = "active";
    } else if (as->parms[2].items) {
	op = ICL_OP_SS_DEACTIVATE;
	operation = "inactive";
    } else if (as->parms[3].items) {
	op = ICL_OP_SS_DEACTIVATE;
	operation = "inactive";
	doFree = 1;
    } else {
	/* assume active" */
	op = ICL_OP_SS_ACTIVATE;
	operation = "active";
    }

    if (as->parms[0].items) {
	/* activate specified sets */
	for (itemp = as->parms[0].items; itemp; itemp = itemp->next) {
	    code = icl_ChangeSetState(itemp->data, op);
	    if (code) {
		(void)fprintf(stderr,
			      "cannot set state of %s to %s (errno = %d)\n",
			      itemp->data, operation, errno);
		retVal = code;
	    } else if (doFree) {
		/* try to make it dormant as well */
		code = icl_ChangeSetState(itemp->data, ICL_OP_SS_FREE);
		if (code) {
		    (void)fprintf(stderr,
				  "cannot set state of %s to dormant (errno = %d)\n",
				  itemp->data, errno);
		    retVal = code;
		}
	    }
	}
    } else {
	/* show all sets */
	code = icl_ChangeAllSetState(op);
	if (code) {
	    (void)fprintf(stderr,
			  "cannot set the state of all sets to %s (errno = %d)\n",
			  operation, errno);
	    retVal = code;
	} else if (doFree) {
	    /* try to make it dormant as well */
	    code = icl_ChangeAllSetState(ICL_OP_SS_FREE);
	    if (code) {
		(void)fprintf(stderr,
			      "cannot set the state of all sets to dormant (errno = %d)\n",
			      errno);
		retVal = code;
	    }
	}
    }

    return retVal;
}

static void
SetUpSet(void)
{
    struct cmd_syndesc *setSyntax;

    setSyntax =
	cmd_CreateSyntax("setset", DoSet, NULL, 0,
			 "set state of event sets");
    (void)cmd_AddParm(setSyntax, "-set", CMD_LIST, CMD_OPTIONAL,
		      "event set name");
    (void)cmd_AddParm(setSyntax, "-active", CMD_FLAG, CMD_OPTIONAL,
		      "enable tracing for event set & allocate kernel memory");
    (void)cmd_AddParm(setSyntax, "-inactive", CMD_FLAG, CMD_OPTIONAL,
		      "disables tracing for event set, keep kernel memory");
    (void)cmd_AddParm(setSyntax, "-dormant", CMD_FLAG, CMD_OPTIONAL,
		      "disable tracing for event set & free kernel memory");
}

static int
DoResize(struct cmd_syndesc *as, void *arock)
{
    afs_int32 retVal = 0;
    afs_int32 code = 0;
    afs_int32 bufferSize;
    struct cmd_item *itemp;

    if (geteuid() != 0) {
	printf("fstrace must be run as root\n");
	exit(1);
    }
    /* get buffer size */
    bufferSize = atoi(as->parms[1].items->data);
    bufferSize *= BUFFER_MULTIPLIER;
    if (bufferSize == 0)
	bufferSize = ICL_DEFAULT_LOGSIZE;

    /* set the size of the specified logs */
    if ((itemp = as->parms[0].items)) {
	for (; itemp; itemp = itemp->next) {
	    code = icl_ChangeLogSize(itemp->data, bufferSize);
	    if (code) {
		(void)fprintf(stderr,
			      "Error in changing log %s buffer size (errno = %d)\n",
			      itemp->data, errno);
		retVal = code;
	    }
	}
    } else {
	/* Use the only current support log, "cmfx" */
	code = icl_ChangeLogSize("cmfx", bufferSize);
	if (code) {
	    (void)fprintf(stderr,
			  "Error in changing log cmfx buffer size (errno = %d)\n",
			  errno);
	    retVal = code;
	}
    }

    return retVal;
}

static void
SetUpResize(void)
{
    struct cmd_syndesc *setsizeSyntax;

    setsizeSyntax =
	cmd_CreateSyntax("setlog", DoResize, NULL, 0,
			 "set the size of a log");
    (void)cmd_AddParm(setsizeSyntax, "-log", CMD_LIST, CMD_OPTIONAL,
		      "trace log name");
    (void)cmd_AddParm(setsizeSyntax, "-buffersize", CMD_SINGLE, CMD_REQUIRED,
		      "# of 1-kbyte blocks to allocate for log");
}

#include "AFS_component_version_number.c"

int
main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");
#ifdef AFS_SGI62_ENV
    set_kernel_sizeof_long();
#endif

    /* set up user interface then dispatch */
    SetUpDump();
    SetUpShowLog();
    SetUpShowSet();
    SetUpClear();
    SetUpSet();
    SetUpResize();

    return (cmd_Dispatch(argc, argv));
}

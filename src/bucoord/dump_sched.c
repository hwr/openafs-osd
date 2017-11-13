/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
 * ALL RIGHTS RESERVED
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <afs/ktime.h>
#include <afs/budb_client.h>
#include <afs/cmd.h>
#include <afs/com_err.h>
#include <afs/bubasics.h>

#include "bc.h"
#include "error_macros.h"
#include "bucoord_internal.h"
#include "bucoord_prototypes.h"

/* code to manage dump schedules
 * specific to the ubik database implementation
 */

extern struct bc_config *bc_globalConfig;
extern struct udbHandleS udbHandle;
extern char *whoami;

static int ListDumpSchedule(struct bc_dumpSchedule *adump, int alevel);

/* ------------------------------------
 * command level routines
 * ------------------------------------
 */

/* bc_AddDumpCmd
 *	add a dump schedule
 * params:
 *	parm 0: list of dump names
 *	parm 1: expiration date (list)
 */

int
bc_AddDumpCmd(struct cmd_syndesc *as, void *arock)
{
    char *dname;	/* dump schedule name */
    int code;
    afs_int32 expType, expDate;
    struct cmd_item *ti;
    udbClientTextP ctPtr;

    /* if an expiration date has been specified */
    if (as->parms[1].items) {
	code = bc_ParseExpiration(&as->parms[1], &expType, &expDate);
	if (code) {
	    printf("Invalid expiration date syntax\n");
	    return (1);
	}
    } else {
	/* no expiration date specified */
	expDate = 0;
	expType = BC_NO_EXPDATE;
    }

    /* lock schedules and check validity */
    ctPtr = &bc_globalConfig->configText[TB_DUMPSCHEDULE];

    code = bc_LockText(ctPtr);
    if (code)
	ERROR(code);

    code = bc_UpdateDumpSchedule();
    if (code) {
	afs_com_err(whoami, code, "; Can't retrieve dump schedule");
	return (code);
    }

    /* process each dump name using the expiration date computed above */
    for (ti = as->parms[0].items; ti != 0; ti = ti->next) {
	/* get next dump name to process */
	dname = ti->data;

	/* validate the name dump name length */
	if (strlen(dname) >= BU_MAX_DUMP_PATH) {
	    afs_com_err(whoami, 0, "Dump names must be < %d characters",
		    BU_MAX_DUMP_PATH);
	    afs_com_err(whoami, 0, "Dump %s not added", dname);
	    code = -1;
	    continue;
	}

	code =
	    bc_CreateDumpSchedule(bc_globalConfig, dname, expDate, expType);
	if (code) {
	    if (code == -1)
		afs_com_err(whoami, 0, "Dump already exists");
	    else if (code == -2)
		afs_com_err(whoami, 0, "Invalid path name '%s'", dname);
	    else if (code == -3)
		afs_com_err(whoami, 0, "Name specification error");
	    else
		afs_com_err(whoami, code, "; Failed to create dump schedule");
	    continue;
	}

	/* save the new schedule item */
	code = bc_SaveDumpSchedule();
	if (code) {
	    afs_com_err(whoami, code, "Cannot save dump schedule");
	    afs_com_err(whoami, 0,
		    "Changes are temporary - for this session only");
	    break;
	}

	afs_com_err(whoami, 0, "Created new dump schedule %s", dname);
    }

  error_exit:
    if (ctPtr->lockHandle)
	bc_UnlockText(ctPtr);
    return (code);
}


/* bc_DeleteDumpCmd
 *	delete a dump schedule
 */

int
bc_DeleteDumpCmd(struct cmd_syndesc *as, void *arock)
{
    /* parm 0 is vol set name
     * parm 1 is dump schedule name
     */
    char *dname;
    int code;
    udbClientTextP ctPtr;

    /* lock schedules and check validity */
    ctPtr = &bc_globalConfig->configText[TB_DUMPSCHEDULE];

    code = bc_LockText(ctPtr);
    if (code)
	ERROR(code);

    code = bc_UpdateDumpSchedule();
    if (code) {
	afs_com_err(whoami, code, "; Can't retrieve dump schedule");
	return (code);
    }

    dname = as->parms[0].items->data;

    code = bc_DeleteDumpSchedule(bc_globalConfig, dname);
    if (code) {
	if (code == -1)
	    afs_com_err(whoami, 0, "No such dump as %s", dname);
	else
	    afs_com_err(whoami, code, "; Failed to delete dump schedule");
	goto error_exit;
    }

    code = bc_SaveDumpSchedule();
    if (code == 0)
	printf("backup: deleted dump schedule %s\n", dname);
    else {
	afs_com_err(whoami, code, "Cannot save dump schedule file");
	afs_com_err(whoami, 0, "Deletion is temporary - for this session only");
    }

  error_exit:
    if (ctPtr->lockHandle != 0)
	bc_UnlockText(ctPtr);
    return code;
}

/* ListDumpSchedule
 *	Print out the dump schedule tree whose root is adump. Alevel should
 *	be passed in as 0, and is incremented for the recursive calls
 * entry:
 *	adump - ptr to the root node of a dump schedule
 *	alevel - 0
 */

static int
ListDumpSchedule(struct bc_dumpSchedule *adump, int alevel)
{
    int i;
    struct bc_dumpSchedule *child;

    /* sanity check for loops */
    if (alevel > 100) {
	printf("backup: recursing listing dump schedule\n");
	return -1;
    }

    /* move to appropriate indentation level */
    for (i = 0; i < alevel; i++)
	printf("    ");

    /* name is a pathname style name, determine trailing name and only print
     * it
     */

    printf("/%s ", tailCompPtr(adump->name));


    /* list expiration time */
    switch (adump->expType) {
    case BC_ABS_EXPDATE:
	/* absolute expiration date. Never expires if date is 0 */
	if (adump->expDate) {
            time_t t = adump->expDate;
	    printf("expires at %.24s", cTIME(&t));
	}
	break;

    case BC_REL_EXPDATE:
	{
	    struct ktime_date kt;

	    /* expiration date relative to the time that the dump is done */
	    LongTo_ktimeRelDate(adump->expDate, &kt);
	    printf(" expires in %s", RelDatetoString(&kt));
	}
	break;

    default:
	break;
    }
    printf("\n");
    for (child = adump->firstChild; child; child = child->nextSibling)
	ListDumpSchedule(child, alevel + 1);

    return 0;
}

/* bc_ListDumpScheduleCmd
 *      list the (internally held) dump schedule tree
 * parameters:
 *      ignored
 */

int
bc_ListDumpScheduleCmd(struct cmd_syndesc *as, void *arock)
{
    /* no parms */
    int code;
    struct bc_dumpSchedule *tdump;

    /* first check to see if schedules must be updated */
    code = bc_UpdateDumpSchedule();
    if (code) {
	afs_com_err(whoami, code, "; Can't retrieve dump schedule");
	return (code);
    }

    /* go through entire list, displaying trees for root-level dump
     * schedules
     */
    for (tdump = bc_globalConfig->dsched; tdump; tdump = tdump->next) {
	/* if this is a root-level dump, show it and its kids */
	if (!tdump->parent)
	    ListDumpSchedule(tdump, 0);
    }
    return 0;
}


/* bc_SetExpCmd
 *	Set/clear expiration date on existing dump node
 * params:
 *	parm 0: list of dump names
 *	parm 1: expiration date (list)
 */

int
bc_SetExpCmd(struct cmd_syndesc *as, void *arock)
{
    char *dname;	/* dump schedule name */
    struct cmd_item *ti;
    struct bc_dumpSchedule *node, *parent;
    afs_int32 expType, expDate;
    udbClientTextP ctPtr;
    int code;

    /* if an expiration date has been specified */
    if (as->parms[1].items) {
	code = bc_ParseExpiration(&as->parms[1], &expType, &expDate);
	if (code) {
	    printf("Invalid expiration date syntax\n");
	    return (1);
	}
    } else {
	/* no expiration date specified */
	expDate = 0;
	expType = BC_NO_EXPDATE;
    }

    /* lock schedules and check validity */
    ctPtr = &bc_globalConfig->configText[TB_DUMPSCHEDULE];

    code = bc_LockText(ctPtr);
    if (code)
	ERROR(code);

    code = bc_UpdateDumpSchedule();
    if (code) {
	afs_com_err(whoami, code, "; Can't retrieve dump schedule");
	return (code);
    }

    /* process each dump name using the expiration date computed above */
    for (ti = as->parms[0].items; ti != 0; ti = ti->next) {
	/* get next dump name to process */
	dname = ti->data;

	/* validate the name dump name length */
	if (strlen(dname) >= BU_MAX_DUMP_PATH) {
	    code = -1;
	    afs_com_err(whoami, 0, "Dump names must be < %d characters",
		    BU_MAX_DUMP_PATH);
	    afs_com_err(whoami, 0, "Dump %s not added", dname);
	    continue;
	}

	code = FindDump(bc_globalConfig, dname, &parent, &node);
	if (code) {
	    afs_com_err(whoami, 0, "Dump level %s not found", dname);
	    continue;
	}

	node->expDate = expDate;
	node->expType = expType;
    }

    code = bc_SaveDumpSchedule();
    if (code) {
	afs_com_err(whoami, code, "Cannot save dump schedule");
	afs_com_err(whoami, 0,
		"Expiration changes effective for this session only");
    }

  error_exit:
    if (ctPtr->lockHandle)
	bc_UnlockText(ctPtr);
    return (code);
}



/* ------------------------------------
 * general dump schedule handling routines
 * ------------------------------------
 */

int
bc_ParseDumpSchedule(void)
{
    char tbuffer[1024];
    char dsname[256], period[64];
    char *tp;
    afs_int32 code;
    udbClientTextP ctPtr;
    struct bc_dumpSchedule *tds;
    struct bc_dumpSchedule **ppds, *pds;
    afs_int32 expDate, expType;

    FILE *stream;

    /* initialize locally used variables */
    ctPtr = &bc_globalConfig->configText[TB_DUMPSCHEDULE];
    stream = ctPtr->textStream;

    if (ctPtr->textSize == 0)	/* nothing defined yet */
	return (0);

    if (stream == NULL)
	return (BC_INTERNALERROR);

    rewind(stream);

    /* check the magic number and version */
    tp = fgets(tbuffer, sizeof(tbuffer), stream);
    if (tp == 0)
	/* can't read first line - error */
	return (BC_INTERNALERROR);
    else {
	afs_int32 dsmagic, dsversion;

	/* read the first line, and then check magic # and version */

	code = sscanf(tbuffer, "%d %d", &dsmagic, &dsversion);
	if ((code != 2)
	    || (dsmagic != BC_SCHEDULE_MAGIC)
	    || (dsversion != BC_SCHEDULE_VERSION)
	    ) {
	    /* invalid or unexpected header - error */
	    afs_com_err(whoami, 0, "Unable to understand dump schedule file");
	    return (BC_INTERNALERROR);
	}
    }

    while (1) {
	/* read all of the lines out */
	tp = fgets(tbuffer, sizeof(tbuffer), stream);
	if (tp == 0)
	    break;		/* hit eof? */
	code =
	    sscanf(tbuffer, "%s %s %d %d", dsname, period, &expDate,
		   &expType);
	if (code != 4) {
	    afs_com_err(whoami, 0,
		    "Syntax error in dump schedule file, line is: %s",
		    tbuffer);
	    return (BC_INTERNALERROR);
	}
	tds = calloc(1, sizeof(struct bc_dumpSchedule));

	tds->next = (struct bc_dumpSchedule *)0;
	tds->name = strdup(dsname);

	tds->expDate = expDate;
	tds->expType = expType;

	/* find the end of the schedule list, and append the new item to it */
	ppds = &bc_globalConfig->dsched;
	pds = *ppds;
	while (pds != 0) {
	    ppds = &pds->next;
	    pds = *ppds;
	}
	*ppds = tds;
    }
    return 0;
}

int
bc_SaveDumpSchedule(void)
{
    struct bc_dumpSchedule *tdump;
    udbClientTextP ctPtr;
    afs_int32 code = 0;

    extern struct bc_config *bc_globalConfig;

    /* setup the right ptr */
    ctPtr = &bc_globalConfig->configText[TB_DUMPSCHEDULE];

    /* must be locked */
    if (ctPtr->lockHandle == 0)
	return (BC_INTERNALERROR);

    /* truncate the file */
    code = ftruncate(fileno(ctPtr->textStream), 0);
    if (code)
	ERROR(errno);

    rewind(ctPtr->textStream);

    /* write the new information */
    fprintf(ctPtr->textStream, "%d %d\n", BC_SCHEDULE_MAGIC,
	    BC_SCHEDULE_VERSION);

    for (tdump = bc_globalConfig->dsched; tdump; tdump = tdump->next) {
	fprintf(ctPtr->textStream, "%s %s %d %d\n", tdump->name, "any",
		tdump->expDate, tdump->expType);
    }

    if (ferror(ctPtr->textStream))
	return (BC_INTERNALERROR);

    fflush(ctPtr->textStream);	/* debug */

    /* send to server */
    code = bcdb_SaveTextFile(ctPtr);
    if (code)
	ERROR(code);

    /* increment local version number */
    ctPtr->textVersion++;

    /* update locally stored file size */
    ctPtr->textSize = filesize(ctPtr->textStream);
  error_exit:
    return (code);
}


/* ------------------------------------
 * misc. support routines - specific to dump schedules
 * ------------------------------------
 */

afs_int32
bc_UpdateDumpSchedule(void)
{
    struct bc_dumpSchedule *dumpPtr, *nextDumpPtr;
    struct udbHandleS *uhptr = &udbHandle;
    udbClientTextP ctPtr;
    afs_int32 code;
    int lock = 0;

    /* lock schedules and check validity */
    ctPtr = &bc_globalConfig->configText[TB_DUMPSCHEDULE];

    code = bc_CheckTextVersion(ctPtr);
    if (code != BC_VERSIONMISMATCH) {
	ERROR(code);		/* Version matches or some other error */
    }

    /* Must update the dump schedules */
    /* If we are not already locked, then lock it now */
    if (!ctPtr->lockHandle) {
	code = bc_LockText(ctPtr);
	if (code)
	    ERROR(code);
	lock = 1;
    }

    if (ctPtr->textVersion != -1) {
	printf("backup: obsolete dump schedule - updating\n");

	/* clear all old schedule information */
	dumpPtr = bc_globalConfig->dsched;
	while (dumpPtr) {
	    nextDumpPtr = dumpPtr->next;
	    free(dumpPtr);
	    dumpPtr = nextDumpPtr;
	}
	bc_globalConfig->dsched = 0;;
    }

    /* open a temp file to store the config text received from buserver *
     * The open file stream is stored in ctPtr->textStream */
    code =
	bc_openTextFile(ctPtr,
			&bc_globalConfig->
			tmpTextFileNames[TB_DUMPSCHEDULE][0]);
    if (code)
	ERROR(code);
    /* now get a fresh set of information from the database */
    code = bcdb_GetTextFile(ctPtr);
    if (code)
	ERROR(code);

    /* fetch the version number */
    code =
	ubik_BUDB_GetTextVersion(uhptr->uh_client, 0, ctPtr->textType,
		  &ctPtr->textVersion);
    if (code)
	ERROR(code);

    /* parse the file */
    code = bc_ParseDumpSchedule();
    if (code)
	ERROR(code);

    /* rebuild the tree */
    code = bc_ProcessDumpSchedule(bc_globalConfig);
    if (code)
	ERROR(code);

  error_exit:
    if (lock && ctPtr->lockHandle)
	bc_UnlockText(ctPtr);
    return (code);
}


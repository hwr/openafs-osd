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
#include <afs/stds.h>

#include <roken.h>

#include <afs/budb_client.h>
#include <afs/cmd.h>
#include <afs/com_err.h>
#include <afs/bubasics.h>

#include "bc.h"
#include "error_macros.h"
#include "bucoord_internal.h"
#include "bucoord_prototypes.h"

/* code to manage volumesets
 * specific to the ubik database implementation
 */

extern struct bc_config *bc_globalConfig;
extern struct udbHandleS udbHandle;
extern char *whoami;

static int ListVolSet(struct bc_volumeSet *aset);

/* ------------------------------------
 * command level routines
 * ------------------------------------
 */


/* bc_AddVolEntryCmd
 * 	add a volume (or volume expression) to a volume set
 * params:
 *	parm 0 is vol set name.
 *	parm 1 is server name
 *	parm 2 is partition name
 *	parm 3 is volume regexp
 */

int
bc_AddVolEntryCmd(struct cmd_syndesc *as, void *arock)
{
    int code;
    char *volSetName, *serverName, *partitionName, *volRegExp;
    udbClientTextP ctPtr;
    struct bc_volumeSet *tset;

    volSetName = as->parms[0].items->data;
    serverName = as->parms[1].items->data;
    partitionName = as->parms[2].items->data;
    volRegExp = as->parms[3].items->data;

    code = bc_UpdateVolumeSet();
    if (code) {
	afs_com_err(whoami, code, "; Can't retrieve volume sets");
	return (code);
    }

    ctPtr = &bc_globalConfig->configText[TB_VOLUMESET];

    tset = bc_FindVolumeSet(bc_globalConfig, volSetName);
    if (!tset) {
	afs_com_err(whoami, code, "; Volume entry not added");
	ERROR(code);
    }

    if (!(tset->flags & VSFLAG_TEMPORARY)) {
	code = bc_LockText(ctPtr);
	if (code)
	    ERROR(code);
    }

    code = bc_UpdateVolumeSet();
    if (code) {
	afs_com_err(whoami, code, "; Can't retrieve volume sets");
	return (code);
    }

    code =
	bc_AddVolumeItem(bc_globalConfig, volSetName, serverName,
			 partitionName, volRegExp);
    if (code) {
	afs_com_err(whoami, code, "; Volume entry not added");
	ERROR(code);
    }

    if (!(tset->flags & VSFLAG_TEMPORARY)) {
	code = bc_SaveVolumeSet();
	if (code) {
	    afs_com_err(whoami, code, "Cannot save volume set file");
	    afs_com_err(whoami, 0,
		    "Changes are temporary - for this session only");
	}
    }

  error_exit:
    if (ctPtr->lockHandle)
	bc_UnlockText(ctPtr);
    return (code);
}



/* bc_AddVolSetCmd
 *	create a new volume set, writing out the new volumeset
 *	file in a safe manner
 * params:
 *	name of new volume set
 */

int
bc_AddVolSetCmd(struct cmd_syndesc *as, void *arock)
{
    /* parm 0 is vol set name */
    int code;
    struct cmd_item *ti;
    udbClientTextP ctPtr;
    afs_int32 flags;

    /* lock schedules and check validity */
    ctPtr = &bc_globalConfig->configText[TB_VOLUMESET];

    flags = (as->parms[1].items ? VSFLAG_TEMPORARY : 0);

    /* Don't lock if adding a temporary volumeset */
    if (!(flags & VSFLAG_TEMPORARY)) {
	code = bc_LockText(ctPtr);
	if (code)
	    ERROR(code);
    }

    code = bc_UpdateVolumeSet();
    if (code) {
	afs_com_err(whoami, code, "; Can't retrieve volume sets");
	return (code);
    }

    /* validate size of volumeset name */
    code =
	bc_CreateVolumeSet(bc_globalConfig, (ti = as->parms[0].items)->data,
			   flags);
    if (code) {
	if (code == -1)
	    afs_com_err(whoami, 0, "Volume set '%s' already exists", ti->data);
	else
	    afs_com_err(whoami, 0, "Unknown problem");
    } else if (!(flags & VSFLAG_TEMPORARY)) {
	code = bc_SaveVolumeSet();
	if (code) {
	    afs_com_err(whoami, code, "Cannot save new volume set file");
	    afs_com_err(whoami, 0,
		    "Changes are temporary - for this session only");
	}
    }

  error_exit:
    if (ctPtr->lockHandle != 0)
	bc_UnlockText(ctPtr);
    return (code);
}


/* bc_DeleteVolEntryCmd
 *	delete a volume specification from a volume set
 * params:
 *	parm 0 is vol set name
 *	parm 1 is entry # (integer, 1 based)
 */

int
bc_DeleteVolEntryCmd(struct cmd_syndesc *as, void *arock)
{
    int code;
    afs_int32 entry;
    char *vsname;
    udbClientTextP ctPtr;
    struct bc_volumeSet *tset;

    vsname = as->parms[0].items->data;

    code = bc_UpdateVolumeSet();
    if (code) {
	afs_com_err(whoami, code, "; Can't retrieve volume sets");
	return (code);
    }

    /* lock schedules and check validity */
    ctPtr = &bc_globalConfig->configText[TB_VOLUMESET];

    tset = bc_FindVolumeSet(bc_globalConfig, vsname);
    if (!tset) {
	afs_com_err(whoami, 0, "No such volume set as '%s'", vsname);
	ERROR(code);
    }

    if (!(tset->flags & VSFLAG_TEMPORARY)) {
	code = bc_LockText(ctPtr);
	if (code)
	    ERROR(code);
    }

    code = bc_UpdateVolumeSet();
    if (code) {
	afs_com_err(whoami, code, "; Can't retrieve volume sets");
	return (code);
    }

    entry = bc_SafeATOI(as->parms[1].items->data);
    if (entry < 0) {
	afs_com_err(whoami, 0, "Can't parse entry number '%s' as decimal integer",
		as->parms[1].items->data);
	ERROR(BC_BADARG);
    }

    code = bc_DeleteVolumeItem(bc_globalConfig, vsname, entry);
    if (code) {
	if (code == -1) {
	    afs_com_err(whoami, 0, "No such volume set as '%s'", vsname);
	} else if (code == -2) {
	    afs_com_err(whoami, 0,
		    "There aren't %d volume items for this volume set",
		    entry);
	    afs_com_err(whoami, 0,
		    "Use the 'listvolsets' command to examine the volume set");
	}
	ERROR(code);
    }

    if (!(tset->flags & VSFLAG_TEMPORARY)) {
	code = bc_SaveVolumeSet();
	if (code == 0) {
	    printf("backup: deleted volume entry %d from volume set %s\n",
		   entry, vsname);
	} else {
	    afs_com_err(whoami, code, "Cannot save volume set file");
	    afs_com_err(whoami, 0,
		    "Deletion is temporary - for this session only");
	}
    }

  error_exit:
    if (ctPtr->lockHandle != 0)
	bc_UnlockText(ctPtr);
    return (code);
}




/* bc_DeleteVolSetCmd
 *	delete a volume set, writing out a new configuration file when
 *	completed
 * params:
 *	name of volumeset to delete
 */

int
bc_DeleteVolSetCmd(struct cmd_syndesc *as, void *arock)
{
    /* parm 0 is vol set name */
    int code;
    struct cmd_item *ti;
    udbClientTextP ctPtr;
    afs_int32 c;
    afs_int32 flags, tosave = 0;

    /* lock schedules and check validity */
    ctPtr = &bc_globalConfig->configText[TB_VOLUMESET];

    code = bc_LockText(ctPtr);
    if (code)
	ERROR(code);

    code = bc_UpdateVolumeSet();
    if (code) {
	afs_com_err(whoami, code, "; Can't retrieve volume sets");
	return (code);
    }

    for (ti = as->parms[0].items; ti; ti = ti->next) {
	code = bc_DeleteVolumeSet(bc_globalConfig, ti->data, &flags);
	if (code) {
	    if (code == -1)
		afs_com_err(whoami, 0, "Can't find volume set '%s'", ti->data);
	    else
		afs_com_err(whoami, code,
			"; Unknown problem deleting volume set '%s'",
			ti->data);
	} else {
	    if (!(flags & VSFLAG_TEMPORARY))
		tosave = 1;
	    printf("backup: deleted volume set '%s'\n", ti->data);
	}
    }

    /* now write out the file */
    if (tosave) {
	c = bc_SaveVolumeSet();
	if (c) {
	    if (!code)
		code = c;
	    afs_com_err(whoami, c, "Cannot save updated volume set file");
	    afs_com_err(whoami, 0, "Deletion effective for this session only");
	}

    }

  error_exit:
    if (ctPtr->lockHandle)
	bc_UnlockText(ctPtr);
    return (code);
}


static int
ListVolSet(struct bc_volumeSet *aset)
{
    struct bc_volumeEntry *tentry;
    int i;

    printf("Volume set %s", aset->name);
    if (aset->flags & VSFLAG_TEMPORARY)
	printf(" (temporary)");
    printf(":\n");
    i = 1;
    for (tentry = aset->ventries; tentry; tentry = tentry->next, i++) {
	printf("    Entry %3d: server %s, partition %s, volumes: %s\n", i,
	       tentry->serverName, tentry->partname, tentry->name);
    }
    return 0;
}

 /* bc_ListVolSetCmd
  *     list out all the information (?) about a volumeset or about all
  *     volumesets
  * entry:
  *     optional parameter specifies a volumeset name
  */

int
bc_ListVolSetCmd(struct cmd_syndesc *as, void *arock)
{
    /* parm 0 is optional volume set to display */
    struct bc_volumeSet *tset;
    struct cmd_item *ti;
    int code = 0;

    code = bc_UpdateVolumeSet();
    if (code) {
	afs_com_err(whoami, code, "; Can't retrieve volume sets");
	return (code);
    }

    /* figure out volume set to list */
    if ((ti = as->parms[0].items)) {
	/* for each volume set in the command item list */
	for (; ti; ti = ti->next) {
	    tset = bc_FindVolumeSet(bc_globalConfig, ti->data);
	    if (tset) {
		ListVolSet(tset);
		printf("\n");
	    } else {
		afs_com_err(whoami, 0, "Can't find volume set '%s'", ti->data);
		code = 1;
	    }
	}
    } else {
	/* no command parameters specified, show entire list */
	for (tset = bc_globalConfig->vset; tset; tset = tset->next) {
	    ListVolSet(tset);
	    printf("\n");
	}
    }

    return code;
}



/* ------------------------------------
 * support routines
 * ------------------------------------
 */

int
bc_ClearVolumeSets(void)
{
    struct bc_volumeSet *vsPtr, *vsNextPtr, **vsPrev;

    extern struct bc_config *bc_globalConfig;

    vsPrev = &(bc_globalConfig->vset);
    for (vsPtr = bc_globalConfig->vset; vsPtr; vsPtr = vsNextPtr) {
	vsNextPtr = vsPtr->next;

	if (vsPtr->flags & VSFLAG_TEMPORARY) {	/* Skip temporary volumeSet */
	    vsPrev = &(vsPtr->next);
	    continue;
	}

	*vsPrev = vsPtr->next;	/* Remove volumeSet from the chain */
	FreeVolumeSet(vsPtr);
    }
    return (0);
}

/* bc_ParseVolumeSet
 *	Open up the volume set configuration file as specified in our argument,
 *	then parse the file to set up our internal representation.
 * exit:
 *	0 on successful processing,
 *	-1 otherwise.
 */

int
bc_ParseVolumeSet(void)
{
    char tbuffer[1024];		/*Buffer for reading config file */
    char vsname[256];		/*Volume set name */
    char serverName[256];	/*Server name */
    char partName[256];		/*Partition name */
    struct bc_volumeEntry *tve;	/*Ptr to generated volume spec struct */
    struct bc_volumeSet *tvs = NULL;	/*Ptr to volume set struct */
    struct bc_volumeEntry **ppve, *pve;
    struct bc_volumeSet **ppvs, *pvs;
    afs_int32 code;	/*Generalized return code */
    char *tp;			/*Result of fgets(), malloc() */
    int readHeader;		/*Is next thing to read a volume set hdr? */

    udbClientTextP ctPtr;
    FILE *stream;

    extern struct bc_config *bc_globalConfig;

    ctPtr = &bc_globalConfig->configText[TB_VOLUMESET];
    stream = ctPtr->textStream;

    /*
     * Open up the volume set configuration file, fail if it can't be done.
     */

    if (ctPtr->textSize == 0)	/* empty is ok */
	return (0);

    /* stream checks and initialization */
    if (stream == NULL)
	return (BC_INTERNALERROR);

    rewind(stream);

    readHeader = 1;
    while (1) {
	/* Read in and process the next line of the volume set description
	 * file.
	 */
	tp = fgets(tbuffer, sizeof(tbuffer), stream);
	if (!tp)
	    break;
	if (readHeader) {	/*r */
	    /*
	     * Scan a header entry.
	     */
	    readHeader = 0;
	    code = sscanf(tbuffer, "%s %s", serverName, vsname);
	    if ((code != 2)
		|| (strcmp(serverName, "volumeset") != 0)
		) {
		afs_com_err(whoami, 0, "Bad volume header line: '%s'", tbuffer);
		return (-1);
	    }

	    /* Create and fill in the volume set descriptor structure from
	     * the info just read placing it at the head of its queue in the
	     * global configuration structure.
	     */
	    tvs = calloc(1, sizeof(struct bc_volumeSet));
	    tvs->name = strdup(vsname);

	    /* append to the end */
	    for (ppvs = &bc_globalConfig->vset, pvs = *ppvs; pvs;
		 ppvs = &pvs->next, pvs = *ppvs);
	    *ppvs = tvs;
	    tvs->next = (struct bc_volumeSet *)0;
	} /*r */
	else {			/*e */
	    /* Scan a volume name entry, which contains the server name,
	     * partition pattern, and volume pattern.
	     */
	    code = sscanf(tbuffer, "%s %s %s", serverName, partName, vsname);
	    if (code == 1 && strcmp(serverName, "end") == 0) {
		/* This was really a line delimiting the current volume set.
		 * Next time around, we should try to read a header.
		 */
		readHeader = 1;
		continue;
	    }

	    /* The line just read in is a volume spec.  Create a new volume
	     * spec record, then get the rest of the information regarding
	     * the host, and stuff everything into place.
	     */
	    tve = calloc(1, sizeof(struct bc_volumeEntry));
	    if (!tve) {
		afs_com_err(whoami, 0,
			"Can't malloc() a new volume spec record!");
		return (-1);
	    }
	    if (bc_ParseHost(serverName, &(tve->server)))
		afs_com_err(whoami, 0, "Can't get required info on host '%s'",
			serverName);

	    /* The above code has filled in the server sockaddr, now fill in
	     * the rest of the fields.
	     */
	    tve->serverName = strdup(serverName);
	    if (!tve->serverName) {
		afs_com_err(whoami, 0,
			"Can't malloc() a new volume spec server name field!");
		return (-1);
	    }
	    tve->partname = strdup(partName);
	    if (!tve->partname) {
		afs_com_err(whoami, 0,
			"Can't malloc() a new volume spec partition pattern field!");
		return (-1);
	    }
	    code = bc_GetPartitionID(partName, &tve->partition);
	    if (code) {
		afs_com_err(whoami, 0, "Can't parse partition '%s'", partName);
		return -1;
	    }
	    tp = strdup(vsname);
	    if (!tp) {
		afs_com_err(whoami, 0,
			"Can't malloc() a new volume spec volume pattern field!");
		return (-1);
	    }
	    tve->name = tp;

	    /* Now, thread it onto the list of other volume spec entries for
	     * the current volume set.
	     */

	    for (ppve = &tvs->ventries, pve = *ppve; pve;
		 ppve = &pve->next, pve = *ppve);
	    *ppve = tve;
	    tve->next = (struct bc_volumeEntry *)0;
	}
    }				/*forever loop */

    /* If we hit an EOF in the middle of a volume set record, we bitch and
     * moan.
     */
    if (!readHeader)
	return (-1);

    /*
     * Well, we did it.  Return successfully.
     */
    return (0);

}				/*bc_ParseVolumeSet */

/* bc_SaveVolumeSet
 *	save the current volume set information to disk
 */

int
bc_SaveVolumeSet(void)
{
    afs_int32 code = 0;
    struct bc_volumeSet *tset;
    struct bc_volumeEntry *tentry;

    udbClientTextP ctPtr;
    FILE *stream;

    extern struct bc_config *bc_globalConfig;

    ctPtr = &bc_globalConfig->configText[TB_VOLUMESET];
    stream = ctPtr->textStream;

    /* must be locked */
    if (ctPtr->lockHandle == 0)
	return (BC_INTERNALERROR);

    /* truncate the file */
    code = ftruncate(fileno(stream), 0);
    if (code)
	ERROR(errno);

    rewind(stream);

    /* now write the volumeset information */

    for (tset = bc_globalConfig->vset; tset != 0; tset = tset->next) {
	if (tset->flags & VSFLAG_TEMPORARY)
	    continue;		/* skip temporary entries */

	fprintf(stream, "volumeset %s\n", tset->name);
	for (tentry = tset->ventries; tentry; tentry = tentry->next) {
	    fprintf(stream, "%s %s %s\n", tentry->serverName,
		    tentry->partname, tentry->name);
	}
	fprintf(stream, "end\n");
    }

    if (ferror(stream))
	return (BC_INTERNALERROR);

    /* send to server */
    code = bcdb_SaveTextFile(ctPtr);
    if (code)
	ERROR(code);

    /* do this on bcdb_SaveTextFile */
    /* increment local version number */
    ctPtr->textVersion++;

    /* update locally stored file size */
    ctPtr->textSize = filesize(ctPtr->textStream);

  error_exit:
    return (code);
}

afs_int32
bc_UpdateVolumeSet(void)
{
    struct udbHandleS *uhptr = &udbHandle;
    udbClientTextP ctPtr;
    afs_int32 code;
    int lock = 0;

    /* lock schedules and check validity */
    ctPtr = &bc_globalConfig->configText[TB_VOLUMESET];

    /* Don't need a lock to check the version */
    code = bc_CheckTextVersion(ctPtr);
    if (code != BC_VERSIONMISMATCH) {
	ERROR(code);		/* version matches or some other error */
    }

    /* Must update the volume sets */
    /* If no lock alredy taken, then lock it */
    if (ctPtr->lockHandle == 0) {
	code = bc_LockText(ctPtr);
	if (code)
	    ERROR(code);
	lock = 1;
    }

    if (ctPtr->textVersion != -1) {
	printf("backup: obsolete volumesets - updating\n");
	bc_ClearVolumeSets();
    }

    /* open a temp file to store the config text received from buserver *
     * The open file stream is stored in ctPtr->textStream */
    code =
	bc_openTextFile(ctPtr,
			&bc_globalConfig->tmpTextFileNames[TB_VOLUMESET][0]);
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
    code = bc_ParseVolumeSet();
    if (code)
	ERROR(code);

  error_exit:
    if (lock && ctPtr->lockHandle)
	bc_UnlockText(ctPtr);
    return (code);
}

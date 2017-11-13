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

#include <lwp.h>

#include "gtxobjects.h"
#include "gtxwindows.h"
#include "gtxcurseswin.h"
#include "gtxinput.h"
#include "gtxkeymap.h"
#include "gtxframe.h"

static struct keymap_map *recursiveMap = 0;
static char menubuffer[1024];	/*Buffer for menu selections */
int gtxframe_exitValue = 0;	/*Program exit value */

int
gtxframe_CtrlUCmd(void *aparam, void *arock)
{
    struct gwin *awindow = (struct gwin *) aparam;
    struct gtx_frame *tframe;

    tframe = awindow->w_frame;
    if (!tframe->defaultLine)
	return -1;
    *(tframe->defaultLine) = 0;
    return 0;
}

int
gtxframe_CtrlHCmd(void *aparam, void *arock)
{
    struct gwin *awindow = (struct gwin *) aparam;

    struct gtx_frame *tframe;
    char *tp;
    int pos;

    tframe = awindow->w_frame;
    if (!(tp = tframe->defaultLine))
	return -1;
    pos = strlen(tp);
    if (pos == 0)
	return 0;		/* rubout at the end of the line */
    tp[pos - 1] = 0;
    return 0;
}

int
gtxframe_RecursiveEndCmd(void *aparam, void *arock)
{
    struct gwin *awindow = (struct gwin *) aparam;

    struct gtx_frame *tframe;

    tframe = awindow->w_frame;
    tframe->flags |= GTXFRAME_RECURSIVEEND;
    tframe->flags &= ~GTXFRAME_RECURSIVEERR;
    return 0;
}

int
gtxframe_RecursiveErrCmd(void *aparam, void *arock)
{
    struct gwin *awindow = (struct gwin *) aparam;

    struct gtx_frame *tframe;

    tframe = awindow->w_frame;
    tframe->flags |= GTXFRAME_RECURSIVEEND;
    tframe->flags |= GTXFRAME_RECURSIVEERR;
    return 0;
}

int
gtxframe_SelfInsertCmd(void *aparam, void *rockparam)
{
    struct gwin *awindow = (struct gwin *) aparam;

    int arock = (intptr_t)rockparam;

    struct gtx_frame *tframe;
    int pos;
    char *tp;

    tframe = awindow->w_frame;
    if (!(tp = tframe->defaultLine))
	return -1;
    pos = strlen(tp);
    tp[pos] = arock;		/* arock has char to insert */
    tp[pos + 1] = 0;		/* null-terminate it, too */
    return 0;
}

/* save map, setup recursive map and install it */
static int
SaveMap(struct gtx_frame *aframe)
{
    char tstring[2];
    int i;

    if (!recursiveMap) {
	/* setup recursive edit map if not previously done */
	recursiveMap = keymap_Create();
	keymap_BindToString(recursiveMap, "\010", gtxframe_CtrlHCmd, NULL,
			    NULL);
	keymap_BindToString(recursiveMap, "\177", gtxframe_CtrlHCmd, NULL,
			    NULL);
	keymap_BindToString(recursiveMap, "\025", gtxframe_CtrlUCmd, NULL,
			    NULL);
	keymap_BindToString(recursiveMap, "\033", gtxframe_RecursiveEndCmd,
			    NULL, NULL);
	keymap_BindToString(recursiveMap, "\015", gtxframe_RecursiveEndCmd,
			    NULL, NULL);
	keymap_BindToString(recursiveMap, "\012", gtxframe_RecursiveEndCmd,
			    NULL, NULL);
	keymap_BindToString(recursiveMap, "\003", gtxframe_RecursiveErrCmd,
			    NULL, NULL);
	keymap_BindToString(recursiveMap, "\007", gtxframe_RecursiveErrCmd,
			    NULL, NULL);

	for (i = 040; i < 0177; i++) {
	    tstring[0] = i;
	    tstring[1] = 0;
	    keymap_BindToString(recursiveMap, tstring, gtxframe_SelfInsertCmd,
				NULL, (void *)(intptr_t)i);
	}
    }
    aframe->savemap = aframe->keymap;
    aframe->keymap = recursiveMap;
    keymap_InitState(aframe->keystate, aframe->keymap);
    return 0;
}

/* Restore map to previous value */
static int
RestoreMap(struct gtx_frame *aframe)
{
    aframe->keymap = aframe->savemap;
    aframe->savemap = (struct keymap_map *)0;
    keymap_InitState(aframe->keystate, aframe->keymap);
    return 0;
}

int
gtxframe_SetFrame(struct gwin *awin, struct gtx_frame *aframe)
{
    if (awin->w_frame) {
	/* Unthread this frame */
	awin->w_frame->window = NULL;
    }
    awin->w_frame = aframe;
    aframe->window = awin;	/* Set frame's window ptr */
    return 0;
}

struct gtx_frame *
gtxframe_GetFrame(struct gwin *awin)
{
    return awin->w_frame;
}

/* Add a menu string to display list */
int
gtxframe_AddMenu(struct gtx_frame *aframe, char *alabel, char *astring)
{
    struct gtxframe_menu *tmenu;

    if (aframe->menus)
	for (tmenu = aframe->menus; tmenu; tmenu = tmenu->next) {
	    if (strcmp(alabel, tmenu->name) == 0)
		break;
    } else
	tmenu = (struct gtxframe_menu *)0;
    if (!tmenu) {
	/* Handle everything but the command string, which is handled by the
	 * common-case code below */
	tmenu = calloc(1, sizeof(*tmenu));
	if (tmenu == (struct gtxframe_menu *)0)
	    return (-1);
	tmenu->next = aframe->menus;
	aframe->menus = tmenu;
	tmenu->name = gtx_CopyString(alabel);
    }

    /*
     * Common case: redo the string labels.  Note: at this point, tmenu
     * points to a valid menu.
     */
    if (tmenu->cmdString)
	free(tmenu->cmdString);
    tmenu->cmdString = gtx_CopyString(astring);
    return 0;
}

/* Delete a given menu from a frame*/
int
gtxframe_DeleteMenu(struct gtx_frame *aframe, char *alabel)
{
    struct gtxframe_menu *tm, **lm;

    for (lm = &aframe->menus, tm = *lm; tm; lm = &tm->next, tm = *lm) {
	if (strcmp(alabel, tm->name) == 0) {
	    /* found it, remove and return success */
	    *lm = tm->next;	/* unthread from list */
	    free(tm->name);
	    free(tm->cmdString);
	    free(tm);
	    return (0);
	}
    }
    return (-1);		/* failed to find entry to delete */
}

/* Function to remove all known menus */
int
gtxframe_ClearMenus(struct gtx_frame *aframe)
{

    struct gtxframe_menu *tm, *nm;

    if (aframe->menus != (struct gtxframe_menu *)0) {
	for (tm = aframe->menus; tm; tm = nm) {
	    nm = tm->next;
	    free(tm->name);
	    free(tm->cmdString);
	    free(tm);
	}
    }

    aframe->menus = (struct gtxframe_menu *)0;
    return 0;
}

int
gtxframe_AskForString(struct gtx_frame *aframe, char *aprompt,
		      char *adefault, char *aresult, int aresultSize)
{
    int code;
    char *tp;

    /* Ensure recursive-edit map is initialized */
    SaveMap(aframe);

    /* Set up display */
    if (aframe->promptLine)
	free(aframe->promptLine);
    if (aframe->defaultLine)
	free(aframe->defaultLine);
    aframe->promptLine = gtx_CopyString(aprompt);
    tp = aframe->defaultLine = malloc(1024);
    if (tp == NULL)
	return (-1);
    if (adefault)
	strcpy(tp, adefault);
    else
	*tp = 0;

    /* Do recursive edit */
    gtx_InputServer(aframe->window);
    tp = aframe->defaultLine;	/* In case command reallocated it */

    /* Back from recursive edit, check out what's happened */
    if (aframe->flags & GTXFRAME_RECURSIVEERR) {
	code = -1;
	goto done;
    }
    code = strlen(tp);
    if (code + 1 > aresultSize) {
	code = -2;
	goto done;
    }
    strcpy(aresult, tp);
    code = 0;

    /* Fall through to cleanup and return code */
  done:
    RestoreMap(aframe);
    if (aframe->promptLine)
	free(aframe->promptLine);
    if (aframe->defaultLine)
	free(aframe->defaultLine);
    aframe->defaultLine = aframe->promptLine = NULL;
    if (code)
	gtxframe_DisplayString(aframe, "[Aborted]");
    return (code);
}

int
gtxframe_DisplayString(struct gtx_frame *aframe, char *amsgLine)
{
    if (aframe->messageLine)
	free(aframe->messageLine);
    aframe->messageLine = gtx_CopyString(amsgLine);
    return 0;
}

/* Called by input processor to try to clear the dude */
int
gtxframe_ClearMessageLine(struct gtx_frame *aframe)
{
    /* If we haven't shown message long enough yet, just return */
    if (aframe->flags & GTXFRAME_NEWDISPLAY)
	return (0);
    if (aframe->messageLine)
	free(aframe->messageLine);
    aframe->messageLine = NULL;
    return (0);
}

static int
ShowMessageLine(struct gtx_frame *aframe)
{
    struct gwin_strparams strparms;
    struct gwin_sizeparams sizeparms;
    char *tp;

    if (!aframe->window)
	return -1;

    /* First, find window size */
    WOP_GETDIMENSIONS(aframe->window, &sizeparms);

    if (aframe->promptLine) {
	memset(&strparms, 0, sizeof(strparms));
	strparms.x = 0;
	strparms.y = sizeparms.maxy - 1;
	strparms.highlight = 1;
	tp = strparms.s = malloc(1024);
	strcpy(tp, aframe->promptLine);
	strcat(tp, aframe->defaultLine);
	WOP_DRAWSTRING(aframe->window, &strparms);
	aframe->flags |= GTXFRAME_NEWDISPLAY;
    } else if (aframe->messageLine) {
	/* Otherwise we're visible, print the message at the bottom */
	memset(&strparms, 0, sizeof(strparms));
	strparms.highlight = 1;
	strparms.x = 0;
	strparms.y = sizeparms.maxy - 1;
	strparms.s = aframe->messageLine;
	WOP_DRAWSTRING(aframe->window, &strparms);
	aframe->flags |= GTXFRAME_NEWDISPLAY;
    }
    return (0);
}

/* Exit function, returning whatever has been put in its argument */
int
gtxframe_ExitCmd(void *a_exitValuep, void *arock)
{				/*gtxframe_ExitCmd */

    int exitval;		/*Value we've been asked to exit with */

    /* This next call should be type independent! */
    gator_cursesgwin_cleanup(&gator_basegwin);

    exitval = *((int *)(a_exitValuep));
    exit(exitval);

}				/*gtxframe_ExitCmd */

struct gtx_frame *
gtxframe_Create(void)
{
    struct gtx_frame *tframe;
    struct keymap_map *newkeymap;
    struct keymap_state *newkeystate;

    /*
     * Allocate all the pieces first: frame, keymap, and key state.
     */
    tframe = calloc(1, sizeof(struct gtx_frame));
    if (tframe == (struct gtx_frame *)0) {
	return ((struct gtx_frame *)0);
    }

    newkeymap = keymap_Create();
    if (newkeymap == (struct keymap_map *)0) {
	/*
	 * Get rid of the frame before exiting.
	 */
	free(tframe);
	return ((struct gtx_frame *)0);
    }

    newkeystate = malloc(sizeof(struct keymap_state));
    if (newkeystate == (struct keymap_state *)0) {
	/*
	 * Get rid of the frame AND the keymap before exiting.
	 */
	free(tframe);
	free(newkeymap);
	return ((struct gtx_frame *)0);
    }

    /*
     * Now that all the pieces exist, fill them in and stick them in
     * the right places.
     */
    tframe->keymap = newkeymap;
    tframe->keystate = newkeystate;
    keymap_InitState(tframe->keystate, tframe->keymap);
    keymap_BindToString(tframe->keymap, "\003", gtxframe_ExitCmd, "ExitCmd",
			(char *)(&gtxframe_exitValue));

    /*
     * At this point, we return successfully.
     */
    return (tframe);
}

int
gtxframe_Delete(struct gtx_frame *aframe)
{
    keymap_Delete(aframe->keymap);
    free(aframe->keystate);
    if (aframe->messageLine)
	free(aframe->messageLine);
    free(aframe);
    return 0;
}

int
gtxframe_Display(struct gtx_frame *aframe, struct gwin *awm)
{
    struct gtxframe_dlist *tlist;
    struct gtxframe_menu *tm;
    struct gwin_strparams strparms;

    /* Run through the menus, displaying them on the top line */
    *menubuffer = 0;
    for (tm = aframe->menus; tm; tm = tm->next) {
	strcat(menubuffer, tm->name);
	strcat(menubuffer, ":");
	strcat(menubuffer, tm->cmdString);
	strcat(menubuffer, " ");
    }
    if (menubuffer[0] != 0) {
	memset(&strparms, 0, sizeof(strparms));
	strparms.x = 0;
	strparms.y = 0;
	strparms.s = menubuffer;
	strparms.highlight = 1;
	WOP_DRAWSTRING(awm, &strparms);
    }

    /* Run through the display list, displaying all objects */
    for (tlist = aframe->display; tlist; tlist = tlist->next) {
	OOP_DISPLAY(((struct onode *)(tlist->data)));
    }

    /* Finally, show the message line */
    ShowMessageLine(awm->w_frame);
    return (0);
}

/* Add an object to a window's display list */
int
gtxframe_AddToList(struct gtx_frame *aframe, struct onode *aobj)
{
    struct gtxframe_dlist *tlist;

    for (tlist = aframe->display; tlist; tlist = tlist->next) {
	if (tlist->data == (char *)aobj) {
	    /*
	     * Don't add the same thing twice.
	     */
	    return (-1);
	}
    }

    /*
     * OK, it's not alreadyt there.  Create a new list object, fill it
     * in, and splice it on.
     */
    tlist = malloc(sizeof(struct gtxframe_dlist));
    if (tlist == (struct gtxframe_dlist *)0)
	return (-1);
    tlist->data = (char *)aobj;
    tlist->next = aframe->display;
    aframe->display = tlist;
    return (0);
}

/* Remove an object from a display list, if it is already there */
int
gtxframe_RemoveFromList(struct gtx_frame *aframe, struct onode *aobj)
{
    struct gtxframe_dlist *tlist, **plist;

    plist = &aframe->display;
    for (tlist = *plist; tlist; plist = &tlist->next, tlist = *plist) {
	if (tlist->data == (char *)aobj) {
	    *plist = tlist->next;
	    free(tlist);
	    return 0;
	}
    }
    return (-1);		/* Item not found */
}

/* Clear out everything on the display list for the given frame*/
int
gtxframe_ClearList(struct gtx_frame *aframe)
{
    struct gtxframe_dlist *tlist, *nlist;

    if (aframe->display != (struct gtxframe_dlist *)0) {
	/*
	 * Throw away each display list structure (we have at least
	 * one).
	 */
	for (tlist = aframe->display; tlist; tlist = nlist) {
	    nlist = tlist->next;
	    free(tlist);
	}
    }

    aframe->display = (struct gtxframe_dlist *)0;
    return 0;
}

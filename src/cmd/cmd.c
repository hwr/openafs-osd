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

#include <roken.h>

#include <ctype.h>
#include <assert.h>

#include "cmd.h"

/* declaration of private token type */
struct cmd_token {
    struct cmd_token *next;
    char *key;
};

static struct cmd_item dummy;		/* non-null ptr used for flag existence */
static struct cmd_syndesc *allSyntax = 0;
static int noOpcodes = 0;
static int (*beforeProc) (struct cmd_syndesc * ts, void *beforeRock) = NULL;
static int (*afterProc) (struct cmd_syndesc * ts, void *afterRock) = NULL;
static int enablePositional = 1;
static int enableAbbreviation = 1;
static void *beforeRock, *afterRock;
static char initcmd_opcode[] = "initcmd";	/*Name of initcmd opcode */
static cmd_config_section *globalConfig = NULL;
static const char *commandName = NULL;

/* take name and string, and return null string if name is empty, otherwise return
   the concatenation of the two strings */
static char *
NName(char *a1, char *a2)
{
    static char tbuffer[300];
    if (strlen(a1) == 0) {
        return "";
    } else {
        strlcpy(tbuffer, a1, sizeof(tbuffer));
        strlcat(tbuffer, a2, sizeof(tbuffer));
        return tbuffer;
    }
}

/* return true if asub is a substring of amain */
static int
SubString(char *amain, char *asub)
{
    int mlen, slen;
    int i, j;
    mlen = (int) strlen(amain);
    slen = (int) strlen(asub);
    j = mlen - slen;
    if (j < 0)
	return 0;		/* not a substring */
    for (i = 0; i <= j; i++) {
	if (strncmp(amain, asub, slen) == 0)
	    return 1;
	amain++;
    }
    return 0;			/* didn't find it */
}

static int
FindType(struct cmd_syndesc *as, char *aname)
{
    int i;
    size_t cmdlen;
    int ambig;
    int best;
    struct cmd_item *alias;

    /* Allow --long-style options. */
    if (aname[0] == '-' && aname[1] == '-' && aname[2] && aname[3]) {
        aname++;
    }

    cmdlen = strlen(aname);
    ambig = 0;
    best = -1;
    for (i = 0; i < CMD_MAXPARMS; i++) {
	if (as->parms[i].type == 0)
	    continue;		/* this slot not set (seeked over) */
	if (strcmp(as->parms[i].name, aname) == 0)
	    return i;
	if (strlen(as->parms[i].name) < cmdlen)
	    continue;

	/* Check for aliases, which must be full matches */
	alias = as->parms[i].aliases;
	while (alias != NULL) {
	    if (strcmp(alias->data, aname) == 0)
		return i;
	    alias = alias->next;
	}

	/* A hidden option, or one which cannot be abbreviated,
	 * must be a full match (no best matches) */
	if (as->parms[i].flags & CMD_HIDE ||
	    as->parms[i].flags & CMD_NOABBRV ||
	    !enableAbbreviation)
	    continue;

	if (strncmp(as->parms[i].name, aname, cmdlen) == 0) {
	    if (best != -1)
		ambig = 1;
	    else
		best = i;
	}
    }
    return (ambig ? -1 : best);
}

static struct cmd_syndesc *
FindSyntax(char *aname, int *aambig)
{
    struct cmd_syndesc *ts;
    struct cmd_syndesc *best;
    size_t cmdLen;
    int ambig;

    cmdLen = strlen(aname);
    best = (struct cmd_syndesc *)0;
    ambig = 0;
    if (aambig)
	*aambig = 0;		/* initialize to unambiguous */
    for (ts = allSyntax; ts; ts = ts->next) {
	if (strcmp(aname, ts->name) == 0)
	    return (ts);
	if (strlen(ts->name) < cmdLen)
	    continue;		/* we typed more than item has */
	/* A hidden command must be a full match (no best matches) */
	if (ts->flags & CMD_HIDDEN)
	    continue;

	/* This is just an alias for *best, or *best is just an alias for us.
	 * If we don't make this check explicitly, then an alias which is just a
	 * short prefix of the real command's name might make things ambiguous
	 * for no apparent reason.
	 */
	if (best && ts->aliasOf == best->aliasOf)
	    continue;
	if (strncmp(ts->name, aname, cmdLen) == 0) {
	    if (best)
		ambig = 1;	/* ambiguous name */
	    else
		best = ts;
	}
    }
    if (ambig) {
	if (aambig)
	    *aambig = ambig;	/* if ambiguous and they care, tell them */
	return (struct cmd_syndesc *)0;	/* fails */
    } else
	return best;		/* otherwise its not ambiguous, and they know */
}

/* print the help for a single parameter */
static char *
ParmHelpString(struct cmd_parmdesc *aparm)
{
    char *str;
    if (aparm->type == CMD_FLAG) {
	return strdup("");
    } else {
	if (asprintf(&str, " %s<%s>%s%s",
		     aparm->type == CMD_SINGLE_OR_FLAG?"[":"",
		     aparm->help?aparm->help:"arg",
		     aparm->type == CMD_LIST?"+":"",
		     aparm->type == CMD_SINGLE_OR_FLAG?"]":"") < 0)
	    return "<< OUT OF MEMORY >>";
	return str;
    }
}

extern char *AFSVersion;

static int
VersionProc(struct cmd_syndesc *as, void *arock)
{
    printf("%s\n", AFSVersion);
    return 0;
}

void
PrintSyntax(struct cmd_syndesc *as)
{
    int i;
    struct cmd_parmdesc *tp;
    char *str;
    char *name;
    size_t len;
    size_t xtralen;

    /* now print usage, from syntax table */
    if (noOpcodes)
	len = printf("Usage: %s", as->a0name);
    else {
	if (!strcmp(as->name, initcmd_opcode))
	    len = printf("Usage: %s[%s]", NName(as->a0name, " "), as->name);
	else
	    len = printf("Usage: %s%s", NName(as->a0name, " "), as->name);
    }

    for (i = 0; i < CMD_MAXPARMS; i++) {
	tp = &as->parms[i];
	if (tp->type == 0)
	    continue;		/* seeked over slot */
	if (tp->flags & CMD_HIDE)
	    continue;		/* skip hidden options */

	/* The parameter name is the real name, plus any aliases */
	if (!tp->aliases) {
	    name = strdup(tp->name);
	} else {
	    size_t namelen;
	    struct cmd_item *alias;
	    namelen = strlen(tp->name) + 1;
	    for (alias = tp->aliases; alias != NULL; alias = alias->next)
		namelen+=strlen(alias->data) + 3;

	    name = malloc(namelen);
	    strlcpy(name, tp->name, namelen);

	    for (alias = tp->aliases; alias != NULL; alias = alias->next) {
		strlcat(name, " | ", namelen);
		strlcat(name, alias->data, namelen);
	    }
	}

	/* Work out if we can fit what we want to on this line, or if we need to
	 * start a new one */
	str = ParmHelpString(tp);
	xtralen = 1 + strlen(name) + strlen(str) +
		  ((tp->flags & CMD_OPTIONAL)? 2: 0);

	if (len + xtralen > 78) {
	    printf("\n        ");
	    len = 8;
	}

	printf(" %s%s%s%s",
	       tp->flags & CMD_OPTIONAL?"[":"",
	       name,
	       str,
	       tp->flags & CMD_OPTIONAL?"]":"");
	free(str);
	free(name);
	len+=xtralen;
    }
    printf("\n");
}

/* must print newline in any case, to terminate preceding line */
static void
PrintAliases(struct cmd_syndesc *as)
{
    struct cmd_syndesc *ts;

    if (as->flags & CMD_ALIAS) {
	ts = as->aliasOf;
	printf("(alias for %s)\n", ts->name);
    } else {
	printf("\n");
	if (!as->nextAlias)
	    return;		/* none, print nothing */
	printf("aliases: ");
	for (as = as->nextAlias; as; as = as->nextAlias) {
	    printf("%s ", as->name);
	}
	printf("\n");
    }
}

void
PrintFlagHelp(struct cmd_syndesc *as)
{
    int i;
    struct cmd_parmdesc *tp;
    int flag_width;
    char *flag_prefix;

    /* find flag name length */
    flag_width = 0;
    for (i = 0; i < CMD_MAXPARMS; i++) {
	if (i == CMD_HELPPARM)
	    continue;
	tp = &as->parms[i];
	if (tp->type != CMD_FLAG)
	    continue;
	if (tp->flags & CMD_HIDE)
	    continue;		/* skip hidden options */
	if (!tp->help)
	    continue;

	if (strlen(tp->name) > flag_width)
	    flag_width = strlen(tp->name);
    }

    /* print flag help */
    flag_prefix = "Where:";
    for (i = 0; i < CMD_MAXPARMS; i++) {
	if (i == CMD_HELPPARM)
	    continue;
	tp = &as->parms[i];
	if (tp->type != CMD_FLAG)
	    continue;
	if (tp->flags & CMD_HIDE)
	    continue;		/* skip hidden options */
	if (!tp->help)
	    continue;

	printf("%-7s%-*s  %s\n", flag_prefix, flag_width, tp->name, tp->help);
	flag_prefix = "";
    }
}

static int
AproposProc(struct cmd_syndesc *as, void *arock)
{
    struct cmd_syndesc *ts;
    char *tsub;
    int didAny;

    didAny = 0;
    tsub = as->parms[0].items->data;
    for (ts = allSyntax; ts; ts = ts->next) {
	if ((ts->flags & CMD_ALIAS) || (ts->flags & CMD_HIDDEN))
	    continue;
	if (SubString(ts->help, tsub)) {
	    printf("%s: %s\n", ts->name, ts->help);
	    didAny = 1;
	} else if (SubString(ts->name, tsub)) {
	    printf("%s: %s\n", ts->name, ts->help);
	    didAny = 1;
	}
    }
    if (!didAny)
	printf("Sorry, no commands found\n");
    return 0;
}

static int
HelpProc(struct cmd_syndesc *as, void *arock)
{
    struct cmd_syndesc *ts;
    struct cmd_item *ti;
    int ambig;
    int code = 0;

    if (as->parms[0].items == 0) {
	printf("%sCommands are:\n", NName(as->a0name, ": "));
	for (ts = allSyntax; ts; ts = ts->next) {
	    if ((ts->flags & CMD_ALIAS) || (ts->flags & CMD_HIDDEN))
		continue;
	    printf("%-15s %s\n", ts->name, (ts->help ? ts->help : ""));
	}
    } else {
	/* print out individual help topics */
	for (ti = as->parms[0].items; ti; ti = ti->next) {
	    code = 0;
	    ts = FindSyntax(ti->data, &ambig);
	    if (ts && (ts->flags & CMD_HIDDEN))
		ts = 0;		/* no hidden commands */
	    if (ts) {
		/* print out command name and help */
		printf("%s%s: %s ", NName(as->a0name, " "), ts->name,
		       (ts->help ? ts->help : ""));
		ts->a0name = as->a0name;
		PrintAliases(ts);
		PrintSyntax(ts);
		PrintFlagHelp(ts);
	    } else {
		if (!ambig)
		    fprintf(stderr, "%sUnknown topic '%s'\n",
			    NName(as->a0name, ": "), ti->data);
		else {
		    /* ambiguous, list 'em all */
		    fprintf(stderr,
			    "%sAmbiguous topic '%s'; use 'apropos' to list\n",
			    NName(as->a0name, ": "), ti->data);
		}
		code = CMD_UNKNOWNCMD;
	    }
	}
    }
    return (code);
}

int
cmd_SetBeforeProc(int (*aproc) (struct cmd_syndesc * ts, void *beforeRock),
		  void *arock)
{
    beforeProc = aproc;
    beforeRock = arock;
    return 0;
}

int
cmd_SetAfterProc(int (*aproc) (struct cmd_syndesc * ts, void *afterRock),
		 void *arock)
{
    afterProc = aproc;
    afterRock = arock;
    return 0;
}

/* thread on list in alphabetical order */
static int
SortSyntax(struct cmd_syndesc *as)
{
    struct cmd_syndesc **ld, *ud;

    for (ld = &allSyntax, ud = *ld; ud; ld = &ud->next, ud = *ld) {
	if (strcmp(ud->name, as->name) > 0) {	/* next guy is bigger than us */
	    break;
	}
    }
    /* thread us on the list now */
    *ld = as;
    as->next = ud;
    return 0;
}

/*!
 * Create a command syntax.
 *
 * \note Use cmd_AddParm() or cmd_AddParmAtOffset() to set the
 *       parameters for the new command.
 *
 * \param[in] aname  name used to invoke the command
 * \param[in] aproc  procedure to be called when command is invoked
 * \param[in] arock  opaque data pointer to be passed to aproc
 * \param[in] aflags command option flags (CMD_HIDDEN)
 * \param[in] ahelp  help string to display for this command
 *
 * \return a pointer to the cmd_syndesc or NULL if error.
 */
struct cmd_syndesc *
cmd_CreateSyntax(char *aname,
		 int (*aproc) (struct cmd_syndesc * ts, void *arock),
		 void *arock, afs_uint32 aflags, char *ahelp)
{
    struct cmd_syndesc *td;

    /* can't have two cmds in no opcode mode */
    if (noOpcodes)
	return NULL;

    /* Allow only valid cmd flags. */
    if (aflags & ~CMD_HIDDEN) {
	return NULL;
    }

    td = calloc(1, sizeof(struct cmd_syndesc));
    assert(td);
    td->aliasOf = td;		/* treat aliasOf as pointer to real command, no matter what */
    td->flags = aflags;

    /* copy in name, etc */
    if (aname) {
	td->name = strdup(aname);
	assert(td->name);
    } else {
	td->name = NULL;
	noOpcodes = 1;
    }
    if (ahelp) {
	td->help = strdup(ahelp);
	assert(td->help);
    } else
	td->help = NULL;
    td->proc = aproc;
    td->rock = arock;

    SortSyntax(td);

    cmd_Seek(td, CMD_HELPPARM);
    cmd_AddParm(td, "-help", CMD_FLAG, CMD_OPTIONAL, "get detailed help");
    cmd_Seek(td, 0);

    return td;
}

int
cmd_CreateAlias(struct cmd_syndesc *as, char *aname)
{
    struct cmd_syndesc *td;

    td = malloc(sizeof(struct cmd_syndesc));
    assert(td);
    memcpy(td, as, sizeof(struct cmd_syndesc));
    td->name = strdup(aname);
    assert(td->name);
    td->flags |= CMD_ALIAS;
    /* if ever free things, make copy of help string, too */

    /* thread on list */
    SortSyntax(td);

    /* thread on alias lists */
    td->nextAlias = as->nextAlias;
    as->nextAlias = td;
    td->aliasOf = as;

    return 0;			/* all done */
}

void
cmd_DisablePositionalCommands(void)
{
    enablePositional = 0;
}

void
cmd_DisableAbbreviations(void)
{
    enableAbbreviation = 0;
}

int
cmd_Seek(struct cmd_syndesc *as, int apos)
{
    if (apos >= CMD_MAXPARMS)
	return CMD_EXCESSPARMS;
    as->nParms = apos;
    return 0;
}

int
cmd_AddParmAtOffset(struct cmd_syndesc *as, int ref, char *aname, int atype,
		    afs_int32 aflags, char *ahelp)
{
    struct cmd_parmdesc *tp;

    if (ref >= CMD_MAXPARMS)
	return CMD_EXCESSPARMS;
    tp = &as->parms[ref];

    tp->name = strdup(aname);
    assert(tp->name);
    tp->type = atype;
    tp->flags = aflags;
    tp->items = NULL;
    if (ahelp) {
	tp->help = strdup(ahelp);
	assert(tp->help);
    } else
	tp->help = NULL;

    tp->aliases = NULL;

    if (as->nParms <= ref)
	as->nParms = ref+1;

    return 0;
}

int
cmd_AddParm(struct cmd_syndesc *as, char *aname, int atype,
	    afs_int32 aflags, char *ahelp)
{
    if (as->nParms >= CMD_MAXPARMS)
	return CMD_EXCESSPARMS;

    return cmd_AddParmAtOffset(as, as->nParms++, aname, atype, aflags, ahelp);
}

int
cmd_AddParmAlias(struct cmd_syndesc *as, int pos, char *alias)
{
    struct cmd_item *item;

    if (pos > as->nParms)
	return CMD_EXCESSPARMS;

    item = calloc(1, sizeof(struct cmd_item));
    item->data = strdup(alias);
    item->next = as->parms[pos].aliases;
    as->parms[pos].aliases = item;

    return 0;
}

/* add a text item to the end of the parameter list */
static int
AddItem(struct cmd_parmdesc *aparm, char *aval, char *pname)
{
    struct cmd_item *ti, *ni;

    if (aparm->type == CMD_SINGLE ||
	aparm->type == CMD_SINGLE_OR_FLAG) {
	if (aparm->items) {
	    fprintf(stderr, "%sToo many values after switch %s\n",
		    NName(pname, ": "), aparm->name);
	    return CMD_NOTLIST;
	}
    }

    ti = calloc(1, sizeof(struct cmd_item));
    assert(ti);
    ti->data = strdup(aval);
    assert(ti->data);
    /* now put ti at the *end* of the list */
    if ((ni = aparm->items)) {
	for (; ni; ni = ni->next)
	    if (ni->next == 0)
		break;		/* skip to last one */
	ni->next = ti;
    } else
	aparm->items = ti;	/* we're first */
    return 0;
}

/* skip to next non-flag item, if any */
static int
AdvanceType(struct cmd_syndesc *as, afs_int32 aval)
{
    afs_int32 next;
    struct cmd_parmdesc *tp;

    /* first see if we should try to grab rest of line for this dude */
    if (as->parms[aval].flags & CMD_EXPANDS)
	return aval;

    /* if not, find next non-flag used slot */
    for (next = aval + 1; next < CMD_MAXPARMS; next++) {
	tp = &as->parms[next];
	if (tp->type != 0 && tp->type != CMD_FLAG)
	    return next;
    }
    return aval;
}

/* discard parameters filled in by dispatch */
static void
ResetSyntax(struct cmd_syndesc *as)
{
    int i;
    struct cmd_parmdesc *tp;
    struct cmd_item *ti, *ni;

    tp = as->parms;
    for (i = 0; i < CMD_MAXPARMS; i++, tp++) {
	switch (tp->type) {
	case CMD_SINGLE_OR_FLAG:
	    if (tp->items == &dummy)
		break;
	    /* Deliberately fall through here */
	case CMD_SINGLE:
	case CMD_LIST:
	    /* free whole list in both cases, just for fun */
	    for (ti = tp->items; ti; ti = ni) {
		ni = ti->next;
		free(ti->data);
		free(ti);
	    }
	    break;

	default:
	    break;
	}
	tp->items = NULL;
    }
}

/* move the expands flag to the last one in the list */
static int
SetupExpandsFlag(struct cmd_syndesc *as)
{
    struct cmd_parmdesc *tp;
    int last, i;

    last = -1;
    /* find last CMD_LIST type parameter, optional or not, and make it expandable
     * if no other dude is expandable */
    for (i = 0; i < CMD_MAXPARMS; i++) {
	tp = &as->parms[i];
	if (tp->type == CMD_LIST) {
	    if (tp->flags & CMD_EXPANDS)
		return 0;	/* done if already specified */
	    last = i;
	}
    }
    if (last >= 0)
	as->parms[last].flags |= CMD_EXPANDS;
    return 0;
}

/* Take the current argv & argc and alter them so that the initialization
 * opcode is made to appear.  This is used in cases where the initialization
 * opcode is implicitly invoked.*/
static char **
InsertInitOpcode(int *aargc, char **aargv)
{
    char **newargv;		/*Ptr to new, expanded argv space */
    char *pinitopcode;		/*Ptr to space for name of init opcode */
    int i;			/*Loop counter */

    /* Allocate the new argv array, plus one for the new opcode, plus one
     * more for the trailing null pointer */
    newargv = malloc(((*aargc) + 2) * sizeof(char *));
    if (!newargv) {
	fprintf(stderr, "%s: Can't create new argv array with %d+2 slots\n",
		aargv[0], *aargc);
	return (NULL);
    }

    /* Create space for the initial opcode & fill it in */
    pinitopcode = strdup(initcmd_opcode);
    if (!pinitopcode) {
	fprintf(stderr, "%s: Can't malloc initial opcode space\n", aargv[0]);
	free(newargv);
	return (NULL);
    }

    /* Move all the items in the old argv into the new argv, in their
     * proper places */
    for (i = *aargc; i > 1; i--)
	newargv[i] = aargv[i - 1];

    /* Slip in the opcode and the trailing null pointer, and bump the
     * argument count up by one for the new opcode */
    newargv[0] = aargv[0];
    newargv[1] = pinitopcode;
    (*aargc)++;
    newargv[*aargc] = NULL;

    /* Return the happy news */
    return (newargv);

}				/*InsertInitOpcode */

static int
NoParmsOK(struct cmd_syndesc *as)
{
    int i;
    struct cmd_parmdesc *td;

    for (i = 0; i < CMD_MAXPARMS; i++) {
	td = &as->parms[i];
	if (td->type != 0 && !(td->flags & CMD_OPTIONAL)) {
	    /* found a non-optional (e.g. required) parm, so NoParmsOK
	     * is false (some parms are required) */
	    return 0;
	}
    }
    return 1;
}

/* Add help, apropos commands once */
static void
initSyntax(void)
{
    struct cmd_syndesc *ts;

    if (!noOpcodes) {
	ts = cmd_CreateSyntax("help", HelpProc, NULL, 0,
			      "get help on commands");
	cmd_AddParm(ts, "-topic", CMD_LIST, CMD_OPTIONAL, "help string");

	ts = cmd_CreateSyntax("apropos", AproposProc, NULL, 0,
			      "search by help text");
	cmd_AddParm(ts, "-topic", CMD_SINGLE, CMD_REQUIRED, "help string");

	cmd_CreateSyntax("version", VersionProc, NULL, 0,
			 "show version");
	cmd_CreateSyntax("-version", VersionProc, NULL, CMD_HIDDEN, NULL);
	cmd_CreateSyntax("-help", HelpProc, NULL, CMD_HIDDEN, NULL);
	cmd_CreateSyntax("--version", VersionProc, NULL, CMD_HIDDEN, NULL);
	cmd_CreateSyntax("--help", HelpProc, NULL, CMD_HIDDEN, NULL);
    }
}

/* Call the appropriate function, or return syntax error code.  Note: if
 * no opcode is specified, an initialization routine exists, and it has
 * NOT been called before, we invoke the special initialization opcode
 */
int
cmd_Parse(int argc, char **argv, struct cmd_syndesc **outsyntax)
{
    char *pname;
    struct cmd_syndesc *ts = NULL;
    struct cmd_parmdesc *tparm;
    int i;
    int curType;
    int positional;
    int ambig;
    int code = 0;
    char *param = NULL;
    char *embeddedvalue = NULL;
    static int initd = 0;	/*Is this the first time this routine has been called? */
    static int initcmdpossible = 1;	/*Should be consider parsing the initial command? */

    *outsyntax = NULL;

    if (!initd) {
	initd = 1;
	initSyntax();
    }

    /*Remember the program name */
    pname = argv[0];

    if (noOpcodes) {
	if (argc == 1) {
	    if (!NoParmsOK(allSyntax)) {
		printf("%s: Type '%s -help' for help\n", pname, pname);
		code = CMD_USAGE;
		goto out;
	    }
	}
    } else {
	if (argc < 2) {
	    /* if there is an initcmd, don't print an error message, just
	     * setup to use the initcmd below. */
	    if (!(initcmdpossible && FindSyntax(initcmd_opcode, NULL))) {
		printf("%s: Type '%s help' or '%s help <topic>' for help\n",
		       pname, pname, pname);
		code = CMD_USAGE;
		goto out;
	    }
	}
    }

    /* Find the syntax descriptor for this command, doing prefix matching properly */
    if (noOpcodes) {
	ts = allSyntax;
    } else {
	ts = (argc < 2 ? 0 : FindSyntax(argv[1], &ambig));
	if (!ts) {
	    /*First token doesn't match a syntax descriptor */
	    if (initcmdpossible) {
		/*If initial command line handling hasn't been done yet,
		 * see if there is a descriptor for the initialization opcode.
		 * Only try this once. */
		initcmdpossible = 0;
		ts = FindSyntax(initcmd_opcode, NULL);
		if (!ts) {
		    /*There is no initialization opcode available, so we declare
		     * an error */
		    if (ambig) {
			fprintf(stderr, "%s", NName(pname, ": "));
			fprintf(stderr,
				"Ambiguous operation '%s'; type '%shelp' for list\n",
				argv[1], NName(pname, " "));
		    } else {
			fprintf(stderr, "%s", NName(pname, ": "));
			fprintf(stderr,
				"Unrecognized operation '%s'; type '%shelp' for list\n",
				argv[1], NName(pname, " "));
		    }
		    code = CMD_UNKNOWNCMD;
		    goto out;
		} else {
		    /*Found syntax structure for an initialization opcode.  Fix
		     * up argv and argc to relect what the user
		     * ``should have'' typed */
		    if (!(argv = InsertInitOpcode(&argc, argv))) {
			fprintf(stderr,
				"%sCan't insert implicit init opcode into command line\n",
				NName(pname, ": "));
			code = CMD_INTERNALERROR;
			goto out;
		    }
		}
	    } /*Initial opcode not yet attempted */
	    else {
		/* init cmd already run and no syntax entry found */
		if (ambig) {
		    fprintf(stderr, "%s", NName(pname, ": "));
		    fprintf(stderr,
			    "Ambiguous operation '%s'; type '%shelp' for list\n",
			    argv[1], NName(pname, " "));
		} else {
		    fprintf(stderr, "%s", NName(pname, ": "));
		    fprintf(stderr,
			    "Unrecognized operation '%s'; type '%shelp' for list\n",
			    argv[1], NName(pname, " "));
		}
		code = CMD_UNKNOWNCMD;
		goto out;
	    }
	}			/*Argv[1] is not a valid opcode */
    }				/*Opcodes are defined */

    /* Found the descriptor; start parsing.  curType is the type we're
     * trying to parse */
    curType = 0;

    /* We start off parsing in "positional" mode, where tokens are put in
     * slots positionally.  If we find a name that takes args, we go
     * out of positional mode, and from that point on, expect a switch
     * before any particular token. */

    positional = enablePositional;	/* Accepting positional cmds ? */
    i = noOpcodes ? 1 : 2;
    SetupExpandsFlag(ts);
    for (; i < argc; i++) {
	if (param) {
	    free(param);
	    param = NULL;
	    embeddedvalue = NULL;
	}

	/* Only tokens that start with a hyphen and are not followed by a digit
	 * are considered switches.  This allow negative numbers. */

	if ((argv[i][0] == '-') && !isdigit(argv[i][1])) {
	    int j;

	    /* Find switch */
	    if (strrchr(argv[i], '=') != NULL) {
		param = strdup(argv[i]);
		embeddedvalue = strrchr(param, '=');
		*embeddedvalue = '\0';
		embeddedvalue ++;
	        j = FindType(ts, param);
	    } else {
	        j = FindType(ts, argv[i]);
	    }

	    if (j < 0) {
		fprintf(stderr,
			"%sUnrecognized or ambiguous switch '%s'; type ",
			NName(pname, ": "), argv[i]);
		if (noOpcodes)
		    fprintf(stderr, "'%s -help' for detailed help\n",
			    argv[0]);
		else
		    fprintf(stderr, "'%shelp %s' for detailed help\n",
			    NName(argv[0], " "), ts->name);
		code = CMD_UNKNOWNSWITCH;
		goto out;
	    }
	    if (j >= CMD_MAXPARMS) {
		fprintf(stderr, "%sInternal parsing error\n",
			NName(pname, ": "));
		code = CMD_INTERNALERROR;
		goto out;
	    }
	    if (ts->parms[j].type == CMD_FLAG) {
		ts->parms[j].items = &dummy;

		if (embeddedvalue) {
		    fprintf(stderr, "%sSwitch '%s' doesn't take an argument\n",
			    NName(pname, ": "), ts->parms[j].name);
		    code = CMD_TOOMANY;
		    goto out;
		}
	    } else {
		positional = 0;
		curType = j;
		ts->parms[j].flags |= CMD_PROCESSED;

		if (embeddedvalue) {
		    AddItem(&ts->parms[curType], embeddedvalue, pname);
		}
	    }
	} else {
	    /* Try to fit in this descr */
	    if (curType >= CMD_MAXPARMS) {
		fprintf(stderr, "%sToo many arguments\n", NName(pname, ": "));
		code = CMD_TOOMANY;
		goto out;
	    }
	    tparm = &ts->parms[curType];

	    if ((tparm->type == 0) ||	/* No option in this slot */
		(tparm->type == CMD_FLAG)) {	/* A flag (not an argument */
		/* skipped parm slot */
		curType++;	/* Skip this slot and reprocess this parm */
		i--;
		continue;
	    }

	    if (!(tparm->flags & CMD_PROCESSED) && (tparm->flags & CMD_HIDE)) {
		curType++;	/* Skip this slot and reprocess this parm */
		i--;
		continue;
	    }

	    if (tparm->type == CMD_SINGLE ||
	        tparm->type == CMD_SINGLE_OR_FLAG) {
		if (tparm->items) {
		    fprintf(stderr, "%sToo many values after switch %s\n",
		            NName(pname, ": "), tparm->name);
		    code = CMD_NOTLIST;
		    goto out;
		}
		AddItem(tparm, argv[i], pname);        /* Add to end of list */
	    } else if (tparm->type == CMD_LIST) {
		AddItem(tparm, argv[i], pname);        /* Add to end of list */
	    }

	    /* Now, if we're in positional mode, advance to the next item */
	    if (positional)
		curType = AdvanceType(ts, curType);
	}
    }

    /* keep track of this for messages */
    ts->a0name = argv[0];

    /* If we make it here, all the parameters are filled in.  Check to see if
     * this is a -help version.  Must do this before checking for all
     * required parms, otherwise it is a real nuisance */
    if (ts->parms[CMD_HELPPARM].items) {
	PrintSyntax(ts);
	/* Display full help syntax if we don't have subcommands */
	if (noOpcodes)
	    PrintFlagHelp(ts);
	code = CMD_HELP;
	goto out;
    }

    /* Parsing done, see if we have all of our required parameters */
    for (i = 0; i < CMD_MAXPARMS; i++) {
	tparm = &ts->parms[i];
	if (tparm->type == 0)
	    continue;		/* Skipped parm slot */
	if ((tparm->flags & CMD_PROCESSED) && tparm->items == 0) {
	    if (tparm->type == CMD_SINGLE_OR_FLAG) {
		tparm->items = &dummy;
	    } else {
	        fprintf(stderr, "%s The field '%s' isn't completed properly\n",
		    NName(pname, ": "), tparm->name);
	        code = CMD_TOOFEW;
	        goto out;
	    }
	}
	if (!(tparm->flags & CMD_OPTIONAL) && tparm->items == 0) {
	    fprintf(stderr, "%sMissing required parameter '%s'\n",
		    NName(pname, ": "), tparm->name);
	    code = CMD_TOOFEW;
	    goto out;
	}
	tparm->flags &= ~CMD_PROCESSED;
    }
    *outsyntax = ts;

out:
    if (code && ts != NULL)
	ResetSyntax(ts);

    return code;
}

int
cmd_Dispatch(int argc, char **argv)
{
    struct cmd_syndesc *ts = NULL;
    int code;

    code = cmd_Parse(argc, argv, &ts);
    if (code) {
	if (code == CMD_HELP) {
	    code = 0; /* displaying help is not an error */
	}
	return code;
    }

    /*
     * Before calling the beforeProc and afterProc and all the implications
     * from those calls, check if the help procedure was called and call it
     * now.
     */
    if ((ts->proc == HelpProc) || (ts->proc == AproposProc)) {
	code = (*ts->proc) (ts, ts->rock);
	goto out;
    }

    /* Now, we just call the procedure and return */
    if (beforeProc)
	code = (*beforeProc) (ts, beforeRock);

    if (code)
	goto out;

    code = (*ts->proc) (ts, ts->rock);

    if (afterProc)
	(*afterProc) (ts, afterRock);
out:
    cmd_FreeOptions(&ts);
    return code;
}

void
cmd_FreeOptions(struct cmd_syndesc **ts)
{
    if (*ts != NULL) {
	ResetSyntax(*ts);
        *ts = NULL;
    }
}

/* free token list returned by parseLine */
static int
FreeTokens(struct cmd_token *alist)
{
    struct cmd_token *nlist;
    for (; alist; alist = nlist) {
	nlist = alist->next;
	free(alist->key);
	free(alist);
    }
    return 0;
}

/* free an argv list returned by parseline */
int
cmd_FreeArgv(char **argv)
{
    char *tp;
    for (tp = *argv; tp; argv++, tp = *argv)
	free(tp);
    return 0;
}

/* copy back the arg list to the argv array, freeing the cmd_tokens as you go;
 * the actual data is still malloc'd, and will be freed when the caller calls
 * cmd_FreeArgv later on
 */
#define INITSTR ""
static int
CopyBackArgs(struct cmd_token *alist, char **argv,
	     afs_int32 * an, afs_int32 amaxn)
{
    struct cmd_token *next;
    afs_int32 count;

    count = 0;
    if (amaxn <= 1)
	return CMD_TOOMANY;
    *argv = strdup(INITSTR);
    assert(*argv);
    amaxn--;
    argv++;
    count++;
    while (alist) {
	if (amaxn <= 1)
	    return CMD_TOOMANY;	/* argv is too small for his many parms. */
	*argv = alist->key;
	next = alist->next;
	free(alist);
	alist = next;
	amaxn--;
	argv++;
	count++;
    }
    *argv = NULL;		/* use last slot for terminating null */
    /* don't count terminating null */
    *an = count;
    return 0;
}

static int
quote(int x)
{
    if (x == '"' || x == 39 /* single quote */ )
	return 1;
    else
	return 0;
}

static int
space(int x)
{
    if (x == 0 || x == ' ' || x == '\t' || x == '\n')
	return 1;
    else
	return 0;
}

int
cmd_ParseLine(char *aline, char **argv, afs_int32 * an, afs_int32 amaxn)
{
    char tbuffer[256];
    char *tptr = 0;
    int inToken, inQuote;
    struct cmd_token *first, *last;
    struct cmd_token *ttok;
    int tc;

    inToken = 0;		/* not copying token chars at start */
    first = NULL;
    last = NULL;
    inQuote = 0;		/* not in a quoted string */
    while (1) {
	tc = *aline++;
	if (tc == 0 || (!inQuote && space(tc))) {	/* terminating null gets us in here, too */
	    if (inToken) {
		inToken = 0;	/* end of this token */
		if (!tptr)
		    return -1;	/* should never get here */
		else
		    *tptr++ = 0;
		ttok = malloc(sizeof(struct cmd_token));
		assert(ttok);
		ttok->next = NULL;
		ttok->key = strdup(tbuffer);
		assert(ttok->key);
		if (last) {
		    last->next = ttok;
		    last = ttok;
		} else
		    last = ttok;
		if (!first)
		    first = ttok;
	    }
	} else {
	    /* an alpha character */
	    if (!inToken) {
		tptr = tbuffer;
		inToken = 1;
	    }
	    if (tptr - tbuffer >= sizeof(tbuffer)) {
		FreeTokens(first);
		return CMD_TOOBIG;	/* token too long */
	    }
	    if (quote(tc)) {
		/* hit a quote, toggle inQuote flag but don't insert character */
		inQuote = !inQuote;
	    } else {
		/* insert character */
		*tptr++ = tc;
	    }
	}
	if (tc == 0) {
	    /* last token flushed 'cause space(0) --> true */
	    if (last)
		last->next = NULL;
	    return CopyBackArgs(first, argv, an, amaxn);
	}
    }
}

/* Read a string in from our configuration file. This checks in
 * multiple places within this file - firstly in the section
 * [command_subcommand], then in [command], then in [subcommand]
 *
 * Returns CMD_MISSING if there is no configuration file configured,
 * or if the file doesn't contain information for the specified option
 * in any of these sections.
 */

static int
_get_file_string(struct cmd_syndesc *syn, int pos, const char **str)
{
    char *section;
    char *optionName;

    /* Nothing on the command line, try the config file if we have one */
    if (globalConfig == NULL)
	return CMD_MISSING;

    /* March past any leading -'s */
    for (optionName = syn->parms[pos].name;
	 *optionName == '-'; optionName++);

    /* First, try the command_subcommand form */
    if (syn->name != NULL && commandName != NULL) {
	if (asprintf(&section, "%s_%s", commandName, syn->name) < 0)
	    return ENOMEM;
	*str = cmd_RawConfigGetString(globalConfig, NULL, section,
				      optionName, NULL);
	free(section);
	if (*str)
	    return 0;
    }

    /* Then, try the command form */
    if (commandName != NULL) {
	*str = cmd_RawConfigGetString(globalConfig, NULL, commandName,
				      optionName, NULL);
	if (*str)
	    return 0;
    }

    /* Then, the defaults section */
    *str = cmd_RawConfigGetString(globalConfig, NULL, "defaults",
				  optionName, NULL);
    if (*str)
	return 0;

    /* Nothing there, return MISSING */
    return CMD_MISSING;
}

static int
_get_config_string(struct cmd_syndesc *syn, int pos, const char **str)
{
    *str = NULL;

    if (pos > syn->nParms)
	return CMD_EXCESSPARMS;

    /* It's a flag, they probably shouldn't be using this interface to access
     * it, but don't blow up for now */
    if (syn->parms[pos].items == &dummy)
        return 0;

    /* We have a value on the command line - this overrides anything in the
     * configuration file */
    if (syn->parms[pos].items != NULL &&
	syn->parms[pos].items->data != NULL) {
	*str = syn->parms[pos].items->data;
	return 0;
    }

    return _get_file_string(syn, pos, str);
}

int
cmd_OptionAsInt(struct cmd_syndesc *syn, int pos, int *value)
{
    const char *str;
    int code;

    code =_get_config_string(syn, pos, &str);
    if (code)
	return code;

    if (str == NULL)
	return CMD_MISSING;

    *value = strtol(str, NULL, 10);

    return 0;
}

int
cmd_OptionAsUint(struct cmd_syndesc *syn, int pos,
		 unsigned int *value)
{
    const char *str;
    int code;

    code = _get_config_string(syn, pos, &str);
    if (code)
	return code;

    if (str == NULL)
	return CMD_MISSING;

    *value = strtoul(str, NULL, 10);

    return 0;
}

int
cmd_OptionAsString(struct cmd_syndesc *syn, int pos, char **value)
{
    const char *str;
    int code;

    code = _get_config_string(syn, pos, &str);
    if (code)
	return code;

    if (str == NULL)
	return CMD_MISSING;

    if (*value)
	free(*value);
    *value = strdup(str);

    return 0;
}

int
cmd_OptionAsList(struct cmd_syndesc *syn, int pos, struct cmd_item **value)
{
    const char *str;
    struct cmd_item *item, **last;
    const char *start, *end;
    size_t len;
    int code;

    if (pos > syn->nParms)
	return CMD_EXCESSPARMS;

    /* If we have a list already, just return the existing list */
    if (syn->parms[pos].items != NULL) {
	*value = syn->parms[pos].items;
	return 0;
    }

    code = _get_file_string(syn, pos, &str);
    if (code)
	return code;

    /* Use strchr to split str into elements, and build a recursive list
     * from them. Hang this list off the configuration structure, so that
     * it is returned by any future calls to this function, and is freed
     * along with everything else when the syntax description is freed
     */
    last = &syn->parms[pos].items;
    start = str;
    while ((end = strchr(start, ' '))) {
	item = calloc(1, sizeof(struct cmd_item));
	len = end - start + 1;
	item->data = malloc(len);
	strlcpy(item->data, start, len);
	*last = item;
	last = &item->next;
	for (start = end; *start == ' '; start++); /* skip any whitespace */
    }

    /* Catch the final element */
    if (*start != '\0') {
	item = calloc(1, sizeof(struct cmd_item));
	len = strlen(start) + 1;
	item->data = malloc(len);
	strlcpy(item->data, start, len);
	*last = item;
    }

    *value = syn->parms[pos].items;

    return 0;
}

int
cmd_OptionAsFlag(struct cmd_syndesc *syn, int pos, int *value)
{
    const char *str = NULL;
    int code;

    code = _get_config_string(syn, pos, &str);
    if (code)
	return code;

    if (str == NULL ||
	strcasecmp(str, "yes") == 0 ||
	strcasecmp(str, "true") == 0 ||
	atoi(str))
	*value = 1;
    else
	*value = 0;

    return 0;
}

int
cmd_OptionPresent(struct cmd_syndesc *syn, int pos)
{
    const char *str;
    int code;

    code = _get_config_string(syn, pos, &str);
    if (code == 0)
	return 1;

    return 0;
}

int
cmd_OpenConfigFile(const char *file)
{
    if (globalConfig) {
	cmd_RawConfigFileFree(globalConfig);
	globalConfig = NULL;
    }

    return cmd_RawConfigParseFile(file, &globalConfig);
}

void
cmd_SetCommandName(const char *command)
{
    commandName = command;
}

const cmd_config_section *
cmd_RawFile(void)
{
    return globalConfig;
}

const cmd_config_section *
cmd_RawSection(void)
{
    if (globalConfig == NULL || commandName == NULL)
	return NULL;

    return cmd_RawConfigGetList(globalConfig, commandName, NULL);
}

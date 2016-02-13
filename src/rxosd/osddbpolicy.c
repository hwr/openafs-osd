/*
 * Copyright (c) 2007, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#ifdef AFS_NT40_ENV
#include <time.h>
#include <fcntl.h>
#else
#include <sys/time.h>
#include <sys/file.h>
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <fnmatch.h>
#include <regex.h>

#include <afsconfig.h>
#include <rx/xdr.h>
#include "vicedosd.h"
#include "volserosd.h"
/*#include <afs/afsint.h>*/
#include <afs/auth.h>
#include <afs/errors.h>
#include "lock.h"
#include "lwp.h"
#include <afs/afssyscalls.h>
#include <afs/afsutil.h>
#include <afs/cellconfig.h>
#include <ubik.h>

#ifdef  AFS_AIX_ENV
#include <sys/lockf.h>
#endif
#if defined(AFS_SUN5_ENV) || defined(AFS_NT40_ENV) || defined(AFS_LINUX20_ENV)
#include <string.h>
#else
#include <strings.h>
#endif
#include "osddb.h"
#include "volint.h"
#include "osddbuser.h"
#ifdef BUILD_SHLIBAFSOSD
#include <afs/ihandle.h>
#define COMPILING_OSDDBUSER 1
#endif
#ifdef BUILD_LIBAFSOSD_A
#include "afsosd.h"
#endif

#ifdef BUILDING_CLIENT_COMMAND
#define OSDDB_LOCK
#define OSDDB_UNLOCK
#define OSDDB_POL_LOCK
#define OSDDB_POL_UNLOCK
#define OSDDB_WAIT
#define OSDDB_SIGNAL
extern struct ubik_client *init_osddb_client(char *cell, int localauth);
#else /* BUILDING_CLIENT_COMMAND */
extern pthread_mutex_t osddb_glock_mutex, osddb_pol_mutex;
extern pthread_cond_t osddb_glock_cond;
extern struct ubik_client *init_osddb_client(char *unused);

#define OSDDB_LOCK MUTEX_ENTER(&osddb_glock_mutex)
#define OSDDB_UNLOCK MUTEX_EXIT(&osddb_glock_mutex)
#define OSDDB_POL_LOCK MUTEX_ENTER(&osddb_pol_mutex)
#define OSDDB_POL_UNLOCK MUTEX_EXIT(&osddb_pol_mutex)
#define OSDDB_WAIT CV_WAIT(&osddb_glock_cond, &osddb_glock_mutex)
#define OSDDB_SIGNAL CV_BROADCAST(&osddb_glock_cond)
#endif /* BUILDING_CLIENT_COMMAND */

unsigned int policy_readers = 0;
static char *juncts[] = { "NOT", "AND", "OR" },
	*cryptic_juncts[] = { "!", "&", "|" };

afs_uint32 policies_revision = 0;
afs_int32 LogLevel = 0;
extern char *cellPtr;

#define POLINDEX_LEN 97
struct pol_info {
    afs_uint32 id;
    char name[OSDDB_MAXNAMELEN];
    afs_uint32 uses_file_name:1;
    afs_uint32 uses_file_size:1;
    afs_uint32 unused:30;
    osddb_policy *pol;
    struct pol_info *next;
};
struct pol_info *pol_index[POLINDEX_LEN];

extern struct ubik_client *osddb_client;

#define MIN_SIZE_FOR_STRIPING 1024 * 1024

/* free the memory allocated by regcomp */
void free_regexes(pol_cond *condition)
{
    pol_pred pred;
    pol_condList *operands;
    int i;
    if ( !condition )
	return;
    switch ( condition->type ) {
	case POLCOND_ATOM:
	    pred = condition->pol_cond_u.predicate;
	    if ( (BASE_PREDTYPE(pred.type) == POLICY_REGEX) 
			    && ( pred.type & PREDFLAG_ANNOTATED ) ) {
		regex_t *ex = (regex_t*)
			&pred.pol_pred_u.regex[strlen(pred.pol_pred_u.regex)+1];
		regfree(ex);
		condition->pol_cond_u.predicate.type ^= PREDFLAG_ANNOTATED;
	    }
	    break;
	case POLCOND_NOT:
	    free_regexes(condition->pol_cond_u.operand);
	    break;
	case POLCOND_OR:
	case POLCOND_AND:
	    operands = condition->pol_cond_u.operands;
	    for (i = 0 ; i < operands->pol_condList_len ; i++)
	    	free_regexes(&operands->pol_condList_val[i]);
    }
}

void free_policy(struct osddb_policy *policy)
{
    int r;
    XDR xdr;
    for ( r = 0 ; r < policy->rules.pol_ruleList_len ; r++ )
	free_regexes(&policy->rules.pol_ruleList_val[r].condition);
    xdrmem_create(&xdr, NULL, 0, XDR_FREE);
    if ( !xdr_osddb_policy(&xdr, policy) )
	ViceLog(0, ("XDR_FREE of policy at 0x%p failed\n", policy));
}

void free_pol_info(struct pol_info *info)
{
    if (info == NULL)
	return;
    free_pol_info(info->next);
    free_policy(info->pol);
    free(info);
}

void annotate_condition(struct pol_info *info, pol_cond *cond)
{
    char *tmp;
    int code, flags, i;
    pol_pred pred;
    switch ( cond->type ) {
	case POLCOND_ATOM: 
	    pred = cond->pol_cond_u.predicate;
	    switch ( BASE_PREDTYPE(pred.type) ) {
		case POLICY_MIN_SIZE:
		case POLICY_MAX_SIZE:
		    info->uses_file_size = 1;
		    break;
		case POLICY_REGEX:
		    /* append the regex_t to the string */
		    tmp = cond->pol_cond_u.predicate.pol_pred_u.regex;
		    cond->pol_cond_u.predicate.pol_pred_u.regex
		    	= malloc(strlen(tmp) + 1 + sizeof(regex_t));
		    strcpy(cond->pol_cond_u.predicate.pol_pred_u.regex, tmp);
		    free(tmp);
		    tmp = cond->pol_cond_u.predicate.pol_pred_u.regex;
		    tmp += strlen(tmp) + 1;
		    flags = REG_EXTENDED 
		    		| (pred.type & PREDFLAG_ICASE ? REG_ICASE : 0); 
		    if (( code = regcomp(
                                  (regex_t*)tmp, pred.pol_pred_u.regex, flags) )) {
			ViceLog(0, ("regex compile failed for /%s/: %d\n",
						pred.pol_pred_u.regex, code)); 
		    }
		    else
			cond->pol_cond_u.predicate.type |= PREDFLAG_ANNOTATED;
		case POLICY_EXPR:
		    info->uses_file_name = 1;
		    break;
	    }
	    break;
	case POLCOND_NOT:
	    annotate_condition(info, cond->pol_cond_u.operand);
	    break;
	case POLCOND_AND:
	case POLCOND_OR:
	    for (i=0 ; i < cond->pol_cond_u.operands->pol_condList_len ; i++)
		annotate_condition(
			info, &cond->pol_cond_u.operands->pol_condList_val[i]);
	    break;
    }
}

struct pol_info *make_pol_info(osddb_policy *pol, afs_uint32 id, char *name,
				struct pol_info *dest)
{
    int r;

    if ( !dest ) { /* osd calls without allocating space */
	dest = malloc(sizeof(struct pol_info));
	memset(dest, 0, sizeof(struct pol_info));
    }

    dest->pol = malloc(sizeof(osddb_policy));
    *dest->pol = *pol;

    for ( r = 0 ; r < pol->rules.pol_ruleList_len ; r++ ) {
	pol_rule *rule = &pol->rules.pol_ruleList_val[r];
	if ( rule->condition.type == POLCOND_TRUE )
	    continue;
	annotate_condition(dest, &rule->condition);
    }

    dest->id = id;
    if ( dest->uses_file_name )
	ViceLog(1, ("policy %d needs file names\n", id));
    strncpy(dest->name, name, OSDDB_MAXNAMELEN-1);
    return dest;
}

void buildPolicyIndex(struct OsdList *l)
{
    static int initialized = 0;
    static struct pol_info *new_index[POLINDEX_LEN];
    int i, r, changes = 1, passes;
    if ( !l ) return;

    memset(&new_index, 0, sizeof(new_index));

    ViceLog(1, ("building policy index\n"));

    for ( i = 0 ; i < l->OsdList_len ; i++ ) {
	struct Osd entry = l->OsdList_val[i];
	osddb_policy pol = entry.t.etype_u.pol;
	int index = entry.id % POLINDEX_LEN;
	struct pol_info *parent, *current;

	if ( new_index[index] != NULL ) {
	    parent = new_index[index];
	    while ( parent->next != NULL )
		parent = parent->next;
	    parent->next = current = malloc(sizeof(struct pol_info));
	}
	else {
	    new_index[index] = current = malloc(sizeof(struct pol_info));
	    ViceLog(1, ("inserting pol %d at %d\n", entry.id, index));
	}
	memset(current, 0, sizeof(struct pol_info));

	make_pol_info(&pol, entry.id, entry.name, current);

	current->next = NULL;
    }
	
    /* inherit annotations from used policies */
    passes = 0;
    while ( changes ) {
	passes++;
	changes = 0;
	for ( i = 0 ; i < l->OsdList_len ; i++ ) {
	    struct Osd entry = l->OsdList_val[i];
	    osddb_policy pol = entry.t.etype_u.pol;
	    int index = entry.id % POLINDEX_LEN;
	    struct pol_info *used = NULL, *me = NULL;

	    me = new_index[index];
	    while ( me->id != entry.id )
		me = me->next;
	    
	    if ( me->uses_file_name && me->uses_file_size )
		continue;

	    for ( r = 0 ; r < pol.rules.pol_ruleList_len ; r++ ) {
		pol_rule rule = pol.rules.pol_ruleList_val[r];
		if ( !rule.used_policy )
		    continue;
		used = new_index[rule.used_policy%POLINDEX_LEN];
		while (used && used->id != rule.used_policy)
		    used = used->next;
		if (!used)
		    continue;	/* referencing unknown policy */

		if ( used->uses_file_name && !me->uses_file_name ) {
		    changes = 1;
		    me->uses_file_name = 1;
		    if ( me->uses_file_size )
			break;
		}
		if ( used->uses_file_size && !me->uses_file_size ) {
		    changes = 1;
		    me->uses_file_size = 1;
		    if ( me->uses_file_name )
			break;
		}
	    }
	}
    }
    ViceLog(1, ("needed %d pass%s over policy index\n",
    			passes, passes > 1 ? "es" : ""));

    OSDDB_LOCK;

#ifdef AFS_PTHREAD_ENV
    if ( policy_readers ) {
	OSDDB_POL_LOCK;	/* forbid any new readers */
	OSDDB_WAIT;
	OSDDB_POL_UNLOCK; /* new readers can advance to OSDDB_LOCK now */
    }
#endif

    if ( initialized ) {
	for ( i = 0 ; i < POLINDEX_LEN ; i++ )
	    free_pol_info(pol_index[i]);
    }
    else
	initialized = 1;
    memcpy(pol_index, new_index, sizeof(new_index));
    OSDDB_UNLOCK;
}

void FillPolicyTable(void)
{
    struct OsdList l;
    afs_int32 code;
    afs_uint32 db_revision;

    if (!osddb_client) {
#ifdef BUILDING_CLIENT_COMMAND
        osddb_client = init_osddb_client(cellPtr, 0);
#else
        osddb_client = init_osddb_client(NULL);
#endif
        if (!osddb_client)
            return;
    }

    code = ubik_Call((int(*)(struct rx_connection*,...))OSDDB_GetPoliciesRevision, osddb_client, 0, &db_revision);
    if (code == RXGEN_OPCODE)
            code = ubik_Call((int(*)(struct rx_connection*,...))OSDDB_GetPoliciesRevision68, osddb_client, 0, &db_revision);
    if ( code ) {
        ViceLog(0, ("failed to query for policy revision, error %d\n", code));
        return;
    }
    ViceLog(1, ("OSDDB policy revision: %d, local revision: %d\n", db_revision,
        policies_revision));
    if ( db_revision == policies_revision )
        return;

    l.OsdList_len = 0;
    l.OsdList_val = 0;
    code = ubik_Call((int(*)(struct rx_connection*,...))OSDDB_PolicyList, osddb_client, 0, &l);
    if (code == RXGEN_OPCODE)
        code = ubik_Call((int(*)(struct rx_connection*,...))OSDDB_PolicyList66, osddb_client, 0, &l);
    if (!code) {
        buildPolicyIndex(&l);
        /* the very policy structures are in the new index now */
        if ( l.OsdList_val)
            free(l.OsdList_val);
        OSDDB_LOCK;
        policies_revision = db_revision;
        OSDDB_UNLOCK;
    }
}

/* call these only while holding the OSDDB_LOCK! */
struct pol_info *get_pol_info(afs_uint32 id)
{
    int i;
    struct pol_info *entry;
    if ( !policies_revision ) {
        OSDDB_UNLOCK;
        FillPolicyTable();
        OSDDB_LOCK;
    }

    i = id % POLINDEX_LEN;
    entry = pol_index[i];
    while ( entry != NULL )
        if ( entry->id == id )
            return entry;
        else
            entry = entry->next;
    return NULL;
}

struct osddb_policy *get_pol(afs_uint32 id)
{
    struct pol_info *info = get_pol_info(id);
    if ( !info )
	return NULL;
    return info->pol;
}

afs_int32
policy_uses_file_name(afs_int32 policyIndex)
{
    struct pol_info *entry;
    int result = 0;
    /* policies 0 and 1 are special */
    if ( policyIndex < 2 )
	return 0;
    OSDDB_LOCK;
    if (( entry = get_pol_info(policyIndex) ))
	result = entry->uses_file_name;
    OSDDB_UNLOCK;
    return result;
}

char *sane_size(afs_uint64 size, char *space)
{
    char *units = "BkMGT";
    while ( size > 1024 && *units != 'T' ) {
	units++;
	size >>= 10;
    }
    sprintf(space, "%llu%c", size, *units);
    return space;
}

void print_predicate(pol_pred pred, char *dest)
{
    char buf[24];
    switch(BASE_PREDTYPE(pred.type)) {
	case POLICY_MIN_SIZE:
	    sprintf(dest,"file > %s",sane_size(pred.pol_pred_u.min_size, buf));
	    break;
	case  POLICY_MAX_SIZE:
	    sprintf(dest,"file < %s",sane_size(pred.pol_pred_u.max_size, buf));
	    break;
	case POLICY_EXPR:
	    sprintf(dest, "name matches '%s'", pred.pol_pred_u.expression);
	    break;
	case POLICY_REGEX:
	    sprintf(dest, "name matches /%s/%s",
		pred.pol_pred_u.regex, (pred.type&PREDFLAG_ICASE) ? "i" : "");
	    break;
	case POLICY_USER:
	    sprintf(dest, "user has ID %d", pred.pol_pred_u.user_id);
	    break;
	case POLICY_GROUP:
	    sprintf(dest, "user in group %d", pred.pol_pred_u.group_id);
	    break;
	default:
	    sprintf(dest, "[unsupported predicate: 0x%x]", pred.type);
    }
}

void print_predicate_cryptic(pol_pred pred, char *dest)
{
    char buf[24];
    switch(BASE_PREDTYPE(pred.type)) {
	case POLICY_MIN_SIZE:
	    sprintf(dest,">%s",sane_size(pred.pol_pred_u.min_size, buf));
	    break;
	case  POLICY_MAX_SIZE:
	    sprintf(dest,"<%s",sane_size(pred.pol_pred_u.max_size, buf));
	    break;
	case POLICY_EXPR:
	    sprintf(dest, "~'%s'", pred.pol_pred_u.expression);
	    break;
	case POLICY_REGEX:
	    sprintf(dest, "~/%s/%s",
		pred.pol_pred_u.regex, (pred.type&PREDFLAG_ICASE) ? "i" : "");
	    break;
	case POLICY_USER:
	    sprintf(dest, "uid=%d", pred.pol_pred_u.user_id);
	    break;
	case POLICY_GROUP:
	    sprintf(dest, "gid=%d", pred.pol_pred_u.group_id);
	    break;
	default:
	    sprintf(dest, "ERROR(pred.type=0x%x", pred.type);
    }
}

/* make string representation for a conditional tree
 * returns: pointer to the terminating 0 */
#define OPND c->pol_cond_u.operand
char *condtree_to_string(pol_cond *c, char *dest, 
	char *at,
	void (*pred_printer) (pol_pred,char*),
	char *junctors[])
{
    int i;
    if ( !at )
	at = dest;
    switch ( c->type ) {
    case POLCOND_ATOM:
	pred_printer(c->pol_cond_u.predicate, at);
	at += strlen(at);
	break;
    case POLCOND_NOT:
	strcpy(at, junctors[0]);
	at += strlen(junctors[0]);
	*at++ = ' ';
	if ( OPND->type == POLCOND_AND || OPND->type == POLCOND_OR ) {
	    *at++ = '(';
	    at = condtree_to_string(OPND, dest, at, pred_printer, junctors);
	    *at++ = ')';
	}
	else
	    at = condtree_to_string(OPND, dest, at, pred_printer, junctors);
	break;
    case POLCOND_AND:
    case POLCOND_OR:
	for ( i = 0 ; i < c->pol_cond_u.operands->pol_condList_len ; i++ ) {
	    pol_cond *o= &c->pol_cond_u.operands->pol_condList_val[i];
	    if ( o->type == POLCOND_AND || o->type == POLCOND_OR ) {
		*at++ = '(';
		at = condtree_to_string(o, dest, at, pred_printer, junctors);
		*at++ = ')';
	    }
	    else
		at = condtree_to_string(o, dest, at, pred_printer, junctors);
	    if ( i < c->pol_cond_u.operands->pol_condList_len-1 ) {
		/* junctors if this is not the last operand but one */
		*at++ = ' ';
		strcpy(at, junctors[c->type]);
		at += strlen(junctors[c->type]);
		*at++ = ' ';
	    }
	}
    	break;
    default:
	sprintf(at, "unknown predicate type %d\n", c->type);
	at += strlen(at);
    }
    *at = 0;
    return at;
}
#undef OPND

static int output_format;
static void (*predicate_printers[])(pol_pred,char*) = {
    print_predicate,
    print_predicate,
    print_predicate_cryptic,
    print_predicate_cryptic};
static char **operator_strings[] = {
    juncts, juncts, cryptic_juncts, cryptic_juncts};
static char *empty_predicate[] = {
    "\talways\t", "\talways\t", "\ttrue => ", "\ttrue => "};
static char *predicate_formats[] = {
    "if %s\n\tthen\t", "if %s\n\tthen\t", "\t%s => ", "\t%s => "};
static char *string_osd[] = {
    "create a file in object storage", "osd", "osd", "o" };
static char *string_local[] = {
    "create a regular AFS file", "local", "local", "l" };
static char *string_dynamic[] = {
    "choose storage location dynamically by size", "dynamic", "dynamic", "d" };
static char *seperator[] = {
    "\n\tand\t", ", ", ", ", ""};
static char *location_format[] = { "%s", "location=%s", "location=%s", "%s"};
static char *stripes_format[] = {
    "use %d stripe(s) when using object storage",
    "stripes=%d", "stripes=%d", "%d"};
static char *ssize_format[] = {
    "use stripe size of %d when writing a striped OSD file",
    "stripe_size=%d", "stripe_size=%d", "%d"};
static char *copies_format[] = {
    "write %d file copies when using object storage",
    "copies=%d", "copies=%d", "%d"};
static char *stop_string[] = {
    "abort policy evaluation to enforce settings!", "stop", "stop", "stop" };
static char *continue_string[] = { "", "continue", "continue", "continue" };
static char *ending[] = { "\n", ";\n", ";\n", ";\n" };
void print_policy(struct osddb_policy *pol, int unroll)
{
    int r = 1;
    char buf[1024];

    for ( r = 0 ; r < pol->rules.pol_ruleList_len ; r++ ) {
	pol_rule rule = pol->rules.pol_ruleList_val[r];
	int copies = POLPROP_NCOPIES(rule.properties);
	int stripes = POLPROP_NSTRIPES(rule.properties);
	int use_osd = POLPROP_OSD(rule.properties);
	int use_local = POLPROP_LOCAL(rule.properties);
	int use_dynamic = POLPROP_DYNAMIC(rule.properties);
	int force = POLPROP_FORCE(rule.properties);
	int log2size = POLPROP_SSTRIPES(rule.properties);

	if ( !rule.used_policy ) {
	    if ( rule.condition.type != POLCOND_TRUE ) {
		condtree_to_string(&rule.condition, buf, NULL,
		    predicate_printers[output_format], 
		    operator_strings[output_format]);
		printf(predicate_formats[output_format], buf);
	    }
	    else
		printf("%s", empty_predicate[output_format]);

	    if ( output_format == POL_OUTPUT_TABULAR ) printf("[");
	    if ( use_osd || use_local || use_dynamic ) {
		printf(location_format[output_format],
			    use_osd ? string_osd[output_format]
			    : use_local ? string_local[output_format]
			    : string_dynamic[output_format]);
		if ( stripes || log2size || copies )
		    printf("%s", seperator[output_format]);
	    }
	    if ( output_format == POL_OUTPUT_TABULAR ) printf(",");
	    if ( stripes ) {
		printf(stripes_format[output_format], stripes);
		if ( log2size || copies ) printf("%s", seperator[output_format]);
	    }
	    if ( output_format == POL_OUTPUT_TABULAR ) printf(",");
	    if ( log2size ) {
		printf(ssize_format[output_format], log2size);
		if ( copies ) printf("%s", seperator[output_format]);
	    }
	    if ( output_format == POL_OUTPUT_TABULAR ) printf(",");
	    if ( copies )
		printf(copies_format[output_format], copies);
	    if ( output_format == POL_OUTPUT_TABULAR ) printf("] ");
	    if ( force || output_format != POL_OUTPUT_LONG )
		printf("%s", seperator[output_format]);
	    printf("%s", force ? stop_string[output_format]
			       : continue_string[output_format]);
	    printf("%s", ending[output_format]);
	}
	else
	    if ( unroll ) {
		struct osddb_policy *inner_policy = get_pol(rule.used_policy);
		if ( !inner_policy ) {
		    printf("\tpolicy(id=%d) not found!\n", rule.used_policy);
		    continue;
		}
		print_policy(inner_policy, 1);
	    }
	    else switch(output_format) {
		case 0:
		case 1:
		    printf("\tuse the rules from policy %d\n",rule.used_policy);
		    break;
		default:
		    printf("\tuse(%d);\n", rule.used_policy);
		    break;
	    }
    }
}

void display_policy_by_id(afs_uint32 id, int format, int unroll, struct ubik_client *uc)
{
    struct osddb_policy *pol;
    if ( uc )
	osddb_client = uc;
    pol = get_pol(id);

    if ( !pol ) {
	printf("\tpolicy(id=%d) not found in database!\n", id);
	return;
    }
    output_format = format;
    print_policy(pol, unroll);
}

#define TRACE_POLICY(l) ViceLog(l, ("pol %d --> [%c,%d,%d,%d] %s\n", policyIndex, POLPROP_OSD(*props) ? 'o' : POLPROP_LOCAL(*props) ? 'l' : POLPROP_DYNAMIC(*props) ? 'd' : '?', POLPROP_NSTRIPES(*props), POLPROP_SSTRIPES(*props), POLPROP_NCOPIES(*props), POLPROP_FORCE(*props) ? " STOP" : ""));

afs_int32
eval_condtree(pol_cond *cond, afs_uint64 size, char *fileName, 
	      afs_int32 (*evalclient) (void *rock, afs_int32 user), void *client,
	      int *result)
{
    afs_int32 tcode;
    int i;
    regex_t *regex;
    char *ex;

    if ( cond->type == POLCOND_TRUE ) {
	*result = 1;
	return 0;
    }

    if ( cond->type == POLCOND_ATOM ) {
	pol_pred predicate;
	*result = 1;
	predicate = cond->pol_cond_u.predicate;
	switch (BASE_PREDTYPE(predicate.type)) {
	    case POLICY_MAX_SIZE:
		if ( size > predicate.pol_pred_u.max_size )
		    *result = 0;
		break;
	    case POLICY_MIN_SIZE:
		if ( size < predicate.pol_pred_u.max_size )
		    *result = 0;
		break;
	    case POLICY_EXPR:
		if (fnmatch(predicate.pol_pred_u.expression, fileName, 0) != 0)
		    *result = 0;
		break;
	    case POLICY_REGEX:
	    	/* during annotate_condition, we hid the regex_t here: */
		if ( predicate.type & PREDFLAG_ANNOTATED ) {
		    ex = predicate.pol_pred_u.regex;
		    regex = (regex_t*)(ex + strlen(ex) + 1);
		    tcode = regexec(regex, fileName, 0, NULL, 0);
		    if ( tcode == REG_NOMATCH ) {
			*result = 0;
			break;
		    }
		    if ( tcode == 0 )
			break;
		    ViceLog(0,
			    ("regex matching '%s' =~ /%s/ failed with %d\n",
				    fileName, ex, tcode));
		    return EIO;
		}
		else {
		    ViceLog(0, ("regex was not annotated: /%s/\n",
		    				predicate.pol_pred_u.regex));
		    return EIO;
		}
		break;
	    case POLICY_USER:
	    case POLICY_GROUP:
		if (!(*evalclient)(client, predicate.pol_pred_u.user_id))
		    *result = 0;
		break;
	    default:
		return EINVAL;
	    }
	return 0;
    }

    if ( cond->type == POLCOND_NOT ) {
	tcode = eval_condtree(
		cond->pol_cond_u.operand, size, fileName, 
		evalclient, client, result);
	if ( tcode ) {
	    *result = 0;
	    return tcode;
	}
	*result = !*result;
	return 0;
    }

    if ( cond->type == POLCOND_AND || cond->type == POLCOND_OR ) {
	for ( i = 0 ; i < cond->pol_cond_u.operands->pol_condList_len ; i++ ) {
	    tcode=eval_condtree(&cond->pol_cond_u.operands->pol_condList_val[i],
				    size, fileName, evalclient, client, result);
	    if ( tcode ) {
		*result = 0;
		return tcode;
	    }
	    if ( cond->type == POLCOND_AND && !*result )
		return 0;
	    if ( cond->type == POLCOND_OR && *result )
		return 0;
	}
	return *result;
    }
    return EINVAL; /* ? we should return something here ... */
}

#define UPDATE(P, M) if ( P(rule.properties) ) *props = ( *props & ~M ) | (rule.properties & M)
static afs_int32 do_eval_policy( unsigned int policyIndex, afs_uint64 size,
		    char *fileName, afs_int32 (*evalclient)(void*, afs_int32), void *client,
		     afs_uint32 *props)
{
    osddb_policy *pol = get_pol(policyIndex);
    afs_int32 tcode;
    int r;

    if ( !pol ) {
	ViceLog(0, ("failed to lookup policy %d\n", policyIndex));
	return ENOENT;
    }

    for ( r = 0 ; r < pol->rules.pol_ruleList_len ; r++ ) {
	pol_rule rule = pol->rules.pol_ruleList_val[r];
	int matched = 1;
	if ( rule.used_policy ) {
	    ViceLog(2, ("recursively evaluating policy %d\n", rule.used_policy));
	    tcode = do_eval_policy(
	    		rule.used_policy, size, fileName, evalclient, client, props);
	    ViceLog(2, ("recursion done, props are now 0x%x\n", *props));
	    if ( ( tcode && tcode != ENOENT ) || POLPROP_FORCE(*props) )
		return tcode;
	}
	else {
	    tcode = eval_condtree(&rule.condition, size, fileName, 
				    evalclient, client, &matched);
	    if ( tcode == EINVAL ) {
		ViceLog(0, ("policy %d may contain unknown predicate type\n",
								policyIndex));
	    }
	    if ( tcode )
		return tcode;
	    if ( matched ) {
		ViceLog(2, ("updating: props 0x%x with 0x%x\n", *props, rule.properties));
		UPDATE(POLPROP_LOCATION, POLICY_LOCATION_MASK);
		UPDATE(POLPROP_NSTRIPES, POLICY_NSTRIPES_MASK);
		UPDATE(POLPROP_SSTRIPES, POLICY_SSTRIPES_MASK);
		UPDATE(POLPROP_NCOPIES, POLICY_NCOPIES_MASK);
		UPDATE(POLPROP_FORCE, POLICY_CONT_OP_MASK);
		if ( POLPROP_FORCE(rule.properties) ) {
		    TRACE_POLICY(2);
		    return 0;
		}
	    }
	}
    }

    TRACE_POLICY(2);
    return 0;
}

afs_int32
eval_policy(unsigned int policyIndex, afs_uint64 size, char *fileName,
	afs_int32 (*evalclient) (void *rock, afs_int32 user),
	void *client, afs_uint32 *use_osd, afs_uint32 *dyn_location,
	afs_uint32 *stripes, afs_uint32 *stripe_size, afs_uint32 *copies,
	afs_uint32 *force)
{
    afs_uint32 tcode = 0;
    /* stripes=1, copies=1, stripe_size=12, location=dynamic */
    afs_uint32 props = 
    	*force << 20 | *copies << 16 | *stripe_size << 8 | *stripes << 4 |
	(*use_osd ? POL_LOC_OSD 
		  : *dyn_location ? POL_LOC_DYNAMIC
		  : POL_LOC_LOCAL);

#ifdef AFS_PTHREAD_ENV
    OSDDB_POL_LOCK;
    OSDDB_LOCK;
    policy_readers++;
    OSDDB_UNLOCK;
    OSDDB_POL_UNLOCK;
#endif

    tcode = do_eval_policy(policyIndex, size, fileName, evalclient, client, &props);

    if ( !tcode ) {
	*use_osd = POLPROP_OSD(props);
	*dyn_location = POLPROP_DYNAMIC(props);
	*stripes = POLPROP_NSTRIPES(props);
	*stripe_size = POLPROP_SSTRIPES(props);
	*copies = POLPROP_NCOPIES(props);
	*force = POLPROP_FORCE(props);
    }

#ifdef AFS_PTHREAD_ENV
    OSDDB_LOCK;
    if ( --policy_readers == 0 )
	OSDDB_SIGNAL;	/* free the writer thread, if any */
    OSDDB_UNLOCK;
#endif

    /* silently ignore nonexistent policies */
    if ( tcode == ENOENT )
	return 0;
    return tcode;
}


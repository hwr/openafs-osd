%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <afs/stds.h>
#include <afs/osddb.h>

struct pp_rule {
    pol_cond *condition;
    int use_local, use_osd, use_dynamic, stripes, stripe_size, copies, stop;
    int used_policy;
    struct pp_rule *next;
};

#define ALLOCPRED(T) $<predicate>$ = malloc(sizeof(struct pp_pred)); $<predicate>$->type = (T); $<predicate>$->next = NULL;

void yyerror (char const *);

/* global variables for random access lexing */
char *pp_input = NULL, *pos = NULL;

/* semantic value of the policy goes here */
pol_ruleList *pp_output;

static pol_pred *make_pred(afs_int32 type) {
    pol_pred *result = malloc(sizeof(pol_pred));
    memset(result, 0, sizeof(pol_pred));
    result->type = type;
    return result;
}

/* the predicate constructors use arbitrary union fields of the given type */
static pol_pred *make_num64_pred(afs_int32 type, afs_uint64 num) {
    pol_pred *result = make_pred(type);
    result->pol_pred_u.min_size = num;
    return result;
}
static pol_pred *make_num32_pred(afs_int32 type, afs_int32 num) {
    pol_pred *result = make_pred(type);
    result->pol_pred_u.user_id = num;
    return result;
}
static pol_pred *make_string_pred(afs_int32 type, char *s) {
    pol_pred *result = make_pred(type);
    result->pol_pred_u.regex = s;
    if ( strlen(s) > POLICY_EXPR_MAX-1 )
	return NULL;
    else
	return result;
}
pol_cond *make_atom(pol_pred *p) {
    pol_cond *result = malloc(sizeof(pol_cond));
    memset(result, 0, sizeof(pol_cond));
    result->type = POLCOND_ATOM;
    result->pol_cond_u.predicate = *p;
    return result;
}

struct pol_cond *make_node(afs_uint32 type) {
    pol_cond *result = malloc(sizeof(pol_cond));
    memset(result, 0, sizeof(pol_cond));
    result->type = type;
    if( type == POLCOND_AND || type == POLCOND_OR )
	result->pol_cond_u.operands = malloc(sizeof(pol_condList));
    return result;
}
static struct pol_cond *set_operands(pol_cond *cond, pol_cond *l, pol_cond *r) {
    int len;
    pol_condList *ops = cond->pol_cond_u.operands;
    if ( l->type == cond->type ) {
	len = l->pol_cond_u.operands->pol_condList_len + 1;
	ops->pol_condList_val = malloc(len * sizeof(pol_cond));
	memcpy(ops->pol_condList_val, l->pol_cond_u.operands->pol_condList_val,
		(len-1) * sizeof(pol_cond));
	free(l->pol_cond_u.operands->pol_condList_val);
	free(l->pol_cond_u.operands);
    }
    else {
	len = 2;
	ops->pol_condList_val = malloc(2 * sizeof(pol_cond));
	ops->pol_condList_val[0] = *l;
    }
    ops->pol_condList_len = len;
    cond->pol_cond_u.operands->pol_condList_val[len-1] = *r;
    free(l);
    free(r);
    return cond;
}
static struct pol_cond *set_operand(pol_cond *cond, pol_cond *operand) {
    cond->pol_cond_u.operand = operand;
    return cond;
}
struct pol_cond *make_and(pol_cond *l, pol_cond *r) {
    return set_operands(make_node(POLCOND_AND), l, r);
}
struct pol_cond *make_or(pol_cond *l, pol_cond *r) {
    return set_operands(make_node(POLCOND_OR), l, r);
}
struct pol_cond *make_neg(pol_cond *c) {
    return set_operand(make_node(POLCOND_NOT), c);
}

static struct pp_rule *makeRule() {
    struct pp_rule *result = malloc(sizeof(struct pp_rule));
    memset(result, 0, sizeof(struct pp_rule));
    return result;
}

#define TRY_TAKE(P) if ( setting->P ) dest->P = setting->P
static void updateRule(struct pp_rule *dest, struct pp_rule *setting) {
    TRY_TAKE(use_osd);
    TRY_TAKE(use_local);
    TRY_TAKE(use_dynamic);
    TRY_TAKE(stripes);
    TRY_TAKE(stripe_size);
    TRY_TAKE(copies);
}

void write_rules_reverse(struct pp_rule *list_head, 
				pol_ruleList *target, int count)
{
    int myIndex = count - 1;
    struct pol_rule *myRule;
    if ( list_head->next == NULL ) {
	target->pol_ruleList_len = count;
	target->pol_ruleList_val = malloc(count * sizeof(struct pol_rule));
    }
    else
	write_rules_reverse(list_head->next, target, count+1);

    myIndex = target->pol_ruleList_len - myIndex - 1;
    myRule = &(target->pol_ruleList_val[myIndex]);

    memset(myRule, 0, sizeof(struct pol_rule));
    if ( list_head->used_policy )
	myRule->used_policy = list_head->used_policy;
    else {
	if ( list_head->use_osd )
	    myRule->properties |= POL_LOC_OSD;
	if ( list_head->use_local )
	    myRule->properties |= POL_LOC_LOCAL;
	if ( list_head->use_dynamic )
	    myRule->properties |= POL_LOC_DYNAMIC;
	myRule->properties |= list_head->stop<<20;
	myRule->properties |= list_head->stripes<<4;
	myRule->properties |= list_head->stripe_size<<8;
	myRule->properties |= list_head->copies<<16;
    }

    myRule->condition.type = POLCOND_TRUE;
    if ( list_head->condition )
	myRule->condition = *list_head->condition;
}

void store_result(struct pp_rule *first_rule)
{
    pp_output = malloc(sizeof(pol_ruleList));
    memset(pp_output, 0, sizeof(pol_ruleList));
    if ( first_rule )
	write_rules_reverse(first_rule, pp_output, 1);
}

struct yylloc_type {
    int first_line;
    int first_column;
    int last_line;
    int last_column;
} yylloc;

%}

%union {
    afs_uint64 num64;
    afs_int32 num32;
    char *string;
    struct pol_cond *condition;
    struct pp_rule *rule;
    pol_pred *predicate;
}

%token <num32> TOKEN_STOP "stop"
%token <num32> TOKEN_CONT "continue"

%token <num32> TOKEN_UID "uid="
%token <num32> TOKEN_GID "gid="

%token <num32> TOKEN_USE "use"

%token <num32> TOKEN_OSD "osd"
%token <num32> TOKEN_LOCAL "local"
%token <num32> TOKEN_DYNAMIC "dynamic"

%token <num32> TOKEN_LOCATION
%token <num32> TOKEN_STRIPES
%token <num32> TOKEN_SSIZE
%token <num32> TOKEN_COPIES
%token <num32> TOKEN_NUM

%token <num32> TOKEN_THEN "=>"

%token <string> TOKEN_STRING
%token <string> TOKEN_REGEX

%left '|' 
%left '&'
%nonassoc '!'

%%

policy: rules			{ store_result($<rule>$);}
;

rules: /* empty */		{ $<rule>$ = NULL; }
	| rules rule		{ $<rule>$ = $<rule>2;
					$<rule>$->next = $<rule>1; }
;

rule: 	"use" '(' TOKEN_NUM ')' ';'
	{
	    $<rule>$ = malloc(sizeof(struct pp_rule));
	    memset($<rule>$, 0, sizeof(struct pp_rule));
	    $<rule>$->used_policy = (int)$<num32>3;
	}
	|
	opt_condition "=>" verdict continue_option ';'
	{
	    $<rule>$ = $<rule>3;
	    $<rule>$->next = NULL;
	    $<rule>$->stop = (int)$<num32>4;
	    $<rule>$->condition = $<condition>1;
	}
;

opt_condition: /* empty */	{ $<condition>$ = NULL; }
	| condition		{ $<condition>$ = $<condition>1; }
;

continue_option: /* empty */		{ $<num32>$ = 0; }
	| TOKEN_CONT			{ $<num32>$ = 0; }
	| TOKEN_STOP			{ $<num32>$ = 1; }
;

verdict: '[' opt_location ',' opt_num ',' opt_num ',' opt_num ']'
	{
	    $<rule>$ = makeRule();
	    $<rule>$->use_osd = ($<num32>2 == 1);
	    $<rule>$->use_local = ($<num32>2 == 2);
	    $<rule>$->use_dynamic = ($<num32>2 == 3);
	    $<rule>$->stripes = (int)$<num32>4;
	    $<rule>$->stripe_size = (int)$<num32>6;
	    $<rule>$->copies = (int)$<num32>8;
	    if ( $<num32>4 && $<num32>4 != 1 && $<num32>4 != 2
			&& $<num32>4 != 4 && $<num32>4 != 8 ) {
		fprintf(stderr, "bad number of stripes: %d\n", $<num32>4);
		YYABORT;
	    }
	    if ( $<num32>6 && ( $<num32>6 < 12 || $<num32>6 > 19 ) ) {
		fprintf(stderr, "bad stripe size: %d\n", $<num32>6);
		YYABORT;
	    }
	    if ( $<num32>8 && ( $<num32>8 < 1 || $<num32>8 > 8 ) ) {
		fprintf(stderr, "bad number of copies: %d\n", $<num32>6);
		YYABORT;
	    }
	}
	| property_list
;

property_list:	/* empty */ {
    		$<rule>$ = malloc(sizeof(struct pp_rule));
		memset($<rule>$, 0, sizeof(struct pp_rule));
	    }
	| property_list opt_comma property
		{
		    $<rule>$ = $<rule>1;
		    updateRule($<rule>$, $<rule>3);
		    free($<rule>3);
		}
;

opt_comma: | ','
;

property: loc | stripes | stripe_size | copies
;

loc: opt_location_token location
	{
	    $<rule>$ = makeRule();
	    $<rule>$->use_osd = ($<num32>2 == 1);
	    $<rule>$->use_local = ($<num32>2 == 2);
	    $<rule>$->use_dynamic = ($<num32>2 == 3);
	}
;

stripes: TOKEN_STRIPES TOKEN_NUM
	{
	    if ( $<num32>2 != 1 && $<num32>2 != 2
			&& $<num32>2 != 4 && $<num32>2 != 8 ) {
		yyerror("bad number of stripes");
		YYABORT;
	    }
	    $<rule>$ = makeRule();
	    $<rule>$->stripes = $<num32>2;
	}
;

stripe_size: TOKEN_SSIZE TOKEN_NUM
	{
	    if ( $<num32>2 < 12 || $<num32>2 > 19) {
		yyerror("bad stripe size");
		YYABORT;
	    }
	    $<rule>$ = makeRule();
	    $<rule>$->stripe_size = $<num32>2;
	}
;

copies: TOKEN_COPIES TOKEN_NUM	
	{
	    if ( $<num32>2 < 1 || $<num32>2 > 8) {
		yyerror("bad number of copies");
		YYABORT;
	    }
	    $<rule>$ = makeRule();
	    $<rule>$->copies = $<num32>2;
	}
;

opt_location_token:		{ $<num32>$ = 0; }
	| TOKEN_LOCATION	{ $<num32>$ = $<num32>1;}
;

opt_num: /* empty */		{ $<num32>$ = 0; }
	| TOKEN_NUM		{ $<num32>$ = $1; }
;

opt_location: /* empty */	{ $<num32>$ = 0; }
	| location		{ $<num32>$ = $<num32>1; }
;

location: 'o'			{ $<num32>$ = 1; }
	| "osd"			{ $<num32>$ = 1; }
	| 'l'			{ $<num32>$ = 2; }
	| "local"		{ $<num32>$ = 2; }
	| 'd'			{ $<num32>$ = 3; }
	| "dynamic"		{ $<num32>$ = 3; }
;

condition: '!' condition	{ $<condition>$ = make_neg($<condition>2); }
	| '(' condition ')'	{ $<condition>$ = $<condition>2; }
	| condition '&' condition { $<condition>$ = make_and(
					$<condition>1, $<condition>3); }
	| condition '|' condition { $<condition>$ = make_or(
					$<condition>1, $<condition>3); }
	| predicate		{ $<condition>$ = make_atom($<predicate>1); }
;

	/* bison macros would have been nice for this, but alas: */
predicate:
	  '>' size
	  	{ $<predicate>$ = make_num64_pred(POLICY_MIN_SIZE, $<num64>2); }
	| '<' size
		{ $<predicate>$ = make_num64_pred(POLICY_MAX_SIZE, $<num64>2); }
	| '~' TOKEN_STRING
		{
		    $<predicate>$ = make_string_pred(POLICY_EXPR, $<string>2);
		    if ( ! $<predicate>$ ) {
			yyerror("expression too long");
			YYABORT;
		    }
	        }
	| '~' TOKEN_REGEX
		{
		    $<predicate>$ = make_string_pred(POLICY_REGEX, $<string>2);
		    if ( ! $<predicate>$ ) {
			yyerror("expression too long");
			YYABORT;
		    }
	        }
	| '~' TOKEN_REGEX 'i'
		{
		    $<predicate>$ = make_string_pred(POLICY_IREGEX, $<string>2);
		    if ( ! $<predicate>$ ) {
			yyerror("expression too long");
			YYABORT;
		    }
	        }
	| "uid=" TOKEN_NUM
		{ $<predicate>$ = make_num32_pred(POLICY_USER, $<num32>2); }
	| "gid=" TOKEN_NUM
		{ $<predicate>$ = make_num32_pred(POLICY_GROUP, $<num32>2); }
;

size: TOKEN_NUM unit /* TODO IS THIS SAFE IN BIG ENDIAN? XXX XXX */
	{ $<num64>$ = ((afs_uint64)$<num32>1) * $<num64>2; }
;

unit: /* empty */ 		{ $<num64>$ = 1; }
	| 'b'			{ $<num64>$ = 1; }
	| 'B'			{ $<num64>$ = 1; }
	| 'k' 			{ $<num64>$ = 1<<10; }
	| 'K' 			{ $<num64>$ = 1<<10; }
	| 'm' 			{ $<num64>$ = 1<<20; }
	| 'M' 			{ $<num64>$ = 1<<20; }
	| 'g' 			{ $<num64>$ = 1<<30; }
	| 'G' 			{ $<num64>$ = 1<<30; }
	| 't' 			{ $<num64>$ = ((afs_int64)1)<<40; }
	| 'T'			{ $<num64>$ = ((afs_int64)1)<<40; }
;

%%

#define POP_TOKEN(T,n) { yylval.num32 = 1; pos += (n); yylloc.last_column += (n); return (T); }
#define TRY_POP_TOKEN(T,s,n) if ( strncmp(pos, s, n) == 0 ) POP_TOKEN(T,n)

int
yylex()
{
    int len;
    char quote;

    /* first call */
    if ( pos == NULL )
	pos = pp_input;
    /* last call */
    if ( *pos == '\0' )
	return 0;

    while ( *pos != '\0' ) {
	yylloc.first_column = yylloc.last_column = pos - pp_input;
	switch ( *pos ) {
			    /* whitespace - skipped */
	    case ' ':
	    case '\t':
	    case '\n':
	    	pos++;
	    	break;
			    /* literal numbers */
	    case '-':
	    case '0':
	    case '1':
	    case '2':
	    case '3':
	    case '4':
	    case '5':
	    case '6':
	    case '7':
	    case '8':
	    case '9':
	    	if ( *pos == '-' && (pos[1] < '0' || pos[1] > '9') )
		    continue;
		yylval.num32 = atol(pos++);
		yylloc.last_column++;
		while ( *pos >= '0' && *pos <= '9' ) {
		    pos++;
		    yylloc.last_column++;
		}
		return TOKEN_NUM;
			    /* reserved words */
	    case 'u':
		TRY_POP_TOKEN(TOKEN_UID, "uid=", 4);
		TRY_POP_TOKEN(TOKEN_USE, "use", 3);
		return (unsigned char)*pos++;
	    case 'g':
		TRY_POP_TOKEN(TOKEN_GID, "gid=", 4);
		return (unsigned char)*pos++;
	    case 's':
		TRY_POP_TOKEN(TOKEN_STOP, "stop", 4);
	    	TRY_POP_TOKEN(TOKEN_STRIPES, "s=", 2);
	    	TRY_POP_TOKEN(TOKEN_STRIPES, "str=", 4);
	    	TRY_POP_TOKEN(TOKEN_STRIPES, "stripes=", 8);
	    	TRY_POP_TOKEN(TOKEN_SSIZE, "ss=", 3);
	    	TRY_POP_TOKEN(TOKEN_SSIZE, "ssize=", 6);
	    	TRY_POP_TOKEN(TOKEN_SSIZE, "stripe_size=", 12);
		return (unsigned char)*pos++;
	    case 'c':
		TRY_POP_TOKEN(TOKEN_CONT, "continue", 8);
		TRY_POP_TOKEN(TOKEN_CONT, "cont", 4);
	    	TRY_POP_TOKEN(TOKEN_COPIES, "c=", 2);
	    	TRY_POP_TOKEN(TOKEN_COPIES, "copies=", 7);
		return (unsigned char)*pos++;
	    case 'l':
	    	TRY_POP_TOKEN(TOKEN_LOCATION, "l=", 2);
	    	TRY_POP_TOKEN(TOKEN_LOCATION, "loc=", 4);
	    	TRY_POP_TOKEN(TOKEN_LOCATION, "location=", 9);
	    	TRY_POP_TOKEN(TOKEN_LOCAL, "local", 5);
		return (unsigned char)*pos++;
	    case 'o':
	    	TRY_POP_TOKEN(TOKEN_OSD, "osd", 3);
		return (unsigned char)*pos++;
	    case 'd':
	    	TRY_POP_TOKEN(TOKEN_DYNAMIC, "dynamic", 7);
		return (unsigned char)*pos++;
	    case '=':
	    	TRY_POP_TOKEN(TOKEN_THEN, "=>", 2);
		return (unsigned char)*pos++;
	    case '&':	/* eat up to two of these */
	    case '|':
	    	yylloc.last_column++;
		if ( pos[0] == pos[1] ) {
		    pos++;
		    yylloc.last_column++;
		}
		return (unsigned char)*pos++;
			    /* quoted strings */
	    case '\'':
	    case '"':
	    	quote = *pos;
	    	for ( len = 1 ; 1 ; len++ ) {
		    if ( pos[len] == '\0' ) {
			yylval.string = strdup(pos);
			pos += len;
			yylloc.last_column += len;
			return TOKEN_STRING;
		    }
		    if ( (pos[len] == quote && pos[len+1] == quote) ||
			 (pos[len] == '\\' && pos[len+1] == quote) ) {
			len++;
			continue;
		    }
		    /* this is now known not to be escaped */
		    if ( pos[len] == quote ) {
			len++;	/* include closing ' */
			break;
		    }
		}
		yylval.string = malloc(len-1);
		strncpy(yylval.string, pos+1, len-2);
		yylval.string[len-2] = '\0';
		pos += len;
		yylloc.last_column += len;
		return TOKEN_STRING;
	    case '/':
	    	for ( len = 1 ; 1 ; len++ ) {
		    if ( pos[len] == '\0' ) {
			yylval.string = strdup(pos);
			pos += len;
			yylloc.last_column += len;
			return TOKEN_REGEX;
		    }
		    if ( pos[len] == '\\' && pos[len+1] == '/' ) {
			len++;
			continue;
		    }
		    if ( pos[len] == '/' ) {
			len++;
			break;
		    }
		}
		yylval.string = malloc(len-1);
		strncpy(yylval.string, pos+1, len-2);
		yylval.string[len-2] = '\0';
		pos += len;
		yylloc.last_column += len;
		return TOKEN_REGEX;
			    /* default: just return the character */
	    default:
		return (unsigned char)*pos++;
	}
    }
    return 0;
}

void yyerror (char const *s)
{
    char save, i;
    int loc_save = yylloc.last_column;
    if ( yylloc.last_column == yylloc.first_column )
	for ( i = 0 ; i < 4 ; i++ )
	    if ( pp_input[++yylloc.last_column] == '\0' )
		break;
    save = pp_input[yylloc.last_column];
    pp_input[yylloc.last_column] = 0;
    fprintf (stderr, "%s near `%s'%s (0.%d-%d)\n", s, 
    	pp_input + yylloc.first_column, 
	yylloc.last_column == loc_save ? "" : "...",
	yylloc.first_column, yylloc.last_column);
    pp_input[yylloc.last_column] = save;
    yylloc.last_column = loc_save;
}

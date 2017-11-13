
/*  A Bison parser, made from error_table.y with Bison version GNU Bison version 1.24
  */

#define YYBISON 1		/* Identify Bison output.  */

#define	ERROR_TABLE	258
#define	ERROR_CODE_ENTRY	259
#define	END	260
#define	STRING	261
#define	QUOTED_STRING	262

#line 1 "error_table.y"

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>


/*
 * If __STDC__ is defined, function prototypes in the SunOS 5.5.1 lex
 * and yacc templates are visible.  We turn this on explicitly on
 * NT because the prototypes help supress certain warning from the
 * Microsoft C compiler.
 */

#ifdef AFS_NT40_ENV
#include <malloc.h>
# ifndef __STDC__
#  define __STDC__ 1
# endif
#endif

#include "internal.h"

char *current_token = NULL;
extern char *table_name;

char *quote(const char *string);
void set_table_1num(char *string);
int char_to_1num(char c);
void add_ec(const char *name, const char *description);
void add_ec_val(const char *name, const char *val, const char *description);
void put_ecs(void);
void set_table_num(char *string);
void set_table_fun(char *astring);


#line 38 "error_table.y"
typedef union {
    char *dynstr;
} YYSTYPE;
#line 45 "error_table.y"


#ifndef YYLTYPE
typedef
    struct yyltype {
    int timestamp;
    int first_line;
    int first_column;
    int last_line;
    int last_column;
    char *text;
} yyltype;

#define YYLTYPE yyltype
#endif

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		24
#define	YYFLAG		-32768
#define	YYNTBASE	10

#define YYTRANSLATE(x) ((unsigned)(x) <= 262 ? yytranslate[x] : 18)

static const char yytranslate[] = { 0,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 8, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    9, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 1, 2, 3, 4, 5,
    6, 7
};

#if YYDEBUG != 0
static const short yyprhs[] = { 0,
    0, 5, 8, 10, 12, 14, 17, 19, 24, 31,
    33
};

static const short yyrhs[] = { 3,
    11, 14, 5, 0, 12, 13, 0, 13, 0, 6,
    0, 6, 0, 14, 15, 0, 15, 0, 4, 16,
    8, 17, 0, 4, 16, 9, 6, 8, 17, 0,
    6, 0, 7, 0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
    50, 56, 59, 66, 73, 79, 80, 83, 87, 95,
    100
};

static const char *const yytname[] =
    { "$", "error", "$undefined.", "ERROR_TABLE",
    "ERROR_CODE_ENTRY", "END", "STRING", "QUOTED_STRING", "','", "'='",
    "error_table",
    "header", "table_fun", "table_id", "error_codes", "ec_entry", "ec_name",
    "description",
    ""
};
#endif

static const short yyr1[] = { 0,
    10, 11, 11, 12, 13, 14, 14, 15, 15, 16,
    17
};

static const short yyr2[] = { 0,
    4, 2, 1, 1, 1, 2, 1, 4, 6, 1,
    1
};

static const short yydefact[] = { 0,
    0, 4, 0, 0, 3, 0, 0, 7, 5, 2,
    10, 0, 1, 6, 0, 0, 11, 8, 0, 0,
    9, 0, 0, 0
};

static const short yydefgoto[] = { 22,
    3, 4, 5, 7, 8, 12, 18
};

static const short yypact[] = { 1,
    -1, 2, 3, 4, -32768, 5, -4, -32768, -32768, -32768,
    -32768, -6, -32768, -32768, 6, 8, -32768, -32768, 0, 6,
    -32768, 9, 12, -32768
};

static const short yypgoto[] = { -32768,
    -32768, -32768, 11, -32768, 10, -32768, -2
};


#define	YYLAST		18


static const short yytable[] = { 6,
    13, 15, 16, 1, 2, -5, 6, 20, 23, 9,
    11, 24, 17, 19, 10, 0, 14, 21
};

static const short yycheck[] = { 4,
    5, 8, 9, 3, 6, 4, 4, 8, 0, 6,
    6, 0, 7, 6, 4, -1, 7, 20
};

/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "bison.simple"

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

#ifndef alloca
#ifdef __GNUC__
#define alloca __builtin_alloca
#else /* not GNU C.  */
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__) || defined (__sparc) || defined (__sgi)
#include <alloca.h>
#else /* not sparc */
#if defined (MSDOS) && !defined (__TURBOC__)
#include <malloc.h>
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
#include <malloc.h>
#pragma alloca
#else /* not MSDOS, __TURBOC__, or _AIX */
#ifdef __hpux
#ifdef __cplusplus
extern "C" {
    void *alloca(unsigned int);
};
#else /* not __cplusplus */
void *alloca();
#endif /* not __cplusplus */
#endif /* __hpux */
#endif /* not _AIX */
#endif /* not MSDOS, or __TURBOC__ */
#endif /* not sparc.  */
#endif /* not GNU C.  */
#endif /* alloca not defined.  */

/* This is the parser code that is written into each bison parser
  when the %semantic_parser declaration is not specified in the grammar.
  It was written by Richard Stallman by simplifying the hairy parser
  used when %semantic_parser is specified.  */

/* Note: there must be only one dollar sign in this file.
   It is replaced by the list of actions, each action
   as one case of the switch.  */

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	return(0)
#define YYABORT 	return(1)
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.
   This remains here temporarily to ease the
   transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(token, value) \
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    { yychar = (token), yylval = (value);			\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { yyerror ("syntax error: cannot back up"); YYERROR; }	\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

#ifndef YYPURE
#define YYLEX		yylex()
#endif

#ifdef YYPURE
#ifdef YYLSP_NEEDED
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, &yylloc, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval, &yylloc)
#endif
#else /* not YYLSP_NEEDED */
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval)
#endif
#endif /* not YYLSP_NEEDED */
#endif

/* If nonreentrant, generate the variables here */

#ifndef YYPURE

int yychar;			/*  the lookahead symbol                */
YYSTYPE yylval;			/*  the semantic value of the           */
				/*  lookahead symbol                    */

#ifdef YYLSP_NEEDED
YYLTYPE yylloc;			/*  location data for the lookahead     */
				/*  symbol                              */
#endif

int yynerrs;			/*  number of parse errors so far       */
#endif /* not YYPURE */

#if YYDEBUG != 0
int yydebug;			/*  nonzero means print parse trace     */
/* Since this is uninitialized, it does not stop multiple parsers
   from coexisting.  */
#endif

/*  YYINITDEPTH indicates the initial size of the parser's stacks	*/

#ifndef	YYINITDEPTH
#define YYINITDEPTH 200
#endif

/*  YYMAXDEPTH is the maximum size the stacks can grow to
    (effective only if the built-in stack extension method is used).  */

#if YYMAXDEPTH == 0
#undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 10000
#endif

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
int yyparse(void);
#endif

#if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#define __yy_memcpy(FROM,TO,COUNT)	__builtin_memcpy(TO,FROM,COUNT)
#else /* not GNU C or C++ */
#ifndef __cplusplus

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy(from, to, count)
     char *from;
     char *to;
     int count;
{
    char *f = from;
    char *t = to;
    int i = count;

    while (i-- > 0)
	*t++ = *f++;
}

#else /* __cplusplus */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy(char *from, char *to, int count)
{
    char *f = from;
    char *t = to;
    int i = count;

    while (i-- > 0)
	*t++ = *f++;
}

#endif
#endif

#line 192 "bison.simple"

/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
#define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
#else
#define YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#endif

int
yyparse(YYPARSE_PARAM)
    YYPARSE_PARAM_DECL
{
    int yystate;
    int yyn;
    short *yyssp;
    YYSTYPE *yyvsp;
    int yyerrstatus;		/*  number of tokens to shift before error messages enabled */
    int yychar1 = 0;		/*  lookahead token as an internal (translated) token number */

    short yyssa[YYINITDEPTH];	/*  the state stack                     */
    YYSTYPE yyvsa[YYINITDEPTH];	/*  the semantic value stack            */

    short *yyss = yyssa;	/*  refer to the stacks thru separate pointers */
    YYSTYPE *yyvs = yyvsa;	/*  to allow yyoverflow to reallocate them elsewhere */

#ifdef YYLSP_NEEDED
    YYLTYPE yylsa[YYINITDEPTH];	/*  the location stack                  */
    YYLTYPE *yyls = yylsa;
    YYLTYPE *yylsp;

#define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
#define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

    int yystacksize = YYINITDEPTH;

#ifdef YYPURE
    int yychar;
    YYSTYPE yylval;
    int yynerrs;
#ifdef YYLSP_NEEDED
    YYLTYPE yylloc;
#endif
#endif

    YYSTYPE yyval;		/*  the variable used to return         */
    /*  semantic values from the action     */
    /*  routines                            */

    int yylen;

#if YYDEBUG != 0
    if (yydebug)
	fprintf(stderr, "Starting parse\n");
#endif

    yystate = 0;
    yyerrstatus = 0;
    yynerrs = 0;
    yychar = YYEMPTY;		/* Cause a token to be read.  */

    /* Initialize stack pointers.
     * Waste one element of value and location stack
     * so that they stay on the same level as the state stack.
     * The wasted elements are never initialized.  */

    yyssp = yyss - 1;
    yyvsp = yyvs;
#ifdef YYLSP_NEEDED
    yylsp = yyls;
#endif

/* Push a new state, which is found in  yystate  .  */
/* In all cases, when you get here, the value and location stacks
   have just been pushed. so pushing a state here evens the stacks.  */
  yynewstate:

    *++yyssp = yystate;

    if (yyssp >= yyss + yystacksize - 1) {
	/* Give user a chance to reallocate the stack */
	/* Use copies of these so that the &'s don't force the real ones into memory. */
	YYSTYPE *yyvs1 = yyvs;
	short *yyss1 = yyss;
#ifdef YYLSP_NEEDED
	YYLTYPE *yyls1 = yyls;
#endif

	/* Get the current used size of the three stacks, in elements.  */
	int size = yyssp - yyss + 1;

#ifdef yyoverflow
	/* Each stack pointer address is followed by the size of
	 * the data in use in that stack, in bytes.  */
#ifdef YYLSP_NEEDED
	/* This used to be a conditional around just the two extra args,
	 * but that might be undefined if yyoverflow is a macro.  */
	yyoverflow("parser stack overflow", &yyss1, size * sizeof(*yyssp),
		   &yyvs1, size * sizeof(*yyvsp), &yyls1,
		   size * sizeof(*yylsp), &yystacksize);
#else
	yyoverflow("parser stack overflow", &yyss1, size * sizeof(*yyssp),
		   &yyvs1, size * sizeof(*yyvsp), &yystacksize);
#endif

	yyss = yyss1;
	yyvs = yyvs1;
#ifdef YYLSP_NEEDED
	yyls = yyls1;
#endif
#else /* no yyoverflow */
	/* Extend the stack our own way.  */
	if (yystacksize >= YYMAXDEPTH) {
	    yyerror("parser stack overflow");
	    return 2;
	}
	yystacksize *= 2;
	if (yystacksize > YYMAXDEPTH)
	    yystacksize = YYMAXDEPTH;
	yyss = (short *)alloca(yystacksize * sizeof(*yyssp));
	__yy_memcpy((char *)yyss1, (char *)yyss, size * sizeof(*yyssp));
	yyvs = (YYSTYPE *) alloca(yystacksize * sizeof(*yyvsp));
	__yy_memcpy((char *)yyvs1, (char *)yyvs, size * sizeof(*yyvsp));
#ifdef YYLSP_NEEDED
	yyls = (YYLTYPE *) alloca(yystacksize * sizeof(*yylsp));
	__yy_memcpy((char *)yyls1, (char *)yyls, size * sizeof(*yylsp));
#endif
#endif /* no yyoverflow */

	yyssp = yyss + size - 1;
	yyvsp = yyvs + size - 1;
#ifdef YYLSP_NEEDED
	yylsp = yyls + size - 1;
#endif

#if YYDEBUG != 0
	if (yydebug)
	    fprintf(stderr, "Stack size increased to %d\n", yystacksize);
#endif

	if (yyssp >= yyss + yystacksize - 1)
	    YYABORT;
    }
#if YYDEBUG != 0
    if (yydebug)
	fprintf(stderr, "Entering state %d\n", yystate);
#endif

    goto yybackup;
  yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

    /* First try to decide what to do without reference to lookahead token.  */

    yyn = yypact[yystate];
    if (yyn == YYFLAG)
	goto yydefault;

    /* Not known => get a lookahead token if don't already have one.  */

    /* yychar is either YYEMPTY or YYEOF
     * or a valid token in external form.  */

    if (yychar == YYEMPTY) {
#if YYDEBUG != 0
	if (yydebug)
	    fprintf(stderr, "Reading a token: ");
#endif
	yychar = YYLEX;
    }

    /* Convert token to internal form (in yychar1) for indexing tables with */

    if (yychar <= 0) {		/* This means end of input. */
	yychar1 = 0;
	yychar = YYEOF;		/* Don't call YYLEX any more */

#if YYDEBUG != 0
	if (yydebug)
	    fprintf(stderr, "Now at end of input.\n");
#endif
    } else {
	yychar1 = YYTRANSLATE(yychar);

#if YYDEBUG != 0
	if (yydebug) {
	    fprintf(stderr, "Next token is %d (%s", yychar, yytname[yychar1]);
	    /* Give the individual parser a way to print the precise meaning
	     * of a token, for further debugging info.  */
#ifdef YYPRINT
	    YYPRINT(stderr, yychar, yylval);
#endif
	    fprintf(stderr, ")\n");
	}
#endif
    }

    yyn += yychar1;
    if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
	goto yydefault;

    yyn = yytable[yyn];

    /* yyn is what to do for this token type in this state.
     * Negative => reduce, -yyn is rule number.
     * Positive => shift, yyn is new state.
     * New state is final state => don't bother to shift,
     * just return success.
     * 0, or most negative number => error.  */

    if (yyn < 0) {
	if (yyn == YYFLAG)
	    goto yyerrlab;
	yyn = -yyn;
	goto yyreduce;
    } else if (yyn == 0)
	goto yyerrlab;

    if (yyn == YYFINAL)
	YYACCEPT;

    /* Shift the lookahead token.  */

#if YYDEBUG != 0
    if (yydebug)
	fprintf(stderr, "Shifting token %d (%s), ", yychar, yytname[yychar1]);
#endif

    /* Discard the token being shifted unless it is eof.  */
    if (yychar != YYEOF)
	yychar = YYEMPTY;

    *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
    *++yylsp = yylloc;
#endif

    /* count tokens shifted since error; after three, turn off error status.  */
    if (yyerrstatus)
	yyerrstatus--;

    yystate = yyn;
    goto yynewstate;

/* Do the default action for the current state.  */
  yydefault:

    yyn = yydefact[yystate];
    if (yyn == 0)
	goto yyerrlab;

/* Do a reduction.  yyn is the number of a rule to reduce with.  */
  yyreduce:
    yylen = yyr2[yyn];
    if (yylen > 0)
	yyval = yyvsp[1 - yylen];	/* implement default value of the action */

#if YYDEBUG != 0
    if (yydebug) {
	int i;

	fprintf(stderr, "Reducing via rule %d (line %d), ", yyn,
		yyrline[yyn]);

	/* Print the symbols being reduced, and their result.  */
	for (i = yyprhs[yyn]; yyrhs[i] > 0; i++)
	    fprintf(stderr, "%s ", yytname[yyrhs[i]]);
	fprintf(stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif


    switch (yyn) {

    case 1:
#line 51 "error_table.y"
	{
	    table_name = strdup(yyvsp[-2].dynstr);
	    current_token = table_name;
	    put_ecs();;
	    break;
	}
    case 2:
#line 57 "error_table.y"
	{
	    current_token = yyvsp[-1].dynstr;
	    yyval.dynstr = yyvsp[0].dynstr;;
	    break;
	}
    case 3:
#line 60 "error_table.y"
	{
	    current_token = yyvsp[0].dynstr;
	    set_table_fun(strdup("1"));
	    yyval.dynstr = yyvsp[0].dynstr;
	    ;
	    break;
	}
    case 4:
#line 67 "error_table.y"
	{
	    current_token = yyvsp[0].dynstr;
	    set_table_fun(yyvsp[0].dynstr);
	    yyval.dynstr = yyvsp[0].dynstr;;
	    break;
	}
    case 5:
#line 74 "error_table.y"
	{
	    current_token = yyvsp[0].dynstr;
	    set_table_num(yyvsp[0].dynstr);
	    yyval.dynstr = yyvsp[0].dynstr;;
	    break;
	}
    case 8:
#line 84 "error_table.y"
	{
	    add_ec(yyvsp[-2].dynstr, yyvsp[0].dynstr);
	    free(yyvsp[-2].dynstr);
	    free(yyvsp[0].dynstr);;
	    break;
	}
    case 9:
#line 88 "error_table.y"
	{
	    add_ec_val(yyvsp[-4].dynstr, yyvsp[-2].dynstr, yyvsp[0].dynstr);
	    free(yyvsp[-4].dynstr);
	    free(yyvsp[-2].dynstr);
	    free(yyvsp[0].dynstr);
	    ;
	    break;
	}
    case 10:
#line 96 "error_table.y"
	{
	    yyval.dynstr = strdup(yyvsp[0].dynstr);
	    current_token = yyval.dynstr;;
	    break;
	}
    case 11:
#line 101 "error_table.y"
	{
	    yyval.dynstr = strdup(yyvsp[0].dynstr);
	    current_token = yyval.dynstr;;
	    break;
	}
    }
    /* the action file gets copied in in place of this dollarsign */
#line 487 "bison.simple"

    yyvsp -= yylen;
    yyssp -= yylen;
#ifdef YYLSP_NEEDED
    yylsp -= yylen;
#endif

#if YYDEBUG != 0
    if (yydebug) {
	short *ssp1 = yyss - 1;
	fprintf(stderr, "state stack now");
	while (ssp1 != yyssp)
	    fprintf(stderr, " %d", *++ssp1);
	fprintf(stderr, "\n");
    }
#endif

    *++yyvsp = yyval;

#ifdef YYLSP_NEEDED
    yylsp++;
    if (yylen == 0) {
	yylsp->first_line = yylloc.first_line;
	yylsp->first_column = yylloc.first_column;
	yylsp->last_line = (yylsp - 1)->last_line;
	yylsp->last_column = (yylsp - 1)->last_column;
	yylsp->text = 0;
    } else {
	yylsp->last_line = (yylsp + yylen - 1)->last_line;
	yylsp->last_column = (yylsp + yylen - 1)->last_column;
    }
#endif

    /* Now "shift" the result of the reduction.
     * Determine what state that goes to,
     * based on the state we popped back to
     * and the rule number reduced by.  */

    yyn = yyr1[yyn];

    yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
    if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
	yystate = yytable[yystate];
    else
	yystate = yydefgoto[yyn - YYNTBASE];

    goto yynewstate;

  yyerrlab:			/* here on detecting error */

    if (!yyerrstatus)
	/* If not already recovering from an error, report this error.  */
    {
	++yynerrs;

#ifdef YYERROR_VERBOSE
	yyn = yypact[yystate];

	if (yyn > YYFLAG && yyn < YYLAST) {
	    int size = 0;
	    char *msg;
	    int x, count;

	    count = 0;
	    /* Start X at -yyn if nec to avoid negative indexes in yycheck.  */
	    for (x = (yyn < 0 ? -yyn : 0);
		 x < (sizeof(yytname) / sizeof(char *)); x++)
		if (yycheck[x + yyn] == x)
		    size += strlen(yytname[x]) + 15, count++;
	    msg = malloc(size + 15);
	    if (msg != 0) {
		strcpy(msg, "parse error");

		if (count < 5) {
		    count = 0;
		    for (x = (yyn < 0 ? -yyn : 0);
			 x < (sizeof(yytname) / sizeof(char *)); x++)
			if (yycheck[x + yyn] == x) {
			    strcat(msg,
				   count == 0 ? ", expecting `" : " or `");
			    strcat(msg, yytname[x]);
			    strcat(msg, "'");
			    count++;
			}
		}
		yyerror(msg);
		free(msg);
	    } else
		yyerror("parse error; also virtual memory exceeded");
	} else
#endif /* YYERROR_VERBOSE */
	    yyerror("parse error");
    }

    goto yyerrlab1;
  yyerrlab1:			/* here on error raised explicitly by an action */

    if (yyerrstatus == 3) {
	/* if just tried and failed to reuse lookahead token after an error, discard it.  */

	/* return failure if at end of input */
	if (yychar == YYEOF)
	    YYABORT;

#if YYDEBUG != 0
	if (yydebug)
	    fprintf(stderr, "Discarding token %d (%s).\n", yychar,
		    yytname[yychar1]);
#endif

	yychar = YYEMPTY;
    }

    /* Else will try to reuse lookahead token
     * after shifting the error token.  */

    yyerrstatus = 3;		/* Each real token shifted decrements this */

    goto yyerrhandle;

  yyerrdefault:		/* current state does not do anything special for the error token. */

#if 0
    /* This is wrong; only states that explicitly want error tokens
     * should shift them.  */
    yyn = yydefact[yystate];	/* If its default is to accept any token, ok.  Otherwise pop it. */
    if (yyn)
	goto yydefault;
#endif

  yyerrpop:			/* pop the current state because it cannot handle the error token */

    if (yyssp == yyss)
	YYABORT;
    yyvsp--;
    yystate = *--yyssp;
#ifdef YYLSP_NEEDED
    yylsp--;
#endif

#if YYDEBUG != 0
    if (yydebug) {
	short *ssp1 = yyss - 1;
	fprintf(stderr, "Error: state stack now");
	while (ssp1 != yyssp)
	    fprintf(stderr, " %d", *++ssp1);
	fprintf(stderr, "\n");
    }
#endif

  yyerrhandle:

    yyn = yypact[yystate];
    if (yyn == YYFLAG)
	goto yyerrdefault;

    yyn += YYTERROR;
    if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
	goto yyerrdefault;

    yyn = yytable[yyn];
    if (yyn < 0) {
	if (yyn == YYFLAG)
	    goto yyerrpop;
	yyn = -yyn;
	goto yyreduce;
    } else if (yyn == 0)
	goto yyerrpop;

    if (yyn == YYFINAL)
	YYACCEPT;

#if YYDEBUG != 0
    if (yydebug)
	fprintf(stderr, "Shifting error token, ");
#endif

    *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
    *++yylsp = yylloc;
#endif

    yystate = yyn;
    goto yynewstate;
}

#line 105 "error_table.y"

/*
 *
 * Copyright 1986, 1987 by the MIT Student Information Processing Board
 *
 * For copyright info, see mit-sipb-cr.h.
 */
#include <afs/param.h>
#include <assert.h>
#include <ctype.h>
#ifdef AFS_NT40_ENV
#include <afs/afsutil.h>
#endif
#include <sys/timeb.h>
#include "error_table.h"
#include "mit-sipb-cr.h"

/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

extern FILE *hfile, *cfile, *msfile;
extern int use_msf;

static afs_int32 gensym_n = 0;

char *
gensym(const char *x)
{
    char *symbol;
    if (!gensym_n) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	gensym_n = (tv.tv_sec % 10000) * 100 + tv.tv_usec / 10000;
    }
    symbol = malloc(32 * sizeof(char));
    gensym_n++;
    sprintf(symbol, "et%ld", gensym_n);
    return (symbol);
}

char *
quote(const char *string)
{
    char *rv;
    rv = (char *)malloc(strlen(string) + 3);
    strcpy(rv, "\"");
    strcat(rv, string);
    strcat(rv, "\"");
    return (rv);
}

afs_int32 table_number = 0;
int current = 0;
char **error_codes = NULL;

void
add_ec(const char *name, const char *description)
{
    if (msfile) {
	if (current > 0)
#ifndef sun
	    fprintf(msfile, "%d\t%s\n", current, description);
#else
	    fprintf(msfile, "%d %s\n", current, description);
#endif /* !sun */
    } else if (cfile) {
	fprintf(cfile, "\t\"%s\",\n", description);
    }
    if (error_codes == NULL) {
	error_codes = malloc(sizeof(char *));
	*error_codes = NULL;
    }
    error_codes = realloc(error_codes, (current + 2) * sizeof(char *));
    error_codes[current++] = strdup(name);
    error_codes[current] = NULL;
}

void
add_ec_val(const char *name, const char *val, const char *description)
{
    const int ncurrent = atoi(val);
    if (ncurrent < current) {
	printf("Error code %s (%d) out of order", name, current);
	return;
    }

    while (ncurrent > current) {
	if (cfile)
	    fputs("\tNULL,\n", cfile);
	current++;
    }
    if (msfile) {
	if (current > 0)
#ifndef sun
	    fprintf(msfile, "%d\t%s\n", current, description);
#else
	    fprintf(msfile, "%d %s\n", current, description);
#endif /* ! sun */
    } else if (cfile) {
	fprintf(cfile, "\t\"%s\",\n", description);
    }
    if (error_codes == NULL) {
	error_codes = malloc(sizeof(char *));
	*error_codes = NULL;
    }
    error_codes = realloc(error_codes, (current + 2) * sizeof(char *));
    error_codes[current++] = strdup(name);
    error_codes[current] = NULL;
}

void
put_ecs(void)
{
    int i;
    if (!hfile)
        return;
    for (i = 0; i < current; i++) {
	if (error_codes[i] != NULL)
	    fprintf(hfile, "#define %-40s (%ldL)\n", error_codes[i],
		    table_number + i);
    }
}

/*
 * char_to_num -- maps letters and numbers into a small numbering space
 * 	uppercase ->  1-26
 *	lowercase -> 27-52
 *	digits    -> 53-62
 *	underscore-> 63
 */

static const char char_set[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";

int
char_to_num(char c)
{
    const char *where;
    int diff;

    where = strchr(char_set, c);
    if (where) {
	diff = where - char_set + 1;
	assert(diff < (1 << ERRCODE_RANGE));
	return diff;
    } else if (isprint(c))
	fprintf(stderr, "Illegal character `%c' in error table name\n", c);
    else
	fprintf(stderr, "Illegal character %03o in error table name\n", c);
    exit(1);
}

void
set_table_num(char *string)
{
    if (use_msf) {
	set_table_1num(string);
	return;
    }
    if (strlen(string) > 4) {
	fprintf(stderr, "Table name %s too long, truncated ", string);
	string[4] = '\0';
	fprintf(stderr, "to %s\n", string);
    }
    if (char_to_num(string[0]) > char_to_num('z')) {
	fprintf(stderr, "%s%s%s%s",
		"First character of error table name must be ",
		"a letter; name ``", string, "'' rejected\n");
	exit(1);
    }
    while (*string != '\0') {
	table_number = (table_number << BITS_PER_CHAR)
	    + char_to_num(*string);
	string++;
    }
    table_number = table_number << ERRCODE_RANGE;
}

void
set_table_fun(char *astring)
{
    char *tp;
    unsigned int tc;

    for (tp = astring; (tc = *tp) != 0; tp++) {
	if (!isdigit(tc)) {
	    fprintf(stderr,
		    "Table function '%s' must be a decimal integer.\n",
		    astring);
	    exit(1);
	}
    }
    if (use_msf)
	table_number += (atoi(astring)) << 28;
}

/* for compatibility with old comerr's, we truncate package name to 4
 * characters, but only store first 3 in the error code.  Note that this
 * function, as a side effect, truncates the table name down to 4 chars.
 */
void
set_table_1num(char *string)
{
    afs_int32 temp;
    int ctr;

    if ((temp = strlen(string)) > 4) {
	fprintf(stderr, "Table name %s too long, truncated ", string);
	string[4] = '\0';
	fprintf(stderr, "to %s\n", string);
    }
    if (temp == 4) {
	fprintf(stderr,
		"Table name %s too long, only 3 characters fit in error code.\n",
		string);
    }
    if (char_to_1num(string[0]) > char_to_1num('z')) {
	fprintf(stderr, "%s%s%s%s",
		"First character of error table name must be ",
		"a letter; name ``", string, "'' rejected\n");
	exit(1);
    }
    temp = 0;
    for (ctr = 0; ctr < 3; ctr++) {	/* copy at most 3 chars to integer */
	if (*string == '\0')
	    break;		/* and watch for early end */
	temp = (temp * 050)	/* "radix fifty" is base 050 = 40 */
	    +char_to_1num(*string);
	string++;
    }
    table_number += temp << 12;
}

/*
 * char_to_num -- maps letters and numbers into very small space
 *      0-9        -> 0-9
 *      mixed case -> 10-35
 *      _          -> 36
 *      others are reserved
 */

static const char char_1set[] = "abcdefghijklmnopqrstuvwxyz_0123456789";

int
char_to_1num(char c)
{
    const char *where;
    int diff;

    if (isupper(c))
	c = tolower(c);

    where = strchr(char_1set, c);
    if (where) {
	/* start at 1 so we can decode */
	diff = where - char_1set;
	assert(diff < 050);	/* it is radix 50, after all */
	return diff;
    } else if (isprint(c))
	fprintf(stderr, "Illegal character `%c' in error table name\n", c);
    else
	fprintf(stderr, "Illegal character %03o in error table name\n", c);
    exit(1);
}

#ifdef AFS_NT40_ENV
#include "et_lex.lex_nt.c"
#else
#include "et_lex.lex.c"
#endif

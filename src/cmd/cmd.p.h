/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 * 
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef __CMD_INCL__
#define	__CMD_INCL__	    1

/* parmdesc types */
#define	CMD_FLAG	1	/* no parms */
#define	CMD_SINGLE	2	/* one parm */
#define	CMD_LIST	3	/* two parms */

/* syndesc flags */
#define	CMD_ALIAS	1	/* this is an alias */
#define CMD_ADMIN       2	/* admin. command, show only with -admin */
#define CMD_HIDDEN      4	/* A hidden command - similar to CMD_HIDE */

#define CMD_HELPPARM	(CMD_MAXPARMS-1)	/* last one is used by -help switch */
#define	CMD_MAXPARMS	64	/* max number of parm types to a cmd line */

/* parse items are here */
struct cmd_item {
    struct cmd_item *next;
    char *data;
};

struct cmd_parmdesc {
    char *name;			/* switch name */
    int type;			/* flag, single or list */
    struct cmd_item *items;	/* list of cmd items */
    afs_int32 flags;		/* flags */
    char *help;			/* optional help descr */
};

/* cmd_parmdesc flags */
#define	CMD_REQUIRED	    0
#define	CMD_OPTIONAL	    1
#define	CMD_EXPANDS	    2	/* if list, try to eat tokens through eoline, instead of just 1 */
#define CMD_HIDE            4	/* A hidden option */
#define	CMD_PROCESSED	    8

struct cmd_syndesc {
    struct cmd_syndesc *next;	/* next one in system list */
    struct cmd_syndesc *nextAlias;	/* next in alias chain */
    struct cmd_syndesc *aliasOf;	/* back ptr for aliases */
    char *name;			/* subcommand name */
    char *a0name;		/* command name from argv[0] */
    char *help;			/* help description */
    int (*proc) (struct cmd_syndesc * ts, void *arock);
    void *rock;
    int nParms;			/* number of parms */
    afs_int32 flags;		/* random flags */
    struct cmd_parmdesc parms[CMD_MAXPARMS];	/* parms themselves */
};

extern struct cmd_syndesc *cmd_CreateSyntax(char *namep,
					    int (*aprocp) (struct cmd_syndesc
							   * ts, void *arock),
					    void *rockp, char *helpp);
extern int
  cmd_SetBeforeProc(int (*aproc) (struct cmd_syndesc * ts, void *beforeRock),
		    void *arock);
extern int
  cmd_SetAfterProc(int (*aproc) (struct cmd_syndesc * ts, void *afterRock),
		   void *arock);
extern int cmd_CreateAlias(struct cmd_syndesc *as, char *aname);
extern int cmd_Seek(struct cmd_syndesc *as, int apos);
extern int cmd_AddParm(struct cmd_syndesc *as, char *aname, int atype,
		       afs_int32 aflags, char *ahelp);
extern int cmd_Dispatch(int argc, char **argv);
extern int cmd_FreeArgv(char **argv);
extern int cmd_ParseLine(char *aline, char **argv, afs_int32 * an,
			 afs_int32 amaxn);
extern int cmd_IsAdministratorCommand(struct cmd_syndesc *as);
extern void PrintSyntax(struct cmd_syndesc *as);
extern void PrintFlagHelp(struct cmd_syndesc *as);

/* For pretty output */
#define T_MAX_CELLS 20
#define T_MAX_CELLCONTENT_LEN 30
#define T_TYPE_ASCII_SPARTAN 0
#define T_TYPE_ASCII_INNERLINE 1
#define T_TYPE_ASCII_FULLNET 2
#define T_TYPE_HTML 3
#define T_TYPE_CSV 4
#define T_TYPE_MAX 4
#define T_CELL_JUST_LEFT -1
#define T_CELL_JUST_CENTRE 0
#define T_CELL_JUST_RIGHT 1


struct TableCell {
    int Width;
    int Justification;
    char Content[T_MAX_CELLCONTENT_LEN];
    struct TableCell *next;
    struct TableCell* (*append) (struct TableCell *,char *Content, int Width,int Justification);
    struct TableCell* (*set) (struct TableCell *,char *Content, int Width,int Justification) ;
};

struct TableRow {
    struct TableCell *Head;
    struct TableRow *next;
    struct TableRow*  (*append) (struct TableRow *, struct TableCell *);
    struct TableRow* (*set) (struct TableRow *, struct TableCell *);
};

struct Table {
    int Type;
    int CellsperRow;
    /* Attribtues required for formatted ASCII-ouput */
    int *CellWidth;
    int RowLength; /* number of character per Row */
    char CellSeparator;
    char RowSeparator;
    /* Basic subentities */
    struct TableCell *Header;
    struct TableRow *Body;
    struct TableCell *Footer;
    /* ouput methods provided for this table */
    void (*printHeader) (struct Table *);
    void (*printBody) (struct Table *);
    void (*printFooter) (struct Table *);
    void (*printRow) (struct Table *, struct TableCell *);
    void (*setLayout) (struct Table *Table,int CellsperRow,int *allCellWidth,int*chosenIdx);
    void (*setType) (struct Table *Table,int TableType);
    int* (*newTableLayout) (int CellsperRow);
};

extern void PrintTime(afs_uint32 intdate);
extern void PrintDate(afs_uint32 intdate);
extern void sprintDate( char *string, afs_uint32 intdate);
extern void printTable(struct Table *Table);
extern struct TableRow* newTableRow(void);
extern struct TableCell* newTableCell(void); 
extern struct Table* newTable(void); 


#endif /* __CMD_INCL__ */

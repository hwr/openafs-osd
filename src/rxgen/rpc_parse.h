/* @(#)rpc_parse.h 1.3 87/03/09 (C) 1987 SMI */
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 *
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */

/*
 * rpc_parse.h, Definitions for the RPCL parser
 * Copyright (C) 1987, Sun Microsystems, Inc.
 */

enum defkind {
    DEF_INPARAM,
    DEF_OUTPARAM,
    DEF_INOUTPARAM,
    DEF_PACKAGE,
    DEF_PREFIX,
    DEF_PARAM,
    DEF_SPECIAL,
    DEF_STARTINGOPCODE,
    DEF_CUSTOMIZED,
    DEF_SPLITPREFIX,
    DEF_PROC,
    DEF_NULL,
    DEF_CONST,
    DEF_STRUCT,
    DEF_UNION,
    DEF_ENUM,
    DEF_TYPEDEF,
};
typedef enum defkind defkind;

typedef char *const_def;

enum relation {
    REL_VECTOR,			/* fixed length array */
    REL_ARRAY,			/* variable length array */
    REL_POINTER,		/* pointer */
    REL_ALIAS			/* simple */
};
typedef enum relation relation;

struct typedef_def {
    char *old_prefix;
    char *old_type;
    relation rel;
    char *array_max;
};
typedef struct typedef_def typedef_def;


struct enumval_list {
    char *name;
    char *assignment;
    struct enumval_list *next;
};
typedef struct enumval_list enumval_list;

struct enum_def {
    enumval_list *vals;
};
typedef struct enum_def enum_def;


struct declaration {
    char *prefix;
    char *type;
    char *name;
    relation rel;
    char *array_max;
};
typedef struct declaration declaration;


struct decl_list {
    declaration decl;
    struct decl_list *next;
};
typedef struct decl_list decl_list;

struct struct_def {
    decl_list *decls;
};
typedef struct struct_def struct_def;


struct case_list {
    char *case_name;
    declaration case_decl;
    struct case_list *next;
};
typedef struct case_list case_list;

struct union_def {
    declaration enum_decl;
    case_list *cases;
    declaration *default_decl;
};
typedef struct union_def union_def;

struct param_list {
    defkind param_kind;
    char *param_name;
    char *param_type;
    char *string_name;
#define	INDIRECT_PARAM	1
#define	PROCESSED_PARAM	2
#define	ARRAYNAME_PARAM	4
#define	ARRAYSIZE_PARAM	8
#define	FREETHIS_PARAM	16
#define	OUT_STRING	32
    char param_flag;
};
typedef struct param_list param_list;

struct proc1_list {
    defkind component_kind;
    char *code, *scode;
    param_list pl;
    struct proc1_list *next;
};
typedef struct proc1_list proc1_list;

struct procedure_def {
    char *proc_name;
    char *proc_prefix;
    char *proc_opcodename;
    int proc_opcodenum;
    char *proc_serverstub;
#undef	IN
#define	IN  0
#undef	OUT
#define	OUT 1
#undef	INOUT
#define	INOUT	2
    short paramtypes[3];
    char split_flag;
    char multi_flag;
    relation rel;
    proc1_list *plists;
};
typedef struct procedure_def procedure_def;

struct special_def {
    char *string_name;
    char *string_value;
};
typedef struct special_def special_def;

struct spec_list {
    special_def sdef;
    struct spec_list *next;
};
typedef struct spec_list spec_list;

struct spec_def {
    spec_list *specs;
};
typedef struct spec_def spec_def;

struct definition {
    char *def_name;
    defkind def_kind;
    union {
	const_def co;
	struct_def st;
	union_def un;
	enum_def en;
	typedef_def ty;
	spec_def sd;
    } def;
    procedure_def pc;
    int can_fail;
    int statindex;
};
typedef struct definition definition;

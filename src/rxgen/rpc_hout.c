/* @(#)rpc_hout.c	1.2 87/11/30 3.9 RPCSRC */
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
 * rpc_hout.c, Header file outputter for the RPC protocol compiler
 * Copyright (C) 1987, Sun Microsystems, Inc.
 */
#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <ctype.h>

#include "rpc_scan.h"
#include "rpc_parse.h"
#include "rpc_util.h"

/* Static declarations */
static void pconstdef(definition * def);
static void pstructdef(definition * def);
static void puniondef(definition * def);
static void psproc1(definition * defp, int callTconnF, char *type,
		    char *prefix, int iomask);
static void psprocdef(definition * defp);
static void penumdef(definition * def);
static void ptypedef(definition * def);
static void pdeclaration(char *name, declaration * dec, int tab);
static int undefined2(char *type, char *stop);

/*
 * Print the C-version of an xdr definition
 */
void
print_datadef(definition * def)
{
    if (Sflag)
	scan_print = 0;
    if ((def->def_kind != DEF_CONST) && (!IsRxgenDefinition(def))) {
	f_print(fout, "\n");
    }
    switch (def->def_kind) {
    case DEF_CUSTOMIZED:
    case DEF_STRUCT:
	pstructdef(def);
	break;
    case DEF_UNION:
	puniondef(def);
	break;
    case DEF_ENUM:
	penumdef(def);
	break;
    case DEF_TYPEDEF:
	ptypedef(def);
	break;
    case DEF_PROC:
	psprocdef(def);
	break;
    case DEF_CONST:
	pconstdef(def);
	break;
    default:
	break;
    }
    if (def->def_kind != DEF_CONST && (!IsRxgenDefinition(def))) {
	f_print(fout, "bool_t xdr_%s(XDR *xdrs, %s *objp);\n", def->def_name,
		def->def_name);
    }
    if (def->def_kind != DEF_CONST && (!IsRxgenDefinition(def))) {
	f_print(fout, "\n");
    }
    if (Sflag)
	scan_print = 1;
}

static void
pconstdef(definition * def)
{
    pdefine(def->def_name, def->def.co);
}

static void
pstructdef(definition * def)
{
    decl_list *l;
    char *name = def->def_name;

    f_print(fout, "struct %s {\n", name);
    for (l = def->def.st.decls; l != NULL; l = l->next) {
	pdeclaration(name, &l->decl, 1);
    }
    f_print(fout, "};\n");
    f_print(fout, "typedef struct %s %s;\n", name, name);
}

static void
puniondef(definition * def)
{
    case_list *l;
    char *name = def->def_name;
    declaration *decl;

    f_print(fout, "struct %s {\n", name);
    decl = &def->def.un.enum_decl;
    if (streq(decl->type, "bool")) {
	f_print(fout, "\tbool_t %s;\n", decl->name);
    } else {
	f_print(fout, "\t%s %s;\n", decl->type, decl->name);
    }
    f_print(fout, "\tunion {\n");
    for (l = def->def.un.cases; l != NULL; l = l->next) {
	pdeclaration(name, &l->case_decl, 2);
    }
    decl = def->def.un.default_decl;
    if (decl && !streq(decl->type, "void")) {
	pdeclaration(name, decl, 2);
    }
    if (brief_flag) {
	f_print(fout, "\t} u;\n");
    } else {
	f_print(fout, "\t} %s_u;\n", name);
    }
    f_print(fout, "};\n");
    f_print(fout, "typedef struct %s %s;\n", name, name);
    STOREVAL(&uniondef_defined, def);
}


void
pdefine(char *name, char *num)
{
    f_print(fout, "#define %s %s\n", name, num);
}

static void
psproc1(definition * defp, int callTconnF, char *type, char *prefix,
	int iomask)
{
    proc1_list *plist;

    f_print(fout, "\nextern %s %s%s%s(\n", type, prefix, defp->pc.proc_prefix,
	    defp->pc.proc_name);

    if (callTconnF == 1 || callTconnF == 3) {
	f_print(fout, "\t/*IN */ struct rx_call *z_call");
    } else if (callTconnF == 2) {
	f_print(fout, "\tstruct ubik_client *aclient, afs_int32 aflags");
    } else {
	f_print(fout, "\t/*IN */ struct rx_connection *z_conn");
    }

    for (plist = defp->pc.plists; plist; plist = plist->next) {
	if (plist->component_kind == DEF_PARAM
	    && (iomask & (1 << plist->pl.param_kind))) {
	    switch (plist->pl.param_kind) {
	    case DEF_INPARAM:
		f_print(fout, ",\n\t/*IN %d*/ ",callTconnF);
		if ((callTconnF != 3)
		    && strcmp(plist->pl.param_type, "char *")== 0)
		    f_print(fout, "const ");
		break;
	    case DEF_OUTPARAM:
		f_print(fout, ",\n\t/*OUT*/ ");
		break;
	    case DEF_INOUTPARAM:
		f_print(fout, ",\n\t/*I/O*/ ");
		break;
	    default:
		break;
	    }
	    if (plist->pl.param_flag & OUT_STRING) {
		f_print(fout, "%s *%s", plist->pl.param_type,
			plist->pl.param_name);
	    } else {
		f_print(fout, "%s %s", plist->pl.param_type,
			plist->pl.param_name);
	    }
	}
    }
    f_print(fout, ");\n");
}

static void
psprocdef(definition * defp)
{
    int split_flag = defp->pc.split_flag;
    int multi_flag = defp->pc.multi_flag;

    if (split_flag || multi_flag) {
	psproc1(defp, 1, "int", "Start",
		(1 << DEF_INPARAM) | (1 << DEF_INOUTPARAM));
	psproc1(defp, 1, "int", "End",
		(1 << DEF_OUTPARAM) | (1 << DEF_INOUTPARAM));
    }
    if (!(!multi_flag && split_flag))
        psproc1(defp, 0, "int", "", 0xFFFFFFFF);

    if (uflag && !kflag) {
	f_print(fout, "\n#ifndef KERNEL");
	psproc1(defp, 2, "int", "ubik_", 0xFFFFFFFF);
	f_print(fout, "#endif /* KERNEL */\n");
    }

    if (*ServerPrefix)
	psproc1(defp, 3, "afs_int32", ServerPrefix, 0xFFFFFFFF);
}

static void
penumdef(definition * def)
{
    char *name = def->def_name;
    enumval_list *l;
    char *last = NULL;
    int count = 0;

    f_print(fout, "enum %s {\n", name);
    for (l = def->def.en.vals; l != NULL; l = l->next) {
	f_print(fout, "\t%s", l->name);
	if (l->assignment) {
	    f_print(fout, " = %s", l->assignment);
	    last = l->assignment;
	    count = 1;
	} else {
	    if (last == NULL) {
		f_print(fout, " = %d", count++);
	    } else {
		f_print(fout, " = %s + %d", last, count++);
	    }
	}
	f_print(fout, ",\n");
    }
    f_print(fout, "};\n");
    f_print(fout, "typedef enum %s %s;\n", name, name);
}

static void
ptypedef(definition * def)
{
    char *name = def->def_name;
    char *old = def->def.ty.old_type;
    char prefix[8];		/* enough to contain "struct ", including NUL */
    relation rel = def->def.ty.rel;


    if (!streq(name, old)) {
	if (streq(old, "string")) {
	    old = "char";
	    rel = REL_POINTER;
	} else if (!brief_flag && streq(old, "opaque")) {
	    old = "char";
	} else if (streq(old, "bool")) {
	    old = "bool_t";
	}
	if (undefined2(old, name) && def->def.ty.old_prefix) {
	    s_print(prefix, "%s ", def->def.ty.old_prefix);
	} else {
	    prefix[0] = 0;
	}
	f_print(fout, "typedef ");
	switch (rel) {
	case REL_ARRAY:
	    if (brief_flag) {
	        if (streq(old, "opaque")) {
		    f_print(fout, "struct rx_opaque %s", name);
		} else {
		    f_print(fout, "struct {\n");
		    f_print(fout, "\tu_int len;\n");
		    f_print(fout, "\t%s%s *val;\n", prefix, old);
		    f_print(fout, "} %s", name);
		}
	    } else {
	        f_print(fout, "struct %s {\n", name);
		f_print(fout, "\tu_int %s_len;\n", name);
		f_print(fout, "\t%s%s *%s_val;\n", prefix, old, name);
	        f_print(fout, "} %s", name);
	    }
	    break;
	case REL_POINTER:
	    f_print(fout, "%s%s *%s", prefix, old, name);
	    break;
	case REL_VECTOR:
	    f_print(fout, "%s%s %s[%s]", prefix, old, name,
		    def->def.ty.array_max);
	    break;
	case REL_ALIAS:
	    f_print(fout, "%s%s %s", prefix, old, name);
	    break;
	}
	def->pc.rel = rel;
	STOREVAL(&typedef_defined, def);
	f_print(fout, ";\n");
    }
}


static void
pdeclaration(char *name, declaration * dec, int tab)
{
    char buf[8];		/* enough to hold "struct ", include NUL */
    char *prefix;
    char *type;

    if (streq(dec->type, "void")) {
	return;
    }
    tabify(fout, tab);
    if (streq(dec->type, name) && !dec->prefix) {
	f_print(fout, "struct ");
    }
    if (streq(dec->type, "string")) {
	f_print(fout, "char *%s", dec->name);
    } else {
	prefix = "";
	if (streq(dec->type, "bool")) {
	    type = "bool_t";
	} else if (streq(dec->type, "opaque")) {
	    type = "char";
	} else {
	    if (dec->prefix) {
		s_print(buf, "%s ", dec->prefix);
		prefix = buf;
	    }
	    type = dec->type;
	}
	switch (dec->rel) {
	case REL_ALIAS:
	    f_print(fout, "%s%s %s", prefix, type, dec->name);
	    break;
	case REL_VECTOR:
	    f_print(fout, "%s%s %s[%s]", prefix, type, dec->name,
		    dec->array_max);
	    break;
	case REL_POINTER:
	    f_print(fout, "%s%s *%s", prefix, type, dec->name);
	    break;
	case REL_ARRAY:
	    if (brief_flag) {
		if (streq(dec->type, "opaque")) {
		    f_print(fout, "struct rx_opaque %s",dec->name);
		} else {
		    f_print(fout, "struct {\n");
		    tabify(fout, tab);
		    f_print(fout, "\tu_int len;\n");
		    tabify(fout, tab);
		    f_print(fout, "\t%s%s *val;\n", prefix, type);
		    tabify(fout, tab);
		    f_print(fout, "} %s", dec->name);
		}
	    } else {
		f_print(fout, "struct %s {\n", dec->name);
		tabify(fout, tab);
		f_print(fout, "\tu_int %s_len;\n", dec->name);
		tabify(fout, tab);
		f_print(fout, "\t%s%s *%s_val;\n", prefix, type, dec->name);
		tabify(fout, tab);
		f_print(fout, "} %s", dec->name);
	    }
	    break;
	}
    }
    f_print(fout, ";\n");
}



static int
undefined2(char *type, char *stop)
{
    list *l;
    definition *def;

    for (l = defined; l != NULL; l = l->next) {
	def = (definition *) l->val;
	if (streq(def->def_name, stop)) {
	    return (1);
	} else if (streq(def->def_name, type)) {
	    return (0);
	}
    }
    return (1);
}

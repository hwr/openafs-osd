/* @(#)rpc_scan.h	1.1 87/11/04 3.9 RPCSRC */
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
 * rpc_scan.h, Definitions for the RPCL scanner
 * Copyright (C) 1987, Sun Microsystems, Inc.
 */

/*
 * kinds of tokens
 */
enum tok_kind {
    TOK_IDENT,
    TOK_STRCONST,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_LBRACE,
    TOK_RBRACE,
    TOK_LBRACKET,
    TOK_RBRACKET,
    TOK_LANGLE,
    TOK_RANGLE,
    TOK_STAR,
    TOK_COMMA,
    TOK_EQUAL,
    TOK_COLON,
    TOK_SEMICOLON,
    TOK_CONST,
    TOK_STRUCT,
    TOK_UNION,
    TOK_SWITCH,
    TOK_CASE,
    TOK_DEFAULT,
    TOK_ENUM,
    TOK_TYPEDEF,
    TOK_INT,
    TOK_SHORT,
    TOK_INT32,
    TOK_UNSIGNED,
    TOK_FLOAT,
    TOK_DOUBLE,
    TOK_OPAQUE,
    TOK_CHAR,
    TOK_STRING,
    TOK_BOOL,
    TOK_VOID,
    TOK_PACKAGE,
    TOK_PREFIX,
    TOK_STATINDEX,
    TOK_SPECIAL,
    TOK_STARTINGOPCODE,
    TOK_CUSTOMIZED,
    TOK_PROC,
    TOK_SPLITPREFIX,
    TOK_SPLIT,
    TOK_MULTI,
    TOK_IN,
    TOK_OUT,
    TOK_INOUT,
    TOK_AFSUUID,
    TOK_EOF
};
typedef enum tok_kind tok_kind;

/*
 * a token
 */
struct token {
    tok_kind kind;
    char *str;
};
typedef struct token token;

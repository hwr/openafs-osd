/* @(#)rpc_main.c	1.4 87/11/30 3.9 RPCSRC */
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
 * rpc_main.c, Top level of the RPC protocol compiler.
 * Copyright (C) 1987, Sun Microsystems, Inc.
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <limits.h>
#include <ctype.h>

#include "rpc_scan.h"
#include "rpc_parse.h"
#include "rpc_util.h"

#define EXTEND	1		/* alias for TRUE */

struct commandline {
    int ansic_flag;
    int brief_flag;
    int cflag;
    int hflag;
    int Cflag;
    int Sflag;
    int rflag;
    int kflag;
    int pflag;
    int dflag;
    int xflag;
    int yflag;
    int uflag;
    char *infile;
    char *outfile;
};

#define MAXCPPARGS	256	/* maximum number of arguments to cpp */

char *prefix = "";
static char *IncludeDir[MAXCPPARGS];
int nincludes = 0;
char *OutFileFlag = "";
char OutFile[256];
char Sflag = 0, Cflag = 0, hflag = 0, cflag = 0, kflag = 0, uflag = 0;
char ansic_flag = 0;		/* If set, build ANSI C style prototypes */
char brief_flag = 0;		/* If set, shorten names */
char zflag = 0;			/* If set, abort server stub if rpc call returns non-zero */
char xflag = 0;			/* if set, add stats code to stubs */
char yflag = 0;			/* if set, only emit function name arrays to xdr file */
int debug = 0;
static int pclose_fin = 0;
static char *cmdname;
#ifdef PATH_CPP
static char *CPP = PATH_CPP;
#else
#ifdef AFS_NT40_ENV
static char *CPP = "cl /EP /C /nologo";
#else
static char *CPP = "/lib/cpp";
#endif
#endif

/*
 * Running "cpp" directly on DEC OSF/1 does not define anything; the "cc"
 * driver is responsible.  To compensate (and allow for other definitions
 * which should always be passed to "cpp"), place definitions which whould
 * always be passed to "rxgen" in this string.
 */
static char *CPPFLAGS = "-C"
#ifdef	AFS_ALPHA_ENV
#ifdef	__alpha
    " -D__alpha"
#endif /* __alpha */
#ifdef	OSF
    " -DOSF"
#endif /* OSF */
#endif
;

#include "AFS_component_version_number.c"

/* static prototypes */
static char *extendfile(char *file, char *ext);
static void open_output(char *infile, char *outfile);
static void open_input(char *infile, char *define);
static void c_output(char *infile, char *define, int extend, char *outfile,
		     int append);
static void h_output(char *infile, char *define, int extend, char *outfile,
		     int append);
static int parseargs(int argc, char *argv[], struct commandline *cmd);
static void C_output(char *infile, char *define, int extend, char *outfile,
		     int append);
static void S_output(char *infile, char *define, int extend, char *outfile,
		     int append);
static char *uppercase(char *str);

int
main(int argc, char *argv[])
{
    struct commandline cmd;
    char *ep;

    ep = getenv("RXGEN_CPPCMD");
    if (ep)
	CPP = ep;
#ifdef	AFS_AIX32_ENV
    /*
     * The following signal action for AIX is necessary so that in case of a
     * crash (i.e. core is generated) we can include the user's data section
     * in the core dump. Unfortunately, by default, only a partial core is
     * generated which, in many cases, isn't too useful.
     */
    struct sigaction nsa;

    sigemptyset(&nsa.sa_mask);
    nsa.sa_handler = SIG_DFL;
    nsa.sa_flags = SA_FULLDUMP;
    sigaction(SIGSEGV, &nsa, NULL);
#endif
    reinitialize();
    if (!parseargs(argc, argv, &cmd)) {
	f_print(stderr, "usage: %s infile\n", cmdname);
	f_print(stderr,
		"       %s [-c | -h | -C | -S | -r | -b | -k | -p | -d | -z | -u] [-Pprefix] [-Idir] [-o outfile] [infile]\n",
		cmdname);
	f_print(stderr, "       %s [-o outfile] [infile]\n",
		cmdname);
	exit(1);
    }
    OutFileFlag = cmd.outfile;
    if (OutFileFlag)
	strcpy(OutFile, cmd.outfile);
    if (cmd.cflag) {
	OutFileFlag = NULL;
	c_output(cmd.infile, "-DRPC_XDR", !EXTEND, cmd.outfile, 0);
    } else if (cmd.hflag) {
	h_output(cmd.infile, "-DRPC_HDR", !EXTEND, cmd.outfile, 0);
    } else if (cmd.Cflag) {
	OutFileFlag = NULL;
	C_output(cmd.infile, "-DRPC_CLIENT", !EXTEND, cmd.outfile, 1);
    } else if (cmd.Sflag) {
	OutFileFlag = NULL;
	S_output(cmd.infile, "-DRPC_SERVER", !EXTEND, cmd.outfile, 1);
    } else {
	if (OutFileFlag && (strrchr(OutFile, '.') == NULL))
	    strcat(OutFile, ".");
	if (cmd.rflag) {
	    C_output((OutFileFlag ? OutFile : cmd.infile), "-DRPC_CLIENT",
		     EXTEND, ".cs.c", 1);
	    reinitialize();
	    S_output((OutFileFlag ? OutFile : cmd.infile), "-DRPC_SERVER",
		     EXTEND, ".ss.c", 1);
	    reinitialize();
	} else {
	    reinitialize();
	    c_output((OutFileFlag ? OutFile : cmd.infile), "-DRPC_XDR",
		     EXTEND, ".xdr.c", 0);
	    reinitialize();
	    h_output((OutFileFlag ? OutFile : cmd.infile), "-DRPC_HDR",
		     EXTEND, ".h", 0);
	    reinitialize();
	    C_output((OutFileFlag ? OutFile : cmd.infile), "-DRPC_CLIENT",
		     EXTEND, ".cs.c", 1);
	    reinitialize();
	    S_output((OutFileFlag ? OutFile : cmd.infile), "-DRPC_SERVER",
		     EXTEND, ".ss.c", 1);
	    reinitialize();
	}
    }
    if (fin && pclose_fin) {
	/* the cpp command we called returned a non-zero exit status */
	if (pclose(fin)) {
	    crash();
	}
    }
    exit(0);
}

/*
 * add extension to filename
 */
static char *
extendfile(char *file, char *ext)
{
    char *res;
    char *p;
    char *sname;

    res = alloc(strlen(file) + strlen(ext) + 1);
    if (res == NULL) {
	abort();
    }
    p = (char *)strrchr(file, '.');
    if (p == NULL) {
	p = file + strlen(file);
    }
    sname = (char *)strrchr(file, '/');
    if (sname == NULL)
	sname = file;
    else
	sname++;
    strcpy(res, sname);
    strcpy(res + (p - sname), ext);
    return (res);
}

/*
 * Open output file with given extension
 */
static void
open_output(char *infile, char *outfile)
{
    if (outfile == NULL) {
	fout = stdout;
	return;
    }
    if (infile != NULL && streq(outfile, infile)) {
	f_print(stderr, "%s: output would overwrite %s\n", cmdname, infile);
	crash();
    }
    fout = fopen(outfile, "w");
    if (fout == NULL) {
	f_print(stderr, "%s: unable to open ", cmdname);
	perror(outfile);
	crash();
    }
    record_open(outfile);
}

/*
 * Open input file with given define for C-preprocessor
 */
static void
open_input(char *infile, char *define)
{
    char *cpp_cmdline;
    int i, l = 0;

    if (debug == 0) {
	infilename = (infile == NULL) ? "<stdin>" : infile;
        l = strlen(CPP) + strlen(CPPFLAGS) + strlen(define) + 3;
	for (i = 0; i < nincludes; i++)
	    l += strlen(IncludeDir[i]) + 1;
        l += strlen(infile) + 1;
	cpp_cmdline = malloc(l);
	if (!cpp_cmdline) {
	  perror("Unable to allocate space for cpp command line");
	  crash();
	}

	sprintf(cpp_cmdline, "%s %s %s", CPP, CPPFLAGS, define);
	l = strlen(cpp_cmdline);
	for (i = 0; i < nincludes; i++) {
	    cpp_cmdline[l++] = ' ';
	    strcpy(cpp_cmdline + l, IncludeDir[i]);
            l += strlen(IncludeDir[i]);
	}
	cpp_cmdline[l++] = ' ';
	strcpy(cpp_cmdline + l, infile);

	fin = popen(cpp_cmdline, "r");
	if (fin == NULL)
	    perror("popen");
	pclose_fin = 1;

    } else {
	if (infile == NULL) {
	    fin = stdin;
	    return;
	}
	fin = fopen(infile, "r");
    }
    if (fin == NULL) {
	f_print(stderr, "%s: ", cmdname);
	perror(infilename);
	crash();
    }
}

/*
 * Compile into an XDR routine output file
 */
static void
c_output(char *infile, char *define, int extend, char *outfile, int append)
{
    definition *def;
    char *include;
    char *outfilename;
    long tell;
    char fullname[1024];
    char *currfile = (OutFileFlag ? OutFile : infile);
    int i, j;

    open_input(infile, define);
    cflag = 1;
    memset(fullname, 0, sizeof(fullname));
    if (append) {
	strcpy(fullname, prefix);
	strcat(fullname, infile);
    } else
	strcpy(fullname, infile);
    outfilename = extend ? extendfile(fullname, outfile) : outfile;
    open_output(infile, outfilename);
    f_print(fout, "/* Machine generated file -- Do NOT edit */\n\n");
    if (xflag) {
	if (kflag) {
	    f_print(fout, "#include \"afsconfig.h\"\n");
	    f_print(fout, "#include \"afs/param.h\"\n");
	} else {
	    f_print(fout, "#include <afsconfig.h>\n");
	    f_print(fout, "#include <afs/param.h>\n");
	    f_print(fout, "#include <roken.h>\n");
	}
	f_print(fout, "#ifdef AFS_NT40_ENV\n");
	f_print(fout, "#define AFS_RXGEN_EXPORT __declspec(dllexport)\n");
	f_print(fout, "#endif /* AFS_NT40_ENV */\n");
    }
    if (currfile && (include = extendfile(currfile, ".h"))) {
	if (kflag) {
	    f_print(fout, "#include \"%s\"\n\n", include);
	} else
	    f_print(fout, "#include \"%s\"\n\n", include);
	free(include);
    } else {
	/* In case we can't include the interface's own header file... */
	if (kflag) {
	    f_print(fout, "#include \"h/types.h\"\n");
	    f_print(fout, "#include \"h/socket.h\"\n");
	    f_print(fout, "#include \"h/file.h\"\n");
	    f_print(fout, "#include \"h/stat.h\"\n");
	    f_print(fout, "#include \"netinet/in.h\"\n");
	    f_print(fout, "#include \"h/time.h\"\n");
	    f_print(fout, "#include \"rx/xdr.h\"\n");
	    f_print(fout, "#include \"afs/rxgen_consts.h\"\n");
	} else {
	    f_print(fout, "#include <rx/xdr.h>\n");
	}
    }

    tell = ftell(fout);
    while ((def = get_definition())) {
	if (!yflag) {
	    if ((!IsRxgenDefinition(def)) && def->def_kind != DEF_CUSTOMIZED)
		emit(def);
	}
    }

    /*
     * Print out array containing list of all functions in the interface
     * in order
     */

    if (xflag) {
	for (j = 0; j <= PackageIndex; j++) {
	    f_print(fout, "AFS_RXGEN_EXPORT\n");
	    f_print(fout, "const char *%sfunction_names[] = {\n",
		    PackagePrefix[j]);

	    for (i = 0; i < no_of_stat_funcs_header[j]; i++) {
		if (i == 0) {
		    f_print(fout, "\t\"%s\"", function_list[j][i]);
		} else {
		    f_print(fout, ",\n\t\"%s\"", function_list[j][i]);
		}
	    }


	    f_print(fout, "\n};\n");
	}
	er_Proc_CodeGeneration();
    }

    if (extend && tell == ftell(fout)) {
	(void)unlink(outfilename);
    }
    cflag = 0;
}

/*
 * Compile into an XDR header file
 */
static void
h_output(char *infile, char *define, int extend, char *outfile, int append)
{
    definition *def;
    char *outfilename;
    long tell;
    char fullname[1024], *p;

    open_input(infile, define);
    hflag = 1;
    memset(fullname, 0, sizeof(fullname));
    if (append) {
	strcpy(fullname, prefix);
	strcat(fullname, infile);
    } else
	strcpy(fullname, infile);
    outfilename = extend ? extendfile(fullname, outfile) : outfile;
    open_output(infile, outfilename);
    strcpy(fullname, outfilename);
    if ((p = strchr(fullname, '.')))
	*p = '\0';
    f_print(fout, "/* Machine generated file -- Do NOT edit */\n\n");
    f_print(fout, "#ifndef	_RXGEN_%s_\n", uppercase(fullname));
    f_print(fout, "#define	_RXGEN_%s_\n\n", uppercase(fullname));
    f_print(fout, "#ifdef	KERNEL\n");
    f_print(fout,
	    "/* The following 'ifndefs' are not a good solution to the vendor's omission of surrounding all system includes with 'ifndef's since it requires that this file is included after the system includes...*/\n");
    f_print(fout, "#include <afsconfig.h>\n");
    f_print(fout, "#include \"afs/param.h\"\n");
    f_print(fout, "#ifdef	UKERNEL\n");
    f_print(fout, "#include \"afs/sysincludes.h\"\n");
    f_print(fout, "#include \"rx/xdr.h\"\n");
    f_print(fout, "#include \"rx/rx.h\"\n");
    if (xflag) {
	f_print(fout, "#include \"rx/rx_globals.h\"\n");
    }
    if (brief_flag) {
	f_print(fout, "#include \"rx/rx_opaque.h\"\n");
    }
    f_print(fout, "#else	/* UKERNEL */\n");
    f_print(fout, "#include \"h/types.h\"\n");
    f_print(fout, "#ifndef	SOCK_DGRAM  /* XXXXX */\n");
    f_print(fout, "#include \"h/socket.h\"\n");
    f_print(fout, "#endif\n");
    f_print(fout, "#ifndef	DTYPE_SOCKET  /* XXXXX */\n");
    f_print(fout, "#ifndef AFS_LINUX22_ENV\n");
    f_print(fout, "#include \"h/file.h\"\n");
    f_print(fout, "#endif\n");
    f_print(fout, "#endif\n");
    f_print(fout, "#ifndef	S_IFMT  /* XXXXX */\n");
    f_print(fout, "#include \"h/stat.h\"\n");
    f_print(fout, "#endif\n");
    f_print(fout, "#if defined (AFS_OBSD_ENV) && !defined (MLEN)\n");
    f_print(fout, "#include \"sys/mbuf.h\"\n");
    f_print(fout, "#endif\n");
    f_print(fout, "#ifndef	IPPROTO_UDP /* XXXXX */\n");
    f_print(fout, "#include \"netinet/in.h\"\n");
    f_print(fout, "#endif\n");
    f_print(fout, "#ifndef	DST_USA  /* XXXXX */\n");
    f_print(fout, "#include \"h/time.h\"\n");
    f_print(fout, "#endif\n");
    f_print(fout, "#ifndef AFS_LINUX22_ENV\n");
    f_print(fout, "#include \"rpc/types.h\"\n");
    f_print(fout, "#endif /* AFS_LINUX22_ENV */\n");
    f_print(fout, "#ifndef	XDR_GETLONG /* XXXXX */\n");
    f_print(fout, "#ifdef AFS_LINUX22_ENV\n");
    f_print(fout, "#ifndef quad_t\n");
    f_print(fout, "#define quad_t __quad_t\n");
    f_print(fout, "#define u_quad_t __u_quad_t\n");
    f_print(fout, "#endif\n");
    f_print(fout, "#endif\n");
    f_print(fout, "#include \"rx/xdr.h\"\n");
    f_print(fout, "#endif /* XDR_GETLONG */\n");
    f_print(fout, "#endif   /* UKERNEL */\n");
    f_print(fout, "#include \"afs/rxgen_consts.h\"\n");
    f_print(fout, "#include \"afs_osi.h\"\n");
    f_print(fout, "#include \"rx/rx.h\"\n");
    if (xflag) {
	f_print(fout, "#include \"rx/rx_globals.h\"\n");
    }
    if (brief_flag) {
	f_print(fout, "#include \"rx/rx_opaque.h\"\n");
    }
    f_print(fout, "#else	/* KERNEL */\n");
    f_print(fout, "#include <afs/param.h>\n");
    f_print(fout, "#include <afs/stds.h>\n");
    f_print(fout, "#include <sys/types.h>\n");
    f_print(fout, "#include <rx/xdr.h>\n");
    f_print(fout, "#include <rx/rx.h>\n");
    if (xflag) {
	f_print(fout, "#include <rx/rx_globals.h>\n");
    }
    if (brief_flag) {
	f_print(fout, "#include <rx/rx_opaque.h>\n");
    }
    f_print(fout, "#include <afs/rxgen_consts.h>\n");
    if (uflag)
	f_print(fout, "#include <ubik.h>\n");
    f_print(fout, "#endif	/* KERNEL */\n\n");
    f_print(fout, "#ifdef AFS_NT40_ENV\n");
    f_print(fout, "#ifndef AFS_RXGEN_EXPORT\n");
    f_print(fout, "#define AFS_RXGEN_EXPORT __declspec(dllimport)\n");
    f_print(fout, "#endif /* AFS_RXGEN_EXPORT */\n");
    f_print(fout, "#else /* AFS_NT40_ENV */\n");
    f_print(fout, "#define AFS_RXGEN_EXPORT\n");
    f_print(fout, "#endif /* AFS_NT40_ENV */\n\n");
    tell = ftell(fout);
    while ((def = get_definition())) {
	print_datadef(def);
    }
    h_Proc_CodeGeneration();
    h_opcode_stats();
    hflag = 0;
    f_print(fout, "#endif	/* _RXGEN_%s_ */\n", uppercase(fullname));
    if (extend && tell == ftell(fout)) {
	(void)unlink(outfilename);
    }
}

static void
C_output(char *infile, char *define, int extend, char *outfile, int append)
{
    char *include;
    char *outfilename;
    char fullname[1024];
    long tell;
    char *currfile = (OutFileFlag ? OutFile : infile);

    Cflag = 1;
    open_input(infile, define);
    memset(fullname, 0, sizeof(fullname));
    if (append) {
	strcpy(fullname, prefix);
	strcat(fullname, infile);
    } else
	strcpy(fullname, infile);
    outfilename = extend ? extendfile(fullname, outfile) : outfile;
    open_output(infile, outfilename);
    f_print(fout, "/* Machine generated file -- Do NOT edit */\n\n");
    if (currfile && (include = extendfile(currfile, ".h"))) {
	if (kflag) {
	    f_print(fout, "#include \"%s\"\n\n", include);
	} else {
	    f_print(fout, "#include <afsconfig.h>\n");
	    f_print(fout, "#include <afs/param.h>\n");
	    f_print(fout, "#include <roken.h>\n");
	    f_print(fout, "#include <afs/opr.h>\n");
	    f_print(fout, "#ifdef AFS_PTHREAD_ENV\n");
	    f_print(fout, "# include <opr/lock.h>\n");
	    f_print(fout, "#endif\n");
	    f_print(fout, "#include \"%s\"\n\n", include);
	}
	free(include);
    } else {
	if (kflag) {
	    f_print(fout, "#include \"h/types.h\"\n");
	    f_print(fout, "#include \"h/socket.h\"\n");
	    f_print(fout, "#include \"h/file.h\"\n");
	    f_print(fout, "#include \"h/stat.h\"\n");
	    f_print(fout, "#include \"netinet/in.h\"\n");
	    f_print(fout, "#include \"h/time.h\"\n");
	    f_print(fout, "#include \"rpc/types.h\"\n");
	    f_print(fout, "#include \"rx/xdr.h\"\n");
	    f_print(fout, "#include \"afs/rxgen_consts.h\"\n");
	    f_print(fout, "#include \"afs/afs_osi.h\"\n");
	    f_print(fout, "#include \"rx/rx.h\"\n");
	    if (xflag) {
		f_print(fout, "#include \"rx/rx_globals.h\"\n");
	    }
	    if (brief_flag) {
		f_print(fout, "#include \"rx/rx_opaque.h\"\n");
	    }
	} else {
	    f_print(fout, "#include <sys/types.h>\n");
	    f_print(fout, "#include <rx/xdr.h>\n");
	    f_print(fout, "#include <rx/rx.h>\n");
	    if (xflag) {
		f_print(fout, "#include <rx/rx_globals.h>\n");
	    }
	    if (brief_flag) {
		f_print(fout, "#include <rx/rx_opaque.h\"\n");
	    }
	    f_print(fout, "#include <afs/rxgen_consts.h>\n");
	}
    }

    tell = ftell(fout);
    while (get_definition())
	continue;
    if (extend && tell == ftell(fout)) {
	(void)unlink(outfilename);
    }

    Cflag = 0;
}

static void
S_output(char *infile, char *define, int extend, char *outfile, int append)
{
    char *include;
    char *outfilename;
    char fullname[1024];
    definition *def;
    long tell;
    char *currfile = (OutFileFlag ? OutFile : infile);

    Sflag = 1;
    open_input(infile, define);
    memset(fullname, 0, sizeof(fullname));
    if (append) {
	strcpy(fullname, prefix);
	strcat(fullname, infile);
    } else
	strcpy(fullname, infile);
    outfilename = extend ? extendfile(fullname, outfile) : outfile;
    open_output(infile, outfilename);
    f_print(fout, "/* Machine generated file -- Do NOT edit */\n\n");
    if (currfile && (include = extendfile(currfile, ".h"))) {
	if (kflag) {
	    f_print(fout, "#include \"%s\"\n", include);
	} else {
	    f_print(fout, "#include <afsconfig.h>\n");
	    f_print(fout, "#include <afs/param.h>\n");
	    f_print(fout, "#include <roken.h>\n");
	    f_print(fout, "#include \"%s\"\n\n", include);
	}
	free(include);
    } else {
	if (kflag) {
	    f_print(fout, "#include \"h/types.h\"\n");
	    f_print(fout, "#include \"h/socket.h\"\n");
	    f_print(fout, "#include \"h/file.h\"\n");
	    f_print(fout, "#include \"h/stat.h\"\n");
	    f_print(fout, "#include \"netinet/in.h\"\n");
	    f_print(fout, "#include \"h/time.h\"\n");
	    f_print(fout, "#include \"rpc/types.h\"\n");
	    f_print(fout, "#include \"rx/xdr.h\"\n");
	    f_print(fout, "#include \"afs/rxgen_consts.h\"\n");
	    f_print(fout, "#include \"afs/afs_osi.h\"\n");
	    f_print(fout, "#include \"rx/rx.h\"\n");
	    if (xflag) {
		f_print(fout, "#include \"rx/rx_globals.h\"\n");
	    }
	    if (brief_flag) {
		f_print(fout, "#include \"rx/rx_opaque.h\"\n");
	    }
	} else {
	    f_print(fout, "#include <sys/types.h>\n");
	    f_print(fout, "#include <rx/xdr.h>\n");
	    f_print(fout, "#include <rx/rx.h>\n");
	    if (xflag) {
		f_print(fout, "#include <rx/rx_globals.h>\n");
	    }
	    if (brief_flag) {
		f_print(fout, "#include <rx/rx_opaque.h>\n");
	    }
	    f_print(fout, "#include <afs/rxgen_consts.h>\n");
	}
    }

    tell = ftell(fout);
    fflush(fout);
    while ((def = get_definition())) {
	fflush(fout);
	print_datadef(def);
    }

    er_Proc_CodeGeneration();

    if (extend && tell == ftell(fout)) {
	(void)unlink(outfilename);
    }
    Sflag = 0;
}

static char *
uppercase(char *str)
{
    static char max_size[100];
    char *pnt;
    int len = (int)strlen(str);

    for (pnt = max_size; len > 0; len--, str++) {
	*pnt++ = (islower(*str) ? toupper(*str) : *str);
    }
    *pnt = '\0';
    return max_size;
}

/*
 * Parse command line arguments
 */
static int
parseargs(int argc, char *argv[], struct commandline *cmd)
{
    int i;
    int j;
    char c;
    char flag[(1 << (8 * sizeof(char)))];
    int nflags;

    cmdname = argv[0];
    cmd->infile = cmd->outfile = NULL;
    if (argc < 2) {
	return (0);
    }
    memset(flag, 0, sizeof(flag));
    cmd->outfile = NULL;
    for (i = 1; i < argc; i++) {
	if (argv[i][0] != '-') {
	    if (cmd->infile) {
		return (0);
	    }
	    cmd->infile = argv[i];
	} else {
	    for (j = 1; argv[i][j] != 0; j++) {
		c = argv[i][j];
		switch (c) {
		case 'A':
		case 'c':
		case 'h':
		case 'C':
		case 'S':
		case 'b':
		case 'r':
		case 'k':
		case 'p':
		case 'd':
		case 'u':
		case 'x':
		case 'y':
		case 'z':
		    if (flag[(int)c]) {
			return (0);
		    }
		    flag[(int)c] = 1;
		    break;
		case 'o':
		    if (argv[i][j - 1] != '-' || argv[i][j + 1] != 0) {
			return (0);
		    }
		    flag[(int)c] = 1;
		    if (++i == argc) {
			return (0);
		    }
		    if (cmd->outfile) {
			return (0);
		    }
		    cmd->outfile = argv[i];
		    goto nextarg;
		case 'P':
		    if (argv[i][j - 1] != '-')
			return (0);
		    prefix = &argv[i][j + 1];
		    goto nextarg;
		case 'I':
		    if (nincludes >= MAXCPPARGS) {
			f_print(stderr, "Too many -I arguments\n");
			return (0);
		    }
		    if (argv[i][j - 1] != '-')
			return (0);
		    IncludeDir[nincludes++] = &argv[i][j - 1];
		    goto nextarg;
		default:
		    return (0);
		}
	    }
	  nextarg:
	    ;
	}
    }
    cmd->ansic_flag = ansic_flag = flag['A'];
    cmd->brief_flag = brief_flag = flag['b'];
    cmd->cflag = cflag = flag['c'];
    cmd->hflag = hflag = flag['h'];
    cmd->xflag = xflag = flag['x'];
    cmd->yflag = yflag = flag['y'];
    cmd->Cflag = Cflag = flag['C'];
    cmd->Sflag = Sflag = flag['S'];
    cmd->rflag = flag['r'];
    cmd->uflag = uflag = flag['u'];
    cmd->kflag = kflag = flag['k'];
    cmd->pflag = flag['p'];
    cmd->dflag = debug = flag['d'];
    zflag = flag['z'];
    if (cmd->pflag)
	combinepackages = 1;
    nflags =
	cmd->cflag + cmd->hflag + cmd->Cflag + cmd->Sflag + cmd->rflag;
    if (nflags == 0) {
	if (cmd->outfile != NULL || cmd->infile == NULL) {
	    return (0);
	}
    } else if (nflags > 1) {
	return (0);
    }
    return (1);
}

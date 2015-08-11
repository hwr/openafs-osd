dnl This file contains the common configuration code which would
dnl otherwise be duplicated between configure and configure-libafs.
dnl
dnl NB: Because this code is a macro, references to positional shell
dnl parameters must be done like $[]1 instead of $1

AC_DEFUN([OPENAFS_CONFIGURE_COMMON],[
AH_BOTTOM([
#undef HAVE_RES_SEARCH
#undef STRUCT_SOCKADDR_HAS_SA_LEN
#if !defined(__BIG_ENDIAN__) && !defined(__LITTLE_ENDIAN__)
# if ENDIANESS_IN_SYS_PARAM_H
#  ifndef KERNEL
#   include <sys/types.h>
#   include <sys/param.h>
#   if BYTE_ORDER == BIG_ENDIAN
#   define WORDS_BIGENDIAN 1
#   endif
#  else
#   if defined(AUTOCONF_FOUND_BIGENDIAN)
#    define WORDS_BIGENDIAN 1
#   else
#    undef WORDS_BIGENDIAN
#   endif
#  endif
# else
#  if defined(AUTOCONF_FOUND_BIGENDIAN)
#   define WORDS_BIGENDIAN 1
#  else
#   undef WORDS_BIGENDIAN
#  endif
# endif
#else
# if defined(__BIG_ENDIAN__)
#  define WORDS_BIGENDIAN 1
# else
#  undef WORDS_BIGENDIAN
# endif
#endif
#ifdef UKERNEL
/*
 * Always use 64-bit file offsets for UKERNEL code. Needed for UKERNEL stuff to
 * play nice with some other interfaces like FUSE. We technically only would
 * need to define this when building for such interfaces, but set it always to
 * try and reduce potential confusion. 
 */
#define _FILE_OFFSET_BITS 64
#define AFS_CACHE_VNODE_PATH
#endif

#undef AFS_NAMEI_ENV
#undef BITMAP_LATER
#undef FAST_RESTART
#undef DEFINED_FOR_EACH_PROCESS
#undef DEFINED_PREV_TASK
#undef EXPORTED_SYS_CALL_TABLE
#undef EXPORTED_IA32_SYS_CALL_TABLE
#undef IRIX_HAS_MEM_FUNCS
#undef RECALC_SIGPENDING_TAKES_VOID
#undef STRUCT_FS_HAS_FS_ROLLED
#undef ssize_t
#undef HAVE_ARPA_NAMESER_COMPAT_H
/* glue for RedHat kernel bug */
#undef ENABLE_REDHAT_BUILDSYS
#if defined(ENABLE_REDHAT_BUILDSYS) && defined(KERNEL) && defined(REDHAT_FIX)
#include "redhat-fix.h"
#endif])

AC_CANONICAL_HOST
SRCDIR_PARENT=`pwd`

#BOZO_SAVE_CORES pam

dnl System identity.
AC_ARG_WITH([afs-sysname],
    [AS_HELP_STRING([--with-afs-sysname=sys], [use sys for the afs sysname])])

dnl General feature options.
AC_ARG_ENABLE([pam],
    [AS_HELP_STRING([--disable-pam], [disable PAM support])],
    ,
    [enable_pam="yes"])
AC_ARG_ENABLE([namei-fileserver],
    [AS_HELP_STRING([--enable-namei-fileserver],
        [force compilation of namei fileserver in preference to inode
         fileserver])],
    , 
    [enable_namei_fileserver="default"])
AC_ARG_ENABLE([supergroups],
    [AS_HELP_STRING([--enable-supergroups],
        [enable support for nested pts groups])],
    , 
    [enable_supergroups="no"])
AC_ARG_ENABLE([bitmap-later],
    [AS_HELP_STRING([--enable-bitmap-later],
        [enable fast startup of file server by not reading bitmap till
         needed])],
    , 
    [enable_bitmap_later="no"])
AC_ARG_ENABLE([object-storage],
    [AS_HELP_STRING([--disable-object-storage],
        [disable use of object storage for AFS files])],
    ,
    [enable_object_storage="yes"])
AC_ARG_ENABLE([vicep-access],
    [AS_HELP_STRING([--enable-vicep-access],
        [enable direct client access to visible fileserver partitions (experimental)])],
    ,
    [enable_vicep_access="no"])
AC_ARG_ENABLE([unix-sockets],
    [AS_HELP_STRING([--disable-unix-sockets],
        [disable use of unix domain sockets for fssync (defaults to enabled)])],
    ,
    [enable_unix_sockets="yes"])
AC_ARG_ENABLE([tivoli-tsm],
    [AS_HELP_STRING([--enable-tivoli-tsm],
        [enable use of the Tivoli TSM API libraries for butc support])],
    , 
    [enable_tivoli_tsm="no"])
AC_ARG_ENABLE([pthreaded-ubik],
    [AS_HELP_STRING([--enable-pthreaded-ubik],
        [enable installation of pthreaded ubik applications (defaults to
         disabled)])],
    ,
    [enable_pthreaded_ubik="no"])

dnl Kernel module build options.
AC_ARG_WITH([linux-kernel-headers],
    [AS_HELP_STRING([--with-linux-kernel-headers=path],
        [use the kernel headers found at path (optional, defaults to
         /lib/modules/`uname -r`/build, then /lib/modules/`uname -r`/source,
         then /usr/src/linux-2.4, and lastly /usr/src/linux)])])
AC_ARG_WITH([linux-kernel-build],
    [AS_HELP_STRING([--with-linux-kernel-build=path],
	[use the kernel build found at path(optional, defaults to 
	kernel headers path)])])
AC_ARG_WITH([bsd-kernel-headers],
    [AS_HELP_STRING([--with-bsd-kernel-headers=path],
        [use the kernel headers found at path (optional, defaults to
         /usr/src/sys)])])
AC_ARG_WITH([bsd-kernel-build],
    [AS_HELP_STRING([--with-bsd-kernel-build=path], 
        [use the kernel build found at path (optional, defaults to
         KSRC/i386/compile/GENERIC)])])
AC_ARG_WITH([linux-kernel-packaging],
    [AS_HELP_STRING([--with-linux-kernel-packaging],
        [use standard naming conventions to aid Linux kernel build packaging
         (disables MPS, sets the kernel module name to openafs.ko, and
         installs kernel modules into the standard Linux location)])],
    [AC_SUBST(LINUX_KERNEL_PACKAGING, "yes")
     AC_SUBST(LINUX_LIBAFS_NAME, "openafs")],
    [AC_SUBST(LINUX_LIBAFS_NAME, "libafs")])
AC_ARG_ENABLE([kernel-module],
    [AS_HELP_STRING([--disable-kernel-module],
        [disable compilation of the kernel module (defaults to enabled)])],
    , 
    [enable_kernel_module="yes"])
AC_ARG_ENABLE([redhat-buildsys],
    [AS_HELP_STRING([--enable-redhat-buildsys],
        [enable compilation of the redhat build system kernel (defaults to
         disabled)])],
    ,
    [enable_redhat_buildsys="no"])

dnl Installation locations.
AC_ARG_ENABLE([transarc-paths],
    [AS_HELP_STRING([--enable-transarc-paths],
        [use Transarc style paths like /usr/afs and /usr/vice])],
    , 
    [enable_transarc_paths="no"])

dnl Optimization and debugging flags.
AC_ARG_WITH([version-string],
    [AS_HELP_STRING([--with-version-string=string],
        [what to display in rxdebug -v])])
AC_ARG_WITH([dcache-path],
    [AS_HELP_STRING([--with-dcache-path=path],
        [where dcap.h and libdcap.a can be found])])
AC_ARG_WITH([hpss-path],
    [AS_HELP_STRING([--with-hpss-path=path],
        [where include and lib for HPSS can be found, typically /opt/hpss])])
AC_ARG_ENABLE([strip-binaries],
    [AS_HELP_STRING([--disable-strip-binaries],
        [disable stripping of symbol information from binaries (defaults to
         enabled)])],
    ,
    [enable_strip_binaries="maybe"])
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
        [enable compilation of the user space code with debugging information
         (defaults to disabled)])],
    , 
    [enable_debug="no"])
AC_ARG_ENABLE([optimize],
    [AS_HELP_STRING([--disable-optimize],
        [disable optimization for compilation of the user space code (defaults
         to enabled)])],
    , 
    [enable_optimize="yes"])
AC_ARG_ENABLE([warnings],
    [AS_HELP_STRING([--enable-warnings],
        [enable compilation warnings when building with gcc (defaults to
         disabled)])],
    ,
    [enable_warnings="no"])
AC_ARG_ENABLE([checking],
    [AS_HELP_STRING([--enable-checking],
	[turn compilation warnings into errors when building with gcc (defaults
	 to disabled)])],
    [enable_checking="$enableval"],
    [enable_checking="no"])
AC_ARG_ENABLE([debug-kernel],
    [AS_HELP_STRING([--enable-debug-kernel],
        [enable compilation of the kernel module with debugging information
         (defaults to disabled)])],
    ,
    [enable_debug_kernel="no"])
AC_ARG_ENABLE([optimize-kernel],
    [AS_HELP_STRING([--disable-optimize-kernel],
        [disable compilation of the kernel module with optimization (defaults
         based on platform)])],
    , 
    [enable_optimize_kernel=""])
AC_ARG_ENABLE([debug-lwp],
    [AS_HELP_STRING([--enable-debug-lwp],
        [enable compilation of the LWP code with debugging information
         (defaults to disabled)])],
    ,
    [enable_debug_lwp="no"])
AC_ARG_ENABLE([optimize-lwp],
    [AS_HELP_STRING([--disable-optimize-lwp],
        [disable optimization for compilation of the LWP code (defaults to
         enabled)])],
    ,
    [enable_optimize_lwp="yes"])
AC_ARG_ENABLE([debug-pam],
    [AS_HELP_STRING([--enable-debug-pam],
        [enable compilation of the PAM code with debugging information
         (defaults to disabled)])],
    ,
    [enable_debug_pam="no"])
AC_ARG_ENABLE([optimize-pam],
    [AS_HELP_STRING([--disable-optimize-pam],
        [disable optimization for compilation of the PAM code (defaults to
         enabled)])],
    ,
    [enable_optimize_pam="yes"])
AC_ARG_ENABLE([linux-syscall-probing],
    [AS_HELP_STRING([--enable-linux-syscall-probing],
	[enable Linux syscall probing (defaults to autodetect)])],
    ,
    [enable_linux_syscall_probing="maybe"])
    
AC_ARG_ENABLE([linux-d_splice_alias-extra-iput],
    [AS_HELP_STRING([--enable-linux-d_splice_alias-extra-iput],
	[Linux has introduced an incompatible behavior change in the
	 d_splice_alias function with no reliable way to determine which
	 behavior will be produced.  If Linux commit
	 51486b900ee92856b977eacfc5bfbe6565028070 (or equivalent) has been
	 applied to your kernel, disable this option.  If that commit is
	 not present in your kernel, enable this option.  We apologize
	 that you are required to know this about your running kernel.])],
    [],
    [case $system in
    *-linux*)
	AS_IF([test "x$LOGNAME" != "xbuildslave" &&
	    test "x$LOGNAME" != "xbuildbot"],
	    [AC_ERROR([Linux users must specify either
		--enable-linux-d_splice_alias-extra-iput or
		--disable-linux-d_splice_alias-extra-iput])],
	    [enable_linux_d_splice_alias_extra_iput="no"])
     esac
    ])
AC_ARG_WITH([xslt-processor],
	AS_HELP_STRING([--with-xslt-processor=ARG],
	[which XSLT processor to use (possible choices are: libxslt, saxon, xalan-j, xsltproc)]),
       	XSLTPROC="$withval",
	AC_CHECK_PROGS([XSLTPROC], [libxslt saxon xalan-j xsltproc], [echo]))

AC_ARG_WITH([html-xsl], 
        AS_HELP_STRING([--with-html-xsl],
	[build HTML documentation using Norman Walsh's DocBook XSL stylesheets (default is no; specify a path to chunk.xsl or docbook.xsl)]),
	HTML_XSL="$withval",
	HTML_XSL=no)

AC_ARG_WITH([docbook2pdf],
	AS_HELP_STRING([--with-docbook2pdf=ARG],
	[which Docbook to PDF utility to use (possible choices are: docbook2pdf, dblatex)]),
       	DOCBOOK2PDF="$withval",
	AC_CHECK_PROGS([DOCBOOK2PDF], [docbook2pdf dblatex], [echo]))

enable_login="no"

dnl weird ass systems
dnl AC_AIX
AC_ISC_POSIX
dnl AC_MINIX

dnl Various compiler setup.
AC_TYPE_PID_T
AC_TYPE_SIZE_T

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB
AC_PROG_YACC
AM_PROG_LEX
dnl if we are flex, be lex-compatible
OPENAFS_LEX_IS_FLEX([AC_SUBST([LEX], ["$LEX -l"])])

OPENAFS_FORCE_ABS_INSTALL
OPENAFS_CHECK_BIGENDIAN
OPENAFS_PRINTF_TAKES_Z_LEN

AC_MSG_CHECKING(your OS)
system=$host
case $system in
        *-linux*)

		MKAFS_OSTYPE=LINUX
		if test "x$enable_redhat_buildsys" = "xyes"; then
		 AC_DEFINE(ENABLE_REDHAT_BUILDSYS, 1, [define if you have redhat buildsystem])
		fi
		if test "x$enable_kernel_module" = "xyes"; then
		 if test "x$with_linux_kernel_headers" != "x"; then
		   LINUX_KERNEL_PATH="$with_linux_kernel_headers"
		 else
		   for utsdir in "/lib/modules/`uname -r`/build" \
		                 "/lib/modules/`uname -r`/source" \
		                 "/usr/src/linux-2.4" \
		                 "/usr/src/linux"; do
		     LINUX_KERNEL_PATH="$utsdir"
		     for utsfile in "include/generated/utsrelease.h" \
		                    "include/linux/utsrelease.h" \
		                    "include/linux/version.h" \
		                    "include/linux/version-up.h"; do
		       if grep "UTS_RELEASE" "$utsdir/$utsfile" >/dev/null 2>&1; then
		         break 2
		       fi
		     done
		   done
		 fi
		 if test "x$with_linux_kernel_build" != "x"; then
			 LINUX_KERNEL_BUILD="$with_linux_kernel_build"
		 else
		   LINUX_KERNEL_BUILD=$LINUX_KERNEL_PATH
		 fi
                 if test -f "$LINUX_KERNEL_BUILD/include/generated/utsrelease.h"; then
		   linux_kvers=`fgrep UTS_RELEASE $LINUX_KERNEL_BUILD/include/generated/utsrelease.h |awk 'BEGIN { FS="\"" } { print $[]2 }'|tail -n 1`
		   LINUX_VERSION="$linux_kvers"
		 else
                   if test -f "$LINUX_KERNEL_BUILD/include/linux/utsrelease.h"; then
		     linux_kvers=`fgrep UTS_RELEASE $LINUX_KERNEL_BUILD/include/linux/utsrelease.h |awk 'BEGIN { FS="\"" } { print $[]2 }'|tail -n 1`
		     LINUX_VERSION="$linux_kvers"
                   else
		     if test -f "$LINUX_KERNEL_BUILD/include/linux/version.h"; then
		       linux_kvers=`fgrep UTS_RELEASE $LINUX_KERNEL_BUILD/include/linux/version.h |awk 'BEGIN { FS="\"" } { print $[]2 }'|tail -n 1`
		       if test "x$linux_kvers" = "x"; then
		         if test -f "$LINUX_KERNEL_BUILD/include/linux/version-up.h"; then
		           linux_kvers=`fgrep UTS_RELEASE $LINUX_KERNEL_BUILD/include/linux/version-up.h |awk 'BEGIN { FS="\"" } { print $[]2 }'|tail -n 1`
		           if test "x$linux_kvers" = "x"; then
		             AC_MSG_ERROR(Linux headers lack version definition [2])
		             exit 1
		           else
		             LINUX_VERSION="$linux_kvers"
                           fi
                         else
                           AC_MSG_ERROR(Linux headers lack version definition)
		           exit 1
		         fi
		       else
		         LINUX_VERSION="$linux_kvers"
		       fi
		     else
                       enable_kernel_module="no"
                     fi
                   fi
		 fi
		 if test ! -f "$LINUX_KERNEL_BUILD/include/generated/autoconf.h" &&
		    test ! -f "$LINUX_KERNEL_BUILD/include/linux/autoconf.h"; then
		     enable_kernel_module="no"
		 fi
		 if test "x$enable_kernel_module" = "xno"; then
		  if test "x$with_linux_kernel_headers" != "x"; then
		   AC_MSG_ERROR(No usable linux headers found at $LINUX_KERNEL_PATH)
		   exit 1
		  else
		   AC_MSG_WARN(No usable linux headers found at $LINUX_KERNEL_PATH so disabling kernel module)
		  fi
		 fi
                 dnl do we need to determine SUBARCH from autoconf.h
                 SUBARCH=default
		fi
		AC_MSG_RESULT(linux)
                if test "x$enable_kernel_module" = "xyes"; then
                 case "$LINUX_VERSION" in
                  2.2.*) AFS_SYSKVERS=22 ;;
                  2.4.*) AFS_SYSKVERS=24 ;;
                  [2.6.* | [3-9]* | [1-2][0-9]*]) AFS_SYSKVERS=26 ;;
                  *) AC_MSG_ERROR(Couldn't guess your Linux version [2]) ;;
                 esac
                fi
                ;;
        *-solaris*)
		MKAFS_OSTYPE=SOLARIS
                AC_MSG_RESULT(sun4)
	        AC_PATH_PROG(SOLARISCC, [cc], ,
		    [/opt/SunStudioExpress/bin:/opt/solarisstudio12.3/bin:/opt/solstudio12.2/bin:/opt/sunstudio12.1/bin:/opt/SUNWspro/bin])
		if test "x$SOLARISCC" = "x" ; then
		    AC_MSG_FAILURE(Could not find the solaris cc program.  Please define the environment variable SOLARISCC to specify the path.)
		fi
		SOLARIS_UFSVFS_HAS_DQRWLOCK
		SOLARIS_FS_HAS_FS_ROLLED
		SOLARIS_SOLOOKUP_TAKES_SOCKPARAMS
		SOLARIS_HAVE_VN_RENAMEPATH
                ;;
        *-sunos*)
		MKAFS_OSTYPE=SUNOS
		enable_kernel_module=no
                AC_MSG_RESULT(sun4)
                ;;
        *-hpux*)
		MKAFS_OSTYPE=HPUX
                AC_MSG_RESULT(hp_ux)
		if test -f "/usr/old/usr/include/ndir.h"; then
		 AC_DEFINE(HAVE_USR_OLD_USR_INCLUDE_NDIR_H, 1, [define if you have old ndir.h])
		fi
                ;;
        *-irix*)
		if test -d /usr/include/sys/SN/SN1; then
		 IRIX_BUILD_IP35="IP35"
		fi
		MKAFS_OSTYPE=IRIX
                AC_MSG_RESULT(sgi)
                ;;
        *-aix*)
		MKAFS_OSTYPE=AIX
                AC_MSG_RESULT(rs_aix)
                ;;
        arm-*-darwin*)
		MKAFS_OSTYPE=DARWIN
                AC_MSG_RESULT(arm_darwin)
                ;;
        powerpc-*-darwin*)
		MKAFS_OSTYPE=DARWIN
                AC_MSG_RESULT(ppc_darwin)
                ;;
        i386-*-darwin*)
		MKAFS_OSTYPE=DARWIN
                AC_MSG_RESULT(x86_darwin)
                ;;
        x86_64-*-darwin*)
		MKAFS_OSTYPE=DARWIN
                AC_MSG_RESULT(x86_darwin)
                ;;
	i386-*-freebsd*)
		MKAFS_OSTYPE=FBSD
		AC_MSG_RESULT(i386_fbsd)
		;;
	x86_64-*-freebsd*)
		MKAFS_OSTYPE=FBSD
		AC_MSG_RESULT(amd64_fbsd)
		;;
	*-netbsd*)
		MKAFS_OSTYPE=NBSD
		AC_MSG_RESULT(nbsd)
		;;
	x86_64-*-openbsd*)
		MKAFS_OSTYPE=OBSD
		AC_MSG_RESULT(amd64_obsd)
		;;
	i386-*-openbsd*)
		MKAFS_OSTYPE=OBSD
		AC_MSG_RESULT(i386_obsd)
		;;
	*-dragonfly*)
		MKAFS_OSTYPE=DFBSD
		AC_MSG_RESULT(i386_dfbsd)
		;;
        *)
                AC_MSG_RESULT($system)
                ;;
esac

if test "x$with_afs_sysname" != "x"; then
        AFS_SYSNAME="$with_afs_sysname"
else
	AC_MSG_CHECKING(your AFS sysname)
	case $host in
		i?86-*-openbsd?.?)
			v=${host#*openbsd}
			vM=${v%.*}
			vm=${v#*.}
			AFS_SYSNAME="i386_obsd${vM}${vm}"
			;;
		sparc64-*-openbsd?.?)
			v=${host#*openbsd}
			vM=${v%.*}
			vm=${v#*.}
			AFS_SYSNAME="sparc64_obsd${vM}${vm}"
			;;
		x86_64-*-openbsd?.?)
			v=${host#*openbsd}
			vM=${v%.*}
			vm=${v#*.}
			AFS_SYSNAME="amd64_obsd${vM}${vm}"
			;;
		i?86-*-freebsd*.*)
			v=${host#*freebsd}
			vM=${v%.*}
			vm=${v#*.}
			AFS_SYSNAME="i386_fbsd_${vM}${vm}"
			;;
		x86_64-*-freebsd*.*)
			v=${host#*freebsd}
			vM=${v%.*}
			vm=${v#*.}
			AFS_SYSNAME="amd64_fbsd_${vM}${vm}"
			;;
		i386-*-dragonfly?.*)
			v=${host#*dragonfly}
			vM=${v%.*}
			vm=${v#*.}
			AFS_SYSNAME="i386_dfbsd_${vM}${vm}"
			;;
		i?86-*-netbsd*1.6[[M-Z]]*)
			AFS_SYSNAME="i386_nbsd20"
			;;
		powerpc-*-netbsd*1.6[[M-Z]]*)
			AFS_SYSNAME="ppc_nbsd20"
			;;
		*-*-netbsd*)
			arch=${host%%-unknown*}
			arch=$(echo $arch |sed -e 's/x86_64/amd64/g' \
					       -e 's/powerpc/ppc/g')
			v=${host#*netbsd}
			v=${v#*aout}
			v=${v#*ecoff}
			v=${v#*elf}
			vM=${v%%.*}
			vM=${vM%.*}
			v=${v#*.}
			vm=${v%%.*}
			vm=${vm%.*}
			vm=${vm%%[[_A-Z]]*}
			if test $vm -eq 99 ; then
				vM=$((vM+1))
			fi
			if test $vM -gt 1 ; then
				vm=0
			fi
			AFS_SYSNAME="${arch}_nbsd${vM}${vm}"
			;;
		hppa*-hp-hpux11.0*)
			AFS_SYSNAME="hp_ux110"
			;;
		hppa*-hp-hpux11.11)
			AFS_SYSNAME="hp_ux11i"
			;;
		hppa*-hp-hpux11.23)
			AFS_SYSNAME="hp_ux1123"
			;;
		ia64-hp-hpux11.22)
			AFS_SYSNAME="ia64_hpux1122"
			;;
		ia64-hp-hpux*)
			AFS_SYSNAME="ia64_hpux1123"
			;;
		hppa*-hp-hpux10*)
			AFS_SYSNAME="hp_ux102"
			;;
		powerpc-apple-darwin7*)
			AFS_SYSNAME="ppc_darwin_70"
			OSXSDK="macosx10.3"
			;;
		powerpc-apple-darwin8.*)
			AFS_SYSNAME="ppc_darwin_80"
			OSXSDK="macosx10.4"
			;;
		i386-apple-darwin8.*)
			AFS_SYSNAME="x86_darwin_80"
			OSXSDK="macosx10.4"
			;;
		powerpc-apple-darwin9.*)
			AFS_SYSNAME="ppc_darwin_90"
			OSXSDK="macosx10.5"
			;;
		i386-apple-darwin9.*)
			AFS_SYSNAME="x86_darwin_90"
			OSXSDK="macosx10.5"
			;;
		i?86-apple-darwin10.*)
			AFS_SYSNAME="x86_darwin_100"
			OSXSDK="macosx10.6"
			;;
		x86_64-apple-darwin10.*)
			AFS_SYSNAME="x86_darwin_100"
			OSXSDK="macosx10.6"
			;;
		arm-apple-darwin10.*)
			AFS_SYSNAME="arm_darwin_100"
			OSXSDK="iphoneos4.0"
			;;
		x86_64-apple-darwin11.*)
			AFS_SYSNAME="x86_darwin_110"
			OSXSDK="macosx10.7"
			;;
		i?86-apple-darwin11.*)
			AFS_SYSNAME="x86_darwin_110"
			OSXSDK="macosx10.7"
			;;
		x86_64-apple-darwin12.*)
			AFS_SYSNAME="x86_darwin_120"
			OSXSDK="macosx10.8"
			;;
		i?86-apple-darwin12.*)
			AFS_SYSNAME="x86_darwin_120"
			OSXSDK="macosx10.8"
			;;
		x86_64-apple-darwin13.*)
			AFS_SYSNAME="x86_darwin_130"
			OSXSDK="macosx10.9"
			;;
		i?86-apple-darwin13.*)
			AFS_SYSNAME="x86_darwin_130"
			OSXSDK="macosx10.9"
			;;
		x86_64-apple-darwin14.*)
			AFS_SYSNAME="x86_darwin_140"
			OSXSDK="macosx10.10"
			;;
		i?86-apple-darwin14.*)
			AFS_SYSNAME="x86_darwin_140"
			OSXSDK="macosx10.10"
			;;
		sparc-sun-solaris2.5*)
			AFS_SYSNAME="sun4x_55"
			enable_login="yes"
			;;
		sparc-sun-solaris2.6)
			AFS_SYSNAME="sun4x_56"
			;;
		sparc-sun-solaris2.7)
			AFS_SYSNAME="sun4x_57"
			;;
		sparc-sun-solaris2.8)
			AFS_SYSNAME="sun4x_58"
			;;
		sparc-sun-solaris2.9)
			AFS_SYSNAME="sun4x_59"
			;;
		sparc-sun-solaris2.10)
			AFS_SYSNAME="sun4x_510"
			;;
		sparc-sun-solaris2.11)
			AFS_SYSNAME="sun4x_511"
			;;
		sparc-sun-sunos4*)
			AFS_SYSNAME="sun4_413"
			enable_login="yes"
			;;
		i386-pc-solaris2.7)
			AFS_SYSNAME="sunx86_57"
			;;
		i386-pc-solaris2.8)
			AFS_SYSNAME="sunx86_58"
			;;
		i386-pc-solaris2.9)
			AFS_SYSNAME="sunx86_59"
			;;
		i386-pc-solaris2.10)
			AFS_SYSNAME="sunx86_510"
			;;
		i386-pc-solaris2.11)
			AFS_SYSNAME="sunx86_511"
			;;
		alpha*-dec-osf4.0*)
			AFS_SYSNAME="alpha_dux40"
			;;
		alpha*-dec-osf5.0*)
			AFS_SYSNAME="alpha_dux50"
			;;
		alpha*-dec-osf5.1*)
			AFS_SYSNAME="alpha_dux51"
			;;
		mips-sgi-irix6.5)
			AFS_SYSNAME="sgi_65"
			;;
		ia64-*-linux*)
			AFS_SYSNAME="ia64_linuxXX"
			;;
		powerpc-*-linux*)
			AFS_SYSNAME="`/bin/arch`_linuxXX"
			;;
		powerpc64-*-linux*)
			AFS_SYSNAME="ppc64_linuxXX"
			;;
		alpha*-linux*)
			AFS_SYSNAME="alpha_linux_XX"
			;;
		s390-*-linux*)
			AFS_SYSNAME="s390_linuxXX"
			;;
		s390x-*-linux*)
			AFS_SYSNAME="s390x_linuxXX"
			;;
		sparc-*-linux*)
			AFS_SYSNAME="`/bin/arch`_linuxXX"
			;;
		sparc64-*-linux*)
			AFS_SYSNAME="sparc64_linuxXX"
			;;
		i?86-*-linux*)
			AFS_SYSNAME="i386_linuxXX"
			;;
		arm*-linux*)
			AFS_SYSNAME="arm_linuxXX"
			;;
		parisc-*-linux-gnu|hppa-*-linux-gnu)
			AFS_SYSNAME="parisc_linuxXX"
			enable_pam="no"
			;;
		power*-ibm-aix4.2*)
			AFS_SYSNAME="rs_aix42"
			enable_pam="no"
			;;
		power*-ibm-aix4.3*)
			AFS_SYSNAME="rs_aix42"
			enable_pam="no"
			;;
		power*-ibm-aix5.1*)
			AFS_SYSNAME="rs_aix51"
			enable_pam="no"
			;;
		power*-ibm-aix5.2*)
			AFS_SYSNAME="rs_aix52"
			enable_pam="no"
			;;
		power*-ibm-aix5.3*)
			AFS_SYSNAME="rs_aix53"
			enable_pam="no"
			;;
		power*-ibm-aix6.1*)
			AFS_SYSNAME="rs_aix61"
			enable_pam="no"
			;;
		x86_64-*-linux-gnu)
			AFS_SYSNAME="amd64_linuxXX"
			enable_pam="yes"
			;;
		*)
			AC_MSG_ERROR(An AFS sysname is required)
			exit 1
			;;
	esac
	case $AFS_SYSNAME in
		*_linux* | *_umlinux*)
			if test "x${AFS_SYSKVERS}" = "x"; then
			 AC_MSG_ERROR(Couldn't guess your Linux version. Please use the --with-afs-sysname option to configure an AFS sysname.)
			fi
			_AFS_SYSNAME=`echo $AFS_SYSNAME|sed s/XX\$/$AFS_SYSKVERS/`
			AFS_SYSNAME="$_AFS_SYSNAME"
			AC_TRY_KBUILD(
			 [],
			 [#ifndef CONFIG_USERMODE
			  #error not UML
			  #endif],
			 ac_cv_linux_is_uml=yes,)
			if test "${ac_cv_linux_is_uml}" = yes; then
			 _AFS_SYSNAME=`echo $AFS_SYSNAME|sed s/linux/umlinux/`
			fi
			AFS_SYSNAME="$_AFS_SYSNAME"
			;;
	esac
        AC_MSG_RESULT($AFS_SYSNAME)
fi

case $AFS_SYSNAME in
	*_darwin*)
		AC_CHECK_HEADERS(crt_externs.h)
		DARWIN_PLIST=src/libafs/afs.${AFS_SYSNAME}.plist
		DARWIN_INFOFILE=afs.${AFS_SYSNAME}.plist
		AC_SUBST(OSXSDK)
		;;
esac

dnl Some hosts have a separate common param file they should include.  Figure
dnl out if we're on one of them now that we know the sysname.
case $AFS_SYSNAME in
    *_nbsd15)   AFS_PARAM_COMMON=param.nbsd15.h  ;;
    *_nbsd16)   AFS_PARAM_COMMON=param.nbsd16.h  ;;
    *_nbsd20)   AFS_PARAM_COMMON=param.nbsd20.h  ;;
    *_nbsd21)   AFS_PARAM_COMMON=param.nbsd21.h  ;;
    *_nbsd30)   AFS_PARAM_COMMON=param.nbsd30.h  ;;
    *_nbsd40)   AFS_PARAM_COMMON=param.nbsd40.h  ;;
    *_nbsd50)   AFS_PARAM_COMMON=param.nbsd50.h  ;;
    *_nbsd60)   AFS_PARAM_COMMON=param.nbsd60.h  ;;
    *_obsd31)   AFS_PARAM_COMMON=param.obsd31.h  ;;
    *_obsd32)   AFS_PARAM_COMMON=param.obsd32.h  ;;
    *_obsd33)   AFS_PARAM_COMMON=param.obsd33.h  ;;
    *_obsd34)   AFS_PARAM_COMMON=param.obsd34.h  ;;
    *_obsd35)   AFS_PARAM_COMMON=param.obsd35.h  ;;
    *_obsd36)   AFS_PARAM_COMMON=param.obsd36.h  ;;
    *_obsd37)   AFS_PARAM_COMMON=param.obsd37.h  ;;
    *_obsd38)   AFS_PARAM_COMMON=param.obsd38.h  ;;
    *_obsd39)   AFS_PARAM_COMMON=param.obsd39.h  ;;
    *_obsd40)   AFS_PARAM_COMMON=param.obsd40.h  ;;
    *_obsd41)   AFS_PARAM_COMMON=param.obsd41.h  ;;
    *_obsd42)   AFS_PARAM_COMMON=param.obsd42.h  ;;
    *_obsd43)   AFS_PARAM_COMMON=param.obsd43.h  ;;
    *_obsd44)   AFS_PARAM_COMMON=param.obsd44.h  ;;
    *_obsd45)   AFS_PARAM_COMMON=param.obsd45.h  ;;
    *_obsd46)   AFS_PARAM_COMMON=param.obsd46.h  ;;
    *_obsd47)   AFS_PARAM_COMMON=param.obsd47.h  ;;
    *_obsd48)   AFS_PARAM_COMMON=param.obsd48.h  ;;
    *_obsd49)   AFS_PARAM_COMMON=param.obsd49.h  ;;
    *_obsd50)   AFS_PARAM_COMMON=param.obsd50.h  ;;
    *_obsd51)   AFS_PARAM_COMMON=param.obsd51.h  ;;
    *_obsd52)   AFS_PARAM_COMMON=param.obsd52.h  ;;
    *_obsd53)   AFS_PARAM_COMMON=param.obsd53.h  ;;
    *_obsd54)   AFS_PARAM_COMMON=param.obsd54.h  ;;
    *_linux22)  AFS_PARAM_COMMON=param.linux22.h ;;
    *_linux24)  AFS_PARAM_COMMON=param.linux24.h ;;
    *_linux26)  AFS_PARAM_COMMON=param.linux26.h ;;
# Linux alpha adds an extra underscore for no good reason.
    *_linux_22) AFS_PARAM_COMMON=param.linux22.h ;;
    *_linux_24) AFS_PARAM_COMMON=param.linux24.h ;;
    *_linux_26) AFS_PARAM_COMMON=param.linux26.h ;;
esac

case $AFS_SYSNAME in *_linux* | *_umlinux*)

		# Add (sub-) architecture-specific paths needed by conftests
		case $AFS_SYSNAME  in
			*_umlinux26)
				UMLINUX26_FLAGS="-I$LINUX_KERNEL_PATH/arch/um/include"
				UMLINUX26_FLAGS="$UMLINUX26_FLAGS -I$LINUX_KERNEL_PATH/arch/um/kernel/tt/include"
 				UMLINUX26_FLAGS="$UMLINUX26_FLAGS -I$LINUX_KERNEL_PATH/arch/um/kernel/skas/include"
				CPPFLAGS="$CPPFLAGS $UMLINUX26_FLAGS"
		esac

		if test "x$enable_kernel_module" = "xyes"; then
		 if test "x$enable_debug_kernel" = "xno"; then
			LINUX_GCC_KOPTS="$LINUX_GCC_KOPTS -fomit-frame-pointer"
		 fi
		 OPENAFS_GCC_SUPPORTS_MARCH
		 AC_SUBST(P5PLUS_KOPTS)
		 OPENAFS_GCC_NEEDS_NO_STRENGTH_REDUCE
		 OPENAFS_GCC_NEEDS_NO_STRICT_ALIASING
		 OPENAFS_GCC_SUPPORTS_NO_COMMON
		 OPENAFS_GCC_SUPPORTS_PIPE
		 AC_SUBST(LINUX_GCC_KOPTS)

		 dnl Setup the kernel build environment
		 LINUX_KBUILD_USES_EXTRA_CFLAGS
		 LINUX_KERNEL_COMPILE_WORKS

		 dnl Check for header files
		 AC_CHECK_LINUX_HEADER([config.h])
		 AC_CHECK_LINUX_HEADER([completion.h])
		 AC_CHECK_LINUX_HEADER([exportfs.h])
		 AC_CHECK_LINUX_HEADER([freezer.h])
		 AC_CHECK_LINUX_HEADER([key-type.h])
		 AC_CHECK_LINUX_HEADER([semaphore.h])
		 AC_CHECK_LINUX_HEADER([seq_file.h])

		 dnl Type existence checks
		 AC_CHECK_LINUX_TYPE([struct vfs_path], [dcache.h])
		 AC_CHECK_LINUX_TYPE([kuid_t], [uidgid.h])

		 dnl Check for structure elements
		 AC_CHECK_LINUX_STRUCT([address_space], [backing_dev_info], [fs.h])
		 AC_CHECK_LINUX_STRUCT([address_space_operations],
				       [write_begin], [fs.h])
		 AC_CHECK_LINUX_STRUCT([backing_dev_info], [name],
				       [backing-dev.h])
		 AC_CHECK_LINUX_STRUCT([cred], [session_keyring], [cred.h])
		 AC_CHECK_LINUX_STRUCT([ctl_table], [ctl_name], [sysctl.h])
		 AC_CHECK_LINUX_STRUCT([dentry], [d_u.d_alias], [dcache.h])
		 AC_CHECK_LINUX_STRUCT([dentry_operations], [d_automount], [dcache.h])
		 AC_CHECK_LINUX_STRUCT([inode], [i_alloc_sem], [fs.h])
		 AC_CHECK_LINUX_STRUCT([inode], [i_blkbits], [fs.h])
		 AC_CHECK_LINUX_STRUCT([inode], [i_blksize], [fs.h])
		 AC_CHECK_LINUX_STRUCT([inode], [i_mutex], [fs.h])
		 AC_CHECK_LINUX_STRUCT([inode], [i_security], [fs.h])
		 AC_CHECK_LINUX_STRUCT([file], [f_path], [fs.h])
		 AC_CHECK_LINUX_STRUCT([file_operations], [flock], [fs.h])
		 AC_CHECK_LINUX_STRUCT([file_operations], [iterate], [fs.h])
		 AC_CHECK_LINUX_STRUCT([file_operations], [read_iter], [fs.h])
		 AC_CHECK_LINUX_STRUCT([file_operations], [sendfile], [fs.h])
		 AC_CHECK_LINUX_STRUCT([file_system_type], [mount], [fs.h])
		 AC_CHECK_LINUX_STRUCT([inode_operations], [truncate], [fs.h])
		 AC_CHECK_LINUX_STRUCT([key_type], [instantiate_prep], [key-type.h])
		 AC_CHECK_LINUX_STRUCT([key_type], [match_preparse], [key-type.h])
		 AC_CHECK_LINUX_STRUCT([key_type], [preparse], [key-type.h])
		 AC_CHECK_LINUX_STRUCT([msghdr], [msg_iter], [socket.h])
		 AC_CHECK_LINUX_STRUCT([nameidata], [path], [namei.h])
		 AC_CHECK_LINUX_STRUCT([proc_dir_entry], [owner], [proc_fs.h])
		 AC_CHECK_LINUX_STRUCT([super_block], [s_bdi], [fs.h])
		 AC_CHECK_LINUX_STRUCT([super_block], [s_d_op], [fs.h])
		 AC_CHECK_LINUX_STRUCT([super_operations], [alloc_inode],
				       [fs.h])
		 AC_CHECK_LINUX_STRUCT([super_operations], [evict_inode],
				       [fs.h])
                 AC_CHECK_LINUX_STRUCT([task_struct], [cred], [sched.h])
		 AC_CHECK_LINUX_STRUCT([task_struct], [exit_state], [sched.h])
		 AC_CHECK_LINUX_STRUCT([task_struct], [parent], [sched.h])
		 AC_CHECK_LINUX_STRUCT([task_struct], [real_parent], [sched.h])
		 AC_CHECK_LINUX_STRUCT([task_struct], [rlim], [sched.h])
		 AC_CHECK_LINUX_STRUCT([task_struct], [sig], [sched.h])
		 AC_CHECK_LINUX_STRUCT([task_struct], [sighand], [sched.h])
		 AC_CHECK_LINUX_STRUCT([task_struct], [sigmask_lock], [sched.h])
		 AC_CHECK_LINUX_STRUCT([task_struct], [tgid], [sched.h])
		 AC_CHECK_LINUX_STRUCT([task_struct], [thread_info], [sched.h])
		 LINUX_SCHED_STRUCT_TASK_STRUCT_HAS_SIGNAL_RLIM

		 dnl Check for typed structure elements
		 AC_CHECK_LINUX_TYPED_STRUCT([read_descriptor_t],
				     	     [buf], [fs.h])

		 dnl Function existence checks

		 AC_CHECK_LINUX_FUNC([__vfs_read],
				     [#include <linux/fs.h>],
				     [__vfs_read(NULL, NULL, 0, NULL);])
                 AC_CHECK_LINUX_FUNC([bdi_init],
				     [#include <linux/backing-dev.h>],
				     [bdi_init(NULL);])
                 AC_CHECK_LINUX_FUNC([PageChecked],
				     [#include <linux/mm.h>
#include <linux/page-flags.h>],
				     [struct page *_page;
                                      int bchecked = PageChecked(_page);])
                 AC_CHECK_LINUX_FUNC([PageFsMisc],
				     [#include <linux/mm.h>
#include <linux/page-flags.h>],
				     [struct page *_page;
                                      int bchecked = PageFsMisc(_page);])
		 AC_CHECK_LINUX_FUNC([clear_inode],
				     [#include <linux/fs.h>],
				     [clear_inode(NULL);])
		 AC_CHECK_LINUX_FUNC([current_kernel_time],
				     [#include <linux/time.h>],
			             [struct timespec s;
				      s = current_kernel_time();])
		 AC_CHECK_LINUX_FUNC([d_alloc_anon],
				     [#include <linux/fs.h>],
				     [d_alloc_anon(NULL);])
		 AC_CHECK_LINUX_FUNC([d_count],
				     [#include <linux/dcache.h>],
				     [d_count(NULL);])
		 AC_CHECK_LINUX_FUNC([d_make_root],
				     [#include <linux/fs.h>],
				     [d_make_root(NULL);])
		 AC_CHECK_LINUX_FUNC([do_sync_read],
				     [#include <linux/fs.h>],
				     [do_sync_read(NULL, NULL, 0, NULL);])
		 AC_CHECK_LINUX_FUNC([find_task_by_pid],
				     [#include <linux/sched.h>],
				     [pid_t p; find_task_by_pid(p);])
		 AC_CHECK_LINUX_FUNC([generic_file_aio_read],
				     [#include <linux/fs.h>],
				     [generic_file_aio_read(NULL,NULL,0,0);])
		 AC_CHECK_LINUX_FUNC([grab_cache_page_write_begin],
				     [#include <linux/pagemap.h>],
				     [grab_cache_page_write_begin(NULL, 0, 0);])
		 AC_CHECK_LINUX_FUNC([hlist_unhashed],
				     [#include <linux/list.h>],
				     [hlist_unhashed(0);])
		 AC_CHECK_LINUX_FUNC([ihold],
				     [#include <linux/fs.h>],
				     [ihold(NULL);])
		 AC_CHECK_LINUX_FUNC([i_size_read],
				     [#include <linux/fs.h>],
				     [i_size_read(NULL);])
		 AC_CHECK_LINUX_FUNC([inode_setattr],
				     [#include <linux/fs.h>],
				     [inode_setattr(NULL, NULL);])
		 AC_CHECK_LINUX_FUNC([iter_file_splice_write],
				     [#include <linux/fs.h>],
				     [iter_file_splice_write(NULL,NULL,NULL,0,0);])
		 AC_CHECK_LINUX_FUNC([kernel_setsockopt],
				     [#include <linux/net.h>],
				     [kernel_setsockopt(NULL, 0, 0, NULL, 0);])
		 AC_CHECK_LINUX_FUNC([page_follow_link],
				     [#include <linux/fs.h>],
				     [page_follow_link(0,0);])
		 AC_CHECK_LINUX_FUNC([page_offset],
				     [#include <linux/pagemap.h>],
				     [page_offset(NULL);])
		 AC_CHECK_LINUX_FUNC([pagevec_lru_add_file],
				     [#include <linux/pagevec.h>],
				     [__pagevec_lru_add_file(NULL);])
		 AC_CHECK_LINUX_FUNC([path_lookup],
				     [#include <linux/fs.h>
				      #include <linux/namei.h>],
				     [path_lookup(NULL, 0, NULL);])
		 AC_CHECK_LINUX_FUNC([proc_create],
				     [#include <linux/proc_fs.h>],
				     [proc_create(NULL, 0, NULL, NULL);])
		 AC_CHECK_LINUX_FUNC([rcu_read_lock],
				     [#include <linux/rcupdate.h>],
				     [rcu_read_lock();])
		 AC_CHECK_LINUX_FUNC([set_nlink],
				     [#include <linux/fs.h>],
				     [set_nlink(NULL, 1);])
		 AC_CHECK_LINUX_FUNC([sock_create_kern],
				     [#include <linux/net.h>],
				     [sock_create_kern(0, 0, 0, NULL);])
		 AC_CHECK_LINUX_FUNC([splice_direct_to_actor],
				     [#include <linux/splice.h>],
				     [splice_direct_to_actor(NULL,NULL,NULL);])
		 AC_CHECK_LINUX_FUNC([svc_addr_in],
				     [#include <linux/sunrpc/svc.h>],
				     [svc_addr_in(NULL);])
		 AC_CHECK_LINUX_FUNC([zero_user_segments],
				     [#include <linux/highmem.h>],
				     [zero_user_segments(NULL, 0, 0, 0, 0);])
		 AC_CHECK_LINUX_FUNC([noop_fsync],
				     [#include <linux/fs.h>],
				     [void *address = &noop_fsync; printk("%p\n", address)];)
		 AC_CHECK_LINUX_FUNC([kthread_run],
				     [#include <linux/kernel.h>
				      #include <linux/kthread.h>],
				     [kthread_run(NULL, NULL, "test");])

		 dnl Consequences - things which get set as a result of the
		 dnl                above tests
		 AS_IF([test "x$ac_cv_linux_func_d_alloc_anon" = "xno"],
		       [AC_DEFINE([AFS_NONFSTRANS], 1,
				  [define to disable the nfs translator])])

		 dnl Assorted more complex tests
		 LINUX_AIO_NONVECTOR
		 LINUX_EXPORTS_PROC_ROOT_FS
                 LINUX_KMEM_CACHE_INIT
		 LINUX_HAVE_KMEM_CACHE_T
                 LINUX_KMEM_CACHE_CREATE_TAKES_DTOR
		 LINUX_KMEM_CACHE_CREATE_CTOR_TAKES_VOID
		 LINUX_D_PATH_TAKES_STRUCT_PATH
		 LINUX_NEW_EXPORT_OPS
		 LINUX_INODE_SETATTR_RETURN_TYPE
		 LINUX_IOP_I_CREATE_TAKES_NAMEIDATA
		 LINUX_IOP_I_LOOKUP_TAKES_NAMEIDATA
		 LINUX_IOP_I_PERMISSION_TAKES_FLAGS
	  	 LINUX_IOP_I_PERMISSION_TAKES_NAMEIDATA
	  	 LINUX_IOP_I_PUT_LINK_TAKES_COOKIE
		 LINUX_DOP_D_DELETE_TAKES_CONST
	  	 LINUX_DOP_D_REVALIDATE_TAKES_NAMEIDATA
	  	 LINUX_FOP_F_FLUSH_TAKES_FL_OWNER_T
	  	 LINUX_FOP_F_FSYNC_TAKES_DENTRY
		 LINUX_FOP_F_FSYNC_TAKES_RANGE
	  	 LINUX_AOP_WRITEBACK_CONTROL
		 LINUX_FS_STRUCT_FOP_HAS_SPLICE
		 LINUX_KERNEL_POSIX_LOCK_FILE_WAIT_ARG
		 LINUX_POSIX_TEST_LOCK_RETURNS_CONFLICT
		 LINUX_POSIX_TEST_LOCK_CONFLICT_ARG
		 LINUX_KERNEL_SOCK_CREATE
		 LINUX_EXPORTS_KEY_TYPE_KEYRING
		 LINUX_KEYS_HAVE_SESSION_TO_PARENT
		 LINUX_NEED_RHCONFIG
		 LINUX_RECALC_SIGPENDING_ARG_TYPE
		 LINUX_EXPORTS_TASKLIST_LOCK
		 LINUX_GET_SB_HAS_STRUCT_VFSMOUNT
		 LINUX_STATFS_TAKES_DENTRY
		 LINUX_REFRIGERATOR
		 LINUX_HAVE_TRY_TO_FREEZE
		 LINUX_LINUX_KEYRING_SUPPORT
		 LINUX_KEY_ALLOC_NEEDS_STRUCT_TASK
		 LINUX_KEY_ALLOC_NEEDS_CRED
		 LINUX_INIT_WORK_HAS_DATA
		 LINUX_REGISTER_SYSCTL_TABLE_NOFLAG
		 LINUX_HAVE_DCACHE_LOCK
		 LINUX_D_COUNT_IS_INT
		 LINUX_IOP_MKDIR_TAKES_UMODE_T
		 LINUX_IOP_CREATE_TAKES_UMODE_T
		 LINUX_EXPORT_OP_ENCODE_FH_TAKES_INODES
		 LINUX_KMAP_ATOMIC_TAKES_NO_KM_TYPE
		 LINUX_DENTRY_OPEN_TAKES_PATH
		 LINUX_D_ALIAS_IS_HLIST
		 LINUX_HLIST_ITERATOR_NO_NODE
		 LINUX_IOP_I_CREATE_TAKES_BOOL
		 LINUX_DOP_D_REVALIDATE_TAKES_UNSIGNED
		 LINUX_IOP_LOOKUP_TAKES_UNSIGNED
		 LINUX_D_INVALIDATE_IS_VOID

		 dnl If we are guaranteed that keyrings will work - that is
		 dnl  a) The kernel has keyrings enabled
		 dnl  b) The code is new enough to give us a key_type_keyring
		 dnl then we just disable syscall probing unless we've been
		 dnl told otherwise

		 AS_IF([test "$enable_linux_syscall_probing" = "maybe"],
		   [AS_IF([test "$ac_cv_linux_keyring_support" = "yes" -a "$ac_cv_linux_exports_key_type_keyring" = "yes"],
			  [enable_linux_syscall_probing="no"],
			  [enable_linux_syscall_probing="yes"])
                 ])

		 dnl Syscall probing needs a few tests of its own, and just
		 dnl won't work if the kernel doesn't export init_mm
		 AS_IF([test "$enable_linux_syscall_probing" = "yes"], [
                   LINUX_EXPORTS_INIT_MM
		   AS_IF([test "$ac_cv_linux_exports_init_mm" = "no"], [
                     AC_MSG_ERROR(
		       [Can't do syscall probing without exported init_mm])
                   ])
		   LINUX_EXPORTS_SYS_CHDIR
	           LINUX_EXPORTS_SYS_OPEN
		   AC_DEFINE(ENABLE_LINUX_SYSCALL_PROBING, 1,
			     [define to enable syscall table probes])
		 ])

		 dnl Packaging and SMP build
		 if test "x$with_linux_kernel_packaging" != "xyes" ; then
		   LINUX_WHICH_MODULES
		 else
		   AC_SUBST(MPS,'SP')
		 fi

		 dnl Syscall probing
                 if test "x$ac_cv_linux_config_modversions" = "xno" -o $AFS_SYSKVERS -ge 26; then
		   AS_IF([test "$enable_linux_syscall_probing" = "yes"], [
                     AC_MSG_WARN([Cannot determine sys_call_table status. assuming it isn't exported])
		   ])
                   ac_cv_linux_exports_sys_call_table=no
		   if test -f "$LINUX_KERNEL_PATH/include/asm/ia32_unistd.h"; then
		     ac_cv_linux_exports_ia32_sys_call_table=yes
		   fi
                 else
                   LINUX_EXPORTS_KALLSYMS_ADDRESS
                   LINUX_EXPORTS_KALLSYMS_SYMBOL
                   LINUX_EXPORTS_SYS_CALL_TABLE
                   LINUX_EXPORTS_IA32_SYS_CALL_TABLE
                   if test "x$ac_cv_linux_exports_sys_call_table" = "xno"; then
                         linux_syscall_method=none
                         if test "x$ac_cv_linux_exports_init_mm" = "xyes"; then
                            linux_syscall_method=scan
                            if test "x$ac_cv_linux_exports_kallsyms_address" = "xyes"; then
                               linux_syscall_method=scan_with_kallsyms_address
                            fi
                         fi
                         if test "x$ac_cv_linux_exports_kallsyms_symbol" = "xyes"; then
                            linux_syscall_method=kallsyms_symbol
                         fi
                         if test "x$linux_syscall_method" = "xnone"; then
			    AC_MSG_WARN([no available sys_call_table access method -- guessing scan])
                            linux_syscall_method=scan
                         fi
                   fi
                 fi
		 if test -f "$LINUX_KERNEL_PATH/include/linux/in_systm.h"; then
		  AC_DEFINE(HAVE_IN_SYSTM_H, 1, [define if you have in_systm.h header file])
	         fi
		 if test -f "$LINUX_KERNEL_PATH/include/linux/mm_inline.h"; then
		  AC_DEFINE(HAVE_MM_INLINE_H, 1, [define if you have mm_inline.h header file])
	         fi
		 if test "x$ac_cv_linux_kernel_page_follow_link" = "xyes" -o "x$ac_cv_linux_func_i_put_link_takes_cookie" = "xyes"; then
		  AC_DEFINE(USABLE_KERNEL_PAGE_SYMLINK_CACHE, 1, [define if your kernel has a usable symlink cache API])
		 else
		  AC_MSG_WARN([your kernel does not have a usable symlink cache API])
		 fi
                :
		fi
		if test "x$enable_linux_d_splice_alias_extra_iput" = xyes; then
		    AC_DEFINE(D_SPLICE_ALIAS_LEAK_ON_ERROR, 1, [for internal use])
		fi
dnl Linux-only, but just enable always.
		AC_DEFINE(AFS_CACHE_BYPASS, 1, [define to activate cache bypassing Unix client])
esac

AC_CACHE_CHECK([if struct sockaddr has sa_len field],
    [ac_cv_sockaddr_len],
    [AC_TRY_COMPILE( [#include <sys/types.h>
#include <sys/socket.h>],
                     [struct sockaddr *a; a->sa_len=0;],
		     [ac_cv_sockaddr_len=yes],
		     [ac_cv_sockaddr_len=no])
])
AS_IF([test "$ac_cv_sockaddr_len" = "yes"],
      [AC_DEFINE(STRUCT_SOCKADDR_HAS_SA_LEN, 1,
		 [define if you struct sockaddr sa_len])])

if test "x${MKAFS_OSTYPE}" = "xIRIX"; then
        echo Skipping library tests because they confuse Irix.
else
  AC_SEARCH_LIBS([socket], [socket inet])
  AC_SEARCH_LIBS([connect], [nsl])
  AC_SEARCH_LIBS([gethostbyname], [dns nsl resolv])

  dnl darwin wants it, aix hates it
  AC_MSG_CHECKING(for the useability of arpa/nameser_compat.h)
  AC_TRY_COMPILE([
  #include <stdlib.h>
  #include <stdio.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <arpa/nameser.h>
  #include <arpa/nameser_compat.h>
  #include <resolv.h>
  ], [static int i; i = 0;],
  [AC_MSG_RESULT(yes)
   AC_DEFINE(HAVE_ARPA_NAMESER_COMPAT_H, 1, [define if arpa/nameser_compat.h exists])],
  [AC_MSG_RESULT(no)
   ])

  openafs_save_libs="$LIBS"
  AC_MSG_CHECKING([for res_search])
  AC_FUNC_RES_SEARCH

  if test "$ac_cv_func_res_search" = no; then
      for lib in dns nsl resolv; do
        if test "$ac_cv_func_res_search" != yes; then
	  LIBS="-l$lib $LIBS"
          AC_FUNC_RES_SEARCH
          LIBS="$openafs_save_libs"
        fi
      done    
      if test "$ac_cv_func_res_search" = yes; then
        LIB_AFSDB="-l$lib"
	AC_DEFINE(HAVE_RES_SEARCH, 1, [])
        AC_MSG_RESULT([yes, in lib$lib])
      else
        AC_MSG_RESULT(no)
      fi
  else
    AC_DEFINE(HAVE_RES_SEARCH, 1, [])
    AC_MSG_RESULT(yes)
  fi
  
fi

AC_CHECK_RESOLV_RETRANS

AC_CACHE_CHECK([for setsockopt(, SOL_IP, IP_RECVERR)],
    [ac_cv_setsockopt_iprecverr],
    [AC_TRY_COMPILE( [
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>],
[int on=1;
setsockopt(0, SOL_IP, IP_RECVERR, &on, sizeof(on));],
	[ac_cv_setsockopt_iprecverr=yes],
	[ac_cv_setsockopt_iprecverr=no])])

AS_IF([test "$ac_cv_setsockopt_iprecverr" = "yes"],
      [AC_DEFINE(ADAPT_PMTU_RECVERR, 1,
		 [define if asynchronous socket errors can be received])])

PTHREAD_LIBS=error
if test "x$MKAFS_OSTYPE" = OBSD; then
        PTHREAD_LIBS="-pthread"
fi
if test "x$MKAFS_OSTYPE" = xDFBSD; then
        PTHREAD_LIBS="-pthread"
fi
if test "x$PTHREAD_LIBS" = xerror; then
        AC_CHECK_LIB(pthread, pthread_attr_init,
                PTHREAD_LIBS="-lpthread")
fi
if test "x$PTHREAD_LIBS" = xerror; then
        AC_CHECK_LIB(pthreads, pthread_attr_init,
                PTHREAD_LIBS="-lpthreads")
fi
if test "x$PTHREAD_LIBS" = xerror; then
        AC_CHECK_LIB(c_r, pthread_attr_init,
                PTHREAD_LIBS="-lc_r")
fi
if test "x$PTHREAD_LIBS" = xerror; then
        AC_CHECK_FUNC(pthread_attr_init, PTHREAD_LIBS="")
fi
if test "x$PTHREAD_LIBS" = xerror; then
        # pthread_attr_init is a macro under HPUX 11.0 and 11.11
        AC_CHECK_LIB(pthread, pthread_attr_destroy,
                PTHREAD_LIBS="-lpthread")
fi
if test "x$PTHREAD_LIBS" = xerror; then
        AC_MSG_WARN(*** Unable to locate working posix thread library ***)
fi
AC_SUBST(PTHREAD_LIBS)

HOST_CPU="$host_cpu"

if test "x$with_bsd_kernel_headers" != "x"; then
	BSD_KERNEL_PATH="$with_bsd_kernel_headers"
else
	BSD_KERNEL_PATH="/usr/src/sys"
fi

if test "x$with_bsd_kernel_build" != "x"; then
	BSD_KERNEL_BUILD="$with_bsd_kernel_build"
else
	case $AFS_SYSNAME in
		*_fbsd_*)
			BSD_KERNEL_BUILD="${BSD_KERNEL_PATH}/${HOST_CPU}/compile/GENERIC"
			;;
		*_nbsd*)
			BSD_KERNEL_BUILD="${BSD_KERNEL_PATH}/arch/${HOST_CPU}/compile/GENERIC"
	esac
fi

# Fast restart
if test "$enable_supergroups" = "yes"; then
	AC_DEFINE(SUPERGROUPS, 1, [define if you want to have support for nested pts groups])
fi

if test "$enable_bitmap_later" = "yes"; then
	AC_DEFINE(BITMAP_LATER, 1, [define if you want to salvager to check bitmasks later])
fi

if test "$enable_object_storage" = "yes"; then
        AC_DEFINE(AFS_RXOSD_SUPPORT, 1, [define if you want to use object storage in your cell])
        WITH_OBJECT_STORAGE="YES"
else
        WITH_OBJECT_STORAGE="NO"
fi
AC_SUBST(WITH_OBJECT_STORAGE)

LIBAFSOSDMINOR=`grep LIBAFSOSD_VERSION ${srcdir}/src/rxosd/afsosd.h | awk '{print $[]3}'`
echo LIBAFSOSDMINOR = $LIBAFSOSDMINOR

AC_SUBST(LIBAFSOSDMINOR)

LIBHPSSMINOR=`grep LIBAFSHPSS_VERSION ${srcdir}/src/rxosd/rxosd_hsm.h | awk '{print $[]3}'`
echo LIBHPSSMINOR = $LIBHPSSMINOR

AC_SUBST(LIBHPSSMINOR)

if test "$enable_vicep_access" = "yes"; then
        AC_DEFINE(AFS_ENABLE_VICEP_ACCESS, 1, [define if client may access visible fileserver partitions directly (experimental)])
fi

if test "x${with_dcache_path}" != "x"; then
        HSM_LIB=${with_dcache_path}/libdcap.a
        HSM_INC=-I${with_dcache_path}
fi
if test "x${with_hpss_path}" != "x"; then
        HSM_LIB=${with_hpss_path}/lib/libhpss.so
        HSM_INC=-I${with_hpss_path}/include
fi
AC_SUBST(HSM_LIB)
AC_SUBST(HSM_INC)

if test "x${with_version_string}" != "x"; then
        VERSION=${with_version_string}
fi

if test "$enable_unix_sockets" = "yes"; then
	AC_DEFINE(USE_UNIX_SOCKETS, 1, [define if you want to use UNIX sockets for fssync.])
	USE_UNIX_SOCKETS="yes"
else
	USE_UNIX_SOCKETS="no"
fi
AC_SUBST(USE_UNIX_SOCKETS)

dnl if test "$ac_cv_setsockopt_iprecverr" = "yes"; then
dnl 	AC_DEFINE(ADAPT_PMTU, 1, [define if you want to decode icmp unreachable packets to discover path mtu])
dnl fi

if test "$enable_namei_fileserver" = "yes"; then
	AC_DEFINE(AFS_NAMEI_ENV, 1, [define if you want to want namei fileserver])
	VFSCK=""
else
	if test "$enable_namei_fileserver" = "default"; then
		case $host in
			*-solaris2.10*)
				AC_MSG_WARN(Some Solaris 10 versions are not safe with the inode fileserver. Forcing namei. Override with --disable-namei-fileserver)
				AC_DEFINE(AFS_NAMEI_ENV, 1, [define if you want to want namei fileserver])
				VFSCK=""
				;;
			*-solaris2.11*)
				AC_MSG_WARN(Solaris 11 versions are not safe with the inode fileserver. Forcing namei. Override with --disable-namei-fileserver)
				AC_DEFINE(AFS_NAMEI_ENV, 1, [define if you want to want namei fileserver])
				VFSCK=""
				;;
			*)
				VFSCK="vfsck"
				;;
		esac
        else
		VFSCK="vfsck"
	fi
fi

dnl check for tivoli
AC_MSG_CHECKING(for tivoli tsm butc support)
XBSA_CFLAGS=""
if test "$enable_tivoli_tsm" = "yes"; then
	XBSADIR1=/usr/tivoli/tsm/client/api/bin/xopen
	XBSADIR2=/opt/tivoli/tsm/client/api/bin/xopen
	XBSADIR3=/usr/tivoli/tsm/client/api/bin/sample
	XBSADIR4=/opt/tivoli/tsm/client/api/bin/sample

	if test -r "$XBSADIR3/dsmapifp.h"; then
		XBSA_CFLAGS="-Dxbsa -DNEW_XBSA -I$XBSADIR3"
		XBSA_XLIBS="-ldl"
		AC_MSG_RESULT([yes, $XBSA_CFLAGS])
	elif test -r "$XBSADIR4/dsmapifp.h"; then
		XBSA_CFLAGS="-Dxbsa -DNEW_XBSA -I$XBSADIR4"
		XBSA_XLIBS="-ldl"
		AC_MSG_RESULT([yes, $XBSA_CFLAGS])
	elif test -r "$XBSADIR1/xbsa.h"; then
		XBSA_CFLAGS="-Dxbsa -I$XBSADIR1"
		XBSA_XLIBS=""
		AC_MSG_RESULT([yes, $XBSA_CFLAGS])
	elif test -r "$XBSADIR2/xbsa.h"; then
		XBSA_CFLAGS="-Dxbsa -I$XBSADIR2"
		XBSA_XLIBS=""
		AC_MSG_RESULT([yes, $XBSA_CFLAGS])
	else
		AC_MSG_RESULT([no, missing xbsa.h and dsmapifp.h header files])
	fi
else
	AC_MSG_RESULT([no])
fi
AC_SUBST(XBSA_CFLAGS)
AC_SUBST(XBSA_XLIBS) 

dnl checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_DIRENT
AC_CHECK_HEADERS([ \
	curses.h \
	direct.h \
	fcntl.h \
	grp.h \
	mntent.h \
	ncurses.h \
	ncurses/ncurses.h \
	netinet/in.h \
	netdb.h \
	regex.h \
	search.h \
	security/pam_modules.h \
	signal.h \
	stdio_ext.h \
	stdlib.h \
	string.h \
	strings.h \
	sys/bitypes.h \
	sys/fcntl.h \
	sys/file.h \
	sys/fs_types.h \
	sys/fstyp.h \
	sys/ipc.h \
	sys/mntent.h \
	sys/mnttab.h \
	sys/mount.h \
	sys/pag.h \
	sys/param.h \
	sys/resource.h \
	sys/statfs.h \
	sys/statvfs.h \
	sys/time.h \
	sys/vfs.h \
	termios.h \
	ucontext.h \
	unistd.h \
	windows.h \
])

AC_CHECK_HEADERS(linux/errqueue.h,,,[#include <linux/types.h>])

AC_CHECK_TYPES([fsblkcnt_t],,,[
#include <sys/types.h>
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
#ifdef HAVE_SYS_STATFS_H
#include <sys/statfs.h>
#endif
#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
])

dnl see what struct stat has for timestamps
AC_CHECK_MEMBERS([struct stat.st_ctimespec, struct stat.st_ctimensec])

dnl check for curses-lib
save_LIBS=$LIBS
AC_CHECK_LIB( [ncurses], [setupterm],
[LIB_curses=-lncurses],
    [AC_CHECK_LIB([Hcurses], [setupterm], [LIB_curses=-lHcurses],
        [AC_CHECK_LIB([curses], [setupterm], [LIB_curses=-lcurses])
    ])
])
LIBS=$save_LIBS
AC_SUBST(LIB_curses)

OPENAFS_TEST_PACKAGE(libintl,[#include <libintl.h>],[-lintl],,,INTL)

dnl Don't build PAM on IRIX; the interface doesn't work for us.
if test "$ac_cv_header_security_pam_modules_h" = yes -a "$enable_pam" = yes; then
        case $AFS_SYSNAME in
        sgi_*)
                HAVE_PAM="no"
                ;;
        *)
	        HAVE_PAM="yes"
                ;;
        esac
else
	HAVE_PAM="no"
fi
AC_SUBST(HAVE_PAM)

if test "$enable_login" = yes; then
	BUILD_LOGIN="yes"
else
	BUILD_LOGIN="no"
fi
AC_SUBST(BUILD_LOGIN)

AC_CHECK_FUNCS([ \
	daemon \
	flock \
	fseeko64 \
	ftello64 \
	getcwd \
	getprogname \
	getrlimit \
	mkstemp \
	poll \
	pread \
	preadv \
	preadv64 \
	pwrite \
	pwritev \
	pwritev64 \
	regcomp \
	regerror \
	regexec \
	setenv \
	setprogname \
	setvbuf \
	sigaction \
	snprintf \
	strcasestr \
	strerror \
	strlcat \
	strlcpy \
	strnlen \
	timegm \
	tsearch \
	unsetenv \
	vsnprintf \
	vsyslog \
])

case $AFS_SYSNAME in
*hp_ux* | *hpux*)
   AC_MSG_WARN([Some versions of HP-UX have a buggy positional I/O implementation. Forcing no positional I/O.])
   ;;
*)
   AC_MSG_CHECKING([for positional I/O])
   if test "$ac_cv_func_pread" = "yes" && \
           test "$ac_cv_func_pwrite" = "yes"; then
      AC_DEFINE(HAVE_PIO, 1, [define if you have pread() and pwrite()])
      AC_MSG_RESULT(yes)
   else
     AC_MSG_RESULT(no)
   fi
   AC_MSG_CHECKING([for vectored positional I/O])
   AS_IF([test "$ac_cv_func_preadv" = "yes" -a \
               "$ac_cv_func_pwritev" = "yes" -a \
	       "$ac_cv_func_preadv64" = "yes" -a \
	       "$ac_cv_func_pwritev64" = "yes"],
	 [AC_DEFINE(HAVE_PIOV, 1, [define if you have preadv() and pwritev()])
  	  AC_MSG_RESULT(yes)],
	 [AC_MSG_RESULT(no)])
   ;;
esac

AC_MSG_CHECKING([for POSIX regex library])
if test "$ac_cv_header_regex_h" = "yes" && \
	test "$ac_cv_func_regcomp" = "yes" && \
	test "$ac_cv_func_regexec" = "yes" && \
	test "$ac_cv_func_regerror" = "yes"; then
    AC_DEFINE(HAVE_POSIX_REGEX, 1, [define if you have POSIX regex library])
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi

AC_TYPE_SIGNAL
AC_CHECK_SIZEOF(void *)
AC_CHECK_SIZEOF(unsigned long long)
AC_CHECK_SIZEOF(unsigned long)
AC_CHECK_SIZEOF(unsigned int)
AC_TYPE_INTPTR_T
AC_TYPE_UINTPTR_T
AC_TYPE_SSIZE_T
AC_CHECK_TYPE([sig_atomic_t],[],
    [AC_DEFINE([sig_atomic_t], [int],
        [Define to int if <signal.h> does not define.])],
[#include <sys/types.h>
#include <signal.h>])
AC_CHECK_TYPE([socklen_t],[],
    [AC_DEFINE([socklen_t], [int],
        [Define to int if <sys/socket.h> does not define.])],
[#include <sys/types.h>
#include <sys/socket.h>])
AC_CHECK_TYPES(off64_t)
AC_SIZEOF_TYPE(long)

AC_HEADER_PAM_CONST


dnl Directory PATH handling
if test "x$enable_transarc_paths" = "xyes"  ; then 
    afsconfdir=${afsconfdir=/usr/afs/etc}
    viceetcdir=${viceetcdir=/usr/vice/etc}
    afskerneldir=${afskerneldir=${viceetcdir}}
    afssrvbindir=${afssrvbindir=/usr/afs/bin}
    afssrvsbindir=${afssrvsbindir=/usr/afs/bin}
    afssrvlibexecdir=${afssrvlibexecdir=/usr/afs/bin}
    afsdbdir=${afsdbdir=/usr/afs/db}
    afslogsdir=${afslogsdir=/usr/afs/logs}
    afslocaldir=${afslocaldir=/usr/afs/local}
    afsbackupdir=${afsbackupdir=/usr/afs/backup}
    afsbosconfigdir=${afsbosconfigdir=/usr/afs/local}
    afsdatadir=${afsdatadir=/usr/vice/etc}
else 
    afsconfdir=${afsconfdir='${sysconfdir}/openafs/server'}
    viceetcdir=${viceetcdir='${sysconfdir}/openafs'}
    afskerneldir=${afskerneldir='${libdir}/openafs'}
    afssrvbindir=${afssrvbindir='${bindir}'}
    afssrvsbindir=${afssrvsbindir='${sbindir}'}
    afssrvlibexecdir=${afssrvlibexecdir='${libexecdir}/openafs'}
    afsdbdir=${afsdbdir='${localstatedir}/openafs/db'}
    afslogsdir=${afslogsdir='${localstatedir}/openafs/logs'}
    afslocaldir=${afslocaldir='${localstatedir}/openafs'}
    afsbackupdir=${afsbackupdir='${localstatedir}/openafs/backup'}
    afsbosconfigdir=${afsbosconfigdir='${sysconfdir}/openafs'}
    afsdatadir=${afsdatadir='${datadir}/openafs'}
fi
AC_SUBST(afsconfdir)
AC_SUBST(viceetcdir)
AC_SUBST(afskerneldir)
AC_SUBST(afssrvbindir)
AC_SUBST(afssrvsbindir)
AC_SUBST(afssrvlibexecdir)
AC_SUBST(afsdbdir)
AC_SUBST(afslogsdir)
AC_SUBST(afslocaldir)
AC_SUBST(afsbackupdir)
AC_SUBST(afsbosconfigdir)
AC_SUBST(afsdatadir)

if test "x$enable_kernel_module" = "xyes"; then
ENABLE_KERNEL_MODULE=libafs
fi

if test "x$enable_pthreaded_ubik" = "xyes"; then
ENABLE_PTHREADED_UBIK=yes
fi

AC_SUBST(VFSCK)
AC_SUBST(AFS_SYSNAME)
AC_SUBST(AFS_PARAM_COMMON)
AC_SUBST(ENABLE_KERNEL_MODULE)
AC_SUBST(ENABLE_PTHREADED_UBIK)
AC_SUBST(LIB_AFSDB)
AC_SUBST(LINUX_KERNEL_PATH)
AC_SUBST(LINUX_KERNEL_BUILD)
AC_SUBST(HOST_CPU)
AC_SUBST(BSD_KERNEL_PATH)
AC_SUBST(BSD_KERNEL_BUILD)
AC_SUBST(LINUX_VERSION)
AC_SUBST(MKAFS_OSTYPE)
AC_SUBST(TOP_OBJDIR)
AC_SUBST(TOP_SRCDIR)
AC_SUBST(TOP_INCDIR)
AC_SUBST(TOP_LIBDIR)
AC_SUBST(DEST)
AC_SUBST(DARWIN_INFOFILE)
AC_SUBST(IRIX_BUILD_IP35)
AC_SUBST(HTML_XSL)
AC_SUBST(XSLTPROC)
AC_SUBST(DOCBOOK2PDF)

OPENAFS_OSCONF
OPENAFS_FUSE

TOP_SRCDIR="${srcdir}/src"
dnl
dnl If we're using ./configure, need a more reasonable TOP_SRCDIR, since relative links don't work everywhere
dnl
case $TOP_SRCDIR in
        /*)
                ;;
        *)
		TOP_SRCDIR=`cd $TOP_SRCDIR; pwd`
		;;
esac

TOP_OBJDIR="${SRCDIR_PARENT}"
TOP_INCDIR="${SRCDIR_PARENT}/include"
TOP_LIBDIR="${SRCDIR_PARENT}/lib"
if test "${DEST}x" = "x"; then
        DEST="${SRCDIR_PARENT}/${AFS_SYSNAME}/dest"
fi

HELPER_SPLINT="${TOP_SRCDIR}/helper-splint.sh"
HELPER_SPLINTCFG="${TOP_SRCDIR}/splint.cfg"
AC_SUBST(HELPER_SPLINT)
AC_SUBST(HELPER_SPLINTCFG)

mkdir -p ${TOP_OBJDIR}/src/JAVA/libjafs


dnl Check to see if crypt lives in a different library
AC_CHECK_LIB(crypt, crypt, LIB_crypt="-lcrypt")
AC_SUBST(LIB_crypt)

dnl Check to see if the compiler support labels in structs
AC_MSG_CHECKING(for label support in structs)
AC_TRY_COMPILE([], [
extern void osi_UFSOpen(void);
struct labeltest {
   void (*open) (void);
};
struct labeltest struct_labeltest = {
   .open       = osi_UFSOpen,
}
],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_STRUCT_LABEL_SUPPORT, 1, [Define to 1 if your compiler supports labels in structs.])
],
[AC_MSG_RESULT(no)
])

])

AC_DEFUN([SUMMARY], [
    # Print a configuration summary
echo 
echo "**************************************"
echo configure summary
echo
AS_IF([test $LIB_curses],[
echo "LIB_curses :                $LIB_curses" ],[
echo "XXX LIB_curses  not found! not building scout and afsmonitor!"
])
echo 
echo "**************************************"
])

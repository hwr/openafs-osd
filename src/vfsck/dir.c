/*
 * Copyright (c) 1980, 1986 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <afsconfig.h>
#include <afs/param.h>

#ifdef AFS_HPUX_ENV
/* We need the old directory type headers (included below), so don't include
 * the normal dirent.h, or it will conflict. */
# undef HAVE_DIRENT_H
# include <sys/inode.h>
# define	LONGFILENAMES	1
# include <sys/sysmacros.h>
# include <sys/ino.h>
# define	DIRSIZ_MACRO
# ifdef HAVE_USR_OLD_USR_INCLUDE_NDIR_H
#  include </usr/old/usr/include/ndir.h>
# else
#  include <ndir.h>
# endif
#endif

#include <roken.h>

#include <ctype.h>

#define VICE			/* allow us to put our changes in at will */

#ifdef	AFS_OSF_ENV
#include <sys/vnode.h>
#include <sys/mount.h>
#include <ufs/inode.h>
#include <ufs/fs.h>
#define	_BSD
#define	_KERNEL
#include <ufs/dir.h>
#undef	_KERNEL
#undef	_BSD
#else /* AFS_OSF_ENV */
#ifdef AFS_VFSINCL_ENV
#define VFS
#include <sys/vnode.h>
#ifdef	  AFS_SUN5_ENV
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>
#define _KERNEL
#include <sys/fs/ufs_fsdir.h>
#undef _KERNEL
#else
#include <ufs/inode.h>
#include <ufs/fs.h>
#define KERNEL
#include <ufs/fsdir.h>
#undef KERNEL
#endif

#else /* AFS_VFSINCL_ENV */
#include <sys/inode.h>
#ifndef	AFS_HPUX_ENV
#define KERNEL
#include <sys/dir.h>
#undef KERNEL
#endif
#include <sys/fs.h>
#endif /* AFS_VFSINCL_ENV */
#endif /* AFS_OSF_ENV */

#ifdef AFS_SUN_ENV
#ifdef	AFS_SUN5_ENV
#include <sys/mnttab.h>
#include <sys/mntent.h>
#else
#include <mntent.h>
#endif
#endif
#include "fsck.h"


#ifdef	AFS_HPUX_ENV
struct dirtemplate_lfn {
    afs_uint32 dot_ino;
    short dot_reclen;
    short dot_namlen;
    char dot_name[4];		/* must be multiple of 4 */
    afs_uint32 dotdot_ino;
    short dotdot_reclen;
    short dotdot_namlen;
    char dotdot_name[4];	/* ditto */
};
#define	dirtemplate dirtemplate_lfn
#endif

#define MINDIRSIZE	(sizeof (struct dirtemplate))

char *endpathname = &pathname[BUFSIZ - 2];
char *lfname = "lost+found";
int lfmode = 01777;
struct dirtemplate emptydir = { 0, DIRBLKSIZ };
struct dirtemplate dirhead = { 0, 12, 1, ".", 0, DIRBLKSIZ - 12, 2, ".." };

struct direct *fsck_readdir();
struct bufarea *getdirblk();

descend(parentino, inumber)
     struct inodesc *parentino;
     ino_t inumber;
{
    struct dinode *dp;
    struct inodesc curino;

    memset(&curino, 0, sizeof(struct inodesc));
    if (statemap[inumber] != DSTATE)
	errexit("BAD INODE %d TO DESCEND", statemap[inumber]);
#if defined(ACLS) && defined(AFS_HPUX_ENV)
    /*
     * keep any continuation inode information
     */
    if (statemap[inumber] & HASCINODE)
	statemap[inumber] = HASCINODE | DFOUND;
    else
	statemap[inumber] = DFOUND;
#else /* no ACLS */
    statemap[inumber] = DFOUND;
#endif /* ACLS */
    dp = ginode(inumber);
    if (dp->di_size == 0) {
	direrror(inumber, "ZERO LENGTH DIRECTORY");
	if (reply("REMOVE") == 1)
#if defined(ACLS) && defined(AFS_HPUX_ENV)
	    /*
	     * keep any continuation inode information
	     */
	    if (statemap[inumber] & HASCINODE)
		statemap[inumber] = HASCINODE | DCLEAR;
	    else
		statemap[inumber] = DCLEAR;
#else /* no ACLS */
	    statemap[inumber] = DCLEAR;
#endif /* ACLS */
	return;
    }
    if (dp->di_size < MINDIRSIZE) {
	direrror(inumber, "DIRECTORY TOO SHORT");
	dp->di_size = MINDIRSIZE;
	if (reply("FIX") == 1)
	    inodirty();
    }
#if	!defined(AFS_HPUX_ENV)
    /* For remaining 4.2 systems.  We shouldn't convert
     * dir size, since Unix 4.2 kernels won't maintain this, and we'll have a
     * lot of spurious directory conversions scaring people */
    if ((dp->di_size & (DIRBLKSIZ - 1)) != 0) {
	pwarn("DIRECTORY %s: LENGTH %d NOT MULTIPLE OF %d", pathname,
	      dp->di_size, DIRBLKSIZ);
	dp->di_size = roundup(dp->di_size, DIRBLKSIZ);
	if (preen)
	    printf(" (ADJUSTED)\n");
	if (preen || reply("ADJUST") == 1)
	    inodirty();
    }
#endif
    curino.id_type = DATA;
    curino.id_func = parentino->id_func;
    curino.id_parent = parentino->id_number;
    curino.id_number = inumber;
    (void)ckinode(dp, &curino);
    if (curino.id_entryno < 2) {
	direrror(inumber, "NULL DIRECTORY");
	if (reply("REMOVE") == 1)
	    statemap[inumber] = DCLEAR;
    }
}

dirscan(idesc)
     struct inodesc *idesc;
{
    struct direct *dp;
    struct bufarea *bp;
    int dsize, n;
    long blksiz;
    char dbuf[DIRBLKSIZ];

    if (idesc->id_type != DATA)
	errexit("wrong type to dirscan %d\n", idesc->id_type);
    if (idesc->id_entryno == 0 && (idesc->id_filesize & (DIRBLKSIZ - 1)) != 0)
	idesc->id_filesize = roundup(idesc->id_filesize, DIRBLKSIZ);
    blksiz = idesc->id_numfrags * sblock.fs_fsize;

    if (chkrange(idesc->id_blkno, idesc->id_numfrags)) {
	idesc->id_filesize -= blksiz;
	return (SKIP);
    }
    idesc->id_loc = 0;
    for (dp = fsck_readdir(idesc); dp != NULL; dp = fsck_readdir(idesc)) {
	dsize = dp->d_reclen;
	memcpy(dbuf, (char *)dp, dsize);
	idesc->id_dirp = (struct direct *)dbuf;
	if ((n = (*idesc->id_func) (idesc)) & ALTERED) {
	    bp = getdirblk(idesc->id_blkno, blksiz);
	    memcpy((char *)dp, dbuf, dsize);
	    dirty(bp);
	    sbdirty();
	}
	if (n & STOP)
	    return (n);
    }
    return (idesc->id_filesize > 0 ? KEEPON : STOP);
}

/*
 * get next entry in a directory.
 */
struct direct *
fsck_readdir(idesc)
     struct inodesc *idesc;
{
    struct direct *dp, *ndp;
    struct bufarea *bp;
    long size, blksiz;

    blksiz = idesc->id_numfrags * sblock.fs_fsize;
    bp = getdirblk(idesc->id_blkno, blksiz);
    if (idesc->id_loc % DIRBLKSIZ == 0 && idesc->id_filesize > 0
	&& idesc->id_loc < blksiz) {
	dp = (struct direct *)(bp->b_un.b_buf + idesc->id_loc);
	if (dircheck(idesc, dp)) {
	    goto dpok;
	}
	idesc->id_loc += DIRBLKSIZ;
	idesc->id_filesize -= DIRBLKSIZ;
	dp->d_reclen = DIRBLKSIZ;
	dp->d_ino = 0;
	dp->d_namlen = 0;
	dp->d_name[0] = '\0';
	if (dofix(idesc, "DIRECTORY CORRUPTED"))
	    dirty(bp);
	return (dp);
    }
  dpok:
    if (idesc->id_filesize <= 0 || idesc->id_loc >= blksiz)
	return NULL;
    dp = (struct direct *)(bp->b_un.b_buf + idesc->id_loc);
    idesc->id_loc += dp->d_reclen;
    idesc->id_filesize -= dp->d_reclen;
    if ((idesc->id_loc % DIRBLKSIZ) == 0)
	return (dp);
    ndp = (struct direct *)(bp->b_un.b_buf + idesc->id_loc);
    if (idesc->id_loc < blksiz && idesc->id_filesize > 0
	&& dircheck(idesc, ndp) == 0) {
	size = DIRBLKSIZ - (idesc->id_loc % DIRBLKSIZ);
	dp->d_reclen += size;
	idesc->id_loc += size;
	idesc->id_filesize -= size;
	if (dofix(idesc, "DIRECTORY CORRUPTED"))
	    dirty(bp);
    }
    return (dp);
}

/*
 * Verify that a directory entry is valid.
 * This is a superset of the checks made in the kernel.
 */
dircheck(idesc, dp)
     struct inodesc *idesc;
     struct direct *dp;
{
    int size;
    char *cp;
    int spaceleft;

    size = DIRSIZ(dp);
    spaceleft = DIRBLKSIZ - (idesc->id_loc % DIRBLKSIZ);
    if (dp->d_ino < maxino && dp->d_reclen != 0 && dp->d_reclen <= spaceleft
	&& (dp->d_reclen & 0x3) == 0 && dp->d_reclen >= size
	&& idesc->id_filesize >= size && dp->d_namlen <= MAXNAMLEN) {
	if (dp->d_ino == 0)
	    return (1);
	for (cp = dp->d_name, size = 0; size < dp->d_namlen; size++)
#if	defined(Next) || defined(AFS_SUN5_ENV)
	    if (*cp == 0)
		return (0);
	    else
		++cp;
#else
	    if (*cp == 0 || (*cp++ & 0200)) {
		return (0);
	    }
#endif
	if (*cp == 0)
	    return (1);
    }
    return (0);
}

direrror(ino, errmesg)
     ino_t ino;
     char *errmesg;
{
    struct dinode *dp;

    pwarn("%s ", errmesg);
    pinode(ino);
    printf("\n");
    if (ino < ROOTINO || ino > maxino) {
	pfatal("NAME=%s\n", pathname);
	return;
    }
    dp = ginode(ino);
    if (ftypeok(dp))
	pfatal("%s=%s\n", (dp->di_mode & IFMT) == IFDIR ? "DIR" : "FILE",
	       pathname);
    else
	pfatal("NAME=%s\n", pathname);
}

adjust(idesc, lcnt)
     struct inodesc *idesc;
     short lcnt;
{
    struct dinode *dp;

    dp = ginode(idesc->id_number);
    if (dp->di_nlink == lcnt) {
	if (linkup(idesc->id_number, (ino_t) 0) == 0)
	    clri(idesc, "UNREF", 0);
    } else {
	pwarn("LINK COUNT %s",
	      (lfdir == idesc->id_number) ? lfname : ((dp->di_mode & IFMT) ==
						      IFDIR ? "DIR" :
						      "FILE"));
	pinode(idesc->id_number);
	printf(" COUNT %d SHOULD BE %d", dp->di_nlink, dp->di_nlink - lcnt);
	if (preen) {
	    if (lcnt < 0) {
		printf("\n");
		pfatal("LINK COUNT INCREASING");
	    }
	    printf(" (ADJUSTED)\n");
	}
	if (preen || reply("ADJUST") == 1) {
	    dp->di_nlink -= lcnt;
	    inodirty();
	}
    }
}

mkentry(idesc)
     struct inodesc *idesc;
{
    struct direct *dirp = idesc->id_dirp;
    struct direct newent;
    int newlen, oldlen;

    newent.d_namlen = 11;
    newlen = DIRSIZ(&newent);
    if (dirp->d_ino != 0)
	oldlen = DIRSIZ(dirp);
    else
	oldlen = 0;
    if (dirp->d_reclen - oldlen < newlen)
	return (KEEPON);
    newent.d_reclen = dirp->d_reclen - oldlen;
    dirp->d_reclen = oldlen;
    dirp = (struct direct *)(((char *)dirp) + oldlen);
    dirp->d_ino = idesc->id_parent;	/* ino to be entered is in id_parent */
    dirp->d_reclen = newent.d_reclen;
    dirp->d_namlen = strlen(idesc->id_name);
    memcpy(dirp->d_name, idesc->id_name, (int)dirp->d_namlen + 1);
    return (ALTERED | STOP);
}

chgino(idesc)
     struct inodesc *idesc;
{
    struct direct *dirp = idesc->id_dirp;

    if (memcmp(dirp->d_name, idesc->id_name, (int)dirp->d_namlen + 1))
	return (KEEPON);
    dirp->d_ino = idesc->id_parent;
    return (ALTERED | STOP);
}

linkup(orphan, parentdir)
     ino_t orphan;
     ino_t parentdir;
{
    struct dinode *dp;
    int lostdir, len;
    ino_t oldlfdir;
    struct inodesc idesc;
    char tempname[BUFSIZ];
    extern int pass4check();

    memset(&idesc, 0, sizeof(struct inodesc));
    dp = ginode(orphan);
    lostdir = (dp->di_mode & IFMT) == IFDIR;
    pwarn("UNREF %s ", lostdir ? "DIR" : "FILE");
    pinode(orphan);
    if (preen && dp->di_size == 0)
	return (0);
    if (preen)
	printf(" (RECONNECTED)\n");
    else if (reply("RECONNECT") == 0)
	return (0);
    pathp = pathname;
    *pathp++ = '/';
    *pathp = '\0';
    if (lfdir == 0) {
	dp = ginode(ROOTINO);
	idesc.id_name = lfname;
	idesc.id_type = DATA;
	idesc.id_func = findino;
	idesc.id_number = ROOTINO;
	if ((ckinode(dp, &idesc) & FOUND) != 0) {
	    lfdir = idesc.id_parent;
	} else {
	    pwarn("NO lost+found DIRECTORY");
	    if (preen || reply("CREATE")) {
		lfdir = allocdir(ROOTINO, (ino_t) 0, lfmode);
		if (lfdir != 0) {
		    if (makeentry(ROOTINO, lfdir, lfname) != 0) {
			if (preen)
			    printf(" (CREATED)\n");
		    } else {
			freedir(lfdir, ROOTINO);
			lfdir = 0;
			if (preen)
			    printf("\n");
		    }
		}
	    }
	}
	if (lfdir == 0) {
	    pfatal("SORRY. CANNOT CREATE lost+found DIRECTORY");
	    printf("\n\n");
	    return (0);
	}
    }
    dp = ginode(lfdir);
    if ((dp->di_mode & IFMT) != IFDIR) {
	pfatal("lost+found IS NOT A DIRECTORY");
	if (reply("REALLOCATE") == 0)
	    return (0);
	oldlfdir = lfdir;
	if ((lfdir = allocdir(ROOTINO, (ino_t) 0, lfmode)) == 0) {
	    pfatal("SORRY. CANNOT CREATE lost+found DIRECTORY\n\n");
	    return (0);
	}
	idesc.id_type = DATA;
	idesc.id_func = chgino;
	idesc.id_number = ROOTINO;
	idesc.id_parent = lfdir;	/* new inumber for lost+found */
	idesc.id_name = lfname;
	if ((ckinode(ginode(ROOTINO), &idesc) & ALTERED) == 0) {
	    pfatal("SORRY. CANNOT CREATE lost+found DIRECTORY\n\n");
	    return (0);
	}
	inodirty();
	idesc.id_type = ADDR;
	idesc.id_func = pass4check;
	idesc.id_number = oldlfdir;
	adjust(&idesc, lncntp[oldlfdir] + 1);
	lncntp[oldlfdir] = 0;
	dp = ginode(lfdir);
    }
    if (statemap[lfdir] != DFOUND) {
	pfatal("SORRY. NO lost+found DIRECTORY\n\n");
	return (0);
    }
    len = strlen(lfname);
    memcpy(pathp, lfname, len + 1);
    pathp += len;
    len = lftempname(tempname, orphan);
    if (makeentry(lfdir, orphan, tempname) == 0) {
	pfatal("SORRY. NO SPACE IN lost+found DIRECTORY");
	printf("\n\n");
	return (0);
    }
    lncntp[orphan]--;
    *pathp++ = '/';
    memcpy(pathp, tempname, len + 1);
    pathp += len;
    if (lostdir) {
	dp = ginode(orphan);
	idesc.id_type = DATA;
	idesc.id_func = chgino;
	idesc.id_number = orphan;
	idesc.id_fix = DONTKNOW;
	idesc.id_name = "..";
	idesc.id_parent = lfdir;	/* new value for ".." */
	(void)ckinode(dp, &idesc);
	dp = ginode(lfdir);
	dp->di_nlink++;
	inodirty();
	lncntp[lfdir]++;
	pwarn("DIR I=%u CONNECTED. ", orphan);
	printf("PARENT WAS I=%u\n", parentdir);
	if (preen == 0)
	    printf("\n");
    }
    return (1);
}

/*
 * make an entry in a directory
 */
makeentry(parent, ino, name)
     ino_t parent, ino;
     char *name;
{
    struct dinode *dp;
    struct inodesc idesc;

    if (parent < ROOTINO || parent >= maxino || ino < ROOTINO
	|| ino >= maxino)
	return (0);
    memset(&idesc, 0, sizeof(struct inodesc));
    idesc.id_type = DATA;
    idesc.id_func = mkentry;
    idesc.id_number = parent;
    idesc.id_parent = ino;	/* this is the inode to enter */
    idesc.id_fix = DONTKNOW;
    idesc.id_name = name;
    dp = ginode(parent);
    if (dp->di_size % DIRBLKSIZ) {
	dp->di_size = roundup(dp->di_size, DIRBLKSIZ);
	inodirty();
    }
    if ((ckinode(dp, &idesc) & ALTERED) != 0)
	return (1);
    if (expanddir(dp) == 0)
	return (0);
    return (ckinode(dp, &idesc) & ALTERED);
}

/*
 * Attempt to expand the size of a directory
 */
expanddir(dp)
     struct dinode *dp;
{
    daddr_t lastbn, newblk;
    struct bufarea *bp;
    char *cp, firstblk[DIRBLKSIZ];

    lastbn = lblkno(&sblock, dp->di_size);
    if (lastbn >= NDADDR - 1)
	return (0);
    if ((newblk = allocblk(sblock.fs_frag)) == 0)
	return (0);
    dp->di_db[lastbn + 1] = dp->di_db[lastbn];
    dp->di_db[lastbn] = newblk;
    dp->di_size += (UOFF_T) sblock.fs_bsize;
    dp->di_blocks += btodb(sblock.fs_bsize);
    bp = getdirblk(dp->di_db[lastbn + 1], dblksize(&sblock, dp, lastbn + 1));
    if (bp->b_errs)
	goto bad;
    memcpy(firstblk, bp->b_un.b_buf, DIRBLKSIZ);
    bp = getdirblk(newblk, sblock.fs_bsize);
    if (bp->b_errs)
	goto bad;
    memcpy(bp->b_un.b_buf, firstblk, DIRBLKSIZ);
    for (cp = &bp->b_un.b_buf[DIRBLKSIZ];
	 cp < &bp->b_un.b_buf[sblock.fs_bsize]; cp += DIRBLKSIZ)
	memcpy(cp, (char *)&emptydir, sizeof emptydir);
    dirty(bp);
    bp = getdirblk(dp->di_db[lastbn + 1], dblksize(&sblock, dp, lastbn + 1));
    if (bp->b_errs)
	goto bad;
    memcpy(bp->b_un.b_buf, (char *)&emptydir, sizeof emptydir);
    pwarn("NO SPACE LEFT IN %s", pathname);
    if (preen)
	printf(" (EXPANDED)\n");
    else if (reply("EXPAND") == 0)
	goto bad;
    dirty(bp);
    inodirty();
    return (1);
  bad:
    dp->di_db[lastbn] = dp->di_db[lastbn + 1];
    dp->di_db[lastbn + 1] = 0;
    dp->di_size -= (UOFF_T) sblock.fs_bsize;
    dp->di_blocks -= btodb(sblock.fs_bsize);
    freeblk(newblk, sblock.fs_frag);
    return (0);
}

/*
 * allocate a new directory
 */
allocdir(parent, request, mode)
     ino_t parent, request;
     int mode;
{
    ino_t ino;
    char *cp;
    struct dinode *dp;
    struct bufarea *bp;

    ino = allocino(request, IFDIR | mode);
    dirhead.dot_ino = ino;
    dirhead.dotdot_ino = parent;
    dp = ginode(ino);
    bp = getdirblk(dp->di_db[0], sblock.fs_fsize);
    if (bp->b_errs) {
	freeino(ino);
	return (0);
    }
    memcpy(bp->b_un.b_buf, (char *)&dirhead, sizeof dirhead);
    for (cp = &bp->b_un.b_buf[DIRBLKSIZ];
	 cp < &bp->b_un.b_buf[sblock.fs_fsize]; cp += DIRBLKSIZ)
	memcpy(cp, (char *)&emptydir, sizeof emptydir);
    dirty(bp);
    dp->di_nlink = 2;
    inodirty();
#ifdef	AFS_SUN5_ENVX
    if (!inocached(ino)) {
	if (debug)
	    printf("inode %d added to directory cache\n", ino);
	cacheino(dp, ino);
    } else {
	/*
	 * re-using an old directory inode
	 */
	inp = getinoinfo(ino);
	inp->i_isize = dp->di_size;
	inp->i_numblks = dp->di_blocks * sizeof(daddr_t);
	inp->i_parent = parent;
	memcpy((char *)&inp->i_blks[0], (char *)&dp->di_db[0],
	       (int)inp->i_numblks);
    }
#endif
    if (ino == ROOTINO) {
	lncntp[ino] = dp->di_nlink;
	return (ino);
    }
    if (statemap[parent] != DSTATE && statemap[parent] != DFOUND) {
	freeino(ino);
	return (0);
    }
    statemap[ino] = statemap[parent];
    if (statemap[ino] == DSTATE) {
	lncntp[ino] = dp->di_nlink;
	lncntp[parent]++;
    }
    dp = ginode(parent);
    dp->di_nlink++;
    inodirty();
    return (ino);
}

/*
 * free a directory inode
 */
freedir(ino, parent)
     ino_t ino, parent;
{
    struct dinode *dp;

    if (ino != parent) {
	dp = ginode(parent);
	dp->di_nlink--;
	inodirty();
    }
    freeino(ino);
}

/*
 * generate a temporary name for the lost+found directory.
 */
lftempname(bufp, ino)
     char *bufp;
     ino_t ino;
{
    ino_t in;
    char *cp;
    int namlen;

    cp = bufp + 2;
    for (in = maxino; in > 0; in /= 10)
	cp++;
    *--cp = 0;
    namlen = cp - bufp;
    in = ino;
    while (cp > bufp) {
	*--cp = (in % 10) + '0';
	in /= 10;
    }
    *cp = '#';
    return (namlen);
}

/*
 * Get a directory block.
 * Insure that it is held until another is requested.
 */
struct bufarea *
getdirblk(blkno, size)
     daddr_t blkno;
     long size;
{
    if (mlk_pbp != 0)
	mlk_pbp->b_flags &= ~B_INUSE;
    mlk_pbp = getdatablk(blkno, size);
    return (mlk_pbp);
}

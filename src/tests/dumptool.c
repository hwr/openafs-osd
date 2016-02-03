/*
 * $Id$
 *
 * dumptool - A tool to manage MR-AFS dump files
 *
 * The dump file format ought to be documented _somewhere_, and
 * this seems like a good as a place as any ...
 *
 * A AFS dump file is marked off into a series of sections.  Each
 * section marked by a dump tag.  A tag is a single byte who's value
 * corresponds with the next section.  The sections are (in order):
 *
 * DUMPHEADER (tag 0x01)
 * VOLUMEHEADER (tag 0x02)
 * VNODE (tag 0x03)
 * DUMPEND (tag 0x04)
 *
 * Descriptions of the sections follow.  Note that in all cases, data is
 * stored in the dump in network byte order.
 *
 * DUMPHEADER:
 *
 * DUMPHEADER contains two parts: the DUMPMAGIC magic number (32 bits)
 * and the dump header itself.
 *
 * The dump header itself consists of a series of tagged values,
 * each tag marking out members of the DumpHeader structure.  The
 * routine ReadDumpHeader explains the specifics of these tags.
 *
 * VOLUMEHEADER:
 *
 * VOLUMEHEADER is a series of tagged values corresponding to the elements
 * of the VolumeDiskData structure.  See ReadVolumeHeader for more
 * information
 *
 * VNODE:
 *
 * The VNODE section is all vnodes contained in the volume (each vnode
 * itself is marked with the VNODE tag, so it's really a sequence of
 * VNODE tags, unlike other sections).
 *
 * Each vnode consists of three parts: the vnode number (32 bits), the
 * uniqifier (32 bits), and a tagged list of elements corresponding to
 * the elements of the VnodeDiskData structure.  See ScanVnodes for
 * more information.  Note that if file data is associated with a vnode,
 * it will be contained here.
 *
 * DUMPEND:
 *
 * The DUMPEND section consists of one part: the DUMPENDMAGIC magic
 * number (32 bits).
 * 
 * Notes:
 *
 * The tagged elements are all ASCII letters, as opposed to the section
 * headers (which are 0x01, 0x02, ...).  Thus, an easy way to tell when
 * you've reached the end of an element sequence is to check to see if
 * the next tag is a printable character (this code tests for < 20).
 *
 * "vos dump" dumps the large vnode index, then the small vnode index,
 * so directories will appear first in the VNODE section.
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <lock.h>
#include <afs/afsint.h>
#include <afs/nfs.h>
#include <afs/acl.h>
#if !defined(PRE_AFS_36)
#include <afs/ihandle.h>
#endif /* !defined(PRE_AFS_36) */
#include <afs/vnode.h>
#include <afs/volume.h>

#ifdef AFS_LINUX24_ENV
#define _LARGEFILE64_SOURCE 1
#endif

#include <afs/dir.h>

#ifndef HAVE_OFF64_T
typedef off_t off64_t;
#endif /* !HAVE_OFF64_T */
#ifndef HAVE_FSEEKO64
#define fseeko64 fseeko
#endif /* HAVE_FSEEKO64 */
#ifndef HAVE_FTELLO64
#define ftello64 ftello
#endif /* HAVE_FTELLO64 */

/*
 * Sigh.  Linux blows it again
 */

#ifdef linux
#include <pty.h>
#endif

/*
 * Stuff that is in private AFS header files, unfortunately
 */

#define DUMPVERSION	1
#define DUMPENDMAGIC	0x3A214B6E
#define DUMPBEGINMAGIC	0xB3A11322
#define D_DUMPHEADER	1
#define D_VOLUMEHEADER	2
#define D_VNODE		3
#define D_DUMPEND	4
#define D_MAX		20

#define MAXDUMPTIMES	50

struct DumpHeader {
    int32_t version;
    VolumeId volumeId;
    char volumeName[VNAMESIZE];
    int nDumpTimes;		/* Number of pairs */
    struct {
	int32_t from, to;
    } dumpTimes[MAXDUMPTIMES];
};

/*
 * Our command-line arguments
 */

#ifdef AFS_RXOSD_SUPPORT
#include "../rxosd/vol_osd.h"

#define MAX_OSD_METADATA_LENGTH 2040
struct osdMetadataHandle {
    afs_uint32 length;
    afs_uint32 offset;
    char data[MAX_OSD_METADATA_LENGTH];
};

struct osdMetadataHandle dummymh;

char cwd[1024];

static bool_t
xdrvol_getint32(void *axdrs, afs_int32 * lp)
{
    afs_int32 l;
    XDR * xdrs = (XDR *)axdrs;
    struct osdMetadataHandle *mh;

    mh = (struct osdMetadataHandle *)(xdrs->x_private);
    if (mh->length >= mh->offset + sizeof(l)) {
        memcpy(&l, &mh->data[mh->offset], sizeof(l));
        mh->offset += sizeof(l);
        *lp = ntohl(l);
        return TRUE;
    }
    return FALSE;
}

static bool_t
xdrvol_getbytes(void *axdrs, caddr_t addr, u_int len)
{
    XDR * xdrs = (XDR *)axdrs;
    struct osdMetadataHandle *mh;

    mh = (struct osdMetadataHandle *)(xdrs->x_private);
    if (mh->length >= mh->offset + len) {
        memcpy(addr, &mh->data[mh->offset], len);
        mh->offset += len;
        return len;
    }
    return FALSE;
}

static struct xdr_ops xdrvol_ops = {
    xdrvol_getint32,            /* deserialize an afs_int32 */
    0,                          /* serialize an afs_int32 */
    xdrvol_getbytes,            /* deserialize counted bytes */
    0,                          /* serialize counted bytes */
    0,                          /* get offset in the stream: not supported. */
    0,                          /* set offset in the stream: not supported. */
    0,                          /* prime stream for inline macros */
    0                           /* destroy stream */
};

xdrvol_create(XDR * xdrs, struct osdMetadataHandle *h,
                enum xdr_op op)
{
    xdrs->x_op = op;
    xdrs->x_ops = & xdrvol_ops;
    xdrs->x_private = (caddr_t) h;
}

void
printOsdMetadata(struct osdMetadataHandle *mh, char *name)
{
    struct osd_p_fileList mylist, *list;
    afs_uint32 version;
    afs_uint64 offset;
    int code, bytes, i, j, k;
    XDR xdr;

    mh->offset = 0;
    list = &mylist;
    list->osd_p_fileList_len = 0;
    list->osd_p_fileList_val = 0;

    xdrvol_create(&xdr, mh, XDR_DECODE);
    if (xdr_afs_uint32(&xdr, &version)) {
        if (!xdr_osd_p_fileList(&xdr, list)) {
            fprintf(stderr, "xdr_osd_p_fileList failed for %s\n", name);
            return;
        }
	printf("%s has %u bytes of osd metadata, v=%u\n",
				name, mh->length, version);
        for (i=0; i<list->osd_p_fileList_len; i++) {
            struct osd_p_file *pfile = &list->osd_p_fileList_val[i];
	    if (pfile->archiveVersion) {
                printf("Archive, dv=%u,",
                        pfile->archiveVersion);
	        PrintTime(pfile->archiveTime);
	    } else 
		printf("On-line");
            printf(", %u segm, flags=0x%x\n",
                        pfile->segmList.osd_p_segmList_len, pfile->flags);
            for (j=0; j<pfile->segmList.osd_p_segmList_len; j++) {
                struct osd_p_segm *psegm = &pfile->segmList.osd_p_segmList_val[j];
                printf("    segment:\n");
		printf("         lng=%llu, offs=%llu, stripess=%u, strsize=%u, cop=%u, %u objects\n",
                        psegm->length, psegm->offset,
                        psegm->nstripes, psegm->stripe_size, psegm->copies,
                        psegm->objList.osd_p_objList_len);
                for (k=0; k<psegm->objList.osd_p_objList_len; k++) {
                    struct osd_p_obj *pobj = &psegm->objList.osd_p_objList_val[k];
                    printf("        object:\n");
		    printf("             pid=%llu, oid=%llu, osd=%u, stripe=%u\n",
                        pobj->part_id, pobj->obj_id, pobj->osd_id, pobj->stripe);
		    printf("             obj=%u.%u.%u.%u\n",
                        (afs_uint32) pobj->part_id, 
			(afs_uint32) pobj->obj_id & 0x3ffffff,
			(afs_uint32) (pobj->obj_id >> 32),
			(afs_uint32) pobj->obj_id >> 26 & 0x3f);
                }
                if (psegm->objList.osd_p_objList_val)
                    free(psegm->objList.osd_p_objList_val);
            }
            if (pfile->segmList.osd_p_segmList_val)
                free(pfile->segmList.osd_p_segmList_val);
            for (j=0; j<pfile->metaList.osd_p_metaList_len; j++) {
		struct osd_p_meta *meta = &pfile->metaList.osd_p_metaList_val[j];
		printf("    metadata:\n");
		if (meta->type == OSD_P_META_MD5) 
		    printf("        md5=%08x%08x%08x%08x ",
				meta->data[0], meta->data[1], 
				meta->data[2], meta->data[3]);
				if (meta->time) {
				    printf(" as from ");
                                    PrintTime(meta->time);
                                }
                                printf("\n");
	    }
            if (pfile->metaList.osd_p_metaList_val)
                free(pfile->metaList.osd_p_metaList_val);
        }
        if (list->osd_p_fileList_val)
            free(list->osd_p_fileList_val);
    }
}
#endif /* AFS_RXOSD_SUPPORT */

static int verbose = 0;
static int numNoDirData = 0;
static int termsize = 0;
int Testing = 0;

/*
 * We use this structure to hold vnode data in our hash table.
 * It's indexed by vnode number.
 */

struct vnodeData {
    struct VnodeDiskObject *vnode;	/* A pointer to the disk vnode */
    int vnodeNumber;		/* The vnode number */
    off64_t dumpdata;		/* File offset of dump data (if
				 * available */
    unsigned char *filedata;	/* A pointer to the actual file
				 * data itself (if available) */
    unsigned int datalength;	/* The length of the data */
#ifdef AFS_RXOSD_SUPPORT
    struct osdMetadataHandle *metadata; /* osd metadata */
#endif
};

/*
 * This contains the current location when we're doing a scan of a
 * directory.
 */

struct DirCursor {
    int hashbucket;		/* Current hash bucket */
    int entry;			/* Entry within hash bucket */
};

/*
 * Arrays to hold vnode data
 */

struct vnodeData **LargeVnodeIndex;
struct vnodeData **SmallVnodeIndex;
int numLargeVnodes = 0;
int numSmallVnodes = 0;

/*
 * Crap for the libraries
 */

int ShutdownInProgress = 0;

/*
 * Our local function prototypes
 */

static int ReadDumpHeader(FILE *, struct DumpHeader *);
static int ReadVolumeHeader(FILE *, VolumeDiskData *);
static int ScanVnodes(FILE *, VolumeDiskData *, int);
static int DumpVnodeFile(FILE *, struct VnodeDiskObject *, VolumeDiskData *);
static struct vnodeData *InsertVnode(unsigned int, struct VnodeDiskObject *);
static struct vnodeData *GetVnode(unsigned int);
static int CompareVnode(const void *, const void *);
static void InteractiveRestore(FILE *, VolumeDiskData *);
static void DirectoryList(int, char **, struct vnodeData *, VolumeDiskData *);
static void DirListInternal(struct vnodeData *, char *[], int, int, int, int,
			    int, int, VolumeDiskData *, char *);
static int CompareDirEntry(const void *, const void *);
static struct vnodeData *ChangeDirectory(int, char **, struct vnodeData *);
static void CopyFile(int, char **, struct vnodeData *, FILE *);
static void CopyVnode(int, char **, FILE *);
static void DumpAllFiles(int, char **, struct vnodeData *, VolumeDiskData *);
static void DumpAllResidencies(FILE *, struct vnodeData *, VolumeDiskData *);
static struct vnodeData *FindFile(struct vnodeData *, char *);
static void ResetDirCursor(struct DirCursor *, struct vnodeData *);
static struct DirEntry *ReadNextDir(struct DirCursor *, struct vnodeData *);
static void MakeArgv(char *, int *, char ***);
static char *GetToken(char *, char **, char *, char *[]);
static int ReadInt16(FILE *, uint16_t *);
static int ReadInt32(FILE *, uint32_t *);
static int ReadString(FILE *, char *, int);
static int ReadByteString(FILE *, void *, int);

int
main(int argc, char *argv[])
{
    int c, errflg = 0, force = 0, inode = 0;
    unsigned int magic;
    struct DumpHeader dheader;
    VolumeDiskData vol;
    off64_t offset;
    int Res, Arg1, Arg2, Arg3, i;
    char *p;
    struct winsize win;
    FILE *f;
    int fd;
    time_t tmv;

    /*
     * Sigh, this is dumb, but we need the terminal window size
     * to do intelligent things with "ls" later on.
     */

    if (isatty(STDOUT_FILENO)) {
	if ((p = getenv("COLUMNS")) != NULL)
	    termsize = atoi(p);
	else if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &win) == 0
		 && win.ws_col > 0)
	    termsize = win.ws_col;
    }

    while ((c = getopt(argc, argv, "difr:t:v")) != EOF)
	switch (c) {
	case 't':
	    fprintf(stderr, "-t not supported in non-MRAFS " "dumptool.\n");
	    errflg++;
	    break;

	case 'r':
	    fprintf(stderr, "-r not supported in non-MRAFS " "dumptool.\n");
	    errflg++;
	    break;
	case 'd':
	    fprintf(stderr, "-d not supported in non-MRAFS " "dumptool.\n");
	    errflg++;
	    break;
	case 'v':
	    verbose++;
	    break;
	case 'f':
	    force++;
	    break;
	case 'i':
	    inode++;
	    break;
	case '?':
	default:
	    errflg++;
	}

    if (errflg || optind == argc) {
	fprintf(stderr, "Usage: %s\n\t[-v] [-f]\n\t"
		"filename\n",
		argv[0]);
	exit(1);
    }

    /*
     * Try opening the dump file
     */

#ifdef O_LARGEFILE
    if ((fd = open(argv[optind], O_RDONLY | O_LARGEFILE)) < 0) {
#else
    if ((fd = open(argv[optind], O_RDONLY)) < 0) {
#endif
	fprintf(stderr, "open of dumpfile %s failed: %s\n", argv[optind],
		strerror(errno));
	exit(1);
    }

    if ((f = fdopen(fd, "rb")) == NULL) {
        fprintf(stderr, "fdopen of dumpfile %s failed: %s\n", argv[optind],
		strerror(errno));
	exit(1);
    }

    if (ReadDumpHeader(f, &dheader)) {
	fprintf(stderr, "Failed to read dump header!\n");
	exit(1);
    }

    if (verbose)
	printf("Dump is for volume %lu (%s)\n", 
	       (unsigned long) dheader.volumeId, dheader.volumeName);

    if (getc(f) != D_VOLUMEHEADER) {
	fprintf(stderr, "Volume header is missing from dump, aborting\n");
	exit(1);
    }

    if (ReadVolumeHeader(f, &vol)) {
	fprintf(stderr, "Unable to read volume header\n");
	exit(1);
    }

    if (verbose) {
	printf("Volume information:\n");
	printf("\tid = %lu\n", (unsigned long) vol.id);
	printf("\tparent id = %lu\n", (unsigned long) vol.parentId);
	printf("\tname = %s\n", vol.name);
	printf("\tflags =");
	if (vol.inUse)
	    printf(" inUse");
	if (vol.inService)
	    printf(" inService");
	if (vol.blessed)
	    printf(" blessed");
	if (vol.needsSalvaged)
	    printf(" needsSalvaged");
	printf("\n");
 	if (vol.osdPolicy)
	    printf("\tosdPolicy = %u\n", vol.osdPolicy);
	printf("\tuniquifier = %lu\n", (unsigned long) vol.uniquifier);
	tmv = vol.creationDate;
	printf("\tCreation date = %s", ctime(&tmv));
        tmv = vol.accessDate;
        printf("\tLast access date = %s", ctime(&tmv));
        tmv = vol.updateDate;
        printf("\tLast update date = %s", ctime(&tmv));
	printf("\tVolume owner = %lu\n", (unsigned long) vol.owner);
    }

    if (verbose)
	printf("Scanning vnodes (this may take a while)\n");

    /*
     * We need to do two vnode scans; one to get the number of
     * vnodes, the other to actually build the index.
     */

    offset = ftello64(f);

    if (ScanVnodes(f, &vol, 1)) {
	fprintf(stderr, "First vnode scan failed, aborting\n");
	exit(1);
    }

    fseeko64(f, offset, SEEK_SET);

    if (ScanVnodes(f, &vol, 0)) {
	fprintf(stderr, "Second vnode scan failed, aborting\n");
	exit(1);
    }

    if (getc(f) != D_DUMPEND || ReadInt32(f, &magic) || magic != DUMPENDMAGIC) {
	fprintf(stderr, "Couldn't find dump postamble, ");
	if (!force) {
	    fprintf(stderr, "aborting (use -f to override)\n");
	    exit(1);
	} else {
	    fprintf(stderr, "continuing anyway\n");
	    fprintf(stderr, "WARNING: Dump may not be complete!\n");
	}
    }

    /*
     * If we wanted to simply dump all vnodes, do it now
     */

    if (inode) {
	/*
	 * Dump out all filenames with their corresponding FID
	 */

	struct vnodeData *rootvdata;

	if ((rootvdata = GetVnode(1)) == NULL) {
	    fprintf(stderr,
		    "Can't get vnode data for root " "vnode!  Aborting\n");
	    exit(1);
	}

	DirListInternal(rootvdata, NULL, 0, 0, 1, 0, 1, 0, &vol, "");

    } else if (argc > optind + 1) {
	fprintf(stderr, "Extra arguments after dump filename: %s\n",
		argv[optind]);
	exit(1);
    } else {
	/*
	 * Perform an interactive restore
	 */

	InteractiveRestore(f, &vol);
    }

    exit(0);
}

/*
 * Read the dump header, which is at the beginning of every dump
 */

static int
ReadDumpHeader(FILE * f, struct DumpHeader *header)
{
    unsigned int magic;
    int tag, i;

    if (getc(f) != D_DUMPHEADER || ReadInt32(f, &magic)
	|| ReadInt32(f, (unsigned int *)
		     &header->version) || magic != DUMPBEGINMAGIC) {
	if (verbose)
	    fprintf(stderr, "Couldn't find dump magic numbers\n");
	return -1;
    }

    header->volumeId = 0;
    header->nDumpTimes = 0;

    while ((tag = getc(f)) > D_MAX && tag != EOF) {
	unsigned short length;
	switch (tag) {
	case 'v':
	    if (ReadInt32(f, &header->volumeId)) {
		if (verbose)
		    fprintf(stderr, "Failed to read " "volumeId\n");
		return -1;
	    }
	    break;
	case 'n':
	    if (ReadString(f, header->volumeName, sizeof(header->volumeName))) {
		if (verbose)
		    fprintf(stderr, "Failed to read " "volume name\n");
		return -1;
	    }
	    break;
	case 't':
	    if (ReadInt16(f, &length)) {
		if (verbose)
		    fprintf(stderr,
			    "Failed to read " "dump time array length\n");
		return -1;
	    }
	    header->nDumpTimes = (length >> 1);
	    for (i = 0; i < header->nDumpTimes; i++)
		if (ReadInt32(f, (unsigned int *)
			      &header->dumpTimes[i].from)
		    || ReadInt32(f, (unsigned int *)
				 &header->dumpTimes[i].to)) {
		    if (verbose)
			fprintf(stderr, "Failed to " "read dump times\n");
		    return -1;
		}
	    break;
	case 0x7e:
	    break;		/* indicate: next tag is critical */
	default:
	    if (verbose)
		fprintf(stderr, "Unknown dump tag \"%c\"\n", tag);
	    return -1;
	}
    }

    if (!header->volumeId || !header->nDumpTimes) {
	if (verbose)
	    fprintf(stderr,
		    "We didn't get a volume Id or " "dump times listing\n");
	return 1;
    }

    ungetc(tag, f);
    return 0;
}

/*
 * Read the volume header; this is the information stored in VolumeDiskData.
 *
 * I'm not sure we need all of this, but read it in just in case.
 */

static int
ReadVolumeHeader(FILE * f, VolumeDiskData * vol)
{
    int tag;
    unsigned int trash;
    memset((void *)vol, 0, sizeof(*vol));

    while ((tag = getc(f)) > D_MAX && tag != EOF) {
	switch (tag) {
	case 'i':
	    if (ReadInt32(f, &vol->id))
		return -1;
	    break;
	case 'v':
	    if (ReadInt32(f, &trash))
		return -1;
	    break;
	case 'n':
	    if (ReadString(f, vol->name, sizeof(vol->name)))
		return -1;
	    break;
	case 's':
	    vol->inService = getc(f);
	    break;
	case 'b':
	    vol->blessed = getc(f);
	    break;
	case 'u':
	    if (ReadInt32(f, &vol->uniquifier))
		return -1;
	    break;
	case 't':
	    vol->type = getc(f);
	    break;
	case 'p':
	    if (ReadInt32(f, &vol->parentId))
		return -1;
	    break;
	case 'c':
	    if (ReadInt32(f, &vol->cloneId))
		return -1;
	    break;
	case 'q':
	    if (ReadInt32(f, (uint32_t *) & vol->maxquota))
		return -1;
	    break;
	case 'm':
	    if (ReadInt32(f, (uint32_t *) & vol->minquota))
		return -1;
	    break;
	case 'd':
	    if (ReadInt32(f, (uint32_t *) & vol->diskused))
		return -1;
	    break;
	case 'f':
	    if (ReadInt32(f, (uint32_t *) & vol->filecount))
		return -1;
	    break;
	case 'a':
	    if (ReadInt32(f, &vol->accountNumber))
		return -1;
	    break;
	case 'o':
	    if (ReadInt32(f, &vol->owner))
		return -1;
	    break;
	case 'C':
	    if (ReadInt32(f, &vol->creationDate))
		return -1;
	    break;
	case 'A':
	    if (ReadInt32(f, &vol->accessDate))
		return -1;
	    break;
	case 'U':
	    if (ReadInt32(f, &vol->updateDate))
		return -1;
	    break;
	case 'E':
	    if (ReadInt32(f, &vol->expirationDate))
		return -1;
	    break;
	case 'B':
	    if (ReadInt32(f, &vol->backupDate))
		return -1;
	    break;
	case 'O':
	    if (ReadString
		(f, vol->offlineMessage, sizeof(vol->offlineMessage)))
		return -1;
	    break;
	case 'M':
	    if (ReadString(f, (char *)vol->stat_reads, VMSGSIZE))
		return -1;
	    break;
	case 'W':{
		unsigned short length;
		int i;
		unsigned int data;
		if (ReadInt16(f, &length))
		    return -1;
		for (i = 0; i < length; i++) {
		    if (ReadInt32(f, &data))
			return -1;
		    if (i < sizeof(vol->weekUse) / sizeof(vol->weekUse[0]))
			vol->weekUse[i] = data;
		}
		break;
	    }
	case 'D':
	    if (ReadInt32(f, &vol->dayUseDate))
		return -1;
	    break;
	case 'Z':
	    if (ReadInt32(f, (uint32_t *) & vol->dayUse))
		return -1;
	    break;
#ifdef AFS_RXOSD_SUPPORT
	case 'F':
	case 'P':
	case 'y':
	    if (ReadInt32(f, (uint32_t *) & vol->osdPolicy))
		return -1;
	    break;
#endif
	default:
	    if (verbose)
		fprintf(stderr, "Unknown dump tag \"%c\"\n", tag);
	    return -1;
	}
    }

    ungetc(tag, f);
    return 0;
}

#ifdef AFS_RXOSD_SUPPORT
/*
 * List OSD metadata for a file
 */

static void
ListMetadata(int argc, char **argv, struct vnodeData *vdatacwd, FILE *f)
{
    struct vnodeData *vdata;
    
    if ((vdata = FindFile(vdatacwd, argv[1])) == NULL)
	return;
    if (vdata->metadata)
        printOsdMetadata(vdata->metadata, argv[1]);
    else if (!vdata->dumpdata)
	printf("Vnode %u.%u not contained in this dump\n", vdata->vnodeNumber,
                                vdata->vnode->uniquifier);
    return;
}
#endif

/*
 * List vnode fields
 */
static void
ListVnode(int argc, char **argv, struct vnodeData *vdatacwd, FILE *f,
			VolumeDiskData *vol)
{
    struct vnodeData *vdata;
    afs_uint64 Length;
    
    if ((vdata = FindFile(vdatacwd, argv[1])) == NULL)
	return;
    printf("Vnode %u.%u.%u", vol->id, vdata->vnodeNumber,
				vdata->vnode->uniquifier);
    if (!vdata->metadata && !vdata->dumpdata) {
	printf(" not contained in this dump\n");
	return;
    }
    printf("\n\tmodeBits\t = 0%3o\n", vdata->vnode->modeBits);
    printf("File %u.%u.%u\n", vol->id, vdata->vnodeNumber,
				vdata->vnode->uniquifier);
    printf("\tmodeBits\t = 0%3o\n", vdata->vnode->modeBits);
    printf("\tlinkCount\t = %u\n", vdata->vnode->linkCount);
    printf("\tauthor\t\t = %u\n", vdata->vnode->author);
    printf("\tgroup \t\t = %u\n", vdata->vnode->group);
    Length = vdata->vnode->vn_length_hi;
    Length = (Length << 32) + vdata->vnode->length;
    printf("\tLength\t\t = %llu	(0x%x, 0x%x)\n", 
				Length,
				vdata->vnode->vn_length_hi, 
				vdata->vnode->length); 
    printf("\tdataVersion\t = %u\n", vdata->vnode->dataVersion);
    printf("\tunixModifyTime\t =");
    PrintTime(vdata->vnode->unixModifyTime);
    printf("\n");
    printf("\tserverModifyTime  =");
    PrintTime(vdata->vnode->serverModifyTime);
    printf("\n");
    printf("\tvn_ino_lo\t = %u	(0x%x) tag = %u\n",
				vdata->vnode->vn_ino_lo, 
				vdata->vnode->vn_ino_lo, 
				vdata->vnode->vn_ino_lo >> 26); 
    printf("\tvn_ino_hi  	= %u	(0x%x)\n",
				vdata->vnode->vn_ino_hi, 
				vdata->vnode->vn_ino_hi);
#ifdef AFS_RXOSD_SUPPORT
    if (vol->osdPolicy && vdata->vnode->osdMetadataIndex)
        printf("\tosd file on disk  = %u\n", vdata->vnode->osdFileOnline);
#endif
    return;
}

/*
 * Scan all our vnode entries, and build indexing information.
 */

static int
ScanVnodes(FILE * f, VolumeDiskData * vol, int sizescan)
{
    int vnodeNumber;
    int tag;
    int numFileVnodes = 0;
    int numDirVnodes = 0;
    unsigned char buf[SIZEOF_LARGEDISKVNODE];
    struct VnodeDiskObject *vnode = (struct VnodeDiskObject *)buf;
    off64_t offset, oldoffset;
    struct vnodeData *vdata;
    unsigned int length, online;

    tag = getc(f);

    memset(vnode, 0, sizeof(struct VnodeDiskObject));
    while (tag == D_VNODE) {

	offset = 0;
	length = 0;
	vnode->type = -1;
	vnode->length = -1;
	vnode->vn_length_hi = 0;
#ifdef AFS_RXOSD_SUPPORT
	vnode->osdMetadataIndex = 0;
	vnode->osdFileOnline = 0;
#endif

	if (ReadInt32(f, (uint32_t *) & vnodeNumber)) {
	    fprintf(stderr, "failed int32 for 'vnodenum'\n");
	    return -1;
	}

	if (ReadInt32(f, &vnode->uniquifier)) {
	    fprintf(stderr, "failed int32 for 'uniquifier'\n");
	    return -1;
	}

	if (verbose > 1 && !sizescan)
	    printf("Got vnode %d\n", vnodeNumber);

	while ((tag = getc(f)) > D_MAX && tag != EOF)
	    switch (tag) {
	    case 't':
		vnode->type = (VnodeType) getc(f);
		break;
	    case 'l':
		{
		    unsigned short tmp;
		    if (ReadInt16(f, &tmp)) {
			fprintf(stderr, "failed int16 for 'l'\n");
			return -1;
		    }
		    vnode->linkCount = tmp;
		}
		break;
	    case 'v':
		if (ReadInt32(f, &vnode->dataVersion)) {
		    fprintf(stderr, "failed int32 for 'v'\n");
		    return -1;
		}
		break;
	    case 'm':
		if (ReadInt32(f, (uint32_t *) & vnode->unixModifyTime)) {
		    fprintf(stderr, "failed int32 for 'm'\n");
		    return -1;
		}
		break;
	    case 's':
		if (ReadInt32(f, (uint32_t *) & vnode->serverModifyTime)) {
		    fprintf(stderr, "failed int32 for 's'\n");
		    return -1;
		}
		break;
	    case 'a':
		if (ReadInt32(f, &vnode->author)) {
		    fprintf(stderr, "failed int32 for 'a'\n");
		    return -1;
		}
		break;
	    case 'o':
		if (ReadInt32(f, &vnode->owner)) {
		    fprintf(stderr, "failed int32 for 'o'\n");
		    return -1;
		}
		break;
	    case 'g':
		if (ReadInt32(f, (uint32_t *) & vnode->group)) {
		    fprintf(stderr, "failed int32 for 'g'\n");
		    return -1;
		}
		break;
	    case 'b':{
		    unsigned short modeBits;
		    if (ReadInt16(f, &modeBits))
			return -1;
		    vnode->modeBits = modeBits;
		    break;
		}
	    case 'p':
		if (ReadInt32(f, &vnode->parent)) {
		    fprintf(stderr, "failed int32 for 'p'\n");
		    return -1;
		}
		break;
	    case 'S':
		if (ReadInt32(f, &vnode->length)) {
		    fprintf(stderr, "failed int32 for 'S'\n");
		    return -1;
		}
		break;
	    case 'F':
		fprintf(stderr, "Strange vnode tag 'F'\n");
		if (ReadInt32(f, (uint32_t *) & vnode->vn_ino_lo))
		    return -1;
		break;
	    case 'A':
		if (ReadByteString
		    (f, (void *)VVnodeDiskACL(vnode), VAclDiskSize(vnode))) {
		    fprintf(stderr, "failed readbystring for 'A'\n");
		    return -1;
		}
#if 0
		acl_NtohACL(VVnodeDiskACL(vnode));
#endif
		break;
	    case 'h':
		if (ReadInt32(f, &vnode->vn_length_hi)) {
		    fprintf(stderr, "failed int32 for 'h'\n");
		    return -1;
		}
	    case 'f':
		if (verbose > 1 && !sizescan)
		    printf("We have file data!\n");
		if (ReadInt32(f, &length)) {
		    fprintf(stderr, "failed int32 for 'f'\n");
		    return -1;
		}
		if (verbose > 1 && sizescan) {
		    afs_uint64 total = ((afs_uint64)vnode->vn_length_hi << 32) + length;
		    printf("vnode %u has %llu bytes of file data!\n", vnodeNumber, total);
		}
		vnode->length = length;
		offset = ftello64(f);
		fseeko64(f, length, SEEK_CUR);
		break;
#ifdef AFS_RXOSD_SUPPORT
	    case 'u':
		{
		    afs_uint32 junk;
		    fprintf(stderr, "Strange vnode tag 'u'\n");
		    if (ReadInt32(f, & junk))
		        return -1;
		    break;
		}
	    case 'x':
		if (ReadInt32(f, &online)) {
		    fprintf(stderr, "failed int32 for 'x'\n");
		    return -1;
		}
		if (online)
		    vnode->osdFileOnline = 1;
		break; 
	    case 'L': {
		 char l;
		 l = getc(f);
		 if (l == 4) {
		  if (ReadInt32(f, &vnode->length)) {
		    fprintf(stderr, "failed int32 for 'L'\n");
		    return -1;
		  }
		  if (verbose >1 && !sizescan)
		    printf("filesize = %u\n", vnode->length);
		  break;
		 }
		}
	    case 'y':	/* old, should not be used anymore */
		{
		 afs_uint32 hi, lo;
		 afs_uint64 filesize;

		 if (ReadInt32(f, &vnode->vn_length_hi) 
		 || ReadInt32(f, &vnode->length)) {
		    fprintf(stderr, "failed int32 for 'y'\n");
		    return -1;
		  }
		  filesize = ((afs_uint64) hi << 32) | lo;
		  if (verbose >1 && !sizescan)
		    printf("filesize = %llu\n", filesize);
		  break;
		}		  
	    case 'O': 
		{
		  unsigned char l, c;
		  afs_uint32 osdlength = 0;

		  if (verbose > 1 && !sizescan)
		    printf("We have osd metadata:\n");
		  vnode->osdMetadataIndex = 1;
		  l = getc(f);
		  l &= 0x7f;
		  while (l) {
		    c = getc(f);
		    osdlength = (osdlength << 8) | c;
		    l--;
		  }
		  if (!sizescan) {
		    dummymh.length = osdlength;
		    dummymh.offset = 0;
		    ReadByteString(f, &dummymh.data, osdlength);
		    if (verbose > 1) {
			char name[256];
			sprintf(name, "%u.%u", vnodeNumber, vnode->uniquifier);
		        printOsdMetadata(&dummymh, name);
		    }
	 	  } else
		    fseeko64(f, osdlength, SEEK_CUR);
		 break;
		}
	    case 'z':
		{
		afs_uint32 osdlength;

		if (verbose > 1 && !sizescan)
		    printf("We have osd metadata:\n");
		vnode->osdMetadataIndex = 1;
		if (ReadInt32(f, &osdlength)) {
		    fprintf(stderr, "failed int32 for 'z'\n");
		    return -1;
		}
		if (!sizescan) {
		    dummymh.length = osdlength;
		    dummymh.offset = 0;
		    ReadByteString(f, &dummymh.data, osdlength);
		    if (verbose > 1) {
			char name[256];
			sprintf(name, "%u.%u", vnodeNumber, vnode->uniquifier);
		        printOsdMetadata(&dummymh, name);
		    }
	 	} else
		    fseeko64(f, osdlength, SEEK_CUR);
		break;
	 	}
	    case 'P':
	    case 'd': 
		{
		    afs_uint32 osdPolicy;
		    if (ReadInt32(f, &osdPolicy)) {
		        fprintf(stderr, "failed int32 for 'P'\n");
		        return -1;
		    }
 		    if (!sizescan) {
		        if (vnode->type == vDirectory)
			    vnode->osdPolicyIndex = osdPolicy;
		        if (verbose > 1)
		            printf("We have osd policy %u\n", osdPolicy);
		    }
		}
#endif
	    case 0x7e:
		break;		/* indicate: next tag is critical */
	    default:
		if (verbose)
		    fprintf(stderr, "Unknown dump tag \"%c\"\n", tag);
		return -1;
	    }

	/*
	 * If we're doing an incremental restore, then vnodes
	 * will be listed in the dump, but won't contain any
	 * vnode information at all (I don't know why they're
	 * included _at all_).  If we get one of these vnodes, then
	 * just skip it (because we can't do anything with it.
	 */

	if (vnode->type == -1)
	    continue;

	if (vnode->type == vDirectory)
	    numDirVnodes++;
	else
	    numFileVnodes++;

	/*
	 * We know now all we would ever know about the vnode;
	 * insert it into our hash table (but only if we're not
	 * doing a vnode scan).
	 */

	if (!sizescan) {

	    vdata = InsertVnode(vnodeNumber, vnode);

	    if (vdata == NULL) {
		if (verbose)
		    fprintf(stderr,
			    "Failed to insert " "vnode into hash table");
		return -1;
	    }

	    vdata->dumpdata = offset;
	    vdata->datalength = length;

	    /*
	     * Save directory data, since we'll need it later.
	     */

	    if (vnode->type == vDirectory && length) {

		vdata->filedata = malloc(length);

		if (!vdata->filedata) {
		    if (verbose)
			fprintf(stderr,
				"Unable to " "allocate space for "
				"file data (%d)\n", length);
		    return -1;
		}

		oldoffset = ftello64(f);
		fseeko64(f, offset, SEEK_SET);

		if (fread(vdata->filedata, length, 1, f) != 1) {
		    if (verbose)
			fprintf(stderr, "Unable to " "read in file data!\n");
		    return -1;
		}

		fseeko64(f, oldoffset, SEEK_SET);
	    } else if (vnode->type == vDirectory)
		/*
		 * Warn the user we may not have all directory
		 * vnodes
		 */
		numNoDirData++;
#ifdef AFS_RXOSD_SUPPORT
	   if (vnode->osdMetadataIndex) {
		vdata->metadata = (struct osdMetadataHandle *) 
			malloc(sizeof(dummymh));
		if (vdata->metadata) 
			memcpy(vdata->metadata, &dummymh, sizeof(dummymh));
	   }
#endif
	}
    }

    ungetc(tag, f);

    if (!sizescan) {

	numLargeVnodes = numDirVnodes;
	numSmallVnodes = numFileVnodes;

    } else {
	LargeVnodeIndex = (struct vnodeData **)
	    malloc(numDirVnodes * sizeof(struct vnodeData));
	SmallVnodeIndex = (struct vnodeData **)
	    malloc(numFileVnodes * sizeof(struct vnodeData));

	if (LargeVnodeIndex == NULL || SmallVnodeIndex == NULL) {
	    if (verbose)
		fprintf(stderr,
			"Unable to allocate space " "for vnode tables\n");
	    return -1;
	}
    }

    if (verbose)
	fprintf(stderr, "%s vnode scan completed\n",
		sizescan ? "Primary" : "Secondary");

    return 0;
}

/*
 * Perform an interactive restore
 *
 * Parsing the directory information is a pain, but other than that
 * we just use the other tools we already have in here.
 */
#define CMDBUFSIZE 	(AFSPATHMAX * 2)
static void
InteractiveRestore(FILE * f, VolumeDiskData * vol)
{
    struct vnodeData *vdatacwd;	/* Vnode data for our current dir */
    char cmdbuf[CMDBUFSIZE];
    int argc;
    char **argv;

    /*
     * Let's see if we can at least get the data for our root directory.
     * If we can't, there's no way we can do an interactive restore.
     */

    if ((vdatacwd = GetVnode(1)) == NULL) {
	fprintf(stderr, "No entry for our root vnode!  Aborting\n");
	return;
    }

    if (!vdatacwd->filedata) {
	fprintf(stderr,
		"There is no directory data for the root "
		"vnode (1.1).  An interactive\nrestore is not "
		"possible.\n");
	return;
    }
    strcpy(cwd,"/");

    /*
     * If you're doing a selective dump correctly, then you should get all
     * directory vnode data.  But just in case you didn't, let the user
     * know there may be a problem.
     */

    if (numNoDirData)
	fprintf(stderr,
		"WARNING: %d directory vnodes had no file "
		"data.  An interactive restore\nmay not be possible\n",
		numNoDirData);

    printf("%s> ", cwd);
    while (fgets(cmdbuf, CMDBUFSIZE, stdin)) {

	if (strlen(cmdbuf) > 0 && cmdbuf[strlen(cmdbuf) - 1] == '\n')
	    cmdbuf[strlen(cmdbuf) - 1] = '\0';

	if (strlen(cmdbuf) == 0) {
	    printf("> ");
	    continue;
	}

	MakeArgv(cmdbuf, &argc, &argv);

	if (strcmp(argv[0], "ls") == 0) {
	    DirectoryList(argc, argv, vdatacwd, vol);
	} else if (strcmp(argv[0], "cd") == 0) {
	    struct vnodeData *newvdata;

	    newvdata = ChangeDirectory(argc, argv, vdatacwd);

	    if (newvdata)
		vdatacwd = newvdata;
	} else if (strcmp(argv[0], "file") == 0) {
	    DumpAllFiles(argc, argv, vdatacwd, vol);
	} else if (strcmp(argv[0], "cp") == 0) {
	    CopyFile(argc, argv, vdatacwd, f);
	} else if (strcmp(argv[0], "vcp") == 0) {
	    CopyVnode(argc, argv, f);
#ifdef AFS_RXOSD_SUPPORT
	} else if (strcmp(argv[0], "osd") == 0) {
	    ListMetadata(argc, argv, vdatacwd, f);
	} else if (strcmp(argv[0], "vnode") == 0) {
	    ListVnode(argc, argv, vdatacwd, f, vol);
#endif
	} else if (strcmp(argv[0], "quit") == 0
		   || strcmp(argv[0], "exit") == 0)
	    break;
	else if (strcmp(argv[0], "?") == 0 || strcmp(argv[0], "help") == 0) {
	    printf("Valid commands are:\n");
	    printf("\tls\t\tList current directory\n");
	    printf("\tcd\t\tChange current directory\n");
	    printf("\tcp\t\tCopy file from dump\n");
	    printf("\tvcp\t\tCopy file from dump (via vnode)\n");
#ifdef AFS_RXOSD_SUPPORT
	    printf("\tosd\t\tList OSD metadata\n");
	    printf("\tvnode\t\tList vnode fields\n");
#endif /* AFS_RXOSD_SUPPORT */
	    printf("\tquit | exit\tExit program\n");
	    printf("\thelp | ?\tBrief help\n");
	} else
	    fprintf(stderr,
		    "Unknown command, \"%s\", enter "
		    "\"help\" for a list of commands.\n", argv[0]);

        memset((void *)cmdbuf, 0, sizeof(cmdbuf));
	printf("%s> ", cwd);
    }

    return;
}

/*
 * Do a listing of all files in a directory.  Sigh, I wish this wasn't
 * so complicated.
 *
 * With the reorganizing, this is just a front-end to DirListInternal()
 */

static void
DirectoryList(int argc, char **argv, struct vnodeData *vdata,
	      VolumeDiskData * vol)
{
    int errflg = 0, lflag = 0, iflag = 0, Fflag = 0, sflag = 0, Rflag = 0;
    int c;

    optind = 1;

    while ((c = getopt(argc, argv, "liFRs")) != EOF)
	switch (c) {
	case 'l':
	    lflag++;
	    break;
	case 'i':
	    iflag++;
	    break;
	case 'F':
	    Fflag++;
	    break;
	case 'R':
	    Rflag++;
	case 's':
	    sflag++;
	    break;
	case '?':
	default:
	    errflg++;
	}

    if (errflg) {
	fprintf(stderr, "Usage: %s [-liFs] filename [filename ...]\n",
		argv[0]);
	return;
    }

    DirListInternal(vdata, &(argv[optind]), argc - optind, lflag, iflag,
		    Fflag, Rflag, 1, vol, NULL);

    return;
}

/*
 * Function that does the REAL work in terms of directory listing
 */

static void
DirListInternal(struct vnodeData *vdata, char *pathnames[], int numpathnames,
		int lflag, int iflag, int Fflag, int Rflag, int verbose,
		VolumeDiskData * vol, char *path)
{
    struct DirEntry *ep, **eplist = NULL, **eprecurse = NULL;
    struct DirCursor cursor;
    struct vnodeData *lvdata;

    int i, j, numentries = 0, longestname = 0, numcols, col, numrows;
    int numrecurse = 0;

    if (!vdata->filedata) {
	fprintf(stderr, "There is no vnode data for this " "directory!\n");
	return;
    }

    ResetDirCursor(&cursor, vdata);

    /*
     * Scan through the whole directory
     */

    while ((ep = ReadNextDir(&cursor, vdata)) != NULL) {

	/*
	 * If we didn't get any filenames on the command line,
	 * get them all.
	 */

	if (numpathnames == 0) {
	    eplist =
		realloc(eplist, sizeof(struct DirEntry *) * ++numentries);
	    eplist[numentries - 1] = ep;
	    if (strlen(ep->name) > longestname)
		longestname = strlen(ep->name);
	    if (Rflag)
		if ((lvdata = GetVnode(ntohl(ep->fid.vnode)))
		    && lvdata->vnode->type == vDirectory
		    && !(strcmp(ep->name, ".") == 0
			 || strcmp(ep->name, "..") == 0)) {
		    eprecurse =
			realloc(eprecurse,
				sizeof(struct DirEntry *) * ++numrecurse);
		    eprecurse[numrecurse - 1] = ep;
		}

	} else {
	    /*
	     * Do glob matching via fnmatch()
	     */

	    for (i = 0; i < numpathnames; i++)
		if (fnmatch(pathnames[i], ep->name, FNM_PATHNAME) == 0) {
		    eplist =
			realloc(eplist,
				sizeof(struct DirEntry *) * ++numentries);
		    eplist[numentries - 1] = ep;
		    if (strlen(ep->name) > longestname)
			longestname = strlen(ep->name);
		    if (Rflag)
			if ((lvdata = GetVnode(ntohl(ep->fid.vnode)))
			    && lvdata->vnode->type == vDirectory
			    && !(strcmp(ep->name, ".") == 0
				 || strcmp(ep->name, "..") == 0)) {
			    eprecurse =
				realloc(eprecurse,
					sizeof(struct DirEntry *) *
					++numrecurse);
			    eprecurse[numrecurse - 1] = ep;
			}
		    break;
		}
	}
    }

    qsort((void *)eplist, numentries, sizeof(struct DirEntry *),
	  CompareDirEntry);

    if (Rflag && eprecurse)
	qsort((void *)eprecurse, numrecurse, sizeof(struct DirEntry *),
	      CompareDirEntry);
    /*
     * We don't have to do column printing if we have the -l or the -i
     * options.  Sigh, column printing is WAY TOO FUCKING COMPLICATED!
     */

    if (!lflag && !iflag) {
	char c;

	if (Fflag)
	    longestname++;

	longestname++;

	numcols = termsize / longestname ? termsize / longestname : 1;
	numrows = numentries / numcols + (numentries % numcols ? 1 : 0);

	for (i = 0; i < numrows; i++) {
	    col = 0;
	    while (col < numcols && (i + col * numrows) < numentries) {
		ep = eplist[i + col++ * numrows];
		if (Fflag) {
		    if (!(lvdata = GetVnode(ntohl(ep->fid.vnode))))
			c = ' ';
		    else if (lvdata->vnode->type == vDirectory)
			c = '/';
		    else if (lvdata->vnode->type == vSymlink)
			c = '@';
		    else if ((lvdata->vnode->modeBits & 0111) != 0)
			c = '*';
		    else
			c = ' ';
		    printf("%s%-*c", ep->name, (int)(longestname - 
						     strlen(ep->name)), c);
		} else
		    printf("%-*s", longestname, ep->name);
	    }

	    printf("\n");
	}
    } else if (iflag)
	for (i = 0; i < numentries; i++)
	    if (!(lvdata = GetVnode(ntohl(eplist[i]->fid.vnode))))
		printf("%d.0.0\t%s\n",
		       vol->parentId ? vol->parentId : vol->id,
		       eplist[i]->name);
	    else if (path)
		printf("%d.%d.%d\t%s/%s\n", vol->id,
		       ntohl(eplist[i]->fid.vnode),
		       ntohl(eplist[i]->fid.vunique), path, eplist[i]->name);
	    else
		printf("%d.%d.%d\t%s\n", vol->id, ntohl(eplist[i]->fid.vnode),
		       ntohl(eplist[i]->fid.vunique), eplist[i]->name);
    else if (lflag) {
	afs_uint64 filesize;
	for (i = 0; i < numentries; i++)
	    if (!(lvdata = GetVnode(ntohl(eplist[i]->fid.vnode))))
		printf("- ---   0 0        " "0                 0 %s\n",
		       eplist[i]->name);
	    else {
		switch (lvdata->vnode->type) {
		case vDirectory:
		    printf("d ");
		    break;
		case vSymlink:
		    printf("l ");
		    break;
		default:
#ifdef AFS_RXOSD_SUPPORT
		    if (lvdata->vnode->osdMetadataIndex) {
			if (lvdata->vnode->osdFileOnline) 
			    printf("o ");
			else
			    printf("w ");
		    } else
#endif
		    {
			if (lvdata->dumpdata)
		    	    printf("F ");
			else {
		    	    printf("f                (not contained in this dump)     %s\n",
				eplist[i]->name); 
			    continue;
			}
		    }
		}

		for (j = 8; j > 5; j--) {
		    if (lvdata->vnode->modeBits & (1 << j))
			switch (j % 3) {
			case 2:
			    printf("r");
			    break;
			case 1:
			    printf("w");
			    break;
			case 0:
			    printf("x");
		    } else
			printf("-");
		}
		filesize = ((afs_int64)lvdata->vnode->vn_length_hi << 32)
				| lvdata->vnode->length;
		printf(" %-3d %-8d %10lld", lvdata->vnode->linkCount,
		       lvdata->vnode->owner, filesize);
		PrintTime(lvdata->vnode->unixModifyTime);
		printf(" %s\n", eplist[i]->name);
	    }
    }

    free(eplist);

    if (Rflag && eprecurse) {
	char *lpath;
	lpath = NULL;
	for (i = 0; i < numrecurse; i++) {
	    if (verbose)
		printf("\n%s:\n", eprecurse[i]->name);
	    if (path) {
		lpath = malloc(strlen(path) + strlen(eprecurse[i]->name) + 2);
		if (lpath)
		    sprintf(lpath, "%s/%s", path, eprecurse[i]->name);
	    }
	    DirListInternal(GetVnode(ntohl(eprecurse[i]->fid.vnode)), NULL, 0,
			    lflag, iflag, Fflag, Rflag, verbose, vol, lpath);
	    if (lpath) {
		free(lpath);
		lpath = NULL;
	    }
	}
    }

    if (eprecurse)
	free(eprecurse);

    return;
}


/*
 * Directory name comparison function, used by qsort
 */

static int
CompareDirEntry(const void *e1, const void *e2)
{
    struct DirEntry **ep1 = (struct DirEntry **)e1;
    struct DirEntry **ep2 = (struct DirEntry **)e2;

    return strcmp((*ep1)->name, (*ep2)->name);
}

/*
 * Change a directory.  Return a pointer to our new vdata structure for
 * this directory.
 */

static struct vnodeData *
ChangeDirectory(int argc, char **argv, struct vnodeData *vdatacwd)
{
    struct vnodeData *newvdatacwd;
    char *p = argv[1];

    if (argc != 2) {
	fprintf(stderr, "Usage: %s directory\n", argv[0]);
	return NULL;
    }

    if ((newvdatacwd = FindFile(vdatacwd, argv[1])) == NULL)
	return NULL;

    if (newvdatacwd->vnode->type != vDirectory) {
	fprintf(stderr, "%s: Not a directory\n", argv[1]);
	return NULL;
    }

    if (newvdatacwd->filedata == NULL) {
	fprintf(stderr, "%s: No directory data found.\n", argv[1]);
	return NULL;
    }
    while (*p) {
	char *cwdend = &cwd[strlen(cwd)-1];
        if (!strncmp(p, "..", 2)) {
	    p +=2;
	    while (strlen(cwd) > 1 && *cwdend != '/') {
		*cwdend = 0;
		cwdend--;
	    }
	    if (strlen(cwd) > 1) {
	        *cwdend = 0;
	        cwdend--;
	    }
	} else {
	    if (strlen(cwd) > 1)
	        *(++cwdend) = '/';	
	    while (*p != '/' && *p != 0) 
		*(++cwdend) = *p++;		
	}
	if (*p == '/')
	    p++;
    }

    return newvdatacwd;
}

#ifdef AFS_RXOSD_SUPPORT
PrintTime(int intdate)
{
    time_t now, date;
    char month[4];
    char weekday[4];
    int  hour, minute, second, day, year;
    char *timestring;
    char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                         "Sep", "Oct", "Nov", "Dec"};
    int i;

    if (!intdate) printf(" never       "); else {
        date = intdate;
        timestring = ctime(&date);
        sscanf(timestring, "%s %s %d %d:%d:%d %d",
                (char *)&weekday,
                (char *)&month, &day, &hour, &minute, &second, &year);
        for (i=0; i<12; i++) {
           if (!strcmp(month, months[i]))
                break;
        }
        printf(" %04d-%02d-%02d %02d:%02d:%02d", year, i+1, day, hour, minute, second);
    }
}
#else
PrintTime(int intdate)
{
    time_t now, date;
    char month[4];
    char weekday[4];
    int  hour, minute, second, day, year;
    char *timestring;
    struct timeval tv;
    struct timezone tz;
 
    if (!intdate) printf(" never       "); else {
        date = intdate;
        timestring = ctime(&date);
        sscanf(timestring, "%s %s %d %d:%d:%d %d",
                (char *)&weekday,
                (char *)&month, &day, &hour, &minute, &second, &year);
	gettimeofday(&tv, &tz); 
        now = tv.tv_sec;
        if (now - date < 15811200)
           printf(" %s %2d %02d:%02d", &month, day, hour, minute);
        else
           printf(" %s %2d %4d ", &month, day, year);
   }
}
#endif


/*
 * Copy a file from out of the dump file
 */

#define COPYBUFSIZE 8192

static void
CopyFile(int argc, char **argv, struct vnodeData *vdatacwd, FILE * f)
{
    struct vnodeData *vdata;
    FILE *out;
    off64_t cur = 0;
    int bytes, ret;
    char buffer[COPYBUFSIZE];

    if (argc != 3) {
	fprintf(stderr, "Usage: %s dumpfile destfile\n", argv[0]);
	return;
    }

    if ((vdata = FindFile(vdatacwd, argv[1])) == NULL)
	return;

    if (vdata->dumpdata == 0) {
	fprintf(stderr, "File %s has no data in dump file\n", argv[1]);
	return;
    }

    if ((out = fopen(argv[2], "wb")) == NULL) {
	fprintf(stderr, "Open of %s failed: %s\n", argv[2], strerror(errno));
	return;
    }

    if (fseeko64(f, vdata->dumpdata, SEEK_SET)) {
	fprintf(stderr, "Seek failed: %s\n", strerror(errno));
	fclose(out);
	return;
    }

    while (cur < vdata->datalength) {

	bytes =
	    cur + COPYBUFSIZE <
	    vdata->datalength ? COPYBUFSIZE : vdata->datalength - cur;

	ret = fread(buffer, sizeof(char), bytes, f);
	if (ret != bytes) {
	    if (ret != 0)
		fprintf(stderr, "Short read (expected %d, " "got %d)\n",
			bytes, ret);
	    else
		fprintf(stderr, "Error during read: %s\n", strerror(errno));
	    fclose(out);
	    return;
	}

	ret = fwrite(buffer, sizeof(char), bytes, out);
	if (ret != bytes) {
	    if (ret != 0)
		fprintf(stderr, "Short write (expected %d, " "got %d)\n",
			bytes, ret);
	    else
		fprintf(stderr, "Error during write: %s\n", strerror(errno));
	    fclose(out);
	    return;
	}

	cur += bytes;
    }

    fclose(out);
}

/*
 * Copy a file from out of the dump file, by using the vnode
 */

static void
CopyVnode(int argc, char *argv[], FILE * f)
{
    struct vnodeData *vdata;
    FILE *out;
    off64_t cur = 0;
    int bytes, ret;
    char buffer[COPYBUFSIZE];
    unsigned int vnode, uniquifier = 0;

    if (argc != 3) {
	fprintf(stderr, "Usage: %s vnode[.uniqifier] destfile\n", argv[0]);
	return;
    }

    ret = sscanf(argv[1], "%d.%d", &vnode, &uniquifier);

    if (ret < 1) {
	fprintf(stderr, "Invalid file identifier: %s\n", argv[1]);
	return;
    }

    if (!(vdata = GetVnode(vnode))) {
	fprintf(stderr, "Vnode %d not in dump file\n", vnode);
	return;
    }

    if (ret == 2 && vdata->vnode->uniquifier != uniquifier) {
	fprintf(stderr,
		"Specified uniquifier %d did not match "
		"uniquifier %d found in dump file!\n", uniquifier,
		vdata->vnode->uniquifier);
	return;
    }

    if (vdata->dumpdata == 0) {
	fprintf(stderr, "File %s has no data in dump file\n", argv[1]);
	return;
    }

    if ((out = fopen(argv[2], "wb")) == NULL) {
	fprintf(stderr, "Open of %s failed: %s\n", argv[2], strerror(errno));
	return;
    }

    if (fseeko64(f, vdata->dumpdata, SEEK_SET)) {
	fprintf(stderr, "Seek failed: %s\n", strerror(errno));
	fclose(out);
	return;
    }

    while (cur < vdata->datalength) {

	bytes =
	    cur + COPYBUFSIZE <
	    vdata->datalength ? COPYBUFSIZE : vdata->datalength - cur;

	ret = fread(buffer, sizeof(char), bytes, f);
	if (ret != bytes) {
	    if (ret != 0)
		fprintf(stderr, "Short read (expected %d, " "got %d)\n",
			bytes, ret);
	    else
		fprintf(stderr, "Error during read: %s\n", strerror(errno));
	    fclose(out);
	    return;
	}

	ret = fwrite(buffer, sizeof(char), bytes, out);
	if (ret != bytes) {
	    if (ret != 0)
		fprintf(stderr, "Short write (expected %d, " "got %d)\n",
			bytes, ret);
	    else
		fprintf(stderr, "Error during write: %s\n", strerror(errno));
	    fclose(out);
	    return;
	}

	cur += bytes;
    }

    fclose(out);
}

/*
 * Dump all residency filenames associated with a file, or all files
 * within a directory.
 */

static void
DumpAllFiles(int argc, char **argv, struct vnodeData *vdatacwd,
	     VolumeDiskData * vol)
{
    fprintf(stderr,
	    "The \"file\" command is not available in the non-"
	    "MRAFS version of dumptool.\n");
    return;
}


/*
 * Given a directory vnode and a filename, return the vnode corresponding
 * to the file in that directory.
 * 
 * We now handle pathnames with directories in them.
 */

static struct vnodeData *
FindFile(struct vnodeData *vdatacwd, char *filename)
{
    struct DirHeader *dhp;
    struct DirEntry *ep;
    int i, num;
    struct vnodeData *vdata;
    char *c, newstr[MAXPATHLEN];

    if (!vdatacwd->filedata) {
	fprintf(stderr, "There is no vnode data for this " "directory!\n");
	return NULL;
    }

    /*
     * If we have a "/" in here, look up the vnode data for the
     * directory (everything before the "/") and use that as our
     * current directory.  We automagically handle multiple directories
     * by using FindFile recursively.
     */

    if ((c = strrchr(filename, '/')) != NULL) {

	strncpy(newstr, filename, c - filename);
	newstr[c - filename] = '\0';

	if ((vdatacwd = FindFile(vdatacwd, newstr)) == NULL)
	    return NULL;

	if (vdatacwd->vnode->type != vDirectory) {
	    fprintf(stderr, "%s: Not a directory\n", newstr);
	    return NULL;
	}

	filename = c + 1;
    }

    dhp = (struct DirHeader *)vdatacwd->filedata;

    i = DirHash(filename);

    num = ntohs(dhp->hashTable[i]);

    while (num) {
	ep = (struct DirEntry *)(vdatacwd->filedata + (num * 32));
	if (strcmp(ep->name, filename) == 0)
	    break;
	num = ntohs(ep->next);
    }

    if (!num) {
	fprintf(stderr, "%s: No such file or directory\n", filename);
	return NULL;
    }

    if ((vdata = GetVnode(ntohl(ep->fid.vnode))) == NULL) {
	fprintf(stderr, "%s: No vnode information for %u found\n", filename,
		ntohl(ep->fid.vnode));
	return NULL;
    }

    return vdata;
}

/*
 * Reset a structure containing the current directory scan location
 */

static void
ResetDirCursor(struct DirCursor *cursor, struct vnodeData *vdata)
{
    struct DirHeader *dhp;

    cursor->hashbucket = 0;

    dhp = (struct DirHeader *)vdata->filedata;

    cursor->entry = ntohs(dhp->hashTable[0]);
}

/*
 * Given a cursor and a directory entry, return the next entry in the
 * directory.
 */

static struct DirEntry *
ReadNextDir(struct DirCursor *cursor, struct vnodeData *vdata)
{
    struct DirHeader *dhp;
    struct DirEntry *ep;

    dhp = (struct DirHeader *)vdata->filedata;

    if (cursor->entry) {
	ep = (struct DirEntry *)(vdata->filedata + (cursor->entry * 32));
	cursor->entry = ntohs(ep->next);
	return ep;
    } else {
	while (++(cursor->hashbucket) < NHASHENT) {
	    cursor->entry = ntohs(dhp->hashTable[cursor->hashbucket]);
	    if (cursor->entry) {
		ep = (struct DirEntry *)(vdata->filedata +
					 (cursor->entry * 32));
		cursor->entry = ntohs(ep->next);
		return ep;
	    }
	}
    }

    return NULL;
}

/*
 * Given a string, split it up into components a la Unix argc/argv.
 *
 * This code is most stolen from ftp.
 */

static void
MakeArgv(char *string, int *argc, char ***argv)
{
    static char *largv[64];
    char **la = largv;
    char *s = string;
    static char argbuf[CMDBUFSIZE];
    char *ap = argbuf;
    memset((void *)largv, 0, sizeof(largv));

    *argc = 0;
    *argv = largv;

    while ((*la++ = GetToken(s, &s, ap, &ap)) != NULL)
	(*argc)++;
}

/*
 * Return a pointer to the next token, and update the current string
 * position.
 */

static char *
GetToken(char *string, char **nexttoken, char argbuf[], char *nextargbuf[])
{
    char *sp = string;
    char *ap = argbuf;
    int got_one = 0;

  S0:
    switch (*sp) {

    case '\0':
	goto OUTTOKEN;

    case ' ':
    case '\t':
	sp++;
	goto S0;

    default:
	goto S1;
    }

  S1:
    switch (*sp) {

    case ' ':
    case '\t':
    case '\0':
	goto OUTTOKEN;		/* End of our token */

    case '\\':
	sp++;
	goto S2;		/* Get next character */

    case '"':
	sp++;
	goto S3;		/* Get quoted string */

    default:
	*ap++ = *sp++;		/* Add a character to our token */
	got_one = 1;
	goto S1;
    }

  S2:
    switch (*sp) {

    case '\0':
	goto OUTTOKEN;

    default:
	*ap++ = *sp++;
	got_one = 1;
	goto S1;
    }

  S3:
    switch (*sp) {

    case '\0':
	goto OUTTOKEN;

    case '"':
	sp++;
	goto S1;

    default:
	*ap++ = *sp++;
	got_one = 1;
	goto S3;
    }

  OUTTOKEN:
    if (got_one)
	*ap++ = '\0';
    *nextargbuf = ap;		/* Update storage pointer */
    *nexttoken = sp;		/* Update token pointer */

    return got_one ? argbuf : NULL;
}

/*
 * Insert vnodes into our hash table.
 */

static struct vnodeData *
InsertVnode(unsigned int vnodeNumber, struct VnodeDiskObject *vnode)
{
    struct VnodeDiskObject *nvnode;
    struct vnodeData *vdata;
    static int curSmallVnodeIndex = 0;
    static int curLargeVnodeIndex = 0;
    struct vnodeData ***vnodeIndex;
    int *curIndex;

    nvnode = (struct VnodeDiskObject *)malloc(sizeof(struct VnodeDiskObject));

    if (!nvnode) {
	if (verbose)
	    fprintf(stderr, "Unable to allocate space for vnode\n");
	return NULL;
    }

    memcpy((void *)nvnode, (void *)vnode, sizeof(struct VnodeDiskObject));

    if (vnodeNumber & 1) {
	vnodeIndex = &LargeVnodeIndex;
	curIndex = &curLargeVnodeIndex;
    } else {
	vnodeIndex = &SmallVnodeIndex;
	curIndex = &curSmallVnodeIndex;
    }

    vdata = (struct vnodeData *)malloc(sizeof(struct vnodeData));

    vdata->vnode = nvnode;
    vdata->vnodeNumber = vnodeNumber;
    vdata->dumpdata = 0;
    vdata->filedata = 0;
#ifdef AFS_RXOSD_SUPPORT
    vdata->metadata = 0;
#endif
    vdata->datalength = 0;

    (*vnodeIndex)[(*curIndex)++] = vdata;

    return vdata;
}

/*
 * Routine to retrieve a vnode from the hash table.
 */

static struct vnodeData *
GetVnode(unsigned int vnodeNumber)
{
    struct vnodeData vnode, *vnodep, **tmp;

    vnode.vnodeNumber = vnodeNumber;
    vnodep = &vnode;

    tmp = (struct vnodeData **)
	bsearch((void *)&vnodep,
		vnodeNumber & 1 ? LargeVnodeIndex : SmallVnodeIndex,
		vnodeNumber & 1 ? numLargeVnodes : numSmallVnodes,
		sizeof(struct vnodeData *), CompareVnode);

    return tmp ? *tmp : NULL;
}

/*
 * Our comparator function for bsearch
 */

static int
CompareVnode(const void *node1, const void *node2)
{
    struct vnodeData **vnode1 = (struct vnodeData **)node1;
    struct vnodeData **vnode2 = (struct vnodeData **)node2;

    if ((*vnode1)->vnodeNumber == (*vnode2)->vnodeNumber)
	return 0;
    else if ((*vnode1)->vnodeNumber > (*vnode2)->vnodeNumber)
	return 1;
    else
	return -1;
}

/*
 * Read a 16 bit integer in network order
 */

static int
ReadInt16(FILE * f, unsigned short *s)
{
    unsigned short in;

    if (fread((void *)&in, sizeof(in), 1, f) != 1) {
	if (verbose)
	    fprintf(stderr, "ReadInt16 failed!\n");
	return -1;
    }

    *s = ntohs(in);

    return 0;
}


/*
 * Read a 32 bit integer in network order
 */

static int
ReadInt32(FILE * f, unsigned int *i)
{
    unsigned int in;

    if (fread((void *)&in, sizeof(in), 1, f) != 1) {
	if (verbose)
	    fprintf(stderr, "ReadInt32 failed!\n");
	return -1;
    }

    *i = ntohl((unsigned long)in);

    return 0;
}

/*
 * Read a string from a dump file
 */

static int
ReadString(FILE * f, char *string, int maxlen)
{
    int c;

    while (maxlen--) {
	if ((*string++ = getc(f)) == 0)
	    break;
    }

    /*
     * I'm not sure what the _hell_ this is supposed to do ...
     * but it was in the original dump code
     */

    if (string[-1]) {
	while ((c = getc(f)) && c != EOF);
	string[-1] = 0;
    }

    return 0;
}

static int
ReadByteString(FILE * f, void *s, int size)
{
    unsigned char *c = (unsigned char *)s;

    while (size--)
	*c++ = getc(f);

    return 0;
}

/*
 * The directory hashing algorithm used by AFS
 */

int
DirHash(char *string)
{
    /* Hash a string to a number between 0 and NHASHENT. */
    unsigned char tc;
    int hval;
    int tval;
    hval = 0;
    while ((tc = (*string++)) != '\0')  {
	hval *= 173;
	hval += tc;
    }
    tval = hval & (NHASHENT - 1);
#ifdef AFS_CRAY_ENV		/* actually, any > 32 bit environment */
    if (tval == 0)
	return tval;
    else if (hval & 0x80000000)
	tval = NHASHENT - tval;
#else /* AFS_CRAY_ENV */
    if (tval == 0)
	return tval;
    else if (hval < 0)
	tval = NHASHENT - tval;
#endif /* AFS_CRAY_ENV */
    return tval;
}


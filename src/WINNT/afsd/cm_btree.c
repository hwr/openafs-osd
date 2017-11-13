/*
 * Copyright 2007-2008 Secure Endpoints Inc.
 *
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 *
 * Thanks to Jan Jannink for B+ tree algorithms.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <roken.h>

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "afsd.h"
#include <assert.h>
#include <strsafe.h>

#ifdef USE_BPLUS
#include "cm_btree.h"

/******************* statistics globals  *********************************/
afs_uint32 bplus_lookup_hits = 0;
afs_uint32 bplus_lookup_hits_inexact = 0;
afs_uint32 bplus_lookup_misses = 0;
afs_uint32 bplus_lookup_ambiguous = 0;
afs_uint32 bplus_create_entry = 0;
afs_uint32 bplus_remove_entry = 0;
afs_uint32 bplus_build_tree = 0;
afs_uint32 bplus_free_tree = 0;
afs_uint32 bplus_dv_error = 0;

afs_uint64 bplus_lookup_time = 0;
afs_uint64 bplus_create_time = 0;
afs_uint64 bplus_remove_time = 0;
afs_uint64 bplus_build_time = 0;
afs_uint64 bplus_free_time = 0;

/***********************   private functions   *************************/
static void initFreeNodePool(Tree *B, int quantity);
static Nptr getFreeNode(Tree *B);
static void putFreeNode(Tree *B, Nptr self);
static void cleanupNodePool(Tree *B);

static Nptr descendToLeaf(Tree *B, Nptr curr);
int getSlot(Tree *B, Nptr curr);
static int findKey(Tree *B, Nptr curr, int lo, int hi);
static int bestMatch(Tree *B, Nptr curr, int slot);

static Nptr getDataNode(Tree *B, keyT key, dataT data);
static Nptr descendSplit(Tree *B, Nptr curr);
static void insertEntry(Tree *B, Nptr node, int slot, Nptr sibling, Nptr downPtr);
static void placeEntry(Tree *B, Nptr node, int slot, Nptr downPtr);
static Nptr split(Tree *B, Nptr node);
static void makeNewRoot(Tree *B, Nptr oldRoot, Nptr newNode);

static Nptr descendBalance(Tree *B, Nptr curr, Nptr left, Nptr right, Nptr lAnc, Nptr rAnc, Nptr parent);
static void collapseRoot(Tree *B, Nptr oldRoot, Nptr newRoot);
static void removeEntry(Tree *B, Nptr curr, int slot);
static Nptr merge(Tree *B, Nptr left, Nptr right, Nptr anchor);
static Nptr shift(Tree *B, Nptr left, Nptr right, Nptr anchor);

static void _clrentry(Nptr node, int entry);
static void _pushentry(Nptr node, int entry, int offset);
static void _pullentry(Nptr node, int entry, int offset);
static void _xferentry(Nptr srcNode, int srcEntry, Nptr destNode, int destEntry);
static void _setentry(Nptr node, int entry, keyT key, Nptr downNode);

/* access key and data values for B+tree methods */
/* pass values to getSlot(), descend...() */
static keyT   getfunkey(Tree  *B);
static dataT  getfundata(Tree *B);
static void   setfunkey(Tree *B,  keyT v);
static void   setfundata(Tree *B, dataT v);


#ifdef DEBUG_BTREE
static int _isRoot(Tree *B, Nptr n)
{
    int flagset = ((n->flags & isROOT) == isROOT);

    if (!isnode(n))
        return 0;

    if (flagset && n != getroot(B))
        DebugBreak();

    return flagset;
}

static int _isFew(Tree *B, Nptr n)
{
    int flagset = ((n->flags & FEWEST) == FEWEST);
    int fanout = getminfanout(B, n);
    int entries = numentries(n);
    int mincnt  = entries <= fanout;

    if (!isnode(n))
        return 0;

    if (flagset && !mincnt || !flagset && mincnt)
        DebugBreak();

    return flagset;
}

static int _isFull(Tree *B, Nptr n)
{
    int flagset = ((n->flags & isFULL) == isFULL);
    int maxcnt  = numentries(n) == getfanout(B);

    if (!isnode(n))
        return 0;

    if (flagset && !maxcnt || !flagset && maxcnt)
        DebugBreak();

    return flagset;
}
#endif /* DEBUG_BTREE */

/***********************************************************************\
|	B+tree Initialization and Cleanup Routines                      |
\***********************************************************************/
static DWORD TlsKeyIndex;
static DWORD TlsDataIndex;

long cm_InitBPlusDir(void)
{
    if ((TlsKeyIndex = TlsAlloc()) == TLS_OUT_OF_INDEXES)
        return 0;

    if ((TlsDataIndex = TlsAlloc()) == TLS_OUT_OF_INDEXES)
        return 0;

    return 1;
}

/********************   Set up B+tree structure   **********************/
Tree *initBtree(unsigned int poolsz, unsigned int fanout, KeyCmp keyCmp)
{
    Tree *B;
    keyT empty = {NULL};
    dataT data = {0,0,0,0,0,0,0};

    if (fanout > MAX_FANOUT)
        fanout = MAX_FANOUT;

    setbplustree(B, malloc(sizeof(Tree)));
    memset(B, 0, sizeof(Tree));
    setfanout(B, fanout);
    setminfanout(B, (fanout + 1) >> 1);
    initFreeNodePool(B, poolsz);

    setleaf(B, getFreeNode(B));		/* set up the first leaf node */
    setroot(B, getleaf(B));		/* the root is initially the leaf */
    setflag(getroot(B), isLEAF);
    setflag(getroot(B), isROOT);
    setflag(getroot(B), FEWEST);
    inittreeheight(B);

    setfunkey(B,empty);
    setfundata(B,data);
    setcomparekeys(B, keyCmp);

#ifdef DEBUG_BTREE
    StringCbPrintfA(B->message, sizeof(B->message), "INIT:  B+tree of fanout %d at %10p.\n", fanout, (void *)B);
    OutputDebugString(B->message);
#endif

  return B;
}

/********************   Clean up B+tree structure   ********************/
/*
 *  dirlock must be write locked
 */
void freeBtree(Tree *B)
{
#ifdef DEBUG_BTREE
    StringCbPrintfA(B->message, sizeof(B->message), "FREE:  B+tree at %10p.\n", (void *) B);
    OutputDebugString(B->message);
#endif

    cleanupNodePool(B);

    memset(B, 0, sizeof(*B));
    free((void *) B);
}


/* access key and data values for B+tree methods */
/* pass values to getSlot(), descend...() */
static keyT getfunkey(Tree *B) {
    keyT *tlsKey;

    // Retrieve a data pointer for the current thread.
    tlsKey = (keyT *) TlsGetValue(TlsKeyIndex);
    if (tlsKey == NULL) {
        if (GetLastError() != ERROR_SUCCESS)
            osi_panic("TlsGetValue failed", __FILE__, __LINE__);
        else
            osi_panic("get before set", __FILE__, __LINE__);
    }

    return *tlsKey;
}

static dataT getfundata(Tree *B) {
    dataT *tlsData;

    // Retrieve a data pointer for the current thread.
    tlsData = (dataT *) TlsGetValue(TlsDataIndex);
    if (tlsData == NULL) {
        if (GetLastError() != ERROR_SUCCESS)
            osi_panic("TlsGetValue failed", __FILE__, __LINE__);
        else
            osi_panic("get before set", __FILE__, __LINE__);
    }

    return *tlsData;
}

static void setfunkey(Tree *B, keyT theKey) {
    keyT *tlsKey;

    tlsKey = (keyT *) TlsGetValue(TlsKeyIndex);
    if (tlsKey == NULL) {
        if (GetLastError() != ERROR_SUCCESS)
            osi_panic("TlsGetValue failed", __FILE__, __LINE__);

        tlsKey = malloc(sizeof(keyT));

        if (!TlsSetValue(TlsKeyIndex, tlsKey))
            osi_panic("TlsSetValue failed", __FILE__, __LINE__);
    }

    *tlsKey = theKey;
}

static void setfundata(Tree *B, dataT theData) {
    dataT *tlsData;

    tlsData = (dataT *) TlsGetValue(TlsDataIndex);
    if (tlsData == NULL) {
        if (GetLastError() != ERROR_SUCCESS)
            osi_panic("TlsGetValue failed", __FILE__, __LINE__);

        tlsData = malloc(sizeof(dataT));

        if (!TlsSetValue(TlsDataIndex, tlsData))
            osi_panic("TlsSetValue failed", __FILE__, __LINE__);
    }

    *tlsData = theData;
}


/***********************************************************************\
|	Find leaf node in which data nodes can be found                 |
\***********************************************************************/

/**********************   top level lookup   **********************/
Nptr bplus_Lookup(Tree *B, keyT key)
{
    Nptr	leafNode;

#ifdef DEBUG_BTREE
    StringCbPrintfA(B->message, sizeof(B->message), "LOOKUP:  key %S.\n", key.name);
    OutputDebugString(B->message);
#endif

    setfunkey(B, key);			/* set search key */
    leafNode = descendToLeaf(B, getroot(B));	/* start search from root node */

#ifdef DEBUG_BTREE
    if (leafNode) {
        int         slot;
        Nptr        dataNode;
        dataT       data;

        slot = getSlot(B, leafNode);
        if (slot <= BTERROR)
            return NONODE;

        dataNode = getnode(leafNode, slot);
        data = getdatavalue(dataNode);

        StringCbPrintfA(B->message, sizeof(B->message), "LOOKUP: %S found on page %d value (%d.%d.%d).\n",
                 key.name,
                 getnodenumber(B, leafNode),
                 data.fid.volume,
                 data.fid.vnode,
                 data.fid.unique);
    } else
        StringCbPrintfA(B->message, sizeof(B->message), "LOOKUP: not found!\n");
    OutputDebugString(B->message);
#endif

    return leafNode;
}

/**********************   `recurse' down B+tree   **********************/
static Nptr descendToLeaf(Tree *B, Nptr curr)
{
    int	slot;
    Nptr	findNode;
    Nptr    prev[64];
    int depth;

    memset(prev, 0, sizeof(prev));

    for (depth = 0, slot = getSlot(B, curr); (slot >= 0) && isinternal(curr); depth++, slot = getSlot(B, curr)) {
        prev[depth] = curr;
        if (slot == 0)
            curr = getfirstnode(curr);
        else if (slot > 0)
            curr = getnode(curr, slot);
        else /* BTERROR, BTLOWER, BTUPPER */ {
            curr = NONODE;
            break;
        }
#ifdef DEBUG_BTREE
        if ( !isnode(curr) )
            DebugBreak();
#endif
    }
    if ((slot > 0) && !comparekeys(B)(getfunkey(B), getkey(curr, slot), 0))
        findNode = curr;			/* correct key value found */
    else
        findNode = NONODE;			/* key value not in tree */

    return findNode;
}

/********************   find slot for search key   *********************/
int getSlot(Tree *B, Nptr curr)
{
    int slot, entries;

    entries = numentries(curr);		/* need this if root is ever empty */
    slot = !entries ? 0 : findKey(B, curr, 1, entries);

    return slot;
}


/********************   recursive binary search   **********************/
static int findKey(Tree *B, Nptr curr, int lo, int hi)
{
    int mid, findslot = BTERROR;

    if (hi == lo) {
        findslot = bestMatch(B, curr, lo);		/* recursion base case */

#ifdef DEBUG_BTREE
        if (findslot == BTERROR) {
            StringCbPrintfA(B->message, sizeof(B->message), "FINDKEY: (lo %d hi %d) Bad key ordering on node %d (0x%p)\n",
                    lo, hi, getnodenumber(B, curr), curr);
            osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
        }
#endif
    } else {
        mid = (lo + hi) >> 1;
        switch (findslot = bestMatch(B, curr, mid)) {
        case BTLOWER:				/* check lower half of range */
            if (mid > 1)
                findslot = findKey(B, curr, lo, mid - 1);		/* never in 2-3+trees */
            break;
        case BTUPPER:				/* check upper half of range */
            if (mid < getfanout(B))
                findslot = findKey(B, curr, mid + 1, hi);
            break;
        case BTERROR:
            StringCbPrintfA(B->message, sizeof(B->message), "FINDKEY: (lo %d hi %d) Bad key ordering on node %d (0x%p)\n",
                    lo, hi, getnodenumber(B, curr), curr);
            osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
        }
    }

    if (isleaf(curr) && findslot == 0)
    {
        StringCbPrintfA(B->message, sizeof(B->message), "FINDKEY: (lo %d hi %d) findslot %d is invalid for leaf nodes, bad key ordering on node %d (0x%p)\n",
                lo, hi, findslot, getnodenumber(B, curr), curr);
        osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    }
    return findslot;
}


/************   comparison of key with a target key slot   *************/
static int bestMatch(Tree *B, Nptr curr, int slot)
{
    int diff, comp=2, findslot;

    diff = comparekeys(B)(getfunkey(B), getkey(curr, slot), 0);
    if (diff == 0) {
        findslot = slot;
    } else if (diff < 0) {		/* also check previous slot */
        if (slot == 1) {
            if (isleaf(curr))
                 findslot = BTLOWER;	/* not found in the tree */
            else
                 findslot = 0;
        }
        else if ((comp = comparekeys(B)(getfunkey(B), getkey(curr, slot - 1), 0)) >= 0) {
            findslot = slot - 1;
        } else if (comp < diff) {
            findslot = BTERROR;		/* inconsistent ordering of keys */
#ifdef DEBUG_BTREE
            DebugBreak();
#endif
        } else {
            findslot = BTLOWER;		/* key must be below in node ordering */
        }
    } else {			/* or check following slot */
        if (slot == numentries(curr)) {
            if (isleaf(curr) && numentries(curr) == getfanout(B))
                findslot = BTUPPER;
            else
                findslot = slot;
        } else if ((comp = comparekeys(B)(getfunkey(B), getkey(curr, slot + 1), 0)) < 0) {
            findslot = slot;
        } else if (comp == 0) {
            findslot = slot + 1;
        } else if (comp > diff) {
            findslot = BTERROR;		/* inconsistent ordering of keys */
#ifdef DEBUG_BTREE
            DebugBreak();
#endif
        } else {
            findslot = BTUPPER;		/* key must be above in node ordering */
        }
    }

    if (findslot == BTERROR || isleaf(curr) && findslot == 0)
    {
        StringCbPrintfA(B->message, sizeof(B->message), "BESTMATCH: node %d (0x%p) slot %d diff %d comp %d findslot %d\n",
                getnodenumber(B, curr), curr, slot, diff, comp, findslot);
        osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    }
    return findslot;
}


/***********************************************************************\
|	Insert new data into tree					|
\***********************************************************************/


/**********************   top level insert call   **********************/
void insert(Tree *B, keyT key, dataT data)
{
    Nptr newNode;

#ifdef DEBUG_BTREE
    StringCbPrintfA(B->message, sizeof(B->message), "INSERT:  key %S.\n", key.name);
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
#endif

    setfunkey(B, key);			        /* set insertion key */
    setfundata(B, data);			/* a node containing data */
    setsplitpath(B, NONODE);
    newNode = descendSplit(B, getroot(B));	/* insertion point search from root */
    if (newNode != getsplitpath(B))		/* indicates the root node has split */
        makeNewRoot(B, getroot(B), newNode);
}


/*****************   recurse down and split back up   ******************/
static Nptr
descendSplit(Tree *B, Nptr curr)
{
    Nptr	downNode = NONODE, sibling = NONODE;
    int	slot;

#ifdef DEBUG_BTREE
    if (!isnode(curr))
        DebugBreak();
#endif
    if (!isfull(curr))
        setsplitpath(B, NONODE);
    else if (getsplitpath(B) == NONODE)
        setsplitpath(B, curr);			/* indicates where nodes must split */

    slot = getSlot(B, curr);		        /* is null only if the root is empty */
    if (slot == BTERROR)
        return NONODE;

    if (isleaf(curr)) {
        if (slot == BTLOWER)
            slot = 0;
        else if (slot == BTUPPER)
            slot = getfanout(B);
    }

    if (isinternal(curr)) {	/* continue recursion to leaves */
        if (slot == 0)
            downNode = descendSplit(B, getfirstnode(curr));
        else
            downNode = descendSplit(B, getnode(curr, slot));
    } else if ((slot > 0) && !comparekeys(B)(getfunkey(B), getkey(curr, slot), 0)) {
        if (!(gettreeflags(B) & TREE_FLAG_UNIQUE_KEYS)) {
            downNode = getDataNode(B, getfunkey(B), getfundata(B));
            getdatanext(downNode) = getnode(curr,slot);
            setnode(curr, slot, downNode);
        }
        downNode = NONODE;
        setsplitpath(B, NONODE);
    }
    else
        downNode = getDataNode(B, getfunkey(B), getfundata(B));	/* an insertion takes place */

    if (downNode != NONODE) {		        /* insert only where necessary */
        if (getsplitpath(B) != NONODE)
            sibling = split(B, curr);		/* a sibling node is prepared */
        insertEntry(B, curr, slot, sibling, downNode);
    }

    return sibling;
}

/***************   determine location of inserted key   ****************/
static void
insertEntry(Tree *B, Nptr currNode, int slot, Nptr sibling, Nptr downPtr)
{
    int split, i, j, k, x, y;
    keyT key;

#ifdef DEBUG_BTREE
    StringCbPrintfA(B->message, sizeof(B->message), "INSERT:  slot %d, down node %d.\n", slot, getnodenumber(B, downPtr));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
#endif

    if (sibling == NONODE) {		/* no split occurred */
        placeEntry(B, currNode, slot + 1, downPtr);
    }
    else {				/* split entries between the two */
        if isinternal(currNode) {
            i = 1;
            split = getfanout(B) - getminfanout(B, currNode);
        } else if (isroot(currNode)) {
            /* split the root node and turn it into just a leaf */
            i = 0;
            split = getminfanout(B, currNode);
        } else  {
            i = 0;
            split = getminfanout(B, currNode);
        }
        j = (slot != split ? 1 : 0);
        k = (slot >= split ? 1 : 0);

        /*
         * Move entries from the top half of the current node to
         * to the sibling node.
         * The number of entries to move is dependent upon where
         * the new entry is going to be added in relationship to
         * the split slot. (slots are 1-based).  If order to produce
         * a balanced tree, if the insertion slot is greater than
         * the split we move one less entry as the new entry will
         * be inserted into the sibling.
         *
         * If the node that is being split is an internal node (i != 0)
         * then we move one less entry due to the extra down pointer
         * when the split slot is not equal to the insertion slot
         */
        for (x = split + k + j * i, y = 1; x <= getfanout(B); x++, y++) {
            xferentry(currNode, x, sibling, y);	/* copy entries to sibling */
            clrentry(currNode, x);
            decentries(currNode);
            incentries(sibling);

#ifdef DEBUG_BTREE
            if (getkey(sibling, numentries(sibling)).name == NULL)
                DebugBreak();
#endif
        }
        clrflag(currNode, isFULL);
        if (numentries(currNode) == getminfanout(B, currNode))
            setflag(currNode, FEWEST);		/* never happens in even size nodes */

#ifdef DEBUG_BTREE
        if (numentries(sibling) > getfanout(B))
            DebugBreak();
#endif
        if (numentries(sibling) == getfanout(B))
            setflag(sibling, isFULL);		/* only ever happens in 2-3+trees */

        if (numentries(sibling) > getminfanout(B, sibling))
            clrflag(sibling, FEWEST);

        if (i) {				/* set first pointer of internal node */
            if (j) {
                setfirstnode(sibling, getnode(currNode, split + k));
                decentries(currNode);
                if (numentries(currNode) == getminfanout(B, currNode))
                    setflag(currNode, FEWEST);
                else
                    clrflag(currNode, FEWEST);
            }
            else
                setfirstnode(sibling, downPtr);
        }

        if (j) {				/* insert new entry into correct spot */
            if (k)
                placeEntry(B, sibling, slot - split + 1 - i, downPtr);
            else
                placeEntry(B, currNode, slot + 1, downPtr);

            /* set key separating nodes */
            if (isleaf(sibling))
                key = getkey(sibling, 1);
            else {
                Nptr leaf = getfirstnode(sibling);
                while ( isinternal(leaf) )
                    leaf = getfirstnode(leaf);
                key = getkey(leaf, 1);
            }
            setfunkey(B, key);
        }
        else if (!i)
            placeEntry(B, sibling, 1, downPtr);
    }
}

/************   place key into appropriate node & slot   ***************/
static void
placeEntry(Tree *B, Nptr node, int slot, Nptr downPtr)
{
    int x;

#ifdef DEBUG_BTREE
    if (isfull(node))
        DebugBreak();
#endif

#ifdef DEBUG_BTREE
    if (numentries(node) != 0 && getkey(node, numentries(node)).name == NULL)
        DebugBreak();
#endif
    for (x = numentries(node); x >= slot && x != 0; x--)	/* make room for new entry */
        pushentry(node, x, 1);
    setentry(node, slot, getfunkey(B), downPtr);/* place it in correct slot */

    incentries(node);				/* adjust entry counter */
#ifdef DEBUG_BTREE
	if (getkey(node, numentries(node)).name == NULL)
		DebugBreak();
#endif

    if (numentries(node) == getfanout(B))
        setflag(node, isFULL);
    if (numentries(node) > getminfanout(B, node))
        clrflag(node, FEWEST);
    else
        setflag(node, FEWEST);
}


/*****************   split full node and set flags   *******************/
static Nptr
split(Tree *B, Nptr node)
{
    Nptr sibling;

    sibling = getFreeNode(B);

    setflag(sibling, FEWEST);			/* set up node flags */

    if (isleaf(node)) {
        setflag(sibling, isLEAF);
        setnextnode(sibling, getnextnode(node));/* adjust leaf pointers */
        setnextnode(node, sibling);
    }
    if (getsplitpath(B) == node)
        setsplitpath(B, NONODE);		/* no more splitting needed */

    if (isroot(node))
        clrflag(node, isROOT);

    return sibling;
}


/**********************   build new root node   ************************/
static void
makeNewRoot(Tree *B, Nptr oldRoot, Nptr newNode)
{
    setroot(B, getFreeNode(B));

    setfirstnode(getroot(B), oldRoot);	/* old root becomes new root's child */
    setentry(getroot(B), 1, getfunkey(B), newNode);	/* old root's sibling also */
    incentries(getroot(B));
#ifdef DEBUG_BTREE
    if (numentries(getroot(B)) > getfanout(B))
        DebugBreak();
#endif

    /* the oldRoot's isROOT flag was cleared in split() */
    setflag(getroot(B), isROOT);
    setflag(getroot(B), FEWEST);
    clrflag(getroot(B), isLEAF);
    inctreeheight(B);
}


/***********************************************************************\
|	Delete data from tree						|
\***********************************************************************/

/**********************   top level delete call   **********************\
|
|	The recursive call for deletion carries 5 additional parameters
|	which may be needed to rebalance the B+tree when removing the key.
|	These parameters are:
|		1. immediate left neighbor of the current node
|		2. immediate right neighbor of the current node
|		3. the anchor of the current node and left neighbor
|		4. the anchor of the current node and right neighbor
|		5. the parent of the current node
|
|	All of these parameters are simple to calculate going along the
|	recursive path to the leaf nodes and the point of key deletion.
|	At that time, the algorithm determines which node manipulations
|	are most efficient, that is, cause the least rearranging of data,
|	and minimize the need for non-local key manipulation.
|
\***********************************************************************/
void delete(Tree *B, keyT key)
{
    Nptr newNode;

#ifdef DEBUG_BTREE
    StringCbPrintfA(B->message, sizeof(B->message), "DELETE:  key %S.\n", key.name);
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
#endif

    setfunkey(B, key);			/* set deletion key */
    setmergepath(B, NONODE);
    newNode = descendBalance(B, getroot(B), NONODE, NONODE, NONODE, NONODE, NONODE);
    if (isnode(newNode)) {
#ifdef DEBUG_BTREE
        StringCbPrintfA(B->message, sizeof(B->message), "DELETE: collapsing node %d", getnodenumber(B, newNode));
        osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
#endif
        collapseRoot(B, getroot(B), newNode);	/* remove root when superfluous */
    }
}


/**********************   remove old root node   ***********************/
static void
collapseRoot(Tree *B, Nptr oldRoot, Nptr newRoot)
{

#ifdef DEBUG_BTREE
    StringCbPrintfA(B->message, sizeof(B->message), "COLLAPSE:  old %d, new %d.\n", getnodenumber(B, oldRoot), getnodenumber(B, newRoot));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    showNode(B, "collapseRoot oldRoot", oldRoot);
    showNode(B, "collapseRoot newRoot", newRoot);
#endif

    setroot(B, newRoot);
    setflag(newRoot, isROOT);
    clrflag(newRoot, FEWEST);
    putFreeNode(B, oldRoot);
    dectreeheight(B);			/* the height of the tree decreases */
}


/****************   recurse down and balance back up   *****************/
static Nptr
descendBalance(Tree *B, Nptr curr, Nptr left, Nptr right, Nptr lAnc, Nptr rAnc, Nptr parent)
{
    Nptr	newMe=NONODE, myLeft=NONODE, myRight=NONODE, lAnchor=NONODE, rAnchor=NONODE, newNode=NONODE;
    int	slot = 0, notleft = 0, notright = 0, fewleft = 0, fewright = 0, test = 0;

#ifdef DEBUG_BTREE
    StringCbPrintfA(B->message, sizeof(B->message), "descendBalance curr %d, left %d, right %d, lAnc %d, rAnc %d, parent %d\n",
             curr ? getnodenumber(B, curr) : -1,
             left ? getnodenumber(B, left) : -1,
             right ? getnodenumber(B, right) : -1,
             lAnc ? getnodenumber(B, lAnc) : -1,
             rAnc ? getnodenumber(B, rAnc) : -1,
             parent ? getnodenumber(B, parent) : -1);
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
#endif

    if (!isfew(curr))
        setmergepath(B,NONODE);
    else if (getmergepath(B) == NONODE)
        setmergepath(B, curr);		/* mark which nodes may need rebalancing */

    slot = getSlot(B, curr);
    if (slot == BTERROR)
        return NONODE;

    if (isleaf(curr)) {
        if (slot == BTLOWER)
            slot = 0;
        else if (slot == BTUPPER)
            slot = getfanout(B);
    }

    if (isinternal(curr)) 	/* set up next recursion call's parameters */
    {
        if (slot == 0) {
            newNode = getfirstnode(curr);
            myLeft = !isnode(left) ? NONODE : getlastnode(left);
            lAnchor = lAnc;
        }
        else {
            newNode = getnode(curr, slot);
            if (slot == 1)
                myLeft = getfirstnode(curr);
            else
                myLeft = getnode(curr, slot - 1);
            lAnchor = curr;
        }

        if (slot == numentries(curr)) {
            myRight = !isnode(right) ? NONODE : getfirstnode(right);
            rAnchor = rAnc;
        }
        else {
            myRight = getnode(curr, slot + 1);
            rAnchor = curr;
        }
        newMe = descendBalance(B, newNode, myLeft, myRight, lAnchor, rAnchor, curr);
    }
    else if ((slot > 0) && !comparekeys(B)(getfunkey(B), getkey(curr, slot), 0))
    {
        Nptr        next;
        int         exact = 0;
        int         count = 0;

        newNode = getnode(curr, slot);
        next = getdatanext(newNode);

        /*
         * We only delete exact matches.
         */
        if (!comparekeys(B)(getfunkey(B), getdatakey(newNode), EXACT_MATCH)) {
            /* exact match, free the first entry */
            setnode(curr, slot, next);

            if (next == NONODE) {
                /* delete this key as there are no more data values */
                newMe = newNode;
            } else {
                /* otherwise, there are more and we leave the key in place */
                setnode(curr, slot, next);
                putFreeNode(B, newNode);

                /* but do not delete the key */
                newMe = NONODE;
                setmergepath(B, NONODE);
            }
        } else if (next == NONODE) {
            /*
             * we didn't find an exact match and there are no more
             * choices.  so we leave it alone and remove nothing.
             */
            newMe = NONODE;
            setmergepath(B, NONODE);
        } else {
            /* The first data node doesn't match but there are other
             * options.  So we must determine if any of the next nodes
             * are the one we are looking for.
             */
            Nptr prev = newNode;

            while ( next ) {
                if (!comparekeys(B)(getfunkey(B), getdatakey(next), EXACT_MATCH)) {
                    /* we found the one to delete */
                    getdatanext(prev) = getdatanext(next);
                    putFreeNode(B, next);
                    break;
                }
                prev = next;
                next = getdatanext(next);
            }

            /* do not delete the key */
            newMe = NONODE;
            setmergepath(B, NONODE);
        }
    }
    else
    {
        newMe = NONODE;		/* no deletion possible, key not found */
        setmergepath(B, NONODE);
    }

/*****************   rebalancing tree after deletion   *****************\
|
|	The simplest B+tree rebalancing consists of the following rules.
|
|	If a node underflows:
|	CASE 1 check if it is the root, and collapse it if it is,
|	CASE 2 otherwise, check if both of its neighbors are minimum
|	    sized and merge the underflowing node with one of them,
|	CASE 3 otherwise shift surplus entries to the underflowing node.
|
|	The choice of which neighbor to use is optional.  However, the
|	rebalancing rules that follow also ensure whenever possible
|	that the merges and shifts which do occur use a neighbor whose
|	anchor is the parent of the underflowing node.
|
|	Cases 3, 4, 5 below are more an optimization than a requirement,
|	and can be omitted, with a change of the action value in case 6,
|	which actually corresponds to the third case described above.
|
\***********************************************************************/

    /* begin deletion, working upwards from leaves */

    if (newMe != NONODE) {	/* this node removal doesn't consider duplicates */
#ifdef DEBUG_BTREE
        StringCbPrintfA(B->message, sizeof(B->message), "descendBalance DELETE:  slot %d, node %d.\n", slot, getnodenumber(B, curr));
        osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
#endif

        removeEntry(B, curr, slot + (newMe != newNode));	/* removes one of two */

#ifdef DEBUG_BTREE
        showNode(B, "descendBalance curr", curr);
#endif
    }

    if (getmergepath(B) == NONODE)
        newNode = NONODE;
    else {		/* tree rebalancing rules for node merges and shifts */
        notleft = !isnode(left);
        notright = !isnode(right);
        if (!notleft)
            fewleft = isfew(left);		/* only used when defined */
        if (!notright)
            fewright = isfew(right);

        /* CASE 1:  prepare root node (curr) for removal */
        if (notleft && notright) {
            test = isleaf(curr);		/* check if B+tree has become empty */
            newNode = test ? NONODE : getfirstnode(curr);
        }
        /* CASE 2:  the merging of two nodes is a must */
        else if ((notleft || fewleft) && (notright || fewright)) {
            test = (lAnc != parent);
            newNode = test ? merge(B, curr, right, rAnc) : merge(B, left, curr, lAnc);
        }
        /* CASE 3: choose the better of a merge or a shift */
        else if (!notleft && fewleft && !notright && !fewright) {
            test = (rAnc != parent) && (curr == getmergepath(B));
            newNode = test ? merge(B, left, curr, lAnc) : shift(B, curr, right, rAnc);
        }
        /* CASE 4: also choose between a merge or a shift */
        else if (!notleft && !fewleft && !notright && fewright) {
            test = !(lAnc == parent) && (curr == getmergepath(B));
            newNode = test ? merge(B, curr, right, rAnc) : shift(B, left, curr, lAnc);
        }
        /* CASE 5: choose the more effective of two shifts */
        else if (lAnc == rAnc) { 		/* => both anchors are the parent */
            test = (numentries(left) <= numentries(right));
            newNode = test ? shift(B, curr, right, rAnc) : shift(B, left, curr, lAnc);
        }
        /* CASE 6: choose the shift with more local effect */
        else {				/* if omitting cases 3,4,5 use below */
            test = (lAnc == parent);		/* test = (!notleft && !fewleft); */
            newNode = test ? shift(B, left, curr, lAnc) : shift(B, curr, right, rAnc);
        }
    }

#ifdef DEBUG_BTREE
    StringCbPrintfA(B->message, sizeof(B->message), "descendBalance returns %d\n", getnodenumber(B, newNode));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
#endif
    return newNode;
}


/****************   remove key and pointer from node   *****************/
static void
removeEntry(Tree *B, Nptr curr, int slot)
{
    int x;

    putFreeNode(B, getnode(curr, slot));	/* return deleted node to free list */
    for (x = slot; x < numentries(curr); x++)
        pullentry(curr, x, 1);		        /* adjust node with removed key */
    decentries(curr);
    clrflag(curr, isFULL);		        /* keep flag information up to date */
    if (numentries(curr) > getminfanout(B, curr))
        clrflag(curr, FEWEST);
    else
        setflag(curr, FEWEST);
}


/*******   merge a node pair & set emptied node up for removal   *******/
static Nptr
merge(Tree *B, Nptr left, Nptr right, Nptr anchor)
{
    int	x, y, z;

#ifdef DEBUG_BTREE
    StringCbPrintfA(B->message, sizeof(B->message), "MERGE:  left %d, right %d.\n", getnodenumber(B, left), getnodenumber(B, right));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    showNode(B, "pre-merge anchor", anchor);
    showNode(B, "pre-merge left", left);
    showNode(B, "pre-merge right", right);
#endif

    if (isinternal(left)) {
        incentries(left);			/* copy key separating the nodes */
#ifdef DEBUG_BTREE
        if (numentries(left) > getfanout(B))
            DebugBreak();
#endif
        setfunkey(B, getkey(right, 1));	/* defined but maybe just deleted */
        z = getSlot(B, anchor);		/* needs the just calculated key */
        if (z <= BTERROR)
            return NONODE;
        setfunkey(B, getkey(anchor, z));	/* set slot to delete in anchor */
        setentry(left, numentries(left), getfunkey(B), getfirstnode(right));
    }
    else
        setnextnode(left, getnextnode(right));

    for (x = numentries(left) + 1, y = 1; y <= numentries(right); x++, y++) {
        incentries(left);
#ifdef DEBUG_BTREE
        if (numentries(left) > getfanout(B))
            DebugBreak();
#endif
        xferentry(right, y, left, x);	/* transfer entries to left node */
    }
    clearentries(right);

    if (numentries(left) > getminfanout(B, left))
        clrflag(left, FEWEST);
    if (numentries(left) == getfanout(B))
        setflag(left, isFULL);		/* never happens in even size nodes */

    if (getmergepath(B) == left || getmergepath(B) == right)
        setmergepath(B, NONODE);		/* indicate rebalancing is complete */

#ifdef DEBUG_BTREE
    showNode(B, "post-merge anchor", anchor);
    showNode(B, "post-merge left", left);
    showNode(B, "post-merge right", right);
#endif
    return right;
}


/******   shift entries in a node pair & adjust anchor key value   *****/
static Nptr
shift(Tree *B, Nptr left, Nptr right, Nptr anchor)
{
    int	i, x, y, z;

#ifdef DEBUG_BTREE
    StringCbPrintfA(B->message, sizeof(B->message), "SHIFT:  left %d, right %d, anchor %d.\n",
             getnodenumber(B, left),
             getnodenumber(B, right),
             getnodenumber(B, anchor));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    showNode(B, "pre-shift anchor", anchor);
    showNode(B, "pre-shift left", left);
    showNode(B, "pre-shift right", right);
#endif

    i = isinternal(left);

    if (numentries(left) < numentries(right)) {	/* shift entries to left */
        y = (numentries(right) - numentries(left)) >> 1;
        x = numentries(left) + y;
        setfunkey(B, getkey(right, y + 1 - i));	/* set new anchor key value */
        z = getSlot(B, anchor);			/* find slot in anchor node */
        if (z <= BTERROR)
            return NONODE;
#ifdef DEBUG_BTREE
        if (z == 0 && !isroot(anchor))
            DebugBreak();
#endif
        if (i) {					/* move out old anchor value */
            decentries(right);			/* adjust for shifting anchor */
            incentries(left);
#ifdef DEBUG_BTREE
            if (numentries(left) > getfanout(B))
                DebugBreak();
#endif
            setentry(left, numentries(left), getkey(anchor, z), getfirstnode(right));
            setfirstnode(right, getnode(right, y + 1 - i));
        }
        clrflag(right, isFULL);
        setkey(anchor, z, getfunkey(B));		/* set new anchor value */
        for (z = y, y -= i; y > 0; y--, x--) {
            decentries(right);			/* adjust entry count */
            incentries(left);
#ifdef DEBUG_BTREE
            if (numentries(left) > getfanout(B))
                DebugBreak();
#endif
            xferentry(right, y, left, x);		/* transfer entries over */
        }

        for (x = 1; x <= numentries(right); x++)	/* adjust reduced node */
            pullentry(right, x, z);
    }
    else if (numentries(left) > numentries(right)) {					/* shift entries to right */
        y = (numentries(left) - numentries(right)) >> 1;
        x = numentries(left) - y + 1;

        for (z = numentries(right); z > 0; z--)	/* adjust increased node */
            pushentry(right, z, y);

        setfunkey(B, getkey(left, x));			/* set new anchor key value */
        z = getSlot(B, anchor);
        if (z <= BTERROR)
            return NONODE;
        z += 1;

        if (i) {
            decentries(left);
            incentries(right);
#ifdef DEBUG_BTREE
            if (numentries(right) > getfanout(B))
                DebugBreak();
#endif
            setentry(right, y, getkey(anchor, z), getfirstnode(right));
            setfirstnode(right, getnode(left, x));
        }
        clrflag(left, isFULL);
        setkey(anchor, z, getfunkey(B));
        for (x = numentries(left) + i, y -= i; y > 0; y--, x--) {
            decentries(left);
            incentries(right);
#ifdef DEBUG_BTREE
            if (numentries(right) > getfanout(B))
                DebugBreak();
#endif
            xferentry(left, x, right, y);		/* transfer entries over */
            clrentry(left, x);
        }
    }
#ifdef DEBUG_BTREE
    else {
        DebugBreak();
    }
#endif /* DEBUG_BTREE */

    if (numentries(left) > getminfanout(B, left))		/* adjust node flags */
        clrflag(left, FEWEST);			/* never happens in 2-3+trees */
    else
        setflag(left, FEWEST);
    if (numentries(right) > getminfanout(B, right))
        clrflag(right, FEWEST);			/* never happens in 2-3+trees */
    else
        setflag(right, FEWEST);
    setmergepath(B, NONODE);

#ifdef DEBUG_BTREE
    StringCbPrintfA(B->message, sizeof(B->message), "SHIFT:  left %d, right %d.\n", getnodenumber(B, left), getnodenumber(B, right));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    showNode(B, "post-shift anchor", anchor);
    showNode(B, "post-shift left", left);
    showNode(B, "post-shift right", right);
#endif

    return NONODE;
}


static void
_clrentry(Nptr node, int entry)
{
    if (getkey(node,entry).name != NULL) {
        free(getkey(node,entry).name);
        getkey(node,entry).name = NULL;
    }
    getnode(node,entry) = NONODE;
}

static void
_pushentry(Nptr node, int entry, int offset)
{
    if (getkey(node,entry + offset).name != NULL)
        free(getkey(node,entry + offset).name);
#ifdef DEBUG_BTREE
    if (entry == 0)
        DebugBreak();
#endif
    getkey(node,entry + offset).name = cm_NormStrDup(getkey(node,entry).name);
#ifdef DEBUG_BTREE
    if ( getnode(node, entry) == NONODE )
        DebugBreak();
#endif
    getnode(node,entry + offset) = getnode(node,entry);
}

static void
_pullentry(Nptr node, int entry, int offset)
{
    if (getkey(node,entry).name != NULL)
        free(getkey(node,entry).name);
    getkey(node,entry).name = cm_NormStrDup(getkey(node,entry + offset).name);
#ifdef DEBUG_BTREE
    if ( getnode(node, entry + offset) == NONODE )
        DebugBreak();
#endif
    getnode(node,entry) = getnode(node,entry + offset);
}

static void
_xferentry(Nptr srcNode, int srcEntry, Nptr destNode, int destEntry)
{
    if (getkey(destNode,destEntry).name != NULL)
        free(getkey(destNode,destEntry).name);
    getkey(destNode,destEntry).name = cm_NormStrDup(getkey(srcNode,srcEntry).name);
#ifdef DEBUG_BTREE
    if ( getnode(srcNode, srcEntry) == NONODE )
        DebugBreak();
#endif
    getnode(destNode,destEntry) = getnode(srcNode,srcEntry);
}

static void
_setentry(Nptr node, int entry, keyT key, Nptr downNode)
{
    if (getkey(node,entry).name != NULL)
        free(getkey(node,entry).name);
    getkey(node,entry).name = cm_NormStrDup(key.name);
#ifdef DEBUG_BTREE
    if ( downNode == NONODE )
        DebugBreak();
#endif
    getnode(node,entry) = downNode;
}


/***********************************************************************\
|	Empty Node Utilities						|
\***********************************************************************/

/*********************   Set up initial pool of free nodes   ***********/
static void
initFreeNodePool(Tree *B, int quantity)
{
    int	i;
    Nptr	n, p;

    setfirstallnode(B, NONODE);
    setfirstfreenode(B, NONODE);

    for (i = 0, p = NONODE; i < quantity; i++) {
        n = malloc(sizeof(*n));
        memset(n, 0, sizeof(*n));
        setnodenumber(B,n,i);

        if (p) {
            setnextnode(p, n);		/* insert node into free node list */
            setallnode(p, n);
        } else {
            setfirstfreenode(B, n);
            setfirstallnode(B, n);
        }
        p = n;
    }
    setnextnode(p, NONODE);		/* indicates end of free node list */
    setallnode(p, NONODE);              /* indicates end of all node list */

    setpoolsize(B, quantity);
}


/*******************   Cleanup Free Node Pool **************************/

static void
cleanupNodePool(Tree *B)
{
    int i, j;
    Nptr node, next;

    for ( i=0, node = getfirstallnode(B); node != NONODE && i<getpoolsize(B); node = next, i++ ) {
        if (isdata(node)) {
            if ( getdatakey(node).name ) {
                free(getdatakey(node).name);
                getdatakey(node).name = NULL;
            }
            if ( getdatavalue(node).cname ) {
                free(getdatavalue(node).cname);
                getdatavalue(node).cname = NULL;
            }
            if ( getdatavalue(node).fsname ) {
                free(getdatavalue(node).fsname);
                getdatavalue(node).fsname = NULL;
            }
        } else { /* data node */
            for ( j=1; j<=getfanout(B); j++ ) {
                if (getkey(node, j).name)
                    free(getkey(node, j).name);
            }
        }
        next = getallnode(node);
        free(node);
    }
}

/**************   take a free B+tree node from the pool   **************/
static Nptr
getFreeNode(Tree *B)
{
    Nptr newNode = getfirstfreenode(B);

    if (newNode != NONODE) {
        setfirstfreenode(B, getnextnode(newNode));	/* adjust free node list */
        setnextnode(newNode, NONODE);		        /* remove node from list */
    }
    else {
        newNode = malloc(sizeof(*newNode));
        memset(newNode, 0, sizeof(*newNode));

        setallnode(newNode, getfirstallnode(B));
        setfirstallnode(B, newNode);
        setnodenumber(B, newNode, getpoolsize(B));
        setpoolsize(B, getpoolsize(B) + 1);
    }

    clearflags(newNode);                        /* Sets MAGIC */
    return newNode;
}


/*************   return a deleted B+tree node to the pool   ************/
static void
putFreeNode(Tree *B, Nptr node)
{
    int i;

    if (isntnode(node))
        return;

    if (isdata(node)) {
        if ( getdatakey(node).name )
            free(getdatakey(node).name);
	if ( getdatavalue(node).cname )
	    free(getdatavalue(node).cname);
        if ( getdatavalue(node).fsname )
            free(getdatavalue(node).fsname);
    } else {    /* data node */
        for ( i=1; i<=getfanout(B); i++ ) {
            if (getkey(node, i).name)
                free(getkey(node, i).name);
        }
    }

    /* free nodes do not have MAGIC set */
    memset(&nAdr(node), 0, sizeof(nAdr(node)));
    setnextnode(node, getfirstfreenode(B));	/* add node to list */
    setfirstfreenode(B, node);			/* set it to be list head */
}


/*******   fill a free data node with a key and associated data   ******/
static Nptr
getDataNode(Tree *B, keyT key, dataT data)
{
    Nptr	newNode = getFreeNode(B);

    setflag(newNode, isDATA);
    getdatakey(newNode).name = cm_NormStrDup(key.name);
    getdatavalue(newNode) = data;
    getdatanext(newNode) = NONODE;

    return newNode;
}


#ifdef DEBUG_BTREE
/***********************************************************************\
|	B+tree Printing Utilities					|
\***********************************************************************/

/***********************   B+tree node printer   ***********************/
void showNode(Tree *B, const char * where, Nptr n)
{
    int x;

    StringCbPrintfA(B->message, sizeof(B->message), "-  --  --  --  --  --  --  --  --  --  --  --  -\n");
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "| %-20s                        |\n", where);
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "| node %6d                 ", getnodenumber(B, n));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "  magic    %4x  |\n", getmagic(n));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "-  --  --  --  --  --  --  --  --  --  --  --  -\n");
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "| flags   %1d%1d%1d%1d ", isfew(n), isfull(n), isroot(n), isleaf(n));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "| keys = %5d ", numentries(n));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "| node = %6d  |\n", getnodenumber(B, getfirstnode(n)));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    for (x = 1; x <= numentries(n); x++) {
        StringCbPrintfA(B->message, sizeof(B->message), "| entry %6d ", x);
        osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
        StringCbPrintfA(B->message, sizeof(B->message), "| key = %6S ", getkey(n, x).name);
        osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
        StringCbPrintfA(B->message, sizeof(B->message), "| node = %6d  |\n", getnodenumber(B, getnode(n, x)));
        osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    }
    StringCbPrintfA(B->message, sizeof(B->message), "-  --  --  --  --  --  --  --  --  --  --  --  -\n");
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
}

/******************   B+tree class variable printer   ******************/
void showBtree(Tree *B)
{
    StringCbPrintfA(B->message, sizeof(B->message), "-  --  --  --  --  --  -\n");
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "|  B+tree  %10p  |\n", (void *) B);
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "-  --  --  --  --  --  -\n");
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "|  root        %6d  |\n", getnodenumber(B, getroot(B)));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "|  leaf        %6d  |\n", getnodenumber(B, getleaf(B)));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "|  fanout         %3d  |\n", getfanout(B) + 1);
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "|  minfanout      %3d  |\n", getminfanout(B, getroot(B)) + 1);
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "|  height         %3d  |\n", gettreeheight(B));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "|  freenode    %6d  |\n", getnodenumber(B, getfirstfreenode(B)));
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "|  theKey      %6s  |\n", getfunkey(B).name);
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "|  theData     %s (%d.%d.%d) |\n", getfundata(B).fsname, getfundata(B).fid.volume,
             getfundata(B).fid.vnode, getfundata(B).fid.unique);
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
    StringCbPrintfA(B->message, sizeof(B->message), "-  --  --  --  --  --  -\n");
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
}

void
listBtreeNodes(Tree *B, const char * parent_desc, Nptr node)
{
    int i;
    char thisnode[64];
    dataT data;

    if (isntnode(node)) {
        StringCbPrintfA(B->message, sizeof(B->message), "%s - NoNode!!!\n");
        osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
        return;
    }

    if (!isnode(node))
    {
        data = getdatavalue(node);
        StringCbPrintfA(B->message, sizeof(B->message), "%s - data node %d (%d.%d.%d)\n",
                 parent_desc, getnodenumber(B, node),
                 data.fid.volume, data.fid.vnode, data.fid.unique);
        osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
        return;
    } else
        showNode(B, parent_desc, node);

    if ( isinternal(node) || isroot(node) ) {
        StringCbPrintfA(thisnode, sizeof(thisnode), "parent %6d", getnodenumber(B , node));

        osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
        for ( i= isinternal(node) ? 0 : 1; i <= numentries(node); i++ ) {
            listBtreeNodes(B, thisnode, i == 0 ? getfirstnode(node) : getnode(node, i));
        }
    }
}

/***********************   B+tree data printer   ***********************/
void
listBtreeValues(Tree *B, Nptr n, int num)
{
    int slot;
    keyT prev = {L""};
    dataT data;

    for (slot = 1; (n != NONODE) && num && numentries(n); num--) {
        if (comparekeys(B)(getkey(n, slot),prev, 0) < 0) {
            StringCbPrintfA(B->message, sizeof(B->message), "BOMB %8s\n", getkey(n, slot).name);
            osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
            DebugBreak();
        }
        prev = getkey(n, slot);
        data = getdatavalue(getnode(n, slot));
        StringCbPrintfA(B->message, sizeof(B->message), "%8S (%d.%d.%d)\n",
                prev.name, data.fid.volume, data.fid.vnode, data.fid.unique);
        osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
        if (++slot > numentries(n))
            n = getnextnode(n), slot = 1;
    }
    StringCbPrintfA(B->message, sizeof(B->message), "\n\n");
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
}

/********************   entire B+tree data printer   *******************/
void
listAllBtreeValues(Tree *B)
{
    listBtreeValues(B, getleaf(B), BTERROR);
}
#endif /* DEBUG_BTREE */

void
findAllBtreeValues(Tree *B)
{
    int num = -1;
    Nptr n = getleaf(B), l;
    int slot;
    keyT prev = {L""};

    for (slot = 1; (n != NONODE) && num && numentries(n); num--) {
        if (comparekeys(B)(getkey(n, slot),prev, 0) < 0) {
            StringCbPrintfA(B->message, sizeof(B->message),"BOMB %8s\n", getkey(n, slot).name);
            osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
#ifdef DEBUG_BTREE
            DebugBreak();
#endif
        }
        prev = getkey(n, slot);
        l = bplus_Lookup(B, prev);
        if ( l != n ){
            if (l == NONODE)
                StringCbPrintfA(B->message, sizeof(B->message),"BOMB %8S cannot be found\n", prev.name);
            else
                StringCbPrintfA(B->message, sizeof(B->message),"BOMB lookup(%8S) finds wrong node\n", prev.name);
            osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, B->message));
#ifdef DEBUG_BTREE
            DebugBreak();
#endif
        }

        if (++slot > numentries(n))
            n = getnextnode(n), slot = 1;
    }
}

/*
 * the return must be -1, 0, or 1.  stricmp() in MSVC 8.0
 * does not return only those values.
 *
 * the sorting of the tree is by case insensitive sort order
 * therefore, unless the strings actually match via a case
 * insensitive search do we want to perform the case sensitive
 * match.  Otherwise, the search order might be considered
 * to be inconsistent when the EXACT_MATCH flag is set.
 */
int
cm_BPlusCompareNormalizedKeys(keyT key1, keyT key2, int flags)
{
    int comp;

    comp = cm_NormStrCmpI(key1.name, key2.name);
    if (comp == 0 && (flags & EXACT_MATCH))
        comp = cm_NormStrCmp(key1.name, key2.name);
    return (comp < 0 ? -1 : (comp > 0 ? 1 : 0));
}

int
cm_BPlusDirLookupOriginalName(cm_dirOp_t * op, clientchar_t *centry,
                              fschar_t **fsnameRetp)
{
    int rc = EINVAL;
    keyT key = {NULL};
    Nptr leafNode = NONODE;
    LARGE_INTEGER start, end;
    fschar_t * fsname = NULL;
    normchar_t * entry = NULL;

    if (op->scp->dirBplus == NULL ||
        op->dataVersion > op->scp->dirDataVersion) {
        rc = EINVAL;
        goto done;
    }

    entry = cm_ClientStringToNormStringAlloc(centry, -1, NULL);
    if (!entry) {
        rc = EINVAL;
        goto done;
    }
    key.name = entry;

    lock_AssertAny(&op->scp->dirlock);

    QueryPerformanceCounter(&start);

    leafNode = bplus_Lookup(op->scp->dirBplus, key);
    if (leafNode != NONODE) {
        int         slot;
        Nptr        firstDataNode, dataNode, nextDataNode;
        int         exact = 0;
        int         count = 0;

        /* Found a leaf that matches the key via a case-insensitive
         * match.  There may be one or more data nodes that match.
         * If we have an exact match, return that.
         * If we have an ambiguous match, return an error.
         * If we have only one inexact match, return that.
         */
        slot = getSlot(op->scp->dirBplus, leafNode);
        if (slot <= BTERROR) {
            op->scp->dirDataVersion = CM_SCACHE_VERSION_BAD;
            rc = (slot == BTERROR ? EINVAL : ENOENT);
            goto done;
        }
        firstDataNode = getnode(leafNode, slot);

        for ( dataNode = firstDataNode; dataNode; dataNode = nextDataNode) {
            count++;
            if (!comparekeys(op->scp->dirBplus)(key, getdatakey(dataNode), EXACT_MATCH) ) {
                exact = 1;
                break;
            }
            nextDataNode = getdatanext(dataNode);
        }

        if (exact) {
            fsname = getdatavalue(dataNode).fsname;
            rc = 0;
            bplus_lookup_hits++;
        } else if (count == 1) {
            fsname = getdatavalue(firstDataNode).fsname;
            rc = CM_ERROR_INEXACT_MATCH;
            bplus_lookup_hits_inexact++;
        } else {
            rc = CM_ERROR_AMBIGUOUS_FILENAME;
            bplus_lookup_ambiguous++;
        }
    } else {
        rc = ENOENT;
        bplus_lookup_misses++;
    }

    if (fsname)
        *fsnameRetp = cm_FsStrDup(fsname);

    QueryPerformanceCounter(&end);

    bplus_lookup_time += (end.QuadPart - start.QuadPart);

  done:
    if (entry)
        free(entry);

    return rc;

}

/* Look up a file name in directory.

   On entry:
       op->scp->dirlock is read locked

   On exit:
       op->scp->dirlock is read locked
*/
int
cm_BPlusDirLookup(cm_dirOp_t * op, clientchar_t * centry, cm_fid_t * cfid)
{
    int rc = EINVAL;
    normchar_t * entry = NULL;
    keyT key = {NULL};
    Nptr leafNode = NONODE;
    LARGE_INTEGER start, end;

    if (op->scp->dirBplus == NULL ||
        op->dataVersion > op->scp->dirDataVersion) {
        rc = EINVAL;
        goto done;
    }

    entry = cm_ClientStringToNormStringAlloc(centry, -1, NULL);
    if (!entry) {
        rc = EINVAL;
        goto done;
    }
    key.name = entry;

    lock_AssertAny(&op->scp->dirlock);

    QueryPerformanceCounter(&start);

    leafNode = bplus_Lookup(op->scp->dirBplus, key);
    if (leafNode != NONODE) {
        int         slot;
        Nptr        firstDataNode, dataNode, nextDataNode;
        int         exact = 0;
        int         count = 0;

        /* Found a leaf that matches the key via a case-insensitive
         * match.  There may be one or more data nodes that match.
         * If we have an exact match, return that.
         * If we have an ambiguous match, return an error.
         * If we have only one inexact match, return that.
         */
        slot = getSlot(op->scp->dirBplus, leafNode);
        if (slot <= BTERROR) {
            op->scp->dirDataVersion = 0;
            rc = (slot == BTERROR ? EINVAL : ENOENT);
            goto done;
        }
        firstDataNode = getnode(leafNode, slot);

        for ( dataNode = firstDataNode; dataNode; dataNode = nextDataNode) {
            count++;
            if (!comparekeys(op->scp->dirBplus)(key, getdatakey(dataNode), EXACT_MATCH) ) {
                exact = 1;
                break;
            }
            nextDataNode = getdatanext(dataNode);
        }

        if (exact) {
            *cfid = getdatavalue(dataNode).fid;
            rc = 0;
            bplus_lookup_hits++;
        } else if (count == 1) {
            *cfid = getdatavalue(firstDataNode).fid;
            rc = CM_ERROR_INEXACT_MATCH;
            bplus_lookup_hits_inexact++;
        } else {
            rc = CM_ERROR_AMBIGUOUS_FILENAME;
            bplus_lookup_ambiguous++;
        }
    } else {
            rc = ENOENT;
        bplus_lookup_misses++;
    }

    QueryPerformanceCounter(&end);

    bplus_lookup_time += (end.QuadPart - start.QuadPart);

  done:
    if (entry)
        free(entry);

    return rc;
}


/*
   On entry:
       op->scp->dirlock is write locked

   On exit:
       op->scp->dirlock is write locked
*/
long cm_BPlusDirCreateEntry(cm_dirOp_t * op, clientchar_t * entry, cm_fid_t * cfid)
{
    long rc = 0;
    keyT key = {NULL};
    dataT  data;
    LARGE_INTEGER start, end;
    normchar_t * normalizedName = NULL;

    if (op->scp->dirBplus == NULL ||
        op->dataVersion != op->scp->dirDataVersion) {
        rc = EINVAL;
        goto done;
    }

    normalizedName = cm_ClientStringToNormStringAlloc(entry, -1, NULL);
    if (!normalizedName) {
        rc = EINVAL;
        goto done;
    }
    key.name = normalizedName;

    lock_AssertWrite(&op->scp->dirlock);

    cm_SetFid(&data.fid, cfid->cell, cfid->volume, cfid->vnode, cfid->unique);
    data.cname = cm_ClientStrDup(entry);
    data.fsname = cm_ClientStringToFsStringAlloc(entry, -1, NULL);
    data.shortform = FALSE;

    QueryPerformanceCounter(&start);
    bplus_create_entry++;

    insert(op->scp->dirBplus, key, data);

    if (cm_shortNames && !cm_Is8Dot3(entry)) {
        cm_dirFid_t dfid;
        clientchar_t wshortName[13];

        dfid.vnode = htonl(data.fid.vnode);
        dfid.unique = htonl(data.fid.unique);

        cm_Gen8Dot3NameIntW(entry, &dfid, wshortName, NULL);

        key.name = wshortName;

        data.cname = cm_ClientStrDup(entry);
        data.fsname = cm_ClientStringToFsStringAlloc(entry, -1, NULL);
        data.shortform = TRUE;

        insert(op->scp->dirBplus, key, data);
    }

    QueryPerformanceCounter(&end);

    bplus_create_time += (end.QuadPart - start.QuadPart);

  done:

    if (normalizedName != NULL)
        free(normalizedName);

    return rc;
}

/*
   On entry:
       op->scp->dirlock is write locked

   On exit:
       op->scp->dirlock is write locked
*/
int  cm_BPlusDirDeleteEntry(cm_dirOp_t * op, clientchar_t *centry)
{
    long rc = 0;
    keyT key = {NULL};
    Nptr leafNode = NONODE;
    LARGE_INTEGER start, end;
    normchar_t * normalizedEntry = NULL;

    if (op->scp->dirBplus == NULL ||
        op->dataVersion != op->scp->dirDataVersion) {
        rc = EINVAL;
        goto done;
    }

    normalizedEntry = cm_ClientStringToNormStringAlloc(centry, -1, NULL);
    if (!normalizedEntry) {
        rc = EINVAL;
        goto done;
    }
    key.name = normalizedEntry;

    lock_AssertWrite(&op->scp->dirlock);

    QueryPerformanceCounter(&start);

    bplus_remove_entry++;

    if (op->scp->dirBplus) {
        if (!cm_Is8Dot3(centry)) {
            cm_dirFid_t dfid;
            cm_fid_t fid;
            clientchar_t shortName[13];

            leafNode = bplus_Lookup(op->scp->dirBplus, key);
            if (leafNode != NONODE) {
                int         slot;
                Nptr        firstDataNode, dataNode, nextDataNode;
                int         exact = 0;
                int         count = 0;

                /* Found a leaf that matches the key via a case-insensitive
                 * match.  There may be one or more data nodes that match.
                 * If we have an exact match, return that.
                 * If we have an ambiguous match, return an error.
                 * If we have only one inexact match, return that.
                 */
                slot = getSlot(op->scp->dirBplus, leafNode);
                if (slot <= BTERROR) {
                    op->scp->dirDataVersion = 0;
                    rc = EINVAL;
                    goto done;
                }
                firstDataNode = getnode(leafNode, slot);

                for ( dataNode = firstDataNode; dataNode; dataNode = nextDataNode) {
                    count++;
                    if (!comparekeys(op->scp->dirBplus)(key, getdatakey(dataNode), EXACT_MATCH) ) {
                        exact = 1;
                        break;
                    }
                    nextDataNode = getdatanext(dataNode);
                }

                if (exact) {
                    fid = getdatavalue(dataNode).fid;
                    rc = 0;
                } else if (count == 1) {
                    fid = getdatavalue(firstDataNode).fid;
                    rc = CM_ERROR_INEXACT_MATCH;
                } else {
                    rc = CM_ERROR_AMBIGUOUS_FILENAME;
                }

                if (rc != CM_ERROR_AMBIGUOUS_FILENAME) {
                    /* delete first the long name and then the short name */
                    delete(op->scp->dirBplus, key);

                    if (cm_shortNames) {
                        dfid.vnode = htonl(fid.vnode);
                        dfid.unique = htonl(fid.unique);
                        cm_Gen8Dot3NameIntW(centry, &dfid, shortName, NULL);

                        key.name = shortName;
                        delete(op->scp->dirBplus, key);
                    }
                }
            } /* !NONODE */
        } else {
            clientchar_t * cname = NULL;

            /* We need to lookup the 8dot3 name to determine what the
             * matching long name is
             */
            leafNode = bplus_Lookup(op->scp->dirBplus, key);
            if (leafNode != NONODE) {
                int         slot;
                Nptr        firstDataNode, dataNode, nextDataNode;
                int         exact = 0;
                int         count = 0;

                /* Found a leaf that matches the key via a case-insensitive
                 * match.  There may be one or more data nodes that match.
                 * If we have an exact match, return that.
                 * If we have an ambiguous match, return an error.
                 * If we have only one inexact match, return that.
                 */
                slot = getSlot(op->scp->dirBplus, leafNode);
                if (slot <= BTERROR) {
                    op->scp->dirDataVersion = 0;
                    rc = EINVAL;
                    goto done;

                }
                firstDataNode = getnode(leafNode, slot);

                for ( dataNode = firstDataNode; dataNode; dataNode = nextDataNode) {
                    count++;
                    if (!comparekeys(op->scp->dirBplus)(key, getdatakey(dataNode), EXACT_MATCH) ) {
                        exact = 1;
                        break;
                    }
                    nextDataNode = getdatanext(dataNode);
                }

                if (exact) {
                    cname = getdatavalue(dataNode).cname;
                    rc = 0;
                } else if (count == 1) {
                    cname = getdatavalue(firstDataNode).cname;
                    rc = CM_ERROR_INEXACT_MATCH;
                } else {
                    rc = CM_ERROR_AMBIGUOUS_FILENAME;
                }
            }

            if (rc != CM_ERROR_AMBIGUOUS_FILENAME) {
                if (cname) {
                    normchar_t * longNName = cm_NormalizeStringAlloc(cname, -1, NULL);

                    key.name = longNName;
                    delete(op->scp->dirBplus, key);
                    key.name = normalizedEntry;

                    free(longNName);
                }

                delete(op->scp->dirBplus, key);
            }
        }
    }

    QueryPerformanceCounter(&end);

    bplus_remove_time += (end.QuadPart - start.QuadPart);

  done:
    if (normalizedEntry)
        free(normalizedEntry);

    return rc;

}

/*
   On entry:
       op->scp->dirlock is read locked

   On exit:
       op->scp->dirlock is read locked

   Return:

*/
int cm_BPlusDirIsEmpty(cm_dirOp_t *op, afs_uint32 *pbEmpty)
{
    int rc = 0;
    afs_uint32 count = 0, slot, numentries;
    Nptr leafNode = NONODE, nextLeafNode;
    Nptr firstDataNode, dataNode, nextDataNode;

    if (op->scp->dirBplus == NULL ||
        op->dataVersion != op->scp->dirDataVersion) {
        rc = EINVAL;
        goto done;
    }

    /* If we find any entry that is not "." or "..", the directory is not empty */

    for (count = 0, leafNode = getleaf(op->scp->dirBplus); leafNode; leafNode = nextLeafNode) {

	for ( slot = 1, numentries = numentries(leafNode); slot <= numentries; slot++) {
	    firstDataNode = getnode(leafNode, slot);

	    for ( dataNode = firstDataNode; dataNode; dataNode = nextDataNode) {

                if ( cm_ClientStrCmp(getdatavalue(dataNode).cname, L".") &&
                     cm_ClientStrCmp(getdatavalue(dataNode).cname, L".."))
                {

                    *pbEmpty = 0;
                    goto done;
                }

		nextDataNode = getdatanext(dataNode);
	    }
	}
	nextLeafNode = getnextnode(leafNode);
    }

    *pbEmpty = 1;

  done:
    return rc;
}

int cm_BPlusDirFoo(struct cm_scache *scp, struct cm_dirEntry *dep,
                   void *dummy, osi_hyper_t *entryOffsetp)
{
    keyT   key = {NULL};
    dataT  data;
    normchar_t *normalized_name=NULL;

    cm_SetFid(&data.fid, scp->fid.cell, scp->fid.volume,
              ntohl(dep->fid.vnode), ntohl(dep->fid.unique));
    data.cname = NULL;
    data.fsname = NULL;

    normalized_name = cm_FsStringToNormStringAlloc(dep->name, -1, NULL);

    if (normalized_name) {
        key.name = normalized_name;
    } else {
#ifdef DEBUG
        DebugBreak();
#endif
        return 0;
    }

    data.cname = cm_FsStringToClientStringAlloc(dep->name, -1, NULL);
    if (data.cname == NULL) {
#ifdef DEBUG
        DebugBreak();
#endif
        return 0;
    }
    data.fsname = cm_FsStrDup(dep->name);
    data.shortform = FALSE;

    /* the Write lock is held in cm_BPlusDirBuildTree() */
    insert(scp->dirBplus, key, data);

    if (cm_shortNames && !cm_Is8Dot3(data.cname)) {
        cm_dirFid_t dfid;
        wchar_t wshortName[13];

        dfid.vnode = dep->fid.vnode;
        dfid.unique = dep->fid.unique;

        cm_Gen8Dot3NameIntW(data.cname, &dfid, wshortName, NULL);

        key.name = wshortName;
        data.cname = cm_FsStringToClientStringAlloc(dep->name, -1, NULL);
        if (data.cname) {
            data.fsname = cm_FsStrDup(dep->name);
            data.shortform = TRUE;

            insert(scp->dirBplus, key, data);
        }
    }

    if (normalized_name)
        free(normalized_name);

#ifdef BTREE_DEBUG
    findAllBtreeValues(scp->dirBplus);
#endif
    return 0;
}


/*
 *   scp->dirlock must be writeLocked before call
 *
 *   scp->mutex must not be held
 */
long cm_BPlusDirBuildTree(cm_scache_t *scp, cm_user_t *userp, cm_req_t* reqp)
{
    long rc = 0;
    osi_hyper_t thyper;
    LARGE_INTEGER start, end;

    osi_assertx(scp->dirBplus == NULL, "cm_BPlusDirBuildTree called on non-empty tree");

    lock_AssertWrite(&scp->dirlock);

    QueryPerformanceCounter(&start);
    bplus_build_tree++;

    if (scp->dirBplus == NULL) {
        scp->dirBplus = initBtree(64, MAX_FANOUT, cm_BPlusCompareNormalizedKeys);
    }
    if (scp->dirBplus == NULL) {
        rc = ENOMEM;
    } else {
        thyper.LowPart = 0;
        thyper.HighPart = 0;
        rc = cm_ApplyDir(scp, cm_BPlusDirFoo, NULL, &thyper, userp, reqp, NULL);
    }

    QueryPerformanceCounter(&end);

    bplus_build_time += (end.QuadPart - start.QuadPart);

#if 0
    cm_BPlusDirEnumTest(scp, 1);
#endif
    return rc;
}

int cm_MemDumpBPlusStats(FILE *outputFile, char *cookie, int lock)
{
    int zilch;
    char output[128];

    StringCbPrintfA(output, sizeof(output), "%s - B+ Lookup    Hits: %-8d\r\n", cookie, bplus_lookup_hits);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    StringCbPrintfA(output, sizeof(output), "%s -      Inexact Hits: %-8d\r\n", cookie, bplus_lookup_hits_inexact);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    StringCbPrintfA(output, sizeof(output), "%s -    Ambiguous Hits: %-8d\r\n", cookie, bplus_lookup_ambiguous);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    StringCbPrintfA(output, sizeof(output), "%s -            Misses: %-8d\r\n", cookie, bplus_lookup_misses);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    StringCbPrintfA(output, sizeof(output), "%s -            Create: %-8d\r\n", cookie, bplus_create_entry);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    StringCbPrintfA(output, sizeof(output), "%s -            Remove: %-8d\r\n", cookie, bplus_remove_entry);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    StringCbPrintfA(output, sizeof(output), "%s -        Build Tree: %-8d\r\n", cookie, bplus_build_tree);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    StringCbPrintfA(output, sizeof(output), "%s -         Free Tree: %-8d\r\n", cookie, bplus_free_tree);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    StringCbPrintfA(output, sizeof(output), "%s -          DV Error: %-8d\r\n", cookie, bplus_dv_error);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);

    StringCbPrintfA(output, sizeof(output), "%s - B+ Time    Lookup: %-16I64d\r\n", cookie, bplus_lookup_time);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    StringCbPrintfA(output, sizeof(output), "%s -            Create: %-16I64d\r\n", cookie, bplus_create_time);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    StringCbPrintfA(output, sizeof(output), "%s -            Remove: %-16I64d\r\n", cookie, bplus_remove_time);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    StringCbPrintfA(output, sizeof(output), "%s -             Build: %-16I64d\r\n", cookie, bplus_build_time);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    StringCbPrintfA(output, sizeof(output), "%s -              Free: %-16I64d\r\n", cookie, bplus_free_time);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);

    return(0);
}

void cm_BPlusDumpStats(void)
{
    afsi_log("B+ Lookup    Hits: %-8d", bplus_lookup_hits);
    afsi_log("     Inexact Hits: %-8d", bplus_lookup_hits_inexact);
    afsi_log("   Ambiguous Hits: %-8d", bplus_lookup_ambiguous);
    afsi_log("           Misses: %-8d", bplus_lookup_misses);
    afsi_log("           Create: %-8d", bplus_create_entry);
    afsi_log("           Remove: %-8d", bplus_remove_entry);
    afsi_log("       Build Tree: %-8d", bplus_build_tree);
    afsi_log("        Free Tree: %-8d", bplus_free_tree);
    afsi_log("         DV Error: %-8d", bplus_dv_error);

    afsi_log("B+ Time    Lookup: %-16I64d", bplus_lookup_time);
    afsi_log("           Create: %-16I64d", bplus_create_time);
    afsi_log("           Remove: %-16I64d", bplus_remove_time);
    afsi_log("            Build: %-16I64d", bplus_build_time);
    afsi_log("             Free: %-16I64d", bplus_free_time);
}

static cm_direnum_t *
cm_BPlusEnumAlloc(afs_uint32 entries)
{
    cm_direnum_t * enump;
    size_t	   size;

    if (entries == 0)
        size = sizeof(cm_direnum_t);
    else
        size = sizeof(cm_direnum_t)+(entries-1)*sizeof(cm_direnum_entry_t);
    enump = (cm_direnum_t *)malloc(size);
    if (enump) {
        memset(enump, 0, size);
        enump->count = entries;
    }
    return enump;
}

long
cm_BPlusDirEnumerate(cm_scache_t *dscp, cm_user_t *userp, cm_req_t *reqp,
                     afs_uint32 locked, clientchar_t * maskp,
                     afs_uint32 fetchStatus, cm_direnum_t **enumpp)
{
    afs_uint32 count = 0, slot, numentries;
    Nptr leafNode = NONODE, nextLeafNode;
    Nptr firstDataNode, dataNode, nextDataNode;
    cm_direnum_t * enump = NULL;
    long rc = 0;
    char buffer[512];

    osi_Log0(afsd_logp, "cm_BPlusDirEnumerate start");

    /* Read lock the bplus tree so the data can't change */
    if (!locked)
	lock_ObtainRead(&dscp->dirlock);

    /*
     * Hold a reference to the directory so that it won't be
     * recycled while the enumeration is active.
     */
    cm_HoldSCache(dscp);
    cm_HoldUser(userp);

    if (dscp->dirBplus == NULL) {
	osi_Log0(afsd_logp, "cm_BPlusDirEnumerate No BPlus Tree");
        rc = CM_ERROR_WOULDBLOCK;
	goto done;
    }

    /* Compute the number of entries */
    for (count = 0, leafNode = getleaf(dscp->dirBplus); leafNode; leafNode = nextLeafNode) {

	for ( slot = 1, numentries = numentries(leafNode); slot <= numentries; slot++) {
	    firstDataNode = getnode(leafNode, slot);

	    for ( dataNode = firstDataNode; dataNode; dataNode = nextDataNode) {

                /* There can be two data nodes for one file.  One for
                   the long name and one for the short name.  We only
                   include one of these for the enumeration */

                if (maskp == NULL) {
                    if (!getdatavalue(dataNode).shortform)
                        count++;
                } else {
		    if (!getdatavalue(dataNode).shortform &&
                        cm_MatchMask(getdatavalue(dataNode).cname, maskp, CM_FLAG_CASEFOLD))
                        count++;
                }
		nextDataNode = getdatanext(dataNode);
	    }
	}

	nextLeafNode = getnextnode(leafNode);
    }

    StringCbPrintfA(buffer, sizeof(buffer), "BPlusTreeEnumerate count = %d", count);
    osi_Log1(afsd_logp, "BPlus: %s", osi_LogSaveString(afsd_logp, buffer));

    /* Allocate the enumeration object */
    enump = cm_BPlusEnumAlloc(count);
    if (enump == NULL) {
	osi_Log0(afsd_logp, "cm_BPlusDirEnumerate Alloc failed");
	rc = ENOMEM;
	goto done;
    }

    /* Copy the name and fid for each cname entry into the enumeration */
    for (count = 0, leafNode = getleaf(dscp->dirBplus); leafNode; leafNode = nextLeafNode) {

	for ( slot = 1, numentries = numentries(leafNode); slot <= numentries; slot++) {
	    firstDataNode = getnode(leafNode, slot);

	    for ( dataNode = firstDataNode; dataNode; dataNode = nextDataNode) {
                clientchar_t * name;
                int includeIt = 0;

                if (maskp == NULL) {
                    if (!getdatavalue(dataNode).shortform) {
                        includeIt = 1;
                    }
                } else {
		    if (!getdatavalue(dataNode).shortform &&
                        cm_MatchMask(getdatavalue(dataNode).cname, maskp, CM_FLAG_CASEFOLD)) {
                        includeIt = 1;
                    }
                }

                if (includeIt) {
                    name = cm_ClientStrDup(getdatavalue(dataNode).cname);

                    if (name == NULL) {
                        osi_Log0(afsd_logp, "cm_BPlusDirEnumerate strdup failed");
                        rc = ENOMEM;
                        goto done;
                    }

                    enump->entry[count].name = name;
                    enump->entry[count].fid  = getdatavalue(dataNode).fid;

                    if (cm_shortNames) {
                        if (!cm_Is8Dot3(name)) {
                            cm_dirFid_t dfid;

                            dfid.vnode = htonl(getdatavalue(dataNode).fid.vnode);
                            dfid.unique = htonl(getdatavalue(dataNode).fid.unique);

                            cm_Gen8Dot3NameIntW(name, &dfid, enump->entry[count].shortName, NULL);
                        } else {
                            StringCbCopyW(enump->entry[count].shortName,
                                          sizeof(enump->entry[count].shortName),
                                          name);
                        }
                    }

                    count++;
                }
		nextDataNode = getdatanext(dataNode);
	    }
	}

	nextLeafNode = getnextnode(leafNode);
    }

    enump->dscp = dscp;
    enump->userp = userp;
    enump->reqFlags = reqp->flags;
    enump->fetchStatus = fetchStatus;
    enump->dataVersion = dscp->dirDataVersion;

  done:
    if (!locked)
	lock_ReleaseRead(&dscp->dirlock);

    /* if we failed, cleanup any mess */
    if (rc != 0) {
	osi_Log0(afsd_logp, "cm_BPlusDirEnumerate rc != 0");

        /*
         * release the directory because we failed to generate an enumeration object.
         * adjust the directory position in the queue to ensure it doesn't get pushed
         * out by the allocation of a large number of cm_scache objects.
         */
        lock_ObtainWrite(&cm_scacheLock);
        cm_AdjustScacheLRU(dscp);
        cm_ReleaseSCacheNoLock(dscp);
        lock_ReleaseWrite(&cm_scacheLock);
        cm_ReleaseUser(userp);
        if (enump) {
	    for ( count = 0; count < enump->count && enump->entry[count].name; count++ ) {
		free(enump->entry[count].name);
	    }
	    free(enump);
	    enump = NULL;
	}
    }

    osi_Log0(afsd_logp, "cm_BPlusDirEnumerate end");
    *enumpp = enump;
    return rc;
}

long
cm_BPlusDirEnumBulkStat(cm_direnum_t *enump)
{
    cm_scache_t *dscp = enump->dscp;
    cm_user_t   *userp = enump->userp;
    cm_bulkStat_t *bsp = NULL;
    afs_uint32 ** bs_errorCodep = NULL;
    afs_uint32 ** bs_flagsp = NULL;
    afs_uint32    dscp_errorCode = 0;
    afs_uint32    dscp_flags = 0;
    afs_uint32 count;
    afs_uint32 code = 0;
    cm_req_t req;
    int i;
    cm_scache_t   *tscp;
    afs_int32 nobulkstat = 0;
    afs_int32 base = 1;

    cm_InitReq(&req);
    req.flags = enump->reqFlags;

    if ( dscp->fid.cell == AFS_FAKE_ROOT_CELL_ID )
        return 0;

    bsp = malloc(sizeof(cm_bulkStat_t));
    if (!bsp) {
        code = ENOMEM;
        goto done;
    }
    memset(bsp, 0, sizeof(cm_bulkStat_t));
    bsp->userp = userp;

    bs_errorCodep = malloc(sizeof(afs_uint32 *) * AFSCBMAX);
    if (!bs_errorCodep) {
        code = ENOMEM;
        goto done;
    }

    bs_flagsp = malloc(sizeof(afs_uint32 *) * AFSCBMAX);
    if (!bs_flagsp) {
        code = ENOMEM;
        goto done;
    }

    /*
     * In order to prevent the directory callback from expiring
     * on really large directories with many symlinks to mount
     * points such as /afs/andrew.cmu.edu/usr/, always include
     * the directory fid in the search.
     */
    bsp->fids[0].Volume = dscp->fid.volume;
    bsp->fids[0].Vnode = dscp->fid.vnode;
    bsp->fids[0].Unique = dscp->fid.unique;
    bs_errorCodep[0] = &dscp_errorCode;
    bs_flagsp[0] = &dscp_flags;
    bsp->counter++;

  restart_stat:
    for ( count = 0; count < enump->count; count++ ) {
        if ( !wcscmp(L".", enump->entry[count].name) || !wcscmp(L"..", enump->entry[count].name) ) {
            continue;
        }
        
        tscp = cm_FindSCache(&enump->entry[count].fid);
        if (tscp) {
            if (lock_TryWrite(&tscp->rw)) {
                /* we have an entry that we can look at */
                if (!cm_EAccesFindEntry(userp, &tscp->fid) && cm_HaveCallback(tscp)) {
                    /* we have a callback on it.  Don't bother
                     * fetching this stat entry, since we're happy
                     * with the info we have.
                     */
                    lock_ReleaseWrite(&tscp->rw);
                    cm_ReleaseSCache(tscp);
                    enump->entry[count].flags |= CM_DIRENUM_FLAG_GOT_STATUS;
                    enump->entry[count].errorCode = 0;
                    continue;
                }

                if (nobulkstat) {
                    code = cm_SyncOp(tscp, NULL, userp, &req, 0,
                                      CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
                    lock_ReleaseWrite(&tscp->rw);
                    cm_ReleaseSCache(tscp);
                    enump->entry[count].flags |= CM_DIRENUM_FLAG_GOT_STATUS;
                    enump->entry[count].errorCode = code;
                    continue;
                }

                lock_ReleaseWrite(&tscp->rw);
            }	/* got lock */
            cm_ReleaseSCache(tscp);
        }	/* found entry */

        i = bsp->counter++;
        bsp->fids[i].Volume = enump->entry[count].fid.volume;
        bsp->fids[i].Vnode = enump->entry[count].fid.vnode;
        bsp->fids[i].Unique = enump->entry[count].fid.unique;
        bs_errorCodep[i] = &enump->entry[count].errorCode;
        bs_flagsp[bsp->counter] = &enump->entry[i].flags;
        enump->entry[count].flags |= CM_DIRENUM_FLAG_GOT_STATUS;

        if (bsp->counter == AFSCBMAX) {
            base = 0;
            code = cm_TryBulkStatRPC(dscp, bsp, userp, &req);
            if (code == CM_ERROR_BULKSTAT_FAILURE) {
                /*
                 * If bulk stat cannot be used for this directory
                 * we must perform individual fetch status calls.
                 * Restart from the beginning of the enumeration.
                 */
                nobulkstat = 1;

                for (i=0; i<bsp->counter; i++) {
                    *(bs_flagsp[i]) &= ~CM_DIRENUM_FLAG_GOT_STATUS;
                }
                goto restart_stat;
            }

            if (code) {
                /* on any other error, exit */
                goto done;
            }
            for ( i=0; i<bsp->counter; i++) {
                *(bs_errorCodep[i]) = cm_MapRPCError(bsp->stats[i].errorCode, &req);
            }

            if (dscp_errorCode) {
                code = dscp_errorCode;
                goto done;
            }
            memset(bsp, 0, sizeof(cm_bulkStat_t));
            bsp->userp = userp;

            /*
             * In order to prevent the directory callback from expiring
             * on really large directories with many symlinks to mount
             * points such as /afs/andrew.cmu.edu/usr/, always include
             * the directory fid in the search.
             */
            bsp->fids[0].Volume = dscp->fid.volume;
            bsp->fids[0].Vnode = dscp->fid.vnode;
            bsp->fids[0].Unique = dscp->fid.unique;
            bs_errorCodep[0] = &dscp_errorCode;
            bsp->counter++;
        }
    }

    /*
     * if the counter is 1, only the directory entry is in the list,
     * do not issue the RPC.
     */

    if (bsp->counter > base) {
        code = cm_TryBulkStatRPC(dscp, bsp, userp, &req);
        if (code == CM_ERROR_BULKSTAT_FAILURE) {
            /*
             * If bulk stat cannot be used for this directory
             * we must perform individual fetch status calls.
             * Restart from the beginning of the enumeration.
             */
            nobulkstat = 1;

            for (i=0; i<bsp->counter; i++) {
                *(bs_flagsp[i]) &= ~CM_DIRENUM_FLAG_GOT_STATUS;
            }
            goto restart_stat;
        }

        if (code)
            goto done;

        for ( i=0; i<bsp->counter; i++) {
            *(bs_errorCodep[i]) = cm_MapRPCError(bsp->stats[i].errorCode, &req);
        }

        if (dscp_errorCode) {
            code = dscp_errorCode;
            goto done;
        }
    }

  done:
    if (bsp)
        free(bsp);
    if (bs_errorCodep)
        free(bs_errorCodep);
    if (bs_flagsp)
        free(bs_flagsp);

    return code;
}

/*
 * Similar to cm_BPlusDirEnumBulkStat() except that only
 * one RPC is issued containing the provided scp FID and up to
 * AFSCBMAX - 2 other FIDs for which the status info has yet
 * to be obtained.
 */
long
cm_BPlusDirEnumBulkStatOne(cm_direnum_t *enump, cm_scache_t *scp)
{
    cm_scache_t *dscp = enump->dscp;
    cm_user_t   *userp = enump->userp;
    cm_bulkStat_t *bsp = NULL;
    afs_uint32 ** bs_errorCodep = NULL;
    afs_uint32 ** bs_flagsp = NULL;
    afs_uint32    dscp_errorCode = 0;
    afs_uint32    dscp_flags = 0;
    afs_uint32    scp_errorCode = 0;
    afs_uint32    scp_flags = 0;
    afs_uint32 code = 0;
    afs_uint32 i;
    cm_req_t req;
    cm_scache_t   *tscp;

    if ( dscp->fid.cell == AFS_FAKE_ROOT_CELL_ID )
        return 0;

    cm_InitReq(&req);
    req.flags = enump->reqFlags;

    bsp = malloc(sizeof(cm_bulkStat_t));
    if (!bsp) {
        code = ENOMEM;
        goto done;
    }
    memset(bsp, 0, sizeof(cm_bulkStat_t));
    bsp->userp = userp;

    bs_errorCodep = malloc(sizeof(afs_uint32 *) * AFSCBMAX);
    if (!bs_errorCodep) {
        code = ENOMEM;
        goto done;
    }

    bs_flagsp = malloc(sizeof(afs_uint32 *) * AFSCBMAX);
    if (!bs_flagsp) {
        code = ENOMEM;
        goto done;
    }

    /*
     * In order to prevent the directory callback from expiring
     * on really large directories with many symlinks to mount
     * points such as /afs/andrew.cmu.edu/usr/, always include
     * the directory fid in the search.
     */
    bsp->fids[0].Volume = dscp->fid.volume;
    bsp->fids[0].Vnode = dscp->fid.vnode;
    bsp->fids[0].Unique = dscp->fid.unique;
    bs_errorCodep[0] = &dscp_errorCode;
    bs_flagsp[0] = &dscp_flags;
    bsp->counter++;

    /*
     * There is an assumption that this FID is located
     * within the directory enumeration but it could be
     * the case that the enumeration is out of date and
     * the FID is not listed.  So we explicitly add it
     * after the directory FID and then skip it later
     * if we find it.
     */
    bsp->fids[1].Volume = scp->fid.volume;
    bsp->fids[1].Vnode = scp->fid.vnode;
    bsp->fids[1].Unique = scp->fid.unique;
    bs_errorCodep[1] = &scp_errorCode;
    bs_flagsp[1] = &scp_flags;
    bsp->counter++;

    if (enump->count <= AFSCBMAX - 1) {
        i = 0;
    } else {
        /*
         * Find the requested FID in the enumeration and start from there.
         */
        for (i=0; i < enump->count && cm_FidCmp(&scp->fid, &enump->entry[i].fid); i++);
    }

    for ( ; bsp->counter < AFSCBMAX && i < enump->count; i++) {
        if ( !wcscmp(L".", enump->entry[i].name) || !wcscmp(L"..", enump->entry[i].name) ) {
            continue;
        }

        tscp = cm_FindSCache(&enump->entry[i].fid);
        if (tscp) {
            if (tscp == scp) {
                cm_ReleaseSCache(tscp);
                continue;
            }

            if (lock_TryWrite(&tscp->rw)) {
                /* we have an entry that we can look at */
                if (!cm_EAccesFindEntry(userp, &tscp->fid) && cm_HaveCallback(tscp)) {
                    /* we have a callback on it.  Don't bother
                     * fetching this stat entry, since we're happy
                     * with the info we have.
                     */
                    lock_ReleaseWrite(&tscp->rw);
                    cm_ReleaseSCache(tscp);
                    enump->entry[i].flags |= CM_DIRENUM_FLAG_GOT_STATUS;
                    enump->entry[i].errorCode = 0;
                    continue;
                }
                lock_ReleaseWrite(&tscp->rw);
            }	/* got lock */
            cm_ReleaseSCache(tscp);
        } /* found entry */

        bsp->fids[bsp->counter].Volume = enump->entry[i].fid.volume;
        bsp->fids[bsp->counter].Vnode = enump->entry[i].fid.vnode;
        bsp->fids[bsp->counter].Unique = enump->entry[i].fid.unique;
        bs_errorCodep[bsp->counter] = &enump->entry[i].errorCode;
        bs_flagsp[bsp->counter] = &enump->entry[i].flags;
        enump->entry[i].flags |= CM_DIRENUM_FLAG_GOT_STATUS;
        bsp->counter++;
    }

    /*
     * if the counter is 1, only the directory entry is in the list,
     * do not issue the RPC.
     */

    if (bsp->counter > 1) {
        code = cm_TryBulkStatRPC(dscp, bsp, userp, &req);

        /* Now process any errors that might have occurred */
        if (code == CM_ERROR_BULKSTAT_FAILURE) {
            for (i=2; i<bsp->counter; i++) {
                *(bs_flagsp[i]) &= ~CM_DIRENUM_FLAG_GOT_STATUS;
            }

            lock_ObtainWrite(&scp->rw);
            code = cm_SyncOp(scp, NULL, userp, &req, 0,
                              CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
            lock_ReleaseWrite(&scp->rw);
            goto done;
        }

        if (code)
            goto done;

        for ( i=0; i<bsp->counter; i++) {
            *(bs_errorCodep[i]) = cm_MapRPCError(bsp->stats[i].errorCode, &req);
        }

        /* Check if there was an error on the requested FID, if so return it */
        if ( scp_errorCode ) {
            code = scp_errorCode;
            goto done;
        }
    }

  done:
    if (bsp)
        free(bsp);
    if (bs_errorCodep)
        free(bs_errorCodep);
    if (bs_flagsp)
        free(bs_flagsp);

    return code;
}

static long
cm_BPlusDirEnumBulkStatNext(cm_direnum_t *enump)
{
    cm_scache_t *dscp = enump->dscp;
    cm_user_t   *userp = enump->userp;
    cm_bulkStat_t *bsp = NULL;
    afs_uint32 ** bs_errorCodep = NULL;
    afs_uint32 ** bs_flagsp = NULL;
    afs_uint32    dscp_errorCode = 0;
    afs_uint32    dscp_flags = 0;
    afs_uint32 count;
    afs_uint32 code = 0;
    cm_req_t req;
    cm_scache_t   *tscp;
    afs_int32     next = -1;
    int i;

    if ( dscp->fid.cell == AFS_FAKE_ROOT_CELL_ID )
        return 0;

    cm_InitReq(&req);
    req.flags = enump->reqFlags;

    bsp = malloc(sizeof(cm_bulkStat_t));
    if (!bsp) {
        code = ENOMEM;
        goto done;
    }
    memset(bsp, 0, sizeof(cm_bulkStat_t));
    bsp->userp = userp;

    bs_errorCodep = malloc(sizeof(afs_uint32 *) * AFSCBMAX);
    if (!bs_errorCodep) {
        code = ENOMEM;
        goto done;
    }

    bs_flagsp = malloc(sizeof(afs_uint32 *) * AFSCBMAX);
    if (!bs_flagsp) {
        code = ENOMEM;
        goto done;
    }

    /*
     * In order to prevent the directory callback from expiring
     * on really large directories with many symlinks to mount
     * points such as /afs/andrew.cmu.edu/usr/, always include
     * the directory fid in the search.
     */
    bsp->fids[0].Volume = dscp->fid.volume;
    bsp->fids[0].Vnode = dscp->fid.vnode;
    bsp->fids[0].Unique = dscp->fid.unique;
    bs_errorCodep[0] = &dscp_errorCode;
    bs_flagsp[0] = &dscp_flags;
    bsp->counter++;

    for ( count = enump->next; count < enump->count && bsp->counter < AFSCBMAX; count++ ) {
        if ( !wcscmp(L".", enump->entry[count].name) || !wcscmp(L"..", enump->entry[count].name) ) {
            continue;
        }

        tscp = cm_FindSCache(&enump->entry[count].fid);
        if (tscp) {
            if (lock_TryWrite(&tscp->rw)) {
                /* we have an entry that we can look at */
                if (!cm_EAccesFindEntry(userp, &tscp->fid) && cm_HaveCallback(tscp)) {
                    /* we have a callback on it.  Don't bother
                     * fetching this stat entry, since we're happy
                     * with the info we have.
                     */
                    lock_ReleaseWrite(&tscp->rw);
                    cm_ReleaseSCache(tscp);
                    enump->entry[count].flags |= CM_DIRENUM_FLAG_GOT_STATUS;
                    enump->entry[count].errorCode = 0;
                    continue;
                }
                lock_ReleaseWrite(&tscp->rw);
            }	/* got lock */
            cm_ReleaseSCache(tscp);
        }	/* found entry */

        /* 'next' is the enump entry that is stored in the [bsp->counter == 1] element */
        if (next == -1)
            next = count;

        bsp->fids[bsp->counter].Volume = enump->entry[count].fid.volume;
        bsp->fids[bsp->counter].Vnode = enump->entry[count].fid.vnode;
        bsp->fids[bsp->counter].Unique = enump->entry[count].fid.unique;
        bs_errorCodep[bsp->counter] = &enump->entry[count].errorCode;
        bs_flagsp[bsp->counter] = &enump->entry[count].flags;
        enump->entry[count].flags |= CM_DIRENUM_FLAG_GOT_STATUS;
        bsp->counter++;
    }

    /*
     * if the counter is 1, only the directory entry is in the list,
     * do not issue the RPC.
     */

    if (bsp->counter > 1) {
        code = cm_TryBulkStatRPC(dscp, bsp, userp, &req);

        /* Now process any errors that might have occurred */
        if (code == CM_ERROR_BULKSTAT_FAILURE) {
            for (i=0; i<bsp->counter; i++) {
                *(bs_flagsp[i]) &= ~CM_DIRENUM_FLAG_GOT_STATUS;
            }

            /* if next == -1, there is no entry to update the status of */
            if (next != -1) {
                code = cm_GetSCache(&enump->entry[next].fid, NULL, &tscp, userp, &req);
                if (code == 0) {
                    if (lock_TryWrite(&tscp->rw)) {
                        code = cm_SyncOp(tscp, NULL, userp, &req, 0,
                                          CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
                        lock_ReleaseWrite(&tscp->rw);
                        *(bs_errorCodep[1]) = code;
                        *(bs_flagsp[1]) |= CM_DIRENUM_FLAG_GOT_STATUS;
                    }
                    cm_ReleaseSCache(tscp);
                } else {
                    *(bs_errorCodep[1]) = code;
                    *(bs_flagsp[1]) |= CM_DIRENUM_FLAG_GOT_STATUS;
                }
            }
            goto done;
        }

        if (code)
            goto done;

        for ( i=0; i<bsp->counter; i++) {
            *(bs_errorCodep[i]) = cm_MapRPCError(bsp->stats[i].errorCode, &req);
        }

        if (dscp_errorCode) {
            code = dscp_errorCode;
            goto done;
        }
    }

  done:
    if (bsp)
        free(bsp);
    if (bs_errorCodep)
        free(bs_errorCodep);
    if (bs_flagsp)
        free(bs_flagsp);

    return code;
}

long
cm_BPlusDirNextEnumEntry(cm_direnum_t *enump, cm_direnum_entry_t **entrypp)
{
    long code = 0;

    if (enump == NULL || entrypp == NULL || enump->next >= enump->count) {
	if (entrypp)
	    *entrypp = NULL;
	osi_Log0(afsd_logp, "cm_BPlusDirNextEnumEntry invalid input");
	return CM_ERROR_INVAL;
    }

    if (enump->fetchStatus &&
		!(enump->entry[enump->next].flags & CM_DIRENUM_FLAG_GOT_STATUS)) {
        code = cm_BPlusDirEnumBulkStatNext(enump);
    }

    *entrypp = &enump->entry[enump->next++];
    if ( enump->next == enump->count ) {
	osi_Log0(afsd_logp, "cm_BPlusDirNextEnumEntry STOPNOW");
	return CM_ERROR_STOPNOW;
    }
    else {
        if (code) {
            (*entrypp)->errorCode = code;
            osi_Log1(afsd_logp, "cm_BPlusDirNextEnumEntry ERROR 0x%x", code);
        } else {
            osi_Log0(afsd_logp, "cm_BPlusDirNextEnumEntry SUCCESS");
        }
	return 0;
    }
}

long
cm_BPlusDirPeekNextEnumEntry(cm_direnum_t *enump, cm_direnum_entry_t **entrypp)
{
    long code;

    if (enump == NULL || entrypp == NULL || enump->next >= enump->count) {
	if (entrypp)
	    *entrypp = NULL;
	osi_Log0(afsd_logp, "cm_BPlusDirPeekNextEnumEntry invalid input");
	return CM_ERROR_INVAL;
    }

    if (enump->fetchStatus &&
        !(enump->entry[enump->next].flags & CM_DIRENUM_FLAG_GOT_STATUS)) {
        code = cm_BPlusDirEnumBulkStatNext(enump);
        if (code)
            return code;
    }

    *entrypp = &enump->entry[enump->next];
    if ( enump->next == enump->count ) {
	osi_Log0(afsd_logp, "cm_BPlusDirPeekNextEnumEntry STOPNOW");
	return CM_ERROR_STOPNOW;
    }
    else {
	osi_Log0(afsd_logp, "cm_BPlusDirPeekNextEnumEntry SUCCESS");
	return 0;
    }
}

long
cm_BPlusDirFreeEnumeration(cm_direnum_t *enump)
{
    afs_uint32 count;

    osi_Log0(afsd_logp, "cm_BPlusDirFreeEnumeration");

    if (enump) {
        /*
         * Release the directory object but first adjust its position
         * in the LRU queue to ensure that it does not get stuck at the
         * end due to the allocation of a large number of cm_scache
         * entries in the directory.
         */
        lock_ObtainWrite(&cm_scacheLock);
        cm_AdjustScacheLRU(enump->dscp);
        cm_ReleaseSCacheNoLock(enump->dscp);
        lock_ReleaseWrite(&cm_scacheLock);
        cm_ReleaseUser(enump->userp);

	for ( count = 0; count < enump->count && enump->entry[count].name; count++ ) {
	    free(enump->entry[count].name);
	}
	free(enump);
    }
    return 0;
}

long
cm_BPlusDirEnumTest(cm_scache_t * dscp, cm_user_t *userp, cm_req_t *reqp, afs_uint32 locked)
{
    cm_direnum_t * 	 enump = NULL;
    cm_direnum_entry_t * entryp;
    long 	   	 code;


    osi_Log0(afsd_logp, "cm_BPlusDirEnumTest start");

    for (code = cm_BPlusDirEnumerate(dscp, userp, reqp, locked, NULL, 1, &enump); code == 0; ) {
	code = cm_BPlusDirNextEnumEntry(enump, &entryp);
	if (code == 0 || code == CM_ERROR_STOPNOW) {
	    char buffer[1024];
	    cm_scache_t *scp;
	    char * type = "ScpNotFound";
	    afs_uint64 dv = -1;

	    scp = cm_FindSCache(&entryp->fid);
	    if (scp) {
		switch (scp->fileType) {
		case CM_SCACHETYPE_FILE	:
		    type = "File";
		    break;
		case CM_SCACHETYPE_DIRECTORY	:
		    type = "Directory";
		    break;
		case CM_SCACHETYPE_SYMLINK	:
		    type = "Symlink";
		    break;
		case CM_SCACHETYPE_MOUNTPOINT:
		    type = "MountPoint";
		    break;
		case CM_SCACHETYPE_DFSLINK   :
		    type = "Dfs";
		    break;
		case CM_SCACHETYPE_INVALID   :
		    type = "Invalid";
		    break;
		default:
		    type = "Unknown";
		    break;
		}

		dv = scp->dataVersion;
                cm_ReleaseSCache(scp);
	    }

	    StringCbPrintfA(buffer, sizeof(buffer), "'%S' Fid = (%d,%d,%d,%d) Short = '%S' Type %s DV %I64d",
		    entryp->name,
		    entryp->fid.cell, entryp->fid.volume, entryp->fid.vnode, entryp->fid.unique,
		    entryp->shortName,
		    type,
		    dv);

	    osi_Log0(afsd_logp, osi_LogSaveString(afsd_logp, buffer));
	}
    }

    if (enump)
	cm_BPlusDirFreeEnumeration(enump);

    osi_Log0(afsd_logp, "cm_BPlusDirEnumTest end");

    return 0;
}
#endif /* USE_BPLUS */

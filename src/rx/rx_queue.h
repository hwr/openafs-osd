/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/* queue.h:  Simple double linked queue package */

/* It's simple, but, I think, it's pretty nice to use, and it's *very* efficient (especially so with a good optimizing compiler).   WARNING:  Since these functions are implemented as macros, it is best to use only *VERY* simple expressions for all parameters.  Double warning:  this uses a lot of type coercion, so you have to be *REAL* careful.  But C doesn't give me a reasonable alternative (i.e.. in-line expanded functions). */

#ifndef _RX_QUEUE_
#define _RX_QUEUE_

/* A queue head is simply a queue element linked to itself (i.e. the null queue is a queue with exactly one element).  Queue elements can be prepended to any structure:  these macros assume that the structure passed is coercible to a (struct q).  Since all of these operations are implemented as macros, the user should beware of side-effects in macro parameters.  Also beware that implicit casting of queue types occurs, so be careful to supply the right parameters at the right times! */
#undef queue			/* Since some OS (ultrix, etc) have their own */
struct rx_queue {
    struct rx_queue *prev;
    struct rx_queue *next;
};

/* Sample usages:

(*A queue head:*)
struct rx_queue myqueue;

(*An element for my queue type:*)
struct myelement {
    struct rx_queue queue_header;
    int mydata;
};

(*Initialize the queue:*)
queue_Init(&myqueue);

(*Append a bunch of items to the queue:*)
for (i=0; i<20; i++) {
    struct myelement *item = (struct myelement *) malloc(sizeof *item);
    item->mydata = i;
    queue_Append(&myqueue, item);
}

(*Scan a queue, incrementing the mydata field in each element, and removing any entries for which mydata>MAX.  Nqe is used by the scan to hold the next queue element, so the current queue element may be removed safely. *)
struct myelement *qe, *nqe;
for (queue_Scan(&myqueue, qe, nqe, myelement)) {
    if (++qe->mydata > MAX)  queue_Remove(qe);
}

(* Count the number of elements in myqueue.  The queue_Scan macro specifies all three elements of the for loop, but an additional initializer and an additional incrementor can be added *)
struct myelement *qe, *nqe;
int n;
for (n=0, queue_Scan(&myqueue, qe, nqe, myelement), n++) {}

*/

/* INTERNAL macros */

/* This one coerces the user's structure to a queue element (or queue head) */
#define	_RXQ(x) ((struct rx_queue *)(x))

/* This one adds a queue element (i) before or after another queue element (or queue head) (q), doubly linking everything together.  It's called by the user usable macros, below.  If (a,b) is (next,prev) then the element i is linked after q; if it is (prev,next) then it is linked before q */
/* N.B.  I don't think it is possible to write this expression, correctly, with less than one comma (you can easily write an alternative expression with no commas that works with most or all compilers, but it's not clear that it really is un-ambiguous, legal C-code). */
#define _RXQA(q,i,a,b) (((i->a=q->a)->b=i)->b=q, q->a=i)

/* These ones splice two queues together.  If (a,b) is (next,prev) then (*q2) is prepended to (*q1), otherwise (*q2) is appended to (*q1). */
#define _RXQS(q1,q2,a,b) \
	do { \
	    if (!queue_IsEmpty(q2)) { \
		((q2->a->b=q1)->a->b=q2->b)->a=q1->a; \
		q1->a=q2->a; \
		queue_Init(q2); \
	    } \
	} while (0)

/* This one removes part of queue (*q1) and attaches it to queue (*q2).
 * If (a,b) is (next,prev) then the subchain is prepended to (*q2),
 * otherwise the subchain is appended to (*q2).
 * If (c,d) is (prev,next) then the subchain is the elements in (*q1) before (i),
 * otherwise the subchain is the elements in (*q1) after (i).
 * If (x,y) is (q1,i) then operation is either BeforePrepend of AfterAppend.
 * If (x,y) is (i,q1) then operation is either BeforeAppend or AfterPrepend. */
#define _RXQSP(q1,q2,i,a,b,c,d,x,y) \
	do { \
	    if (!queue_IsEnd(q1, i->c)) { \
		(y->b->a=q2->a)->b=y->b; \
		(x->a->b=q2)->a=x->a; \
		(i->c=q1)->d=i; \
	    } \
	} while (0)

/* This one moves a chain of elements from (s) to (e) from its
 * current position to either before or after element (i)
 * if (a,b,x,y) is (prev,next,s,e) then chain is moved before (i)
 * if (a,b,x,y) is (next,prev,e,s) then chain is moved after (i) */
#define _RXQMV(i, s, e, a, b, x, y) \
	do { \
	    if (i->a != y) { \
		(e->next->prev=s->prev)->next=e->next; \
		(i->a->b=x)->a=i->a; \
		(y->b=i)->a=y; \
	    } \
	} while (0)

/* Basic remove operation.  Doesn't update the queue item to indicate it's been removed */
#define _RXQR(i) \
	do { \
	    struct rx_queue *_qp = _RXQ(i); \
	    (_qp->prev->next = _qp->next)->prev = _qp->prev; \
	} while (0)

/* EXPORTED macros */

/* Initialize a queue head (*q).  A queue head is just a queue element */
#define queue_Init(q) \
	do { _RXQ(q)->prev = _RXQ(q)->next = _RXQ(q); } while (0)

/* initialize a node in the queue */
#define queue_NodeInit(q) \
	do { _RXQ(q)->prev = _RXQ(q)->next = NULL; } while (0)

/* Prepend a queue element (*i) to the head of the queue, after the queue head (*q).  The new queue element should not currently be on any list. */
#define queue_Prepend(q,i) _RXQA(_RXQ(q),_RXQ(i),next,prev)

/* Append a queue element (*i) to the end of the queue, before the queue head (*q).  The new queue element should not currently be on any list. */
#define queue_Append(q,i) _RXQA(_RXQ(q),_RXQ(i),prev,next)

/* Insert a queue element (*i2) before another element (*i1) in the queue.  The new queue element should not currently be on any list. */
#define queue_InsertBefore(i1,i2) _RXQA(_RXQ(i1),_RXQ(i2),prev,next)

/* Insert a queue element (*i2) after another element (*i1) in the queue.  The new queue element should not currently be on any list. */
#define queue_InsertAfter(i1,i2) _RXQA(_RXQ(i1),_RXQ(i2),next,prev)

/* Spice the members of (*q2) to the beginning of (*q1), re-initialize (*q2) */
#define queue_SplicePrepend(q1,q2) _RXQS(_RXQ(q1),_RXQ(q2),next,prev)

/* Splice the members of queue (*q2) to the end of (*q1), re-initialize (*q2) */
#define queue_SpliceAppend(q1,q2) _RXQS(_RXQ(q1),_RXQ(q2),prev,next)

/* split the members after i off of queue (*q1), and append them onto queue (*q2) */
#define queue_SplitAfterAppend(q1,q2,i) _RXQSP(_RXQ(q1),_RXQ(q2),_RXQ(i),prev,next,next,prev,_RXQ(q1),_RXQ(i))

/* split the members after i off of queue (*q1), and prepend them onto queue (*q2) */
#define queue_SplitAfterPrepend(q1,q2,i) _RXQSP(_RXQ(q1),_RXQ(q2),_RXQ(i),next,prev,next,prev,_RXQ(i),_RXQ(q1))

/* split the members before i off of queue (*q1), and append them onto queue (*q2) */
#define queue_SplitBeforeAppend(q1,q2,i) _RXQSP(_RXQ(q1),_RXQ(q2),_RXQ(i),prev,next,prev,next,_RXQ(i),_RXQ(q1))

/* split the members before i off of queue (*q1), and prepend them onto queue (*q2) */
#define queue_SplitBeforePrepend(q1,q2,i) _RXQSP(_RXQ(q1),_RXQ(q2),_RXQ(i),next,prev,prev,next,_RXQ(q1),_RXQ(i))

/* Replace the queue (*q1) with the contents of the queue (*q2), re-initialize (*q2) */
#define queue_Replace(q1,q2) \
	do { \
	    if (queue_IsEmpty(q2)) \
		queue_Init(q1); \
	    else { \
		*_RXQ(q1) = *_RXQ(q2); \
		_RXQ(q1)->next->prev = _RXQ(q1)->prev->next = _RXQ(q1); \
		queue_Init(q2); \
	    } \
	} while (0)

/* move a chain of elements beginning at (s) and ending at (e) before node (i) */
#define queue_MoveChainBefore(i, s, e) _RXQMV(_RXQ(i),_RXQ(s),_RXQ(e),prev,next,_RXQ(s),_RXQ(e))

/* move a chain of elements beginning at (s) and ending at (e) after node (i) */
#define queue_MoveChainAfter(i, s, e) _RXQMV(_RXQ(i),_RXQ(s),_RXQ(e),next,prev,_RXQ(e),_RXQ(s))

/* Remove a queue element (*i) from its queue.  The next field is 0'd, so that any further use of this q entry will hopefully cause a core dump.  Multiple removes of the same queue item are not supported */
#define queue_Remove(i) \
	do { \
	    _RXQR(i); \
	    _RXQ(i)->next = NULL; \
	} while (0)

/* Move the queue element (*i) from its queue to the end of the queue (*q) */
#define	queue_MoveAppend(q,i) \
	do { \
	    _RXQR(i); \
	    queue_Append(q, i); \
	} while (0)

/* Move the queue element (*i) from its queue to the head of the queue (*q) */
#define	queue_MovePrepend(q,i) \
	do { \
	    _RXQR(i); \
	    queue_Prepend(q, i); \
	} while (0)

/* Return the first element of a queue, coerced too the specified structure s */
/* Warning:  this returns the queue head, if the queue is empty */
#define queue_First(q,s) ((struct s *)_RXQ(q)->next)

/* Return the last element of a queue, coerced to the specified structure s */
/* Warning:  this returns the queue head, if the queue is empty */
#define queue_Last(q,s) ((struct s *)_RXQ(q)->prev)

/* Return the next element in a queue, beyond the specified item, coerced to the specified structure s */
/* Warning:  this returns the queue head, if the item specified is the last in the queue */
#define queue_Next(i,s) ((struct s *)_RXQ(i)->next)

/* Return the previous element to a specified element of a queue, coerced to the specified structure s */
/* Warning:  this returns the queue head, if the item specified is the first in the queue */
#define queue_Prev(i,s) ((struct s *)_RXQ(i)->prev)

/* Return true if the queue is empty, i.e. just consists of a queue head.  The queue head must have been initialized some time prior to this call */
#define queue_IsEmpty(q) (_RXQ(q)->next == _RXQ(q))

/* Return true if the queue is non-empty, i.e. consists of a queue head plus at least one queue item */
#define queue_IsNotEmpty(q) (_RXQ(q)->next != _RXQ(q))

/* Return true if the queue item is currently in a queue */
/* Returns false if the item was removed from a queue OR is uninitialized (zero) */
#define queue_IsOnQueue(i) (_RXQ(i)->next != 0)

/* Returns true if the item was removed from a queue OR is uninitialized (zero) */
/* Return false if the queue item is currently in a queue */
#define queue_IsNotOnQueue(i) (_RXQ(i)->next == 0)

/* Returns true if the queue item (i) is the first element of the queue (q) */
#define queue_IsFirst(q,i) (_RXQ(q)->first == _RXQ(i))

/* Returns true if the queue item (i) is the last element of the queue (q) */
#define queue_IsLast(q,i) (_RXQ(q)->prev == _RXQ(i))

/* Returns true if the queue item (i) is the end of the queue (q), that is, i is the head of the queue */
#define queue_IsEnd(q,i) (_RXQ(q) == _RXQ(i))

/* Returns false if the queue item (i) is the end of the queue (q), that is, i is the head of the queue */
#define queue_IsNotEnd(q,i) (_RXQ(q) != _RXQ(i))

/* Prototypical loop to scan an entire queue forwards.  q is the queue
 * head, qe is the loop variable, next is a variable used to store the
 * queue entry for the next iteration of the loop, s is the user's
 * queue structure name.  Called using "for (queue_Scan(...)) {...}".
 * Note that extra initializers can be added before the queue_Scan,
 * and additional expressions afterwards.  So "for (sum=0,
 * queue_Scan(...), sum += value) {value = qe->value}" is possible.
 * If the current queue entry is deleted, the loop will work
 * correctly.  Care must be taken if other elements are deleted or
 * inserted.  Next may be updated within the loop to alter the item
 * used in the next iteration. */
#define	queue_Scan(q, qe, next,	s)			\
    (qe) = queue_First(q, s), next = queue_Next(qe, s);	\
	!queue_IsEnd(q,	qe);				\
	(qe) = (next), next = queue_Next(qe, s)

/* similar to queue_Scan except start at element 'start' instead of the beginning */
#define        queue_ScanFrom(q, start, qe, next, s)      \
    (qe) = (struct s*)(start), next = queue_Next(qe, s);  \
       !queue_IsEnd(q, qe);                               \
       (qe) = (next), next = queue_Next(qe, s)

/* This is similar to queue_Scan, but scans from the end of the queue to the beginning.  Next is the previous queue entry.  */
#define	queue_ScanBackwards(q, qe, prev, s)		\
    (qe) = queue_Last(q, s), prev = queue_Prev(qe, s);	\
	!queue_IsEnd(q,	qe);				\
	(qe) = prev, prev = queue_Prev(qe, s)

/* This is similar to queue_ScanBackwards, but start at element 'start' instead of the end.  Next is the previous queue entry.  */
#define        queue_ScanBackwardsFrom(q, start, qe, prev, s)  \
    (qe) = (struct s*)(start), prev = queue_Prev(qe, s);       \
       !queue_IsEnd(q, qe);                                    \
       (qe) = prev, prev = queue_Prev(qe, s)

#define queue_Count(q, qe, nqe, s, n) 			\
    for (n=0, queue_Scan(q, qe, nqe, s), n++) {}
#endif /* _RX_QUEUE_ */

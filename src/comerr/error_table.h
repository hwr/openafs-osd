/*
 * Copyright 1988 by the Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * For copyright info, see mit-sipb-cr.h.
 */

#include <sys/types.h>
#include <errno.h>

#ifndef _AFS_ET_H

struct error_table {
    char const *const *msgs;
    int base;
    int n_msgs;
};
struct et_list {
    struct et_list *next;
    const struct error_table *table;
};


#define	ERRCODE_RANGE	8	/* # of bits to shift table number */
#define	BITS_PER_CHAR	6	/* # bits to shift per character in name */

extern char const *afs_error_table_name(int num);
extern void afs_add_to_error_table(struct et_list *new_table);
extern const char *afs_com_right(struct et_list *list, long code);
extern const char *afs_com_right_r(struct et_list *list, long code, char *str, size_t len);

#ifdef AFS_OLD_COM_ERR
#define error_table_name        afs_error_table_name
#define add_to_error_table(X) afs_add_to_error_table(X)
#endif /* AFS_OLD_COM_ERR */
#define _AFS_ET_H
#endif

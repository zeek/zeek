/*
 * See the file "COPYING" in the main distribution directory for copyright.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <math.h>

#ifdef CQ_DEVELOPMENT
#include <lbl/gnuc.h>
#include <lbl/os-proto.h>
#endif

#include "cq.h"

/* Priority to virtual bucket (int) */
#define PRI2VBUCKET(hp, p) ((int)((p) / (hp)->bwidth))

/* Priority to bucket (int) */
#define PRI2BUCKET(hp, p) \
    ((int)fmod((p) / (hp)->bwidth, (double)((hp)->nbuckets)))

/* Priority to bucket top (double) */
#define PRI2BUCKETTOP(hp, p) ((hp)->bwidth * (((p) / (hp)->bwidth) + 1.5))

/* True if bucket is in use */
#define BUCKETINUSE(bp) ((bp)->cookie != NULL)

/* Private data */
struct cq_handle {
	int nbuckets;			/* number of buckets */
	int qlen;			/* number of queued entries */
	int max_qlen;			/* max. number of queued entries */
	int himark;			/* high bucket threshold */
	int lowmark;			/* low bucket threshold */
	int nextbucket;			/* next bucket to check */
	int noresize;			/* don't resize while we're resizing */
	double lastpri;			/* last priority */
	double ysize;			/* length of a year */
	double bwidth;			/* width of each bucket */
	double buckettop;		/* priority of top of current bucket */
	struct cq_bucket *buckets;	/* array of buckets */
};

struct cq_bucket {
	double pri;
	void *cookie;
	struct cq_bucket *next;
};

#ifdef DEBUG
#ifdef CQ_DEVELOPMENT
extern int debug;
#else
int debug = 0;
#endif
#endif

static unsigned int memory_allocation = 0;

static struct cq_bucket *free_list = 0;

/* Forwards */
static int cq_resize(struct cq_handle *, int);
static void cq_destroybuckets(struct cq_bucket *, int);
#ifdef DEBUG
static int cq_debugbucket(struct cq_handle *, struct cq_bucket *);
void cq_debug(struct cq_handle *, int);
#endif


/* Initialize a calendar queue */
struct cq_handle *
cq_init(register double ysize, register double placebo)
{
	register struct cq_handle *hp;

#ifdef DEBUG
	if (debug > 1)
		fprintf(stderr, "cq_init(%f)\n", ysize);
#endif
	/* The year size be positive */
	if (ysize <= 0.0) {
		errno = EINVAL;
		return (NULL);
	}

	/* Allocate handle */
	hp = (struct cq_handle *)malloc(sizeof(*hp));
	memory_allocation += sizeof(*hp);
	if (hp == NULL)
		return (NULL);
	memset(hp, 0, sizeof(*hp));

	/* Initialize handle */
	hp->ysize = ysize;
	hp->max_qlen = 0;

	/* Allocate initial buckets and finish handle initialization */
	if (cq_resize(hp, 0) < 0) {
		free(hp);
		memory_allocation -= sizeof(*hp);
		return (NULL);
	}
	return (hp);
}

/* Returns zero on success, -1 on error (with errno set) */
int
cq_enqueue(register struct cq_handle *hp, register double pri,
    register void *cookie)
{
	register struct cq_bucket *bp, *bp2;
#ifdef DEBUG
	register int q1, q2;
	register struct cq_bucket *buckethead;
#endif

#ifdef DEBUG
	if (debug > 1)
		fprintf(stderr, "cq_enqueue(%f)\n", pri);
#endif

	/* The priority must be positive and the cookie non-null */
	if (pri <= 0.0 || cookie == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* We might as well resize now if we're going to need to */
	if (hp->qlen + 1 > hp->himark && cq_resize(hp, 1) < 0)
		return (-1);

	bp = hp->buckets + PRI2BUCKET(hp, pri);
#ifdef DEBUG
	if (debug) {
		buckethead = bp;
		q1 = cq_debugbucket(hp, buckethead);
	} else {
		buckethead = NULL;
		q1 = 0;
	}
#endif
	if (BUCKETINUSE(bp)) {
		/* Allocate chained bucket */
		if (free_list) {
			bp2 = free_list;
			free_list = free_list->next;
		} else {
			bp2 = (struct cq_bucket *)malloc(sizeof(*bp2));
			memory_allocation += sizeof(*bp2);
			if (bp2 == NULL)
				return (-1);
		}
		memset(bp2, 0, sizeof(*bp2));
		if (pri < bp->pri) {
			/* Insert new bucket at head of queue */
			*bp2 = *bp;
			bp->next = bp2;
		} else {
			/* Insert entry in order (fifo when pri's are equal) */
			while (bp->next != NULL && pri >= bp->next->pri)
				bp = bp->next;
			bp2->next = bp->next;
			bp->next = bp2;
			bp = bp2;
		}
	}
	bp->pri = pri;
	bp->cookie = cookie;
	if (++hp->qlen > hp->max_qlen)
		hp->max_qlen = hp->qlen;
#ifdef DEBUG
	if (debug) {
		q2 = cq_debugbucket(hp, buckethead);
		if (q1 + 1 != q2) {
			fprintf(stderr, "enqueue length wrong\n");
			cq_dump(hp);
			abort();
		}
	}
#endif

	/* If new priority is old, we need to recalculate nextbucket */
	if (hp->lastpri == 0.0 || hp->lastpri > pri) {
		hp->lastpri = pri;
		hp->nextbucket = PRI2BUCKET(hp, hp->lastpri);
		hp->buckettop = PRI2BUCKETTOP(hp, hp->lastpri);
	}
#ifdef notdef
	if (debug)
		cq_debug(hp, 0);
#endif
	return (0);
}

void *
cq_dequeue(register struct cq_handle *hp, double pri)
{
	register int n;
	register struct cq_bucket *bp, *bp2, *lowbp;
	register void *cookie;

#ifdef DEBUG
	if (debug > 1)
		fprintf(stderr, "cq_dequeue(%f)\n", pri);
#endif
	if (pri < hp->lastpri)
		/* For sure nothing to do. */
		return (NULL);

	lowbp = NULL;
	for (n = hp->nbuckets, bp = hp->buckets + hp->nextbucket; n > 0; --n) {
		/* Check bucket if it contains an entry (in the current year) */
		if (BUCKETINUSE(bp)) {
			if (bp->pri < hp->buckettop) {
				/* Check first entry in this bucket */
				if (pri >= bp->pri) {
					cookie = bp->cookie;
					hp->lastpri = bp->pri;
					/* Shouldn't nextbucket now point here?? */
					hp->nextbucket = PRI2BUCKET(hp, hp->lastpri);
					hp->buckettop = PRI2BUCKETTOP(hp, hp->lastpri);
					if (bp->next == NULL) {
						/* Zero out first entry */
						bp->pri = 0.0;
						bp->cookie = NULL;
					} else {
						/* Update 1st entry with next */
						bp2 = bp->next;
						*bp = *bp2;
						bp2->next = free_list;
						free_list = bp2;
						/* free(bp2); */
					}
					--hp->qlen;
					if (hp->qlen < hp->lowmark)
						(void)cq_resize(hp, 0);
#ifdef notdef
					if (debug)
						cq_debug(hp, 0);
#endif
					return (cookie);
				}

				/* The first entry is in the current year
				 * but comes after pri.  This means we're
				 * not going to find *any* subsequent entries
				 * that come before pri.  So we're done.
				 */
				hp->lastpri = bp->pri;
				hp->nextbucket = PRI2BUCKET(hp, hp->lastpri);
				hp->buckettop = PRI2BUCKETTOP(hp, hp->lastpri);
				return (NULL);
#if 0
				/* Search linked list */
				/* Why is this necessary?  Since the list
				 * is sorted, and we already know that the
				 * first entry has too high a priority,
				 * none of the others can be ready to
				 * dequeue, right??
				 */
				for (bp2 = bp; (bp3 = bp2->next) != NULL;
				    bp2 = bp3) {
					/* Don't look past end of bucket */
					if (bp3->pri >= hp->buckettop)
						break;
					if (pri >= bp3->pri) {
						/* Unlink entry */
						cookie = bp3->cookie;
						hp->lastpri = bp->pri;
						bp2->next = bp3->next;
						free(bp3);
						memory_allocation -= sizeof(*bp3);
						--hp->qlen;
						if (hp->qlen < hp->lowmark)
							(void)cq_resize(hp, 0);
						return (cookie);
					}
				}
#endif
			}

			/* Keep track of lowest priority bucket */
			if (lowbp == NULL || lowbp->pri > bp->pri)
				lowbp = bp;
		}

		/* Step to next bucket */
		hp->buckettop += hp->bwidth;
		++hp->nextbucket;
		if (hp->nextbucket < hp->nbuckets)
			++bp;
		else {
			bp = hp->buckets;
			hp->nextbucket = 0;
		}
	}

	/*
	 * If we got here, we checked all the buckets but came up
	 * empty. This can happen when the queued priorities are
	 * really sparse (e.g. when there is more than a year
	 * between two adjacent entries).
	 *
	 * If there was at least one bucket in use, check to see
	 * if it's the one we're looking for. Also, update nextbucket
	 * (and buckettop) with this bucket.
	 */
	if (lowbp != NULL) {
		cookie = NULL;
		bp = lowbp;
		if (pri >= bp->pri) {
			cookie = bp->cookie;
			if (bp->next == NULL) {
				/* Zero out first entry */
				bp->pri = 0.0;
				bp->cookie = NULL;
			} else {
				/* Update 1st entry with next */
				bp2 = bp->next;
				*bp = *bp2;
				bp2->next = free_list;
				free_list = bp2;
				/* free(bp2); */
			}
			--hp->qlen;
			/* If we resize, we don't need to update */
			if (hp->qlen < hp->lowmark) {
				(void)cq_resize(hp, 0);
				return (cookie);
			}
		}
		hp->lastpri = lowbp->pri;
		hp->nextbucket = PRI2BUCKET(hp, hp->lastpri);
		hp->buckettop = PRI2BUCKETTOP(hp, hp->lastpri);
		if (cookie != NULL)
			return (cookie);
	}

	/* Checked all buckets */
	return (NULL);
}

void *
cq_remove(register struct cq_handle *hp, register double pri,
		            register void *cookie)
{
	register struct cq_bucket *bp, *bp2;

	/* The priority must be positive and the cookie non-null */
	if (pri <= 0.0 || cookie == NULL)
		return (-0);

	bp = hp->buckets + PRI2BUCKET(hp, pri);
	if (! BUCKETINUSE(bp))
		return (0);

	for ( bp2 = 0; bp && cookie != bp->cookie; bp = bp->next ) {
		if ( pri < bp->pri )
			return (0);
		bp2 = bp;
		}

	if ( ! bp )
		return (-0);

	/* Unlink entry */
	if ( ! bp2 ) {
		/* Remove first element */
		if ( ! bp->next ) {
			/* Zero out first entry */
			bp->pri = 0.0;
			bp->cookie = NULL;
		} else {
			/* Update 1st entry with next */
			bp2 = bp->next;
			*bp = *bp2;
			bp2->next = free_list;
			free_list = bp2;
		}
	}
	else {
		/* Remove not-first element */
		bp2->next = bp->next;
		bp->next = free_list;
		free_list = bp;
	}
	--hp->qlen;

	if (hp->qlen < hp->lowmark)
		(void)cq_resize(hp, 0);

	/* buckettop etc. don't need to be updated, right? */
	return cookie;
}

int
cq_size(struct cq_handle *hp)
{
	return hp->qlen;
}

int
cq_max_size(struct cq_handle *hp)
{
	return hp->max_qlen;
}

/* Return without doing anything if we fail to allocate a new bucket array */
static int
cq_resize(register struct cq_handle *hp, register int grow)
{
	register int n, nbuckets, oldnbuckets;
	register size_t size;
	register struct cq_bucket *bp, *bp2, *buckets, *oldbuckets;
	struct cq_handle savedhandle;

	if (hp->noresize)
		return (0);
#ifdef DEBUG
	if (debug)
		cq_debug(hp, 0);
#endif

	/* Save old bucket array */
	oldnbuckets = hp->nbuckets;
	oldbuckets = hp->buckets;

	/* If no old buckets, we're initializing */
	if (oldbuckets == NULL)
		nbuckets = 2;
	else if (grow)
		nbuckets = oldnbuckets * 2;
	else
		nbuckets = oldnbuckets / 2;

	/* XXX could check that nbuckets is a power of 2 */

	size = sizeof(*buckets) * nbuckets;
	buckets = (struct cq_bucket *)malloc(size);
	memory_allocation += size;

	if (buckets == NULL)
		return (-1);
	memset(buckets, 0, size);

	/* Save a copy of the handle in case we have dynamic memory problems */
	savedhandle = *hp;

	/* Install new bucket array */
	hp->nbuckets = nbuckets;
	hp->buckets = buckets;

	/* Initialize other parameters */
	hp->himark = hp->nbuckets * 1.5;
	hp->lowmark = (hp->nbuckets / 2) - 2;
	hp->bwidth = hp->ysize / (double)hp->nbuckets;

	/* Tell cq_enqueue() to update nextbucket and buckettop */
	hp->lastpri = 0.0;

#ifdef DEBUG
	if (debug > 1)
		fprintf(stderr,
		    "buckets 0x%lx, nbuckets %d, bwidth %f, buckettop %f\n",
		    (u_long)hp->buckets,
		    hp->nbuckets,
		    hp->bwidth, hp->buckettop);
#endif

	/* We're done if we were just initializing */
	if (oldbuckets == NULL)
		return (0);

	/* Insert entries from old bucket array into new one */
	++hp->noresize;
	hp->qlen = 0;
	for (bp = oldbuckets, n = oldnbuckets; n > 0; --n, ++bp)
		if (BUCKETINUSE(bp))
			for (bp2 = bp; bp2 != NULL; bp2 = bp2->next) {
				if (cq_enqueue(hp, bp2->pri, bp2->cookie) < 0) {
					/* Bummer! */
					*hp = savedhandle;
					/* hp->resize restored */
					cq_destroybuckets(buckets, nbuckets);
					free(buckets);
					memory_allocation -= size;
					return (-1);
				}
			}
	--hp->noresize;

	cq_destroybuckets(oldbuckets, oldnbuckets);
	free(oldbuckets);
	memory_allocation -= sizeof(*buckets) * oldnbuckets;
#ifdef DEBUG
	if (debug)
		cq_debug(hp, 0);
#endif
	return (0);
}

static void
cq_destroybuckets(register struct cq_bucket *buckets, register int n)
{
	register struct cq_bucket *bp, *bp2, *bp3;

	for (bp = buckets; n > 0; --n, ++bp) {
		bp2 = bp->next;
		while (bp2 != NULL) {
			bp3 = bp2->next;
			bp2->next = free_list;
			free_list = bp2;
			/* free(bp2); */
			bp2 = bp3;
		}
	}
}

/* Destroy a calendar queue */
void
cq_destroy(register struct cq_handle *hp)
{

	cq_destroybuckets(hp->buckets, hp->nbuckets);
	while (free_list) {
		struct cq_bucket *next_free = free_list->next;
		free(free_list);
		free_list = next_free;
	}
	memory_allocation -= sizeof(struct cq_bucket) * hp->nbuckets;
	free(hp->buckets);
	free(hp);
	memory_allocation -= sizeof(*hp);
}

unsigned int
cq_memory_allocation(void)
{
	return memory_allocation;
}

#ifdef DEBUG
static int
cq_debugbucket(register struct cq_handle *hp,
    register struct cq_bucket *buckets)
{
	register int qlen;
	register struct cq_bucket *bp, *bp2;
	double pri;

	qlen = 0;
	pri = 0.0;
	for (bp = buckets; bp != NULL; bp = bp->next) {
		if (BUCKETINUSE(bp)) {
			++qlen;
			bp2 = hp->buckets + PRI2BUCKET(hp, bp->pri);
			if (bp2 != buckets) {
				fprintf(stderr,
				    "%f in wrong bucket! (off by %ld)\n",
				    bp->pri, (long)(bp2 - buckets));
				cq_dump(hp);
				abort();
			}
			if (bp->pri < pri) {
				fprintf(stderr,
				    "bad pri order %f < %f (qlen %d)\n",
				    bp->pri, pri, qlen);
				cq_dump(hp);
				abort();
			}
			pri = bp->pri;
		}
	}
	return (qlen);
}

void
cq_debug(register struct cq_handle *hp, register int print)
{
	register int n, qlen, xnextbucket, nextbucket;
	register struct cq_bucket *bp, *lowbp;
	register double xbuckettop, buckettop;

	qlen = 0;
	lowbp = NULL;
	bp = hp->buckets + hp->nextbucket;
	for (n = hp->nbuckets; n > 0; --n) {
		if (BUCKETINUSE(bp) && (lowbp == NULL || lowbp->pri > bp->pri))
			lowbp = bp;

		qlen += cq_debugbucket(hp, bp);

		/* Step to next bucket */
		++bp;
		if (bp >= hp->buckets + hp->nbuckets)
			bp = hp->buckets;
	}

	if (lowbp != NULL) {
		/* We expect lastpri gt or eq to the lowest queued priority */
		if (lowbp->pri < hp->lastpri) {
			fprintf(stderr, "lastpri wacked (%f < %f)\n",
			    lowbp->pri, hp->lastpri);
			cq_dump(hp);
			abort();
		}

		/* Must search for the next entry just as cq_dequeue() would */
		nextbucket = hp->nextbucket;
		buckettop = hp->buckettop;
		bp = hp->buckets + nextbucket;
		for (n = hp->nbuckets; n > 0; --n) {
			if (BUCKETINUSE(bp) && bp->pri < buckettop)
				break;

			/* Step to next bucket */
			++bp;
			++nextbucket;
			buckettop += hp->bwidth;
			if (bp >= hp->buckets + hp->nbuckets) {
				bp = hp->buckets;
				nextbucket = 0;
			}
		}

		xnextbucket = PRI2BUCKET(hp, lowbp->pri);
		if (xnextbucket != nextbucket) {
			fprintf(stderr, "nextbucket wacked (%d != %d)\n",
			     xnextbucket, nextbucket);
			cq_dump(hp);
			abort();
		}

		xbuckettop = PRI2BUCKETTOP(hp, lowbp->pri);
		if (xbuckettop != buckettop) {
			fprintf(stderr, "buckettop wacked (%f != %f)\n",
			    xbuckettop, buckettop);
			cq_dump(hp);
			abort();
		}
	}
	if (qlen != hp->qlen) {
		fprintf(stderr, "qlen wacked (%d != %d)\n", qlen, hp->qlen);
		cq_dump(hp);
		abort();
	}
}

void
cq_dump(register struct cq_handle *hp)
{
	// ### FIXME
	register struct cq_bucket *bp, *bp2;
	register int n;

	fprintf(stderr,
	    "\ncq_dump(): nbucket %d, qlen %d, nextbucket %d, lastpri %f\n",
	    hp->nbuckets, hp->qlen, hp->nextbucket, hp->lastpri);
	fprintf(stderr, "\tysize %f, bwidth %f, buckettop %f\n",
	    hp->ysize, hp->bwidth, hp->buckettop);

	bp = hp->buckets;
	for (n = 0, bp = hp->buckets; n < hp->nbuckets; ++n, ++bp) {
		fprintf(stderr, "  %c %2d: %f (0x%lx)\n",
		    (n == hp->nextbucket) ? '+' : ' ', n,
		    bp->pri, (u_long)bp->cookie);
		for (bp2 = bp->next; bp2 != NULL; bp2 = bp2->next)
			fprintf(stderr, "        %f (0x%lx)\n",
			    bp2->pri, (u_long)bp2->cookie);
	}
}
#endif

struct cq_handle *cq_init(double, double);
void cq_destroy(struct cq_handle *);
int cq_enqueue(struct cq_handle *, double, void *);
void *cq_dequeue(struct cq_handle *, double);
void *cq_remove(struct cq_handle *, double, void *);
int cq_size(struct cq_handle *);
int cq_max_size(struct cq_handle *);
unsigned int cq_memory_allocation(void);
#ifdef DEBUG
void cq_debug(struct cq_handle *, int);
void cq_dump(struct cq_handle *);
#endif

/*
       B R O C C O L I  --  The Bro Client Communications Library

Copyright (C) 2004-2008 Christian Kreibich <christian (at) icir.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies of the Software and its documentation and acknowledgment shall be
given in the documentation and software packages that this Software was
used.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#ifndef broccoli_sem_h
#define broccoli_sem_h

#include <broccoli.h>

typedef struct bro_sem_impl BroSemImpl;

typedef struct bro_sem {
  int          sem_blocked;
  BroSemImpl  *sem_impl;
} BroSem;

/* Broccoli semaphore abstractions.
 * ================================
 *
 * Semaphores are created with __bro_sem_new() and released with
 * __bro_sem_free(). Before being used they have to be
 * __bro_sem_attach()ed and after using them __bro_sem_detach()ed.
 *
 * Semaphores are initalized to 0.
 *
 * All functions can be called with NULL parameters, for robustness.
 */

int     __bro_sem_init(BroSem *sem, const BroConn *bc);
void    __bro_sem_cleanup(BroSem *sem);

int     __bro_sem_attach(BroSem *sem);
int     __bro_sem_detach(BroSem *sem);

/**
 * __bro_sem_decr - decreases semaphore.
 * @sem: semaphore.
 *
 * The function decreases the value of the semaphore by one, returning
 * if the initial value was greater than 0, and blocking otherwise.
 * 
 * Returns: %TRUE on success, %FALSE otherwise.
 */
int     __bro_sem_decr(BroSem *sem);


/**
 * __bro_sem_trydecr - decreases semaphore, but never blocks
 * @sem: semaphore.
 *
 * The function decreases the value of the semaphore by one, returning
 * if the initial value was greater than 0. If the semaphore is
 * currently locked, the function returns %FALSE immediately.
 * 
 * Returns: %TRUE on success, %FALSE otherwise.
 */
int     __bro_sem_trydecr(BroSem *sem);


/**
 * __bro_sem_incr - increases semaphore.
 * @sem: semaphore.
 *
 * The function increases the value of the semaphore by 1.
 *
 * Returns: %TRUE on success, %FALSE otherwise.
 */
int     __bro_sem_incr(BroSem *sem);


/**
 * __bro_sem_get - returns current value of sempahore.
 * @sem: semaphore.
 * @result: result pointer.
 *
 * The function returns the current value of the semaphore through
 * the @result pointer.
 *
 * Returns: %TRUE on success, %FALSE otherwise.
 */
int     __bro_sem_get(BroSem *sem, int *result);

int     __bro_sem_get_blocked(BroSem *sem, int *result);

#endif

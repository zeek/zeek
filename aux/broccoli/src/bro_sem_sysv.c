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
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#include <bro_debug.h>
#include <bro_util.h>
#include <bro_openssl.h>
#include <bro_sem.h>

#define BRO_SEM_ATTEMPTS_MAX 50

#ifdef SEM_R
#define BRO_SEMFLAGS SEM_A|SEM_R
#else
#define BRO_SEMFLAGS S_IRWXU
#endif

/* It's not my fault -- blame the standards and deviating
 * implementations for this goop. :(
 */
#if defined(BSD_HOST) && ! defined(__NetBSD__)
/* union semun is defined by including <sys/sem.h> */
#else
/* according to X/OPEN we have to define it ourselves */
union semun {
  int val;                  /* value for SETVAL */
  struct semid_ds *buf;     /* buffer for IPC_STAT, IPC_SET */
  unsigned short *array;    /* array for GETALL, SETALL */
  /* Linux specific part: */
  struct seminfo *__buf;    /* buffer for IPC_INFO */
};
#endif


struct bro_sem_impl { 
  int      sem_id;
};


int
__bro_sem_init(BroSem *sem, const BroConn *bc)
{
  int sem_id = -1;
  union semun arg;

  D_ENTER;

  if (! sem || ! sem->sem_impl)
    D_RETURN_(FALSE);

  memset(sem, 0, sizeof(BroSem));

  /* Attempt to allocate the semaphore set */
  if ( (sem_id = semget(IPC_PRIVATE, 1, IPC_CREAT|IPC_EXCL|BRO_SEMFLAGS)) < 0)
    {
      D(("semget error: %s\n", strerror(errno)));
      D_RETURN_(FALSE);
    }
  
  /* Initialize the semaphore. Note: I'm not 100% sure whether this
   * code is prone to the race condition that Stevens describes on
   * p. 284 of UNP Vol 2 (IPC). It would likely be safer to take
   * precautions, this is a FIXME.
   */
  arg.val = 1;
  if (semctl(sem_id, 0, SETVAL, arg) < 0)
    {
      D(("semctl failed: %s\n", strerror(errno)));
      D_RETURN_(FALSE);
    }
  
  if (! (sem->sem_impl = calloc(1, sizeof(BroSemImpl))))
    D_RETURN_(FALSE);
  
  sem->sem_impl->sem_id = sem_id;
  
  D_RETURN_(TRUE);
  bc = NULL;
}


void
__bro_sem_cleanup(BroSem *sem)
{
  D_ENTER;

  if (! sem || ! sem->sem_impl)
    D_RETURN;
  
  if (semctl(sem->sem_impl->sem_id, 0, IPC_RMID) < 0)
    {
      D(("semctl could not remove semaphore: %s.\n", strerror(errno)));
    }
  
  free(sem->sem_impl);
  memset(sem, 0, sizeof(BroSem));
  D_RETURN;
}


int
__bro_sem_attach(BroSem *sem)
{
  /* Unused in SYSV. */
  return TRUE;
  sem = NULL;
}


int
__bro_sem_detach(BroSem *sem)
{
  /* Unused in SYSV. */
  return TRUE;
  sem = NULL;
}


int
__bro_sem_decr(BroSem *sem)
{
  struct sembuf opt;

  if (! sem || ! sem->sem_impl)
    return FALSE;

  /* This hopefully does the following atomically:
   * 
   * (1) block until the semaphore's value becomes >= 1
   * (2) subtracts 1 from the semaphore's value (i.e., sets it to 0)
   * (3) wakes up thread.
   *
   * This is how I parse Stevens UNP Vol 2 (IPC), p. 287.
   */
  opt.sem_num =  0;
  opt.sem_op  = -1;
  opt.sem_flg =  0;
  sem->sem_blocked++;

  if (semop(sem->sem_impl->sem_id, &opt, 1) < 0)
    {
      sem->sem_blocked--;
      return FALSE;
    }
  
  sem->sem_blocked--;
  return TRUE;
}


int
__bro_sem_trydecr(BroSem *sem)
{
  struct sembuf opt;

  if (! sem || ! sem->sem_impl)
    return FALSE;

  opt.sem_num =  0;
  opt.sem_op  = -1;
  opt.sem_flg =  IPC_NOWAIT;
  sem->sem_blocked++;

  if (semop(sem->sem_impl->sem_id, &opt, 1) < 0)
    {
      sem->sem_blocked--;
      return FALSE;
    }

  sem->sem_blocked--;
  return TRUE;
}


int
__bro_sem_incr(BroSem *sem)
{
  struct sembuf opt;
  
  if (! sem || ! sem->sem_impl)
    return FALSE;
  
  /* Add one to the semaphore's value. That one should
   * be easy ...
   */
  opt.sem_num =  0;
  opt.sem_op  =  1;
  opt.sem_flg =  0;
  
  if (semop(sem->sem_impl->sem_id, &opt, 1) < 0)
    return FALSE;
  
  return TRUE;
}


int
__bro_sem_get(BroSem *sem, int *result)
{
  if (! sem || ! sem->sem_impl || ! result)
    return FALSE;
  
  if (semctl(sem->sem_impl->sem_id, 0, GETVAL, result) < 0)
    {
      D(("semctl failed: %s\n", strerror(errno)));
      return FALSE;
    }
  
  return TRUE;
}


int
__bro_sem_get_blocked(BroSem *sem, int *result)
{
  if (! sem || ! sem->sem_impl || ! result)
    return FALSE;
  
  *result = sem->sem_blocked;
  
  return TRUE;
}

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
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <semaphore.h>
#include <errno.h>

#ifdef __EMX__
#include <strings.h>
#endif 

#include <bro_debug.h>
#include <bro_util.h>
#include <bro_types.h>
#include <bro_sem.h>

struct bro_sem_impl { 
  char    *name;
  sem_t   *sem;
};

int
__bro_sem_init(BroSem *sem, const BroConn *bc)
{
  static int counter = 0;
  char sem_name[512]; 
  
  D_ENTER;
  
  if (! sem || ! bc)
    D_RETURN_(FALSE);
  
  memset(sem, 0, sizeof(BroSem));
  
  if (! (sem->sem_impl = calloc(1, sizeof(BroSemImpl))))
    D_RETURN_(FALSE);
  
  __bro_util_snprintf(sem_name, 512, "/broccoli-%u-%i-%i", bc->id_pid, bc->id_num, counter++);
  sem->sem_impl->name = strdup(sem_name);
  sem->sem_impl->sem = sem_open(sem_name, O_CREAT, S_IRWXU, 1);
  
  if (sem->sem_impl->sem == SEM_FAILED)
    {
      if (sem->sem_impl->name)
	free(sem->sem_impl->name);
      
      free(sem->sem_impl);
      
      D(("POSIX semaphore creation failed: %s\n", strerror(errno)));
      D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}


void
__bro_sem_cleanup(BroSem *sem)
{
  D_ENTER;
  
  if (! sem || ! sem->sem_impl)
    D_RETURN;
  
  sem_unlink(sem->sem_impl->name);
  
  free(sem->sem_impl->name);
  free(sem->sem_impl);
  memset(sem, 0, sizeof(BroSem));
  
  D_RETURN;
}


int
__bro_sem_attach(BroSem *sem)
{
  /* Unused in Posix. */
  return TRUE;
  sem = NULL;
}


int
__bro_sem_detach(BroSem *sem)
{
  if (! sem || ! sem->sem_impl)
    return FALSE;

  sem_close(sem->sem_impl->sem);
  return TRUE;
}


int
__bro_sem_decr(BroSem *sem)
{
  D_ENTER;
  
  if (! sem || ! sem->sem_impl)
    D_RETURN_(FALSE);

  sem->sem_blocked++;

  if (sem_wait(sem->sem_impl->sem) < 0)
    {
      D(("sem_wait() error: %s\n", strerror(errno)));
      sem->sem_blocked--;
      D_RETURN_(FALSE);
    }
  
  sem->sem_blocked--;
  D_RETURN_(TRUE);
}


int
__bro_sem_trydecr(BroSem *sem)
{
  if (! sem || ! sem->sem_impl)
    return FALSE;

  sem->sem_blocked++;

  if (sem_trywait(sem->sem_impl->sem) < 0)
    {
      sem->sem_blocked--;

      if (errno == EAGAIN)
	return FALSE;

      D(("sem_wait() error: %s\n", strerror(errno)));
      return FALSE;
    }
  
  sem->sem_blocked--;
  return TRUE;
}


int
__bro_sem_incr(BroSem *sem)
{
  D_ENTER;

  if (! sem || ! sem->sem_impl)
    D_RETURN_(FALSE);

  if (sem_post(sem->sem_impl->sem) < 0)
    {
      D(("sem_post() error: %s\n", strerror(errno)));
      D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}


int
__bro_sem_get(BroSem *sem, int *result)
{
  if (! sem || ! sem->sem_impl || ! result)
    return FALSE;

  if (! sem_getvalue(sem->sem_impl->sem, result))
    return FALSE;
  
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

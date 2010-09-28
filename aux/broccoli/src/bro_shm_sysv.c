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
#include <sys/stat.h>
#include <sys/shm.h>
#include <errno.h>
#include <string.h>

#include <bro_debug.h>
#include <bro_shm.h>

struct bro_shared_mem {
  int      shm_id;
  int      shm_size;
  void    *shm_mem;

  int      shm_attached;
};

BroSharedMem  *
__bro_shm_new(int size)
{
  int shm_id;
  BroSharedMem *shm;

  if (size <= 0)
    return NULL;

  if ( (shm_id = shmget(IPC_PRIVATE,size,  IPC_CREAT|IPC_EXCL|S_IRWXU)) < 0)
    {
      D(("shmget error: %s\n", strerror(errno)));
      return NULL;
    }
  
  if (! (shm = calloc(1, sizeof(BroSharedMem))))
    return NULL;
  
  shm->shm_id = shm_id;
  shm->shm_size = size;

  return shm;
}


void
__bro_shm_free(BroSharedMem *shm)
{
  if (! shm)
    return;

  shmctl(shm->shm_id, IPC_RMID, NULL);
  free(shm);
}


void *
__bro_shm_get_mem(const BroSharedMem *shm)
{
  if (! shm || ! shm->shm_attached)
    return NULL;
  
  return shm->shm_mem;
}


int
__bro_shm_get_size(const BroSharedMem *shm)
{
  return shm->shm_size;
}



int
__bro_shm_attach(BroSharedMem *shm)
{
  if (! shm)
    return FALSE;

  shm->shm_mem = shmat(shm->shm_id, NULL, 0);
  
  if ((int) shm->shm_mem == -1)
    {
      D(("shmat problem: %s.\n", strerror(errno)));
      return FALSE;
    }

  shm->shm_attached = TRUE;
  return TRUE;
}


int
__bro_shm_detach(BroSharedMem *shm)
{
  if (! shm || ! shm->shm_attached)
    return FALSE;

  if (shmdt(shm->shm_mem) < 0)
    {
      D(("shmdt problem: %s.\n", strerror(errno)));
      return FALSE;
    }
 
  return TRUE;
}

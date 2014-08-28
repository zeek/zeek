// See the file "COPYING" in the main distribution directory for copyright.

#include "Flare.h"
#include "util.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

using namespace bro;

Flare::Flare()
	: pipe(FD_CLOEXEC, FD_CLOEXEC, O_NONBLOCK, O_NONBLOCK)
	{
	}

void Flare::Fire()
	{
	char tmp;
	safe_write(pipe.WriteFD(), &tmp, 1);
	}

void Flare::Extinguish()
	{
	char tmp[256];

	for ( ; ; )
		if ( read(pipe.ReadFD(), &tmp, sizeof(tmp)) == -1 && errno == EAGAIN )
			break;
	}

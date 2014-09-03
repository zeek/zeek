// See the file "COPYING" in the main distribution directory for copyright.

#include "Flare.h"
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

	for ( ; ; )
		{
		int n = write(pipe.WriteFD(), &tmp, 1);

		if ( n > 0 )
			// Success -- wrote a byte to pipe.
			break;

		if ( n < 0 && errno == EAGAIN )
			// Success -- pipe is full and just need at least one byte in it.
			break;

		// Loop because either the byte wasn't written or got EINTR error.
		}
	}

void Flare::Extinguish()
	{
	char tmp[256];

	for ( ; ; )
		if ( read(pipe.ReadFD(), &tmp, sizeof(tmp)) == -1 && errno == EAGAIN )
			// Pipe is now drained.
			break;
	}

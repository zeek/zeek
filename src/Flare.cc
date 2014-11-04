// See the file "COPYING" in the main distribution directory for copyright.

#include "Flare.h"
#include "Reporter.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

using namespace bro;

Flare::Flare()
	: pipe(FD_CLOEXEC, FD_CLOEXEC, O_NONBLOCK, O_NONBLOCK)
	{
	}

static void bad_pipe_op(const char* which)
	{
	char buf[256];
	strerror_r(errno, buf, sizeof(buf));
	reporter->FatalErrorWithCore("unexpected pipe %s failure: %s", which, buf);
	}

void Flare::Fire()
	{
	char tmp = 0;

	for ( ; ; )
		{
		int n = write(pipe.WriteFD(), &tmp, 1);

		if ( n > 0 )
			// Success -- wrote a byte to pipe.
			break;

		if ( n < 0 )
			{
			if ( errno == EAGAIN )
				// Success: pipe is full and just need at least one byte in it.
				break;

			if ( errno == EINTR )
				// Interrupted: try again.
				continue;

			bad_pipe_op("write");
			}

		// No error, but didn't write a byte: try again.
		}
	}

void Flare::Extinguish()
	{
	char tmp[256];

	for ( ; ; )
		{
		int n = read(pipe.ReadFD(), &tmp, sizeof(tmp));

		if ( n >= 0 )
			// Pipe may not be empty yet: try again.
			continue;

		if ( errno == EAGAIN )
			// Success: pipe is now empty.
			break;

		if ( errno == EINTR )
			// Interrupted: try again.
			continue;

		bad_pipe_op("read");
		}
	}

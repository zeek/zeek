// See the file "COPYING" in the main distribution directory for copyright.

#include "Flare.h"
#include "Reporter.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

using namespace zeek::detail;

Flare::Flare()
	: pipe(FD_CLOEXEC, FD_CLOEXEC, O_NONBLOCK, O_NONBLOCK)
	{
	}

[[noreturn]] static void bad_pipe_op(const char* which, bool signal_safe)
	{
	if ( signal_safe )
		abort();

	char buf[256];
	zeek::util::zeek_strerror_r(errno, buf, sizeof(buf));

	if ( zeek::reporter )
		zeek::reporter->FatalErrorWithCore("unexpected pipe %s failure: %s", which, buf);
	else
		{
		fprintf(stderr, "unexpected pipe %s failure: %s", which, buf);
		abort();
		}
	}

void Flare::Fire(bool signal_safe)
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

			bad_pipe_op("write", signal_safe);
			}

		// No error, but didn't write a byte: try again.
		}
	}

int Flare::Extinguish(bool signal_safe)
	{
	int rval = 0;
	char tmp[256];

	for ( ; ; )
		{
		int n = read(pipe.ReadFD(), &tmp, sizeof(tmp));

		if ( n >= 0 )
			{
			rval += n;
			// Pipe may not be empty yet: try again.
			continue;
			}

		if ( errno == EAGAIN )
			// Success: pipe is now empty.
			break;

		if ( errno == EINTR )
			// Interrupted: try again.
			continue;

		bad_pipe_op("read", signal_safe);
		}

	return rval;
	}

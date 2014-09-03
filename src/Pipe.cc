// See the file "COPYING" in the main distribution directory for copyright.

#include "Pipe.h"
#include "Reporter.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstdio>

using namespace bro;

static void pipe_fail(int eno)
	{
	char tmp[256];
	strerror_r(eno, tmp, sizeof(tmp));
	reporter->FatalError("Pipe failure: %s", tmp);
	}

static void set_flags(int fd, int flags)
	{
	if ( flags )
		fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | flags);
	}

static void set_status_flags(int fd, int flags)
	{
	if ( flags )
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | flags);
	}

static int dup_or_fail(int fd, int flags)
	{
	int rval = dup(fd);

	if ( rval < 0 )
		pipe_fail(errno);

	set_flags(fd, flags);
	return rval;
	}

Pipe::Pipe(int flags0, int flags1, int status_flags0, int status_flags1)
	{
	// pipe2 can set flags atomically, but not yet available everywhere.
	if ( ::pipe(fds) )
		pipe_fail(errno);

	flags[0] = flags0;
	flags[1] = flags1;

	set_flags(fds[0], flags[0]);
	set_flags(fds[1], flags[1]);
	set_status_flags(fds[0], status_flags0);
	set_status_flags(fds[1], status_flags1);
	}

Pipe::~Pipe()
	{
	close(fds[0]);
	close(fds[1]);
	}

Pipe::Pipe(const Pipe& other)
	{
	fds[0] = dup_or_fail(other.fds[0], other.flags[0]);
	fds[1] = dup_or_fail(other.fds[1], other.flags[1]);
	flags[0] = other.flags[0];
	flags[1] = other.flags[1];
	}

Pipe& Pipe::operator=(const Pipe& other)
	{
	if ( this == &other )
		return *this;

	close(fds[0]);
	close(fds[1]);
	fds[0] = dup_or_fail(other.fds[0], other.flags[0]);
	fds[1] = dup_or_fail(other.fds[1], other.flags[1]);
	flags[0] = other.flags[0];
	flags[1] = other.flags[1];
	return *this;
	}

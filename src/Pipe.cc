// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Pipe.h"

#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>

#include "zeek/Reporter.h"

namespace zeek::detail
	{

static void pipe_fail(int eno)
	{
	char tmp[256];
	zeek::util::zeek_strerror_r(eno, tmp, sizeof(tmp));

	if ( reporter )
		reporter->FatalError("Pipe failure: %s", tmp);
	else
		fprintf(stderr, "Pipe failure: %s", tmp);
	}

static int set_flags(int fd, int flags)
	{
	auto rval = fcntl(fd, F_GETFD);

	if ( rval == -1 )
		pipe_fail(errno);

	if ( flags )
		{
		rval |= flags;

		if ( fcntl(fd, F_SETFD, rval) == -1 )
			pipe_fail(errno);
		}

	return rval;
	}

static int unset_flags(int fd, int flags)
	{
	auto rval = fcntl(fd, F_GETFD);

	if ( rval == -1 )
		pipe_fail(errno);

	if ( flags )
		{
		rval &= ~flags;

		if ( fcntl(fd, F_SETFD, rval) == -1 )
			pipe_fail(errno);
		}

	return rval;
	}

static int set_status_flags(int fd, int flags)
	{
	auto rval = fcntl(fd, F_GETFL);

	if ( rval == -1 )
		pipe_fail(errno);

	if ( flags )
		{
		rval |= flags;

		if ( fcntl(fd, F_SETFL, rval) == -1 )
			pipe_fail(errno);
		}

	return rval;
	}

static int dup_or_fail(int fd, int flags, int status_flags)
	{
	int rval = dup(fd);

	if ( rval < 0 )
		pipe_fail(errno);

	set_flags(fd, flags);
	set_status_flags(fd, status_flags);
	return rval;
	}

Pipe::Pipe(int flags0, int flags1, int status_flags0, int status_flags1, int* arg_fds)
	{
	if ( arg_fds )
		{
		fds[0] = arg_fds[0];
		fds[1] = arg_fds[1];
		}
	else
		{
		// pipe2 can set flags atomically, but not yet available everywhere.
		if ( ::pipe(fds) )
			pipe_fail(errno);
		}

	flags[0] = set_flags(fds[0], flags0);
	flags[1] = set_flags(fds[1], flags1);
	status_flags[0] = set_status_flags(fds[0], status_flags0);
	status_flags[1] = set_status_flags(fds[1], status_flags1);
	}

void Pipe::SetFlags(int arg_flags)
	{
	flags[0] = set_flags(fds[0], arg_flags);
	flags[1] = set_flags(fds[1], arg_flags);
	}

void Pipe::UnsetFlags(int arg_flags)
	{
	flags[0] = unset_flags(fds[0], arg_flags);
	flags[1] = unset_flags(fds[1], arg_flags);
	}

Pipe::~Pipe()
	{
	close(fds[0]);
	close(fds[1]);
	}

Pipe::Pipe(const Pipe& other)
	{
	fds[0] = dup_or_fail(other.fds[0], other.flags[0], other.status_flags[0]);
	fds[1] = dup_or_fail(other.fds[1], other.flags[1], other.status_flags[1]);
	flags[0] = other.flags[0];
	flags[1] = other.flags[1];
	status_flags[0] = other.status_flags[0];
	status_flags[1] = other.status_flags[1];
	}

Pipe& Pipe::operator=(const Pipe& other)
	{
	if ( this == &other )
		return *this;

	close(fds[0]);
	close(fds[1]);
	fds[0] = dup_or_fail(other.fds[0], other.flags[0], other.status_flags[0]);
	fds[1] = dup_or_fail(other.fds[1], other.flags[1], other.status_flags[1]);
	flags[0] = other.flags[0];
	flags[1] = other.flags[1];
	status_flags[0] = other.status_flags[0];
	status_flags[1] = other.status_flags[1];
	return *this;
	}

PipePair::PipePair(int flags, int status_flags, int* fds)
	: pipes{Pipe(flags, flags, status_flags, status_flags, fds ? fds + 0 : nullptr),
            Pipe(flags, flags, status_flags, status_flags, fds ? fds + 2 : nullptr)}
	{
	}

	} // namespace zeek::detail

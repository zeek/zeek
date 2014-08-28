#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>

#include <algorithm>

#include "util.h"
#include "IOSource.h"

IOSourceRegistry io_sources;

IOSourceRegistry::~IOSourceRegistry()
	{
	for ( SourceList::iterator i = sources.begin(); i != sources.end(); ++i )
		delete *i;

	sources.clear();
	}

void IOSourceRegistry::RemoveAll()
	{
	// We're cheating a bit here ...
	dont_counts = sources.size();
	}

static void fd_vector_set(const std::vector<int>& fds, fd_set* set, int* max)
	{
	for ( size_t i = 0; i < fds.size(); ++i )
		{
		FD_SET(fds[i], set);
		*max = ::max(fds[i], *max);
		}
	}

IOSource* IOSourceRegistry::FindSoonest(double* ts)
	{
	// Remove sources which have gone dry. For simplicity, we only
	// remove at most one each time.
	for ( SourceList::iterator i = sources.begin();
	      i != sources.end(); ++i )
		if ( ! (*i)->src->IsOpen() )
			{
			delete *i;
			sources.erase(i);
			break;
			}

	// Ideally, we would always call select on the fds to see which
	// are ready, and return the soonest. Unfortunately, that'd mean
	// one select-call per packet, which we can't afford in high-volume
	// environments.  Thus, we call select only every SELECT_FREQUENCY
	// call (or if all sources report that they are dry).

	++call_count;

	IOSource* soonest_src = 0;
	double soonest_ts = 1e20;
	double soonest_local_network_time = 1e20;
	bool all_idle = true;

	// Find soonest source of those which tell us they have something to
	// process.
	for ( SourceList::iterator i = sources.begin(); i != sources.end(); ++i )
		{
		if ( ! (*i)->src->IsIdle() )
			{
			all_idle = false;
			double local_network_time = 0;
			double ts = (*i)->src->NextTimestamp(&local_network_time);
			if ( ts > 0 && ts < soonest_ts )
				{
				soonest_ts = ts;
				soonest_src = (*i)->src;
				soonest_local_network_time =
					local_network_time ?
						local_network_time : ts;
				}
			}
		}

	// If we found one and aren't going to select this time,
	// return it.
	int maxx = 0;

	if ( soonest_src && (call_count % SELECT_FREQUENCY) != 0 )
		goto finished;

	// Select on the join of all file descriptors.
	fd_set fd_read, fd_write, fd_except;

	FD_ZERO(&fd_read);
	FD_ZERO(&fd_write);
	FD_ZERO(&fd_except);

	for ( SourceList::iterator i = sources.begin();
	      i != sources.end(); ++i )
		{
		Source* src = (*i);

		if ( ! src->src->IsIdle() )
			// No need to select on sources which we know to
			// be ready.
			continue;

		src->fd_read.clear();
		src->fd_write.clear();
		src->fd_except.clear();
		src->src->GetFds(&src->fd_read, &src->fd_write, &src->fd_except);

		fd_vector_set(src->fd_read, &fd_read, &maxx);
		fd_vector_set(src->fd_write, &fd_write, &maxx);
		fd_vector_set(src->fd_except, &fd_except, &maxx);
		}

	// We can't block indefinitely even when all sources are dry:
	// we're doing some IOSource-independent stuff in the main loop,
	// so we need to return from time to time. (Instead of no time-out
	// at all, we use a very small one. This lets FreeBSD trigger a
	// BPF buffer switch on the next read when the hold buffer is empty
	// while the store buffer isn't filled yet.

	struct timeval timeout;

	if ( all_idle )
		{
		// Interesting: when all sources are dry, simply sleeping a
		// bit *without* watching for any fd becoming ready may
		// decrease CPU load. I guess that's because it allows
		// the kernel's packet buffers to fill. - Robin
		timeout.tv_sec = 0;
		timeout.tv_usec = 20; // SELECT_TIMEOUT;
		select(0, 0, 0, 0, &timeout);
		}

	if ( ! maxx )
		// No selectable fd at all.
		goto finished;

	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	if ( select(maxx + 1, &fd_read, &fd_write, &fd_except, &timeout) > 0 )
		{ // Find soonest.
		for ( SourceList::iterator i = sources.begin();
		      i != sources.end(); ++i )
			{
			Source* src = (*i);

			if ( ! src->src->IsIdle() )
				continue;

			if ( src->Ready(&fd_read, &fd_write, &fd_except) )
				{
				double local_network_time = 0;
				double ts = src->src->NextTimestamp(&local_network_time);
				if ( ts > 0.0 && ts < soonest_ts )
					{
					soonest_ts = ts;
					soonest_src = src->src;
					soonest_local_network_time =
						local_network_time ?
							local_network_time : ts;
					}
				}
			}
		}

finished:
	*ts = soonest_local_network_time;
	return soonest_src;
	}

void IOSourceRegistry::Register(IOSource* src, bool dont_count)
	{
	Source* s = new Source;
	s->src = src;
	if ( dont_count )
		++dont_counts;
	return sources.push_back(s);
	}

static bool fd_vector_ready(const std::vector<int>& fds, fd_set* set)
	{
	for ( size_t i = 0; i < fds.size(); ++i )
		if ( FD_ISSET(fds[i], set) )
			return true;

	return false;
	}

bool IOSourceRegistry::Source::Ready(fd_set* read, fd_set* write,
                                     fd_set* except) const
	{
	if ( fd_vector_ready(fd_read, read) ||
	     fd_vector_ready(fd_write, write) ||
	     fd_vector_ready(fd_except, except) )
		return true;

	return false;
	}

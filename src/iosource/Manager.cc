// See the file "COPYING" in the main distribution directory for copyright.

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>

#include <algorithm>

#include "Manager.h"
#include "IOSource.h"
#include "PktSrc.h"
#include "PktDumper.h"
#include "plugin/Manager.h"

#include "util.h"

#define DEFAULT_PREFIX "pcap"

using namespace iosource;

Manager::~Manager()
	{
	for ( SourceList::iterator i = sources.begin(); i != sources.end(); ++i )
		{
		(*i)->src->Done();
		delete (*i)->src;
		delete *i;
		}

	sources.clear();

	for ( PktDumperList::iterator i = pkt_dumpers.begin(); i != pkt_dumpers.end(); ++i )
		{
		(*i)->Done();
		delete *i;
		}

	pkt_dumpers.clear();
	}

void Manager::RemoveAll()
	{
	// We're cheating a bit here ...
	dont_counts = sources.size();
	}

IOSource* Manager::FindSoonest(double* ts)
	{
	// Remove sources which have gone dry. For simplicity, we only
	// remove at most one each time.
	for ( SourceList::iterator i = sources.begin();
	      i != sources.end(); ++i )
		if ( ! (*i)->src->IsOpen() )
			{
			(*i)->src->Done();
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
			if ( ts >= 0 && ts < soonest_ts )
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

		src->Clear();
		src->src->GetFds(&src->fd_read, &src->fd_write, &src->fd_except);
		src->SetFds(&fd_read, &fd_write, &fd_except, &maxx);
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
				if ( ts >= 0.0 && ts < soonest_ts )
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

void Manager::Register(IOSource* src, bool dont_count)
	{
	// First see if we already have registered that source. If so, just
	// adjust dont_count.
	for ( SourceList::iterator i = sources.begin(); i != sources.end(); ++i )
		{
		if ( (*i)->src == src )
			{
			if ( (*i)->dont_count != dont_count )
				// Adjust the global counter.
				dont_counts += (dont_count ? 1 : -1);

			return;
			}
		}

	src->Init();
	Source* s = new Source;
	s->src = src;
	s->dont_count = dont_count;
	if ( dont_count )
		++dont_counts;

	sources.push_back(s);
	}

void Manager::Register(PktSrc* src)
	{
	pkt_src = src;
	Register(src, false);
	}

static std::pair<std::string, std::string> split_prefix(std::string path)
	{
	// See if the path comes with a prefix telling us which type of
	// PktSrc to use. If not, choose default.
	std::string prefix;

	std::string::size_type i = path.find("::");
	if ( i != std::string::npos )
		{
		prefix = path.substr(0, i);
		path = path.substr(i + 2, std::string::npos);
		}

	else
		prefix= DEFAULT_PREFIX;

	return std::make_pair(prefix, path);
	}

PktSrc* Manager::OpenPktSrc(const std::string& path, bool is_live)
	{
	std::pair<std::string, std::string> t = split_prefix(path);
	std::string prefix = t.first;
	std::string npath = t.second;

	// Find the component providing packet sources of the requested prefix.

	PktSrcComponent* component = 0;

	std::list<PktSrcComponent*> all_components = plugin_mgr->Components<PktSrcComponent>();

	for ( std::list<PktSrcComponent*>::const_iterator i = all_components.begin();
	      i != all_components.end(); i++ )
		{
		PktSrcComponent* c = *i;

		if ( c->HandlesPrefix(prefix) &&
		     ((  is_live && c->DoesLive() ) ||
		      (! is_live && c->DoesTrace())) )
			{
			component = c;
			break;
			}
		}


	if ( ! component )
		reporter->FatalError("type of packet source '%s' not recognized, or mode not supported", prefix.c_str());

	// Instantiate packet source.

	PktSrc* ps = (*component->Factory())(npath, is_live);
	assert(ps);

	if ( ! ps->IsOpen() && ps->IsError() )
		// Set an error message if it didn't open successfully.
		ps->Error("could not open");

	DBG_LOG(DBG_PKTIO, "Created packet source of type %s for %s", component->Name().c_str(), npath.c_str());

	Register(ps);
	return ps;
	}


PktDumper* Manager::OpenPktDumper(const string& path, bool append)
	{
	std::pair<std::string, std::string> t = split_prefix(path);
	std::string prefix = t.first;
	std::string npath = t.second;

	// Find the component providing packet dumpers of the requested prefix.

	PktDumperComponent* component = 0;

	std::list<PktDumperComponent*> all_components = plugin_mgr->Components<PktDumperComponent>();

	for ( std::list<PktDumperComponent*>::const_iterator i = all_components.begin();
	      i != all_components.end(); i++ )
		{
		if ( (*i)->HandlesPrefix(prefix) )
			{
			component = (*i);
			break;
			}
		}

	if ( ! component )
		reporter->FatalError("type of packet dumper '%s' not recognized", prefix.c_str());

	// Instantiate packet dumper.

	PktDumper* pd = (*component->Factory())(npath, append);
	assert(pd);

	if ( ! pd->IsOpen() && pd->IsError() )
		// Set an error message if it didn't open successfully.
		pd->Error("could not open");

	DBG_LOG(DBG_PKTIO, "Created packer dumper of type %s for %s", component->Name().c_str(), npath.c_str());

	pd->Init();
	pkt_dumpers.push_back(pd);

	return pd;
	}

void Manager::Source::SetFds(fd_set* read, fd_set* write, fd_set* except,
                             int* maxx) const
	{
	*maxx = std::max(*maxx, fd_read.Set(read));
	*maxx = std::max(*maxx, fd_write.Set(write));
	*maxx = std::max(*maxx, fd_except.Set(except));
	}

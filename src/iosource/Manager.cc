// See the file "COPYING" in the main distribution directory for copyright.

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>
#include <poll.h>
#include <sys/epoll.h>

#include <algorithm>
#include <limits>

#include "Manager.h"
#include "IOSource.h"
#include "PktSrc.h"
#include "PktDumper.h"
#include "plugin/Manager.h"
#include "DNS_Mgr.h"

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

void Manager::RemoveDrySources()
	{
	auto it = sources.begin();

	while ( it != sources.end() )
		{
		if ( (*it)->src->IsOpen() )
			++it;
		else
			{
			(*it)->src->Done();
			delete *it;
			it = sources.erase(it);
			}
		}
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
	// environments.  Thus, we call select only every POLL_FREQUENCY
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
	if ( soonest_src && (call_count % POLL_FREQUENCY) != 0 )
		goto finished;

	if ( all_idle )
		{
		// We can't block indefinitely even when all sources are dry:
		// we're doing some IOSource-independent stuff in the main loop,
		// so we need to return from time to time. (Instead of no time-out
		// at all, we use a very small one. This lets FreeBSD trigger a
		// BPF buffer switch on the next read when the hold buffer is empty
		// while the store buffer isn't filled yet.

		// Interesting: when all sources are dry, simply sleeping a
		// bit *without* watching for any fd becoming ready may
		// decrease CPU load. I guess that's because it allows
		// the kernel's packet buffers to fill. - Robin
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 20; // SELECT_TIMEOUT;
		select(0, 0, 0, 0, &timeout);
		}

	poll_function(this, soonest_ts, soonest_local_network_time, soonest_src);

finished:
	*ts = soonest_local_network_time;
	return soonest_src;
	}

void Manager::PollSources(double& soonest_ts,
                          double soonest_local_network_time,
                          IOSource*& soonest_src)
	{
	for ( auto src : sources )
		{
		// @note: just checking PktSources for now as it's the quickets way
		// get performance analysis of the runloops done.  Otherwise, would
		// have to mess around with changing the IOSource API to be more
		// generic with how it obtains FDs.
		auto pkt_src = dynamic_cast<PktSrc*>(src->src);

		if ( ! pkt_src )
			continue;

		pollfd pfd{pkt_src->PollableFD(), POLLIN, 0};
		auto res = poll(&pfd, 1, 0);

		if ( res > 0 )
			{
			if ( pfd.revents & POLLIN )
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
	}

void Manager::EpollSources(double& soonest_ts,
                           double soonest_local_network_time,
                           IOSource*& soonest_src)
	{
	static int epoll_fd = -1;

	if ( epoll_fd == -1 )
		{
		epoll_fd = epoll_create1(0);

		for ( auto src : sources )
			{
			// @note: just checking PktSources for now as it's the quickets way
			// get performance analysis of the runloops done.  Otherwise, would
			// have to mess around with changing the IOSource API to be more
			// generic with how it obtains FDs.
			auto pkt_src = dynamic_cast<PktSrc*>(src->src);

			if ( ! pkt_src )
				continue;

			epoll_event ev;
			ev.data.ptr = pkt_src;
			ev.events = EPOLLIN;

			epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pkt_src->PollableFD(), &ev);
			break;
			}
		}

	epoll_event rev;
	auto res = epoll_wait(epoll_fd, &rev, 1, 0);

	if ( res > 0 )
		{
		if ( rev.events & EPOLLIN )
			{
			auto src = (IOSource*)rev.data.ptr;
			double local_network_time = 0;
			double ts = src->NextTimestamp(&local_network_time);
			if ( ts > 0.0 && ts < soonest_ts )
				{
				soonest_ts = ts;
				soonest_src = src;
				soonest_local_network_time =
				        local_network_time ?
				            local_network_time : ts;
				}
			}
		}
	}

void Manager::SelectSources(double& soonest_ts,
                            double soonest_local_network_time,
                            IOSource*& soonest_src)
	{
	int maxx = 0;
	// Select on the join of all file descriptors.
	fd_set fd_read, fd_write, fd_except;
	struct timeval timeout;

	FD_ZERO(&fd_read);
	FD_ZERO(&fd_write);
	FD_ZERO(&fd_except);

	for ( auto src : sources )
		{
		// @note: always poll FDs for sake of how performance tests are designed
//		if ( ! src->src->IsIdle() )
//			// No need to select on sources which we know to
//			// be ready.
//			continue;

		// @note: just checking PktSources for now as it's the quickets way
		// get performance analysis of the runloops done.  Otherwise, would
		// have to mess around with changing the IOSource API to be more
		// generic with how it obtains FDs.
		auto pkt_src = dynamic_cast<PktSrc*>(src->src);

		if ( ! pkt_src )
			continue;

		src->Clear();
		src->src->GetFds(&src->fd_read, &src->fd_write, &src->fd_except);
		src->SetFds(&fd_read, &fd_write, &fd_except, &maxx);
		}

	// @note: force the select() for sake of how performance tests are designed
	// (we're only looking at offline packet sources and the overheads of the
	// various polling mechanisms in the typical use-cases).
//	if ( ! maxx )
//		// No selectable fd at all.
//		return;

	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	if ( select(maxx + 1, &fd_read, &fd_write, &fd_except, &timeout) > 0 )
		{ // Find soonest.
		for ( auto src : sources )
			{
//			if ( ! src->src->IsIdle() )
//				continue;

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

	}

IOSource* Manager::SoonestSource() const
	{
	IOSource* soonest_src = nullptr;
	double soonest_ts = std::numeric_limits<double>::max();
	double local_network_time = 0;

	for ( auto& source : sources )
		{
		// @todo: nothing except RemoteSerializer uses the timestamp argument,
		// and its value was only used in debug logs, so can we ditch it?
		double ts = source->src->NextTimestamp(&local_network_time);

		if ( ts > 0 && ts < soonest_ts )
			{
			soonest_ts = ts;
			soonest_src = source->src;
			}
		}

	return soonest_src;
	}

std::list<IOSource*> Manager::GetSources() const
	{
	std::list<IOSource*> rval;

	for ( auto s : sources )
		rval.push_back(s->src);

	return rval;
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
	pkt_srcs.push_back(src);
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

// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/iosource/Manager.h"

#include <cassert>
// These two files have to remain in the same order or FreeBSD builds
// stop working.
// clang-format off
#include <sys/types.h>
#include <sys/event.h>
// clang-format on
#include <sys/time.h>
#include <unistd.h>

#include "zeek/NetVar.h"
#include "zeek/RunState.h"
#include "zeek/broker/Manager.h"
#include "zeek/iosource/Component.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/iosource/PktDumper.h"
#include "zeek/iosource/PktSrc.h"
#include "zeek/plugin/Manager.h"
#include "zeek/util.h"

#define DEFAULT_PREFIX "pcap"

extern int signal_val;

namespace zeek::iosource
	{

Manager::WakeupHandler::WakeupHandler()
	{
	if ( ! iosource_mgr->RegisterFd(flare.FD(), this) )
		reporter->FatalError("Failed to register WakeupHandler's fd with iosource_mgr");
	}

Manager::WakeupHandler::~WakeupHandler()
	{
	iosource_mgr->UnregisterFd(flare.FD(), this);
	}

void Manager::WakeupHandler::Process()
	{
	flare.Extinguish();
	}

void Manager::WakeupHandler::Ping(std::string_view where)
	{
	// Calling DBG_LOG calls fprintf, which isn't safe to call in a signal
	// handler.
	if ( signal_val != 0 )
		DBG_LOG(DBG_MAINLOOP, "Pinging WakeupHandler from %s", where.data());

	flare.Fire(true);
	}

Manager::Manager()
	{
	event_queue = kqueue();
	if ( event_queue == -1 )
		reporter->FatalError("Failed to initialize kqueue: %s", strerror(errno));
	}

Manager::~Manager()
	{
	delete wakeup;
	wakeup = nullptr;

	// Make sure all of the sources are done before we try to delete any of them.
	for ( auto& src : sources )
		src->src->Done();

	for ( auto& src : sources )
		{
		if ( src->manage_lifetime )
			delete src->src;

		delete src;
		}

	sources.clear();

	for ( PktDumperList::iterator i = pkt_dumpers.begin(); i != pkt_dumpers.end(); ++i )
		{
		(*i)->Done();
		delete *i;
		}

	pkt_dumpers.clear();

#ifndef _MSC_VER
	// There's a bug here with builds on Windows that causes an assertion with debug builds
	// related to libkqueue returning a zero for the file descriptor. The assert happens
	// because something else has already closed FD zero by the time we get here, and Windows
	// doesn't like that very much. We only do this close when shutting down, so it should
	// be fine to just skip it.
	//
	// See https://github.com/mheily/libkqueue/issues/151 for more details.
	if ( event_queue != -1 )
		close(event_queue);
#endif
	}

void Manager::InitPostScript()
	{
	wakeup = new WakeupHandler();
	poll_interval = BifConst::io_poll_interval_default;
	}

void Manager::RemoveAll()
	{
	// We're cheating a bit here ...
	dont_counts = sources.size();
	}

void Manager::Wakeup(std::string_view where)
	{
	if ( wakeup )
		wakeup->Ping(where);
	}

void Manager::FindReadySources(ReadySources* ready)
	{
	ready->clear();

	// Remove sources which have gone dry. For simplicity, we only
	// remove at most one each time.
	for ( SourceList::iterator i = sources.begin(); i != sources.end(); ++i )
		if ( ! (*i)->src->IsOpen() )
			{
			(*i)->src->Done();
			delete *i;
			sources.erase(i);
			break;
			}

	// If there aren't any sources and exit_only_after_terminate is false, just
	// return an empty set of sources. We want the main loop to end.
	if ( Size() == 0 && (! BifConst::exit_only_after_terminate || run_state::terminating) )
		return;

	double timeout = -1;
	IOSource* timeout_src = nullptr;
	bool time_to_poll = false;

	++poll_counter;
	if ( poll_counter % poll_interval == 0 )
		{
		poll_counter = 0;
		time_to_poll = true;
		}

	// Find the source with the next timeout value.
	for ( auto src : sources )
		{
		auto iosource = src->src;
		if ( iosource->IsOpen() )
			{
			double next = iosource->GetNextTimeout();

			if ( timeout == -1 || (next >= 0.0 && next < timeout) )
				{
				timeout = next;
				timeout_src = iosource;
				}

			// If a source has a zero timeout then it's ready. Just add it to the
			// list already. Only do this if it's not time to poll though, since
			// we don't want things in the vector passed into Poll() or it'll end
			// up inserting duplicates. A source with a zero timeout that was not
			// selected as the timeout_src can be safely added, whether it's time
			// to poll or not though.
			if ( next == 0 && (! time_to_poll || iosource != timeout_src) )
				{
				ready->push_back({iosource, -1, 0});
				}
			else if ( iosource == pkt_src )
				{
				if ( pkt_src->IsLive() )
					{
					if ( ! time_to_poll )
						// Avoid calling Poll() if we can help it since on very
						// high-traffic networks, we spend too much time in
						// Poll() and end up dropping packets.
						ready->push_back({pkt_src, -1, 0});
					}
				}
			}
		}

	DBG_LOG(DBG_MAINLOOP, "timeout: %f   ready size: %zu   time_to_poll: %d\n", timeout,
	        ready->size(), time_to_poll);

	// If we didn't find any IOSources with zero timeouts or it's time to
	// force a poll, do that and return. Otherwise return the set of ready
	// sources that we have.
	if ( ready->empty() || time_to_poll )
		Poll(ready, timeout, timeout_src);
	}

void Manager::Poll(ReadySources* ready, double timeout, IOSource* timeout_src)
	{
	struct timespec kqueue_timeout;
	ConvertTimeout(timeout, kqueue_timeout);

	int ret = kevent(event_queue, NULL, 0, events.data(), events.size(), &kqueue_timeout);
	if ( ret == -1 )
		{
		// Ignore interrupts since we may catch one during shutdown and we don't want the
		// error to get printed.
		if ( errno != EINTR )
			reporter->InternalWarning("Error calling kevent: %s", strerror(errno));
		}
	else if ( ret == 0 )
		{
		// If a timeout_src was provided and nothing else was ready, we timed out
		// according to the given source's timeout and can add it as ready.
		if ( timeout_src )
			ready->push_back({timeout_src, -1, 0});
		}
	else
		{
		// kevent returns the number of events that are ready, so we only need to loop
		// over that many of them.
		bool timeout_src_added = false;
		for ( int i = 0; i < ret; i++ )
			{
			if ( events[i].filter == EVFILT_READ )
				{
				std::map<int, IOSource*>::const_iterator it = fd_map.find(events[i].ident);
				if ( it != fd_map.end() )
					ready->push_back({it->second, static_cast<int>(events[i].ident),
					                  IOSource::ProcessFlags::READ});
				}
			else if ( events[i].filter == EVFILT_WRITE )
				{
				std::map<int, IOSource*>::const_iterator it = write_fd_map.find(events[i].ident);
				if ( it != write_fd_map.end() )
					ready->push_back({it->second, static_cast<int>(events[i].ident),
					                  IOSource::ProcessFlags::WRITE});
				}

			// If we added a source that is the same as the passed timeout_src, take
			// note as to avoid adding it twice.
			timeout_src_added |= ready->size() > 0 ? ready->back().src == timeout_src : false;
			}

		// A timeout_src with a zero timeout can be considered ready.
		if ( timeout_src && timeout == 0.0 && ! timeout_src_added )
			ready->push_back({timeout_src, -1, 0});
		}
	}

void Manager::ConvertTimeout(double timeout, struct timespec& spec)
	{
	// If timeout ended up -1, set it to some nominal value just to keep the loop
	// from blocking forever. This is the case of exit_only_after_terminate when
	// there isn't anything else going on.
	if ( timeout < 0 )
		{
		spec.tv_sec = 0;
		spec.tv_nsec = 1e8;
		}
	else
		{
		spec.tv_sec = static_cast<time_t>(timeout);
		spec.tv_nsec = static_cast<long>((timeout - spec.tv_sec) * 1e9);
		}
	}

bool Manager::RegisterFd(int fd, IOSource* src, int flags)
	{
	std::vector<struct kevent> new_events;

	if ( (flags & IOSource::READ) != 0 )
		{
		if ( fd_map.count(fd) == 0 )
			{
			new_events.push_back({});
			EV_SET(&(new_events.back()), fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
			}
		}
	if ( (flags & IOSource::WRITE) != 0 )
		{
		if ( write_fd_map.count(fd) == 0 )
			{
			new_events.push_back({});
			EV_SET(&(new_events.back()), fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
			}
		}

	if ( ! new_events.empty() )
		{
		int ret = kevent(event_queue, new_events.data(), new_events.size(), NULL, 0, NULL);
		if ( ret != -1 )
			{
			DBG_LOG(DBG_MAINLOOP, "Registered fd %d from %s", fd, src->Tag());
			for ( const auto& a : new_events )
				events.push_back({});

			if ( (flags & IOSource::READ) != 0 )
				fd_map[fd] = src;
			if ( (flags & IOSource::WRITE) != 0 )
				write_fd_map[fd] = src;

			Wakeup("RegisterFd");
			return true;
			}
		else
			{
			reporter->Error("Failed to register fd %d from %s: %s (flags %d)", fd, src->Tag(),
			                strerror(errno), flags);
			return false;
			}
		}

	return true;
	}

bool Manager::UnregisterFd(int fd, IOSource* src, int flags)
	{
	std::vector<struct kevent> new_events;

	if ( (flags & IOSource::READ) != 0 )
		{
		if ( fd_map.count(fd) != 0 )
			{
			new_events.push_back({});
			EV_SET(&(new_events.back()), fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
			}
		}
	if ( (flags & IOSource::WRITE) != 0 )
		{
		if ( write_fd_map.count(fd) != 0 )
			{
			new_events.push_back({});
			EV_SET(&(new_events.back()), fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
			}
		}

	if ( ! new_events.empty() )
		{
		int ret = kevent(event_queue, new_events.data(), new_events.size(), NULL, 0, NULL);
		if ( ret != -1 )
			{
			DBG_LOG(DBG_MAINLOOP, "Unregistered fd %d from %s", fd, src->Tag());
			for ( const auto& a : new_events )
				events.pop_back();

			if ( (flags & IOSource::READ) != 0 )
				fd_map.erase(fd);
			if ( (flags & IOSource::WRITE) != 0 )
				write_fd_map.erase(fd);

			Wakeup("UnregisterFd");
			return true;
			}

		// We don't care about failure here. If it failed to unregister, it's likely because
		// the file descriptor was already closed, and kqueue already automatically removed
		// it.
		}
	else
		{
		reporter->Error("Attempted to unregister an unknown file descriptor %d from %s", fd,
		                src->Tag());
		return false;
		}

	return true;
	}

void Manager::Register(IOSource* src, bool dont_count, bool manage_lifetime)
	{
	// First see if we already have registered that source. If so, just
	// adjust dont_count.
	for ( const auto& iosrc : sources )
		{
		if ( iosrc->src == src )
			{
			if ( iosrc->dont_count != dont_count )
				// Adjust the global counter.
				dont_counts += (dont_count ? 1 : -1);

			return;
			}
		}

	src->InitSource();
	Source* s = new Source;
	s->src = src;
	s->dont_count = dont_count;
	s->manage_lifetime = manage_lifetime;
	if ( dont_count )
		++dont_counts;

	sources.push_back(s);
	}

void Manager::Register(PktSrc* src)
	{
	pkt_src = src;

	Register(src, false);

	// Once we know if the source is live or not, adapt the
	// poll_interval accordingly.
	//
	// Note that src->IsLive() is only valid after calling Register().
	if ( src->IsLive() )
		poll_interval = BifConst::io_poll_interval_live;
	else if ( run_state::pseudo_realtime )
		poll_interval = 1;
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
		prefix = DEFAULT_PREFIX;

	return std::make_pair(prefix, path);
	}

PktSrc* Manager::OpenPktSrc(const std::string& path, bool is_live)
	{
	std::pair<std::string, std::string> t = split_prefix(path);
	const auto& prefix = t.first;
	const auto& npath = t.second;

	// Find the component providing packet sources of the requested prefix.

	PktSrcComponent* component = nullptr;

	std::list<PktSrcComponent*> all_components = plugin_mgr->Components<PktSrcComponent>();
	for ( const auto& c : all_components )
		{
		if ( c->HandlesPrefix(prefix) &&
		     ((is_live && c->DoesLive()) || (! is_live && c->DoesTrace())) )
			{
			component = c;
			break;
			}
		}

	if ( ! component )
		reporter->FatalError("type of packet source '%s' not recognized, or mode not supported",
		                     prefix.c_str());

	// Instantiate packet source.

	PktSrc* ps = (*component->Factory())(npath, is_live);
	assert(ps);

	DBG_LOG(DBG_PKTIO, "Created packet source of type %s for %s", component->Name().c_str(),
	        npath.c_str());

	Register(ps);
	return ps;
	}

PktDumper* Manager::OpenPktDumper(const std::string& path, bool append)
	{
	std::pair<std::string, std::string> t = split_prefix(path);
	std::string prefix = t.first;
	std::string npath = t.second;

	// Find the component providing packet dumpers of the requested prefix.

	PktDumperComponent* component = nullptr;

	std::list<PktDumperComponent*> all_components = plugin_mgr->Components<PktDumperComponent>();
	for ( const auto& c : all_components )
		{
		if ( c->HandlesPrefix(prefix) )
			{
			component = c;
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

	DBG_LOG(DBG_PKTIO, "Created packer dumper of type %s for %s", component->Name().c_str(),
	        npath.c_str());

	pd->Init();
	pkt_dumpers.push_back(pd);

	return pd;
	}

	} // namespace zeek::iosource

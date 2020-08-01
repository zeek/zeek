// See the file "COPYING" in the main distribution directory for copyright.

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>

#include "Manager.h"
#include "Component.h"
#include "IOSource.h"
#include "Net.h"
#include "PktSrc.h"
#include "PktDumper.h"
#include "plugin/Manager.h"
#include "broker/Manager.h"
#include "NetVar.h"

#include "util.h"

#define DEFAULT_PREFIX "pcap"

namespace zeek::iosource {

Manager::WakeupHandler::WakeupHandler()
	{
	if ( ! iosource_mgr->RegisterFd(flare.FD(), this) )
		zeek::reporter->FatalError("Failed to register WakeupHandler's fd with iosource_mgr");
	}

Manager::WakeupHandler::~WakeupHandler()
	{
	iosource_mgr->UnregisterFd(flare.FD(), this);
	}

void Manager::WakeupHandler::Process()
	{
	flare.Extinguish();
	}

void Manager::WakeupHandler::Ping(const std::string& where)
	{
	DBG_LOG(zeek::DBG_MAINLOOP, "Pinging WakeupHandler from %s", where.c_str());
	flare.Fire();
	}

Manager::Manager()
	{
	event_queue = kqueue();
	if ( event_queue == -1 )
		zeek::reporter->FatalError("Failed to initialize kqueue: %s", strerror(errno));
	}

Manager::~Manager()
	{
	delete wakeup;
	wakeup = nullptr;

	for ( SourceList::iterator i = sources.begin(); i != sources.end(); ++i )
		{
		auto src = *i;
		src->src->Done();

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

	if ( event_queue != -1 )
		close(event_queue);
	}

void Manager::InitPostScript()
	{
	wakeup = new WakeupHandler();
	}

void Manager::RemoveAll()
	{
	// We're cheating a bit here ...
	dont_counts = sources.size();
	}

void Manager::Wakeup(const std::string& where)
	{
	if ( wakeup )
		wakeup->Ping(where);
	}

void Manager::FindReadySources(std::vector<IOSource*>* ready)
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
	if ( Size() == 0 && ( ! zeek::BifConst::exit_only_after_terminate || terminating ) )
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
			bool added = false;

			if ( timeout == -1 || ( next >= 0.0 && next < timeout ) )
				{
				timeout = next;
				timeout_src = iosource;

				// If a source has a zero timeout then it's ready. Just add it to the
				// list already. Only do this if it's not time to poll though, since
				// we don't want things in the vector passed into Poll() or it'll end
				// up inserting duplicates.
				if ( timeout == 0 && ! time_to_poll )
					{
					added = true;
					ready->push_back(timeout_src);
					}
				}

			if ( iosource == pkt_src && ! added )
				{
				if ( pkt_src->IsLive() )
					{
					if ( ! time_to_poll )
						// Avoid calling Poll() if we can help it since on very
						// high-traffic networks, we spend too much time in
						// Poll() and end up dropping packets.
						ready->push_back(pkt_src);
					}
				else
					{
					if ( ! pseudo_realtime )
						// A pcap file is always ready to process unless it's suspended
						ready->push_back(pkt_src);
					}
				}
			}
		}

	DBG_LOG(zeek::DBG_MAINLOOP, "timeout: %f   ready size: %zu   time_to_poll: %d\n",
		timeout, ready->size(), time_to_poll);

	// If we didn't find any IOSources with zero timeouts or it's time to
	// force a poll, do that and return. Otherwise return the set of ready
	// sources that we have.
	if ( ready->empty() || time_to_poll )
		Poll(ready, timeout, timeout_src);
	}

void Manager::Poll(std::vector<IOSource*>* ready, double timeout, IOSource* timeout_src)
	{
	struct timespec kqueue_timeout;
	ConvertTimeout(timeout, kqueue_timeout);

	int ret = kevent(event_queue, NULL, 0, events.data(), events.size(), &kqueue_timeout);
	if ( ret == -1 )
		{
		// Ignore interrupts since we may catch one during shutdown and we don't want the
		// error to get printed.
		if ( errno != EINTR )
			zeek::reporter->InternalWarning("Error calling kevent: %s", strerror(errno));
		}
	else if ( ret == 0 )
		{
		if ( timeout_src )
			ready->push_back(timeout_src);
		}
	else
		{
		// kevent returns the number of events that are ready, so we only need to loop
		// over that many of them.
		for ( int i = 0; i < ret; i++ )
			{
			if ( events[i].filter == EVFILT_READ )
				{
				std::map<int, IOSource*>::const_iterator it = fd_map.find(events[i].ident);
				if ( it != fd_map.end() )
					ready->push_back(it->second);
				}
			}
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

bool Manager::RegisterFd(int fd, IOSource* src)
	{
	struct kevent event;
	EV_SET(&event, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	int ret = kevent(event_queue, &event, 1, NULL, 0, NULL);
	if ( ret != -1 )
		{
		events.push_back({});
		DBG_LOG(zeek::DBG_MAINLOOP, "Registered fd %d from %s", fd, src->Tag());
		fd_map[fd] = src;

		Wakeup("RegisterFd");
		return true;
		}
	else
		{
		zeek::reporter->Error("Failed to register fd %d from %s: %s", fd, src->Tag(), strerror(errno));
		return false;
		}
	}

bool Manager::UnregisterFd(int fd, IOSource* src)
	{
	if ( fd_map.find(fd) != fd_map.end() )
		{
		struct kevent event;
		EV_SET(&event, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		int ret = kevent(event_queue, &event, 1, NULL, 0, NULL);
		if ( ret != -1 )
			DBG_LOG(zeek::DBG_MAINLOOP, "Unregistered fd %d from %s", fd, src->Tag());

		fd_map.erase(fd);

		Wakeup("UnregisterFd");
		return true;
		}
	else
		{
		zeek::reporter->Error("Attempted to unregister an unknown file descriptor %d from %s", fd, src->Tag());
		return false;
		}
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

	// The poll interval gets defaulted to 100 which is good for cases like reading
	// from pcap files and when there isn't a packet source, but is a little too
	// infrequent for live sources (especially fast live sources). Set it down a
	// little bit for those sources.
	if ( src->IsLive() )
		poll_interval = 10;
	else if ( pseudo_realtime )
		poll_interval = 1;

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
	const auto& prefix = t.first;
	const auto& npath = t.second;

	// Find the component providing packet sources of the requested prefix.

	PktSrcComponent* component = nullptr;

	std::list<PktSrcComponent*> all_components = zeek::plugin_mgr->Components<PktSrcComponent>();
	for ( const auto& c : all_components )
		{
		if ( c->HandlesPrefix(prefix) &&
		     ((  is_live && c->DoesLive() ) ||
		      (! is_live && c->DoesTrace())) )
			{
			component = c;
			break;
			}
		}


	if ( ! component )
		zeek::reporter->FatalError("type of packet source '%s' not recognized, or mode not supported", prefix.c_str());

	// Instantiate packet source.

	PktSrc* ps = (*component->Factory())(npath, is_live);
	assert(ps);

	DBG_LOG(zeek::DBG_PKTIO, "Created packet source of type %s for %s", component->Name().c_str(), npath.c_str());

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

	std::list<PktDumperComponent*> all_components = zeek::plugin_mgr->Components<PktDumperComponent>();
	for ( const auto& c : all_components )
		{
		if ( c->HandlesPrefix(prefix) )
			{
			component = c;
			break;
			}
		}

	if ( ! component )
		zeek::reporter->FatalError("type of packet dumper '%s' not recognized", prefix.c_str());

	// Instantiate packet dumper.

	PktDumper* pd = (*component->Factory())(npath, append);
	assert(pd);

	if ( ! pd->IsOpen() && pd->IsError() )
		// Set an error message if it didn't open successfully.
		pd->Error("could not open");

	DBG_LOG(zeek::DBG_PKTIO, "Created packer dumper of type %s for %s", component->Name().c_str(), npath.c_str());

	pd->Init();
	pkt_dumpers.push_back(pd);

	return pd;
	}

} // namespace zeek::iosource

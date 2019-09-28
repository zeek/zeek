// See the file "COPYING" in the main distribution directory for copyright.

#include <assert.h>

#include <algorithm>

#include "Manager.h"
#include "IOSource.h"
#include "PktSrc.h"
#include "PktDumper.h"
#include "plugin/Manager.h"

#define DEFAULT_PREFIX "pcap"

using namespace iosource;

static void close_handle(uv_handle_t* handle)
	{
	}

Manager::Manager()
	{
	loop = uv_default_loop();
	}

Manager::~Manager()
	{
	Terminate();
	}

void Manager::Terminate()
	{
	// Shut down all of the non-packet sources first. This is because shutting down the last
	// packet source clears out all of these.
	for ( auto i : sources )
		i->Done();

	sources.clear();

	for ( auto i : pkt_dumpers )
		{
		i->Done();
		delete i;
		}

	pkt_dumpers.clear();
	
	// Calling PktSrc::Done() causes a call to Unregister(), which removes the source from
	// the list of packet sources. Just loop until it's done doing that.
	if ( pkt_src )
		pkt_src->Done();
	}

void Manager::Register(IOSource* src)
	{
	src->Init();
	if ( src->IsPacketSource() )
		pkt_src = dynamic_cast<PktSrc*>(src);
	else
		sources.push_back(src);
	}

void Manager::Unregister(IOSource* src)
	{
	if ( src->IsPacketSource() )
		{
		delete pkt_src;
		pkt_src = nullptr;
		}
	else
		{
		auto it = std::find(sources.begin(), sources.end(), src);
		if ( it != sources.end() )
			sources.erase(it);
		}

	if ( pkt_src == nullptr )
		{
		for ( auto source : sources )
			source->Done();

		sources.clear();

		// This should cause the loop to stop at the end of this iteration and go into
		// the shutdown mode.
		uv_stop(loop);
		}
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
	if ( pkt_src )
		{
		DBG_LOG(DBG_PKTIO, "Packet source is already active: %s", pkt_src->Tag());
		return nullptr;
		}

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

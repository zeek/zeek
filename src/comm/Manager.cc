#include "Manager.h"
#include <broker/broker.hh>
#include <cstdio>
#include <unistd.h>
#include "util.h"
#include "Var.h"
#include "Reporter.h"
#include "comm/comm.bif.h"

bool comm::Manager::InitPreScript()
	{
	return true;
	}

bool comm::Manager::InitPostScript()
	{
	auto res = broker::init();

	if ( res )
		{
		fprintf(stderr, "broker::init failed: %s\n", broker::strerror(res));
		return false;
		}

	const char* name;
	auto name_from_script = internal_val("Comm::endpoint_name")->AsString();

	if ( name_from_script->Len() )
		name = name_from_script->CheckString();
	else
		{
		char host[256];

		if ( gethostname(host, sizeof(host)) == 0 )
			name = fmt("bro@%s.%ld", host, static_cast<long>(getpid()));
		else
			name = fmt("bro@<unknown>.%ld", static_cast<long>(getpid()));
		}

	endpoint = std::unique_ptr<broker::endpoint>(new broker::endpoint(name));
	return true;
	}

bool comm::Manager::Listen(uint16_t port, const char* addr)
	{
	auto rval = endpoint->listen(port, addr);

	if ( ! rval )
		{
		reporter->Error("Failed to listen on %s:%" PRIu16 " : %s",
		                addr ? addr : "INADDR_ANY", port,
		                endpoint->last_error().data());
		}

	return rval;
	}

bool comm::Manager::Connect(string addr, uint16_t port,
                            std::chrono::duration<double> retry_interval)
	{
	auto& peer = peers[std::make_pair(addr, port)];

	if ( peer )
		return false;

	peer = endpoint->peer(std::move(addr), port, retry_interval);
	return true;
	}

bool comm::Manager::Disconnect(const string& addr, uint16_t port)
	{
	auto it = peers.find(std::make_pair(addr, port));

	if ( it == peers.end() )
		return false;

	return endpoint->unpeer(it->second);
	}

void comm::Manager::GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
                           iosource::FD_Set* except)
	{
	read->Insert(endpoint->peer_status().fd());
	}

double comm::Manager::NextTimestamp(double* local_network_time)
	{
	// TODO: do something better?
	return timer_mgr->Time();
	}

void comm::Manager::Process()
	{
	bool idle = true;
	auto peer_status_updates = endpoint->peer_status().want_pop();

	if ( ! peer_status_updates.empty() )
		idle = false;

	for ( auto& u : peer_status_updates )
		{
		if ( ! u.relation.remote() )
			continue;

		switch ( u.status ) {
		case broker::peer_status::tag::established:
			if ( Comm::remote_connection_established )
				{
				val_list* vl = new val_list;
				vl->append(new StringVal(u.relation.remote_tuple().first));
				vl->append(new PortVal(u.relation.remote_tuple().second,
				                       TRANSPORT_TCP));
				vl->append(new StringVal(u.peer_name));
				mgr.QueueEvent(Comm::remote_connection_established, vl);
				}

			break;

		case broker::peer_status::tag::disconnected:
			if ( Comm::remote_connection_broken )
				{
				val_list* vl = new val_list;
				vl->append(new StringVal(u.relation.remote_tuple().first));
				vl->append(new PortVal(u.relation.remote_tuple().second,
				                       TRANSPORT_TCP));
				mgr.QueueEvent(Comm::remote_connection_broken, vl);
				}

			break;

		case broker::peer_status::tag::incompatible:
			if ( Comm::remote_connection_incompatible )
				{
				val_list* vl = new val_list;
				vl->append(new StringVal(u.relation.remote_tuple().first));
				vl->append(new PortVal(u.relation.remote_tuple().second,
				                       TRANSPORT_TCP));
				mgr.QueueEvent(Comm::remote_connection_incompatible, vl);
				}

			break;

		default:
			reporter->InternalWarning("unknown broker::peer_status::tag : %d",
			                          static_cast<int>(u.status));
			break;
		}
		}

	SetIdle(idle);
	}

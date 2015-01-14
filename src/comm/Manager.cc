#include "Manager.h"
#include <broker/broker.hh>
#include <cstdio>
#include <unistd.h>
#include "util.h"
#include "Var.h"
#include "Reporter.h"
#include "comm/comm.bif.h"

using namespace std;

bool comm::Manager::InitPreScript()
	{
	return true;
	}

static int require_field(const RecordType* rt, const char* name)
	{
	auto rval = rt->FieldOffset(name);

	if ( rval < 0 )
		reporter->InternalError("no field named '%s' in record type '%s'", name,
		                        rt->GetName().data());

	return rval;
	}

bool comm::Manager::InitPostScript()
	{
	auto send_flags_type = internal_type("Comm::SendFlags")->AsRecordType();
	send_flags_self_idx = require_field(send_flags_type, "self");
	send_flags_peers_idx = require_field(send_flags_type, "peers");
	send_flags_unsolicited_idx = require_field(send_flags_type, "unsolicited");

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

	endpoint = unique_ptr<broker::endpoint>(new broker::endpoint(name));
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
                            chrono::duration<double> retry_interval)
	{
	auto& peer = peers[make_pair(addr, port)];

	if ( peer )
		return false;

	peer = endpoint->peer(move(addr), port, retry_interval);
	return true;
	}

bool comm::Manager::Disconnect(const string& addr, uint16_t port)
	{
	auto it = peers.find(make_pair(addr, port));

	if ( it == peers.end() )
		return false;

	auto rval = endpoint->unpeer(it->second);
	peers.erase(it);
	return rval;
	}

bool comm::Manager::Print(string topic, string msg, const Val* flags)
	{
	endpoint->send(move(topic), broker::message{move(msg)}, get_flags(flags));
	return true;
	}

bool comm::Manager::SubscribeToPrints(string topic_prefix)
	{
	auto& q = print_subscriptions[topic_prefix];

	if ( q )
		return false;

	q = broker::message_queue(move(topic_prefix), *endpoint);
	return true;
	}

bool comm::Manager::UnsubscribeToPrints(const string& topic_prefix)
	{
	return print_subscriptions.erase(topic_prefix);
	}

int comm::Manager::get_flags(const Val* flags)
	{
	auto r = flags->AsRecordVal();
	int rval = 0;
	Val* self_flag = r->LookupWithDefault(send_flags_self_idx);
	Val* peers_flag = r->LookupWithDefault(send_flags_peers_idx);
	Val* unsolicited_flag = r->LookupWithDefault(send_flags_unsolicited_idx);

	if ( self_flag->AsBool() )
		rval |= broker::SELF;

	if ( peers_flag->AsBool() )
		rval |= broker::PEERS;

	if ( unsolicited_flag->AsBool() )
		rval |= broker::UNSOLICITED;

	Unref(self_flag);
	Unref(peers_flag);
	Unref(unsolicited_flag);
	return rval;
	}

void comm::Manager::GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
                           iosource::FD_Set* except)
	{
	read->Insert(endpoint->peer_status().fd());

	for ( const auto& ps : print_subscriptions )
		read->Insert(ps.second.fd());
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

	for ( const auto& ps : print_subscriptions )
		{
		auto print_messages = ps.second.want_pop();

		if ( print_messages.empty() )
			continue;

		idle = false;

		if ( ! Comm::print_handler )
			continue;

		for ( auto& pm : print_messages )
			{
			if ( pm.size() != 1 )
				{
				reporter->Warning("got print message of invalid size: %zd",
				                  pm.size());
				continue;
				}

			std::string* msg = broker::get<std::string>(pm[0]);

			if ( ! msg )
				{
				reporter->Warning("got print message of invalid type: %d",
				                  static_cast<int>(broker::which(pm[0])));
				continue;
				}

			val_list* vl = new val_list;
			vl->append(new StringVal(move(*msg)));
			mgr.QueueEvent(Comm::print_handler, vl);
			}
		}

	SetIdle(idle);
	}

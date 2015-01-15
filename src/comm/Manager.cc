#include "Manager.h"
#include "Data.h"
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

	comm::opaque_of_data_type = new OpaqueType("Comm::Data");
	vector_of_data_type = new VectorType(internal_type("Comm::Data")->Ref());

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

bool comm::Manager::Event(std::string topic, const RecordVal* args,
                          const Val* flags)
	{
	if ( ! args->Lookup(0) )
		return false;

	auto event_name = args->Lookup(0)->AsString()->CheckString();
	auto vv = args->Lookup(1)->AsVectorVal();
	broker::message msg;
	msg.reserve(vv->Size() + 1);
	msg.emplace_back(event_name);

	for ( auto i = 0u; i < vv->Size(); ++i )
		{
		auto val = vv->Lookup(i)->AsRecordVal()->Lookup(0);
		auto data_val = dynamic_cast<DataVal*>(val);
		msg.emplace_back(data_val->data);
		}

	endpoint->send(move(topic), move(msg), get_flags(flags));
	return true;
	}

RecordVal* comm::Manager::MakeEventArgs(const val_list* args)
	{
	auto rval = new RecordVal(BifType::Record::Comm::EventArgs);
	auto arg_vec = new VectorVal(vector_of_data_type);
	rval->Assign(1, arg_vec);
	const Func* func;

	for ( auto i = 0u; i < args->length(); ++i )
		{
		auto arg_val = (*args)[i];

		if ( i == 0 )
			{
			// Event val must come first.

			if ( arg_val->Type()->Tag() != TYPE_FUNC )
				{
				reporter->Error("1st param of Comm::event_args must be event");
				return rval;
				}

			func = arg_val->AsFunc();

			if ( func->Flavor() != FUNC_FLAVOR_EVENT )
				{
				reporter->Error("1st param of Comm::event_args must be event");
				return rval;
				}

			auto num_args = func->FType()->Args()->NumFields();

			if ( num_args != args->length() - 1 )
				{
				reporter->Error("bad # of Comm::event_args: got %d, expect %d",
				                args->length(), num_args + 1);
				return rval;
				}

			rval->Assign(0, new StringVal(func->Name()));
			continue;
			}

		auto expected_type = (*func->FType()->ArgTypes()->Types())[i - 1];

		if ( ! same_type((*args)[i]->Type(), expected_type) )
			{
			rval->Assign(0, 0);
			reporter->Error("Comm::event_args param %d type mismatch", i);
			return rval;
			}

		auto data_val = make_data_val((*args)[i]);

		if ( ! data_val->Lookup(0) )
			{
			Unref(data_val);
			rval->Assign(0, 0);
			reporter->Error("Comm::event_args unsupported event/params");
			return rval;
			}

		arg_vec->Assign(i - 1, data_val);
		}

	return rval;
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

bool comm::Manager::SubscribeToEvents(string topic_prefix)
	{
	auto& q = event_subscriptions[topic_prefix];

	if ( q )
		return false;

	q = broker::message_queue(move(topic_prefix), *endpoint);
	return true;
	}

bool comm::Manager::UnsubscribeToEvents(const string& topic_prefix)
	{
	return event_subscriptions.erase(topic_prefix);
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

	for ( const auto& ps : event_subscriptions )
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

	for ( const auto& es : event_subscriptions )
		{
		auto event_messages = es.second.want_pop();

		if ( event_messages.empty() )
			continue;

		idle = false;

		for ( auto& em : event_messages )
			{
			if ( em.empty() )
				{
				reporter->Warning("got empty event message");
				continue;
				}

			std::string* event_name = broker::get<std::string>(em[0]);

			if ( ! event_name )
				{
				reporter->Warning("got event message w/o event name: %d",
				                  static_cast<int>(broker::which(em[0])));
				continue;
				}

			EventHandlerPtr ehp = event_registry->Lookup(event_name->data());

			if ( ! ehp )
				continue;

			auto arg_types = ehp->FType()->ArgTypes()->Types();

			if ( arg_types->length() != em.size() - 1 )
				{
				reporter->Warning("got event message with invalid # of args,"
				                  " got %zd, expected %d", em.size() - 1,
				                  arg_types->length());
				continue;
				}

			val_list* vl = new val_list;

			for ( auto i = 1u; i < em.size(); ++i )
				{
				auto val = data_to_val(move(em[i]), (*arg_types)[i - 1]);

				if ( val )
					vl->append(val);
				else
					{
					reporter->Warning("failed to convert remote event arg # %d",
					                  i - 1);
					break;
					}
				}

			if ( vl->length() == em.size() - 1 )
				mgr.QueueEvent(ehp, vl);
			else
				delete_vals(vl);
			}
		}

	SetIdle(idle);
	}

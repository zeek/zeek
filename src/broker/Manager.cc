#include "Manager.h"
#include "Data.h"
#include "Store.h"
#include <broker/broker.hh>
#include <broker/report.hh>
#include <cstdio>
#include <unistd.h>
#include "util.h"
#include "Var.h"
#include "Reporter.h"
#include "broker/comm.bif.h"
#include "broker/data.bif.h"
#include "broker/messaging.bif.h"
#include "broker/store.bif.h"
#include "logging/Manager.h"
#include "DebugLogger.h"
#include "iosource/Manager.h"

using namespace std;

VectorType* bro_broker::Manager::vector_of_data_type;
EnumType* bro_broker::Manager::log_id_type;
int bro_broker::Manager::send_flags_self_idx;
int bro_broker::Manager::send_flags_peers_idx;
int bro_broker::Manager::send_flags_unsolicited_idx;

bro_broker::Manager::Manager()
	: iosource::IOSource(), next_timestamp(-1)
	{
	SetIdle(true);
	}

bro_broker::Manager::~Manager()
	{
	vector<decltype(data_stores)::key_type> stores_to_close;

	for ( auto& s : data_stores )
		stores_to_close.emplace_back(s.first);

	for ( auto& s : stores_to_close )
		// This doesn't loop directly over data_stores, because CloseStore
		// modifies the map and invalidates iterators.
		CloseStore(s.first, s.second);
	}

static int require_field(RecordType* rt, const char* name)
	{
	auto rval = rt->FieldOffset(name);

	if ( rval < 0 )
		reporter->InternalError("no field named '%s' in record type '%s'", name,
		                        rt->GetName().data());

	return rval;
	}

static int endpoint_flags_to_int(Val* broker_endpoint_flags)
	{
	int rval = 0;
	auto r = broker_endpoint_flags->AsRecordVal();
	Val* auto_publish_flag = r->Lookup("auto_publish", true);
	Val* auto_advertise_flag = r->Lookup("auto_advertise", true);

	if ( auto_publish_flag->AsBool() )
		rval |= broker::AUTO_PUBLISH;

	if ( auto_advertise_flag->AsBool() )
		rval |= broker::AUTO_ADVERTISE;

	Unref(auto_publish_flag);
	Unref(auto_advertise_flag);
	return rval;
	}

bool bro_broker::Manager::Enable(Val* broker_endpoint_flags)
	{
	if ( endpoint != nullptr )
		return true;

	auto send_flags_type = internal_type("BrokerComm::SendFlags")->AsRecordType();
	send_flags_self_idx = require_field(send_flags_type, "self");
	send_flags_peers_idx = require_field(send_flags_type, "peers");
	send_flags_unsolicited_idx = require_field(send_flags_type, "unsolicited");

	log_id_type = internal_type("Log::ID")->AsEnumType();

	bro_broker::opaque_of_data_type = new OpaqueType("BrokerComm::Data");
	bro_broker::opaque_of_set_iterator = new OpaqueType("BrokerComm::SetIterator");
	bro_broker::opaque_of_table_iterator = new OpaqueType("BrokerComm::TableIterator");
	bro_broker::opaque_of_vector_iterator = new OpaqueType("BrokerComm::VectorIterator");
	bro_broker::opaque_of_record_iterator = new OpaqueType("BrokerComm::RecordIterator");
	bro_broker::opaque_of_store_handle = new OpaqueType("BrokerStore::Handle");
	vector_of_data_type = new VectorType(internal_type("BrokerComm::Data")->Ref());

	auto res = broker::init();

	if ( res )
		{
		fprintf(stderr, "broker::init failed: %s\n", broker::strerror(res));
		return false;
		}

	res = broker::report::init(true);

	if ( res )
		{
		fprintf(stderr, "broker::report::init failed: %s\n",
		        broker::strerror(res));
		return false;
		}

	const char* name;
	auto name_from_script = internal_val("BrokerComm::endpoint_name")->AsString();

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

	int flags = endpoint_flags_to_int(broker_endpoint_flags);
	endpoint = unique_ptr<broker::endpoint>(new broker::endpoint(name, flags));
	iosource_mgr->Register(this, true);
	return true;
	}

bool bro_broker::Manager::SetEndpointFlags(Val* broker_endpoint_flags)
	{
	if ( ! Enabled() )
		return false;

	int flags = endpoint_flags_to_int(broker_endpoint_flags);
	endpoint->set_flags(flags);
	return true;
	}

bool bro_broker::Manager::Listen(uint16_t port, const char* addr, bool reuse_addr)
	{
	if ( ! Enabled() )
		return false;

	auto rval = endpoint->listen(port, addr, reuse_addr);

	if ( ! rval )
		{
		reporter->Error("Failed to listen on %s:%" PRIu16 " : %s",
		                addr ? addr : "INADDR_ANY", port,
		                endpoint->last_error().data());
		}

	return rval;
	}

bool bro_broker::Manager::Connect(string addr, uint16_t port,
                            chrono::duration<double> retry_interval)
	{
	if ( ! Enabled() )
		return false;

	auto& peer = peers[make_pair(addr, port)];

	if ( peer )
		return false;

	peer = endpoint->peer(move(addr), port, retry_interval);
	return true;
	}

bool bro_broker::Manager::Disconnect(const string& addr, uint16_t port)
	{
	if ( ! Enabled() )
		return false;

	auto it = peers.find(make_pair(addr, port));

	if ( it == peers.end() )
		return false;

	auto rval = endpoint->unpeer(it->second);
	peers.erase(it);
	return rval;
	}

bool bro_broker::Manager::Print(string topic, string msg, Val* flags)
	{
	if ( ! Enabled() )
		return false;

	endpoint->send(move(topic), broker::message{move(msg)},
	               send_flags_to_int(flags));
	return true;
	}

bool bro_broker::Manager::Event(std::string topic, broker::message msg, int flags)
	{
	if ( ! Enabled() )
		return false;

	endpoint->send(move(topic), move(msg), flags);
	return true;
	}

bool bro_broker::Manager::Log(EnumVal* stream, RecordVal* columns, RecordType* info,
                        int flags)
	{
	if ( ! Enabled() )
		return false;

	auto stream_name = stream->Type()->AsEnumType()->Lookup(stream->AsEnum());

	if ( ! stream_name )
		{
		reporter->Error("Failed to remotely log: stream %d doesn't have name",
		                stream->AsEnum());
		return false;
		}

	broker::record column_data;

	for ( auto i = 0u; i < static_cast<size_t>(info->NumFields()); ++i )
		{
		if ( ! info->FieldDecl(i)->FindAttr(ATTR_LOG) )
			continue;

		auto field_val = columns->LookupWithDefault(i);

		if ( ! field_val )
			{
			column_data.fields.emplace_back(broker::record::field{});
			continue;
			}

		auto opt_field_data = val_to_data(field_val);
		Unref(field_val);

		if ( ! opt_field_data )
			{
			reporter->Error("Failed to remotely log stream %s: "
			                "unsupported type '%s'",
			                stream_name,
			                type_name(info->FieldDecl(i)->type->Tag()));
			return false;
			}

		column_data.fields.emplace_back(
		            broker::record::field{move(*opt_field_data)});
		}

	broker::message msg{broker::enum_value{stream_name}, move(column_data)};
	std::string topic = std::string("bro/log/") + stream_name;
	endpoint->send(move(topic), move(msg), flags);
	return true;
	}

bool bro_broker::Manager::Event(std::string topic, RecordVal* args, Val* flags)
	{
	if ( ! Enabled() )
		return false;

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
		auto data_val = static_cast<DataVal*>(val);
		msg.emplace_back(data_val->data);
		}

	endpoint->send(move(topic), move(msg), send_flags_to_int(flags));
	return true;
	}

bool bro_broker::Manager::AutoEvent(string topic, Val* event, Val* flags)
	{
	if ( ! Enabled() )
		return false;

	if ( event->Type()->Tag() != TYPE_FUNC )
		{
		reporter->Error("BrokerComm::auto_event must operate on an event");
		return false;
		}

	auto event_val = event->AsFunc();

	if ( event_val->Flavor() != FUNC_FLAVOR_EVENT )
		{
		reporter->Error("BrokerComm::auto_event must operate on an event");
		return false;
		}

	auto handler = event_registry->Lookup(event_val->Name());

	if ( ! handler )
		{
		reporter->Error("BrokerComm::auto_event failed to lookup event '%s'",
		                event_val->Name());
		return false;
		}

	handler->AutoRemote(move(topic), send_flags_to_int(flags));
	return true;
	}

bool bro_broker::Manager::AutoEventStop(const string& topic, Val* event)
	{
	if ( ! Enabled() )
		return false;

	if ( event->Type()->Tag() != TYPE_FUNC )
		{
		reporter->Error("BrokerComm::auto_event_stop must operate on an event");
		return false;
		}

	auto event_val = event->AsFunc();

	if ( event_val->Flavor() != FUNC_FLAVOR_EVENT )
		{
		reporter->Error("BrokerComm::auto_event_stop must operate on an event");
		return false;
		}

	auto handler = event_registry->Lookup(event_val->Name());

	if ( ! handler )
		{
		reporter->Error("BrokerComm::auto_event_stop failed to lookup event '%s'",
		                event_val->Name());
		return false;
		}


	handler->AutoRemoteStop(topic);
	return true;
	}

RecordVal* bro_broker::Manager::MakeEventArgs(val_list* args)
	{
	if ( ! Enabled() )
		return nullptr;

	auto rval = new RecordVal(BifType::Record::BrokerComm::EventArgs);
	auto arg_vec = new VectorVal(vector_of_data_type);
	rval->Assign(1, arg_vec);
	Func* func = 0;

	for ( auto i = 0; i < args->length(); ++i )
		{
		auto arg_val = (*args)[i];

		if ( i == 0 )
			{
			// Event val must come first.

			if ( arg_val->Type()->Tag() != TYPE_FUNC )
				{
				reporter->Error("1st param of BrokerComm::event_args must be event");
				return rval;
				}

			func = arg_val->AsFunc();

			if ( func->Flavor() != FUNC_FLAVOR_EVENT )
				{
				reporter->Error("1st param of BrokerComm::event_args must be event");
				return rval;
				}

			auto num_args = func->FType()->Args()->NumFields();

			if ( num_args != args->length() - 1 )
				{
				reporter->Error("bad # of BrokerComm::event_args: got %d, expect %d",
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
			reporter->Error("BrokerComm::event_args param %d type mismatch", i);
			return rval;
			}

		auto data_val = make_data_val((*args)[i]);

		if ( ! data_val->Lookup(0) )
			{
			Unref(data_val);
			rval->Assign(0, 0);
			reporter->Error("BrokerComm::event_args unsupported event/params");
			return rval;
			}

		arg_vec->Assign(i - 1, data_val);
		}

	return rval;
	}

bool bro_broker::Manager::SubscribeToPrints(string topic_prefix)
	{
	if ( ! Enabled() )
		return false;

	auto& q = print_subscriptions[topic_prefix].q;

	if ( q )
		return false;

	q = broker::message_queue(move(topic_prefix), *endpoint);
	return true;
	}

bool bro_broker::Manager::UnsubscribeToPrints(const string& topic_prefix)
	{
	if ( ! Enabled() )
		return false;

	return print_subscriptions.erase(topic_prefix);
	}

bool bro_broker::Manager::SubscribeToEvents(string topic_prefix)
	{
	if ( ! Enabled() )
		return false;

	auto& q = event_subscriptions[topic_prefix].q;

	if ( q )
		return false;

	q = broker::message_queue(move(topic_prefix), *endpoint);
	return true;
	}

bool bro_broker::Manager::UnsubscribeToEvents(const string& topic_prefix)
	{
	if ( ! Enabled() )
		return false;

	return event_subscriptions.erase(topic_prefix);
	}

bool bro_broker::Manager::SubscribeToLogs(string topic_prefix)
	{
	if ( ! Enabled() )
		return false;

	auto& q = log_subscriptions[topic_prefix].q;

	if ( q )
		return false;

	q = broker::message_queue(move(topic_prefix), *endpoint);
	return true;
	}

bool bro_broker::Manager::UnsubscribeToLogs(const string& topic_prefix)
	{
	if ( ! Enabled() )
		return false;

	return log_subscriptions.erase(topic_prefix);
	}

bool bro_broker::Manager::PublishTopic(broker::topic t)
	{
	if ( ! Enabled() )
		return false;

	endpoint->publish(move(t));
	return true;
	}

bool bro_broker::Manager::UnpublishTopic(broker::topic t)
	{
	if ( ! Enabled() )
		return false;

	endpoint->unpublish(move(t));
	return true;
	}

bool bro_broker::Manager::AdvertiseTopic(broker::topic t)
	{
	if ( ! Enabled() )
		return false;

	endpoint->advertise(move(t));
	return true;
	}

bool bro_broker::Manager::UnadvertiseTopic(broker::topic t)
	{
	if ( ! Enabled() )
		return false;

	endpoint->unadvertise(move(t));
	return true;
	}

int bro_broker::Manager::send_flags_to_int(Val* flags)
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

void bro_broker::Manager::GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
                           iosource::FD_Set* except)
	{
	read->Insert(endpoint->outgoing_connection_status().fd());
	read->Insert(endpoint->incoming_connection_status().fd());

	for ( const auto& ps : print_subscriptions )
		read->Insert(ps.second.q.fd());

	for ( const auto& ps : event_subscriptions )
		read->Insert(ps.second.q.fd());

	for ( const auto& ps : log_subscriptions )
		read->Insert(ps.second.q.fd());

	for ( const auto& s : data_stores )
		read->Insert(s.second->store->responses().fd());

	read->Insert(broker::report::default_queue->fd());
	}

double bro_broker::Manager::NextTimestamp(double* local_network_time)
	{
	if ( next_timestamp < 0 )
		next_timestamp = timer_mgr->Time();

	return next_timestamp;
	}

struct response_converter {
	using result_type = RecordVal*;
	broker::store::query::tag query_tag;

	result_type operator()(bool d)
		{
		switch ( query_tag ) {
		case broker::store::query::tag::pop_left:
		case broker::store::query::tag::pop_right:
		case broker::store::query::tag::lookup:
			// A boolean result means the key doesn't exist (if it did, then
			// the result would contain the broker::data value, not a bool).
			return new RecordVal(BifType::Record::BrokerComm::Data);
		default:
			return bro_broker::make_data_val(broker::data{d});
		}
		}

	result_type operator()(uint64_t d)
		{
		return bro_broker::make_data_val(broker::data{d});
		}

	result_type operator()(broker::data& d)
		{
		return bro_broker::make_data_val(move(d));
		}

	result_type operator()(std::vector<broker::data>& d)
		{
		return bro_broker::make_data_val(broker::data{move(d)});
		}

	result_type operator()(broker::store::snapshot& d)
		{
		broker::table table;

		for ( auto& item : d.entries )
			{
			auto& key = item.first;
			auto& val = item.second.item;
			table[move(key)] = move(val);
			}

		return bro_broker::make_data_val(broker::data{move(table)});
		}
};

static RecordVal* response_to_val(broker::store::response r)
	{
	return broker::visit(response_converter{r.request.type}, r.reply.value);
	}

void bro_broker::Manager::Process()
	{
	auto outgoing_connection_updates =
	        endpoint->outgoing_connection_status().want_pop();
	auto incoming_connection_updates =
	        endpoint->incoming_connection_status().want_pop();

	statistics.outgoing_conn_status_count += outgoing_connection_updates.size();
	statistics.incoming_conn_status_count += incoming_connection_updates.size();

	for ( auto& u : outgoing_connection_updates )
		{
		switch ( u.status ) {
		case broker::outgoing_connection_status::tag::established:
			if ( BrokerComm::outgoing_connection_established )
				{
				val_list* vl = new val_list;
				vl->append(new StringVal(u.relation.remote_tuple().first));
				vl->append(new PortVal(u.relation.remote_tuple().second,
				                       TRANSPORT_TCP));
				vl->append(new StringVal(u.peer_name));
				mgr.QueueEvent(BrokerComm::outgoing_connection_established, vl);
				}
			break;

		case broker::outgoing_connection_status::tag::disconnected:
			if ( BrokerComm::outgoing_connection_broken )
				{
				val_list* vl = new val_list;
				vl->append(new StringVal(u.relation.remote_tuple().first));
				vl->append(new PortVal(u.relation.remote_tuple().second,
				                       TRANSPORT_TCP));
				mgr.QueueEvent(BrokerComm::outgoing_connection_broken, vl);
				}
			break;

		case broker::outgoing_connection_status::tag::incompatible:
			if ( BrokerComm::outgoing_connection_incompatible )
				{
				val_list* vl = new val_list;
				vl->append(new StringVal(u.relation.remote_tuple().first));
				vl->append(new PortVal(u.relation.remote_tuple().second,
				                       TRANSPORT_TCP));
				mgr.QueueEvent(BrokerComm::outgoing_connection_incompatible, vl);
				}
			break;

		default:
			reporter->InternalWarning(
			            "unknown broker::outgoing_connection_status::tag : %d",
			            static_cast<int>(u.status));
			break;
		}
		}

	for ( auto& u : incoming_connection_updates )
		{
		switch ( u.status ) {
		case broker::incoming_connection_status::tag::established:
			if ( BrokerComm::incoming_connection_established )
				{
				val_list* vl = new val_list;
				vl->append(new StringVal(u.peer_name));
				mgr.QueueEvent(BrokerComm::incoming_connection_established, vl);
				}
			break;

		case broker::incoming_connection_status::tag::disconnected:
			if ( BrokerComm::incoming_connection_broken )
				{
				val_list* vl = new val_list;
				vl->append(new StringVal(u.peer_name));
				mgr.QueueEvent(BrokerComm::incoming_connection_broken, vl);
				}
			break;

		default:
			reporter->InternalWarning(
			            "unknown broker::incoming_connection_status::tag : %d",
			            static_cast<int>(u.status));
			break;
		}
		}

	for ( auto& ps : print_subscriptions )
		{
		auto print_messages = ps.second.q.want_pop();

		if ( print_messages.empty() )
			continue;

		ps.second.received += print_messages.size();

		if ( ! BrokerComm::print_handler )
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
			mgr.QueueEvent(BrokerComm::print_handler, vl);
			}
		}

	for ( auto& es : event_subscriptions )
		{
		auto event_messages = es.second.q.want_pop();

		if ( event_messages.empty() )
			continue;

		es.second.received += event_messages.size();

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

			if ( static_cast<size_t>(arg_types->length()) != em.size() - 1 )
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

			if ( static_cast<size_t>(vl->length()) == em.size() - 1 )
				mgr.QueueEvent(ehp, vl);
			else
				delete_vals(vl);
			}
		}

	struct unref_guard {
		unref_guard(Val* v) : val(v) {}
		~unref_guard() { Unref(val); }
		Val* val;
	};

	for ( auto& ls : log_subscriptions )
		{
		auto log_messages = ls.second.q.want_pop();

		if ( log_messages.empty() )
			continue;

		ls.second.received += log_messages.size();

		for ( auto& lm : log_messages )
			{
			if ( lm.size() != 2 )
				{
				reporter->Warning("got bad remote log size: %zd (expect 2)",
				                  lm.size());
				continue;
				}

			if ( ! broker::get<broker::enum_value>(lm[0]) )
				{
				reporter->Warning("got remote log w/o stream id: %d",
				                  static_cast<int>(broker::which(lm[0])));
				continue;
				}

			if ( ! broker::get<broker::record>(lm[1]) )
				{
				reporter->Warning("got remote log w/o columns: %d",
				                  static_cast<int>(broker::which(lm[1])));
				continue;
				}

			auto stream_id = data_to_val(move(lm[0]), log_id_type);

			if ( ! stream_id )
				{
				reporter->Warning("failed to unpack remote log stream id");
				continue;
				}

			unref_guard stream_id_unreffer{stream_id};
			auto columns_type = log_mgr->StreamColumns(stream_id->AsEnumVal());

			if ( ! columns_type )
				{
				reporter->Warning("got remote log for unknown stream: %s",
				                  stream_id->Type()->AsEnumType()->Lookup(
				                      stream_id->AsEnum()));
				continue;
				}

			auto columns = data_to_val(move(lm[1]), columns_type, true);

			if ( ! columns )
				{
				reporter->Warning("failed to unpack remote log stream columns"
				                  " for stream: %s",
				                  stream_id->Type()->AsEnumType()->Lookup(
				                      stream_id->AsEnum()));
				continue;
				}

			log_mgr->Write(stream_id->AsEnumVal(), columns->AsRecordVal());
			Unref(columns);
			}
		}

	for ( const auto& s : data_stores )
		{
		auto responses = s.second->store->responses().want_pop();

		if ( responses.empty() )
			continue;

		statistics.report_count += responses.size();

		for ( auto& response : responses )
			{
			auto ck = static_cast<StoreQueryCallback*>(response.cookie);
			auto it = pending_queries.find(ck);

			if ( it == pending_queries.end() )
				{
				reporter->Warning("unmatched response to query on store %s",
				                  s.second->store->id().data());
				continue;
				}

			auto query = *it;

			if ( query->Disabled() )
				{
				// Trigger timer must have timed the query out already.
				delete query;
				pending_queries.erase(it);
				continue;
				}

			switch ( response.reply.stat ) {
			case broker::store::result::status::timeout:
				// Fine, trigger's timeout takes care of things.
				break;
			case broker::store::result::status::failure:
				query->Result(query_result());
				break;
			case broker::store::result::status::success:
				query->Result(query_result(response_to_val(move(response))));
				break;
			default:
				reporter->InternalWarning("unknown store response status: %d",
				                         static_cast<int>(response.reply.stat));
				break;
			}

			delete query;
			pending_queries.erase(it);
			}
		}

	auto reports = broker::report::default_queue->want_pop();
	statistics.report_count += reports.size();

	for ( auto& report : reports )
		{
		if ( report.size() < 2 )
			{
			reporter->Warning("got broker report msg of size %zu, expect 4",
			                  report.size());
			continue;
			}

		uint64_t* level = broker::get<uint64_t>(report[1]);

		if ( ! level )
			{
			reporter->Warning("got broker report msg w/ bad level type: %d",
			                  static_cast<int>(broker::which(report[1])));
			continue;
			}

		auto lvl = static_cast<broker::report::level>(*level);

		switch ( lvl ) {
		case broker::report::level::debug:
			DBG_LOG(DBG_BROKER, broker::to_string(report).data());
			break;
		case broker::report::level::info:
			reporter->Info("broker info: %s",
			               broker::to_string(report).data());
			break;
		case broker::report::level::warn:
			reporter->Warning("broker warning: %s",
			                  broker::to_string(report).data());
			break;
		case broker::report::level::error:
			reporter->Error("broker error: %s",
			                broker::to_string(report).data());
			break;
			}
		}

	next_timestamp = -1;
	}

bool bro_broker::Manager::AddStore(StoreHandleVal* handle)
	{
	if ( ! Enabled() )
		return false;

	if ( ! handle->store )
		return false;

	auto key = make_pair(handle->store->id(), handle->store_type);

	if ( data_stores.find(key) != data_stores.end() )
		return false;

	data_stores[key] = handle;
	Ref(handle);
	return true;
	}

bro_broker::StoreHandleVal*
bro_broker::Manager::LookupStore(const broker::store::identifier& id,
                           bro_broker::StoreType type)
	{
	if ( ! Enabled() )
		return nullptr;

	auto key = make_pair(id, type);
	auto it = data_stores.find(key);

	if ( it == data_stores.end() )
		return nullptr;

	return it->second;
	}

bool bro_broker::Manager::CloseStore(const broker::store::identifier& id,
                               StoreType type)
	{
	if ( ! Enabled() )
		return false;

	auto key = make_pair(id, type);
	auto it = data_stores.find(key);

	if ( it == data_stores.end() )
		return false;

	for ( auto it = pending_queries.begin(); it != pending_queries.end(); )
		{
		auto query = *it;

		if ( query->GetStoreType() == type && query->StoreID() == id )
			{
			it = pending_queries.erase(it);
			query->Abort();
			delete query;
			}
		else
			++it;
		}

	delete it->second->store;
	it->second->store = nullptr;
	Unref(it->second);
	data_stores.erase(it);
	return true;
	}

bool bro_broker::Manager::TrackStoreQuery(StoreQueryCallback* cb)
	{
	assert(Enabled());
	return pending_queries.insert(cb).second;
	}

bro_broker::Stats bro_broker::Manager::ConsumeStatistics()
	{
	statistics.outgoing_peer_count = peers.size();
	statistics.data_store_count = data_stores.size();
	statistics.pending_query_count = pending_queries.size();

	for ( auto& s : print_subscriptions )
		{
		statistics.print_count[s.first] = s.second.received;
		s.second.received = 0;
		}

	for ( auto& s : event_subscriptions )
		{
		statistics.event_count[s.first] = s.second.received;
		s.second.received = 0;
		}

	for ( auto& s : log_subscriptions )
		{
		statistics.log_count[s.first] = s.second.received;
		s.second.received = 0;
		}

	auto rval = move(statistics);
	statistics = Stats{};
	return rval;
	}

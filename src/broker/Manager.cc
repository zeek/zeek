
#include <broker/broker.hh>
#include <cstdio>
#include <unistd.h>

#include "Manager.h"
#include "Data.h"
#include "Store.h"
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

namespace bro_broker {

VectorType* Manager::vector_of_data_type;
EnumType* Manager::log_id_type;

#ifdef DEBUG
static std::string RenderMessage(std::string topic, broker::data x)
	{
	return fmt("%s -> %s", broker::to_string(x).c_str(), topic.c_str());
	}

static std::string RenderMessage(const broker::vector* xs)
	{
	return broker::to_string(*xs);
	}

static std::string RenderMessage(const broker::status* s)
	{
	return broker::to_string(s->code());
	}

static std::string RenderMessage(broker::error e)
	{
	return fmt("%s (%s)", broker::to_string(e.code()).c_str(),
		   caf::to_string(e.context()).c_str());
	}

#endif

Manager::Manager()
	{
	routable = false;
	name = "";
	bound_port = 0;

	next_timestamp = 1;
	SetIdle(true);
	}

Manager::~Manager()
	{
	}

static int require_field(RecordType* rt, const char* name)
	{
	auto rval = rt->FieldOffset(name);

	if ( rval < 0 )
		reporter->InternalError("no field named '%s' in record type '%s'", name,
		                        rt->GetName().data());

	return rval;
	}

void Manager::InitPostScript()
	{
	DBG_LOG(DBG_BROKER, "Initializing");

	log_id_type = internal_type("Log::ID")->AsEnumType();

	opaque_of_data_type = new OpaqueType("Broker::Data");
	opaque_of_set_iterator = new OpaqueType("Broker::SetIterator");
	opaque_of_table_iterator = new OpaqueType("Broker::TableIterator");
	opaque_of_vector_iterator = new OpaqueType("Broker::VectorIterator");
	opaque_of_record_iterator = new OpaqueType("Broker::RecordIterator");
	opaque_of_store_handle = new OpaqueType("Broker::Handle");
	vector_of_data_type = new VectorType(internal_type("Broker::Data")->Ref());

	endpoint = context.spawn<broker::blocking>();

	iosource_mgr->Register(this, true);
	}

void Manager::Terminate()
	{
	// TODO: Is there a better way to shutdown communication regularly?
	for ( auto p : endpoint.peers() )
		endpoint.unpeer(p.peer.network->address, p.peer.network->port);

	// TODO: How to "unlisten"?

	vector<string> stores_to_close;

	for ( auto& x : data_stores )
		stores_to_close.push_back(x.first);

	for ( auto& x: stores_to_close )
		// This doesn't loop directly over data_stores, because CloseStore
		// modifies the map and invalidates iterators.
		CloseStore(x);
	}

bool Manager::Active()
	{
	return bound_port > 0 || endpoint.peers().size();
	}

bool Manager::Configure(std::string arg_name, bool arg_routable)
	{
	DBG_LOG(DBG_BROKER, "Configuring endpoint: name=%s, routable=%s",
		name.c_str(), (routable ? "yes" : "no"));;

	name = std::move(arg_name);
	routable = arg_routable;
	// TODO: process routable flag
	return true;
	}

uint16_t Manager::Listen(const string& addr, uint16_t port)
	{
	bound_port = endpoint.listen(addr, port);

	if ( bound_port == 0 )
		reporter->Error("Failed to listen on %s:%" PRIu16,
		                addr.empty() ? "INADDR_ANY" : addr.c_str(), port);

	DBG_LOG(DBG_BROKER, "Listening on %s:%" PRIu16,
		addr.empty() ? "INADDR_ANY" : addr.c_str(), port);

	return bound_port;
	}

void Manager::Peer(const string& addr, uint16_t port)
	{
	DBG_LOG(DBG_BROKER, "Starting to peer with %s:%" PRIu16,
		addr.c_str(), port);

	endpoint.peer(addr, port);
	}

void Manager::Unpeer(const string& addr, uint16_t port)
	{
	DBG_LOG(DBG_BROKER, "Stopping to peer with %s:%" PRIu16,
		addr.c_str(), port);
	endpoint.unpeer(addr, port);
	}

bool Manager::Publish(broker::message msg)
	{
	DBG_LOG(DBG_BROKER, "Publishing event: %s",
		RenderMessage(msg.topic().string(), msg.data()).c_str());
	endpoint.publish(std::move(msg));
	return true;
	}

bool Manager::Publish(string topic, broker::data x)
	{
	DBG_LOG(DBG_BROKER, "Publishing event: %s",
		RenderMessage(topic, x).c_str());
	endpoint.publish(move(topic), move(x));
	return true;
	}

bool Manager::Publish(EnumVal* stream, RecordVal* columns,
                              RecordType* info)
	{
	auto stream_name = stream->Type()->AsEnumType()->Lookup(stream->AsEnum());

	if ( ! stream_name )
		{
		reporter->Error("Failed to remotely log: stream %d doesn't have name",
		                stream->AsEnum());
		return false;
		}

	broker::vector xs;
	xs.reserve(info->NumFields() + 1);
	xs.emplace_back(broker::enum_value{stream_name});

	for ( auto i = 0u; i < static_cast<size_t>(info->NumFields()); ++i )
		{
		if ( ! info->FieldDecl(i)->FindAttr(ATTR_LOG) )
			continue;

		auto field_val = columns->LookupWithDefault(i);

		if ( ! field_val )
			{
			xs.emplace_back(broker::nil);
			continue;
			}

		auto field_data = val_to_data(field_val);
		Unref(field_val);

		if ( ! field_data )
			{
			reporter->Error("Failed to remotely log stream %s: "
			                "unsupported type '%s'",
			                stream_name,
			                type_name(info->FieldDecl(i)->type->Tag()));
			return false;
			}

		xs.push_back(move(*field_data));
		}

	auto stream_enum = broker::enum_value{stream_name};
	auto topic = "bro/log"_t / stream_name;
	auto data = broker::vector{stream_enum, move(xs)};

	DBG_LOG(DBG_BROKER, "Publishing log record: %s", RenderMessage(topic.string(), data).c_str());
	endpoint.publish(move(topic), move(data));

	return true;
	}

bool Manager::Publish(string topic, RecordVal* args)
	{
	if ( ! args->Lookup(0) )
		return false;

	auto event_name = args->Lookup(0)->AsString()->CheckString();
	auto vv = args->Lookup(1)->AsVectorVal();
	broker::vector xs;
	xs.reserve(vv->Size() + 1);
	xs.emplace_back(event_name);

	for ( auto i = 0u; i < vv->Size(); ++i )
		{
		auto val = vv->Lookup(i)->AsRecordVal()->Lookup(0);
		auto data_val = static_cast<DataVal*>(val);
		xs.emplace_back(data_val->data);
		}

	DBG_LOG(DBG_BROKER, "Publishing message: %s", RenderMessage(topic, xs).c_str());
	endpoint.publish(move(topic), move(xs));

	return true;
	}

bool Manager::AutoPublish(string topic, Val* event)
	{
	if ( event->Type()->Tag() != TYPE_FUNC )
		{
		reporter->Error("Broker::auto_publish must operate on an event");
		return false;
		}

	auto event_val = event->AsFunc();
	if ( event_val->Flavor() != FUNC_FLAVOR_EVENT )
		{
		reporter->Error("Broker::auto_publish must operate on an event");
		return false;
		}

	auto handler = event_registry->Lookup(event_val->Name());
	if ( ! handler )
		{
		reporter->Error("Broker::auto_publish failed to lookup event '%s'",
		                event_val->Name());
		return false;
		}

	DBG_LOG(DBG_BROKER, "Enabling auto-publising of event %s to topic %s", handler->Name(), topic.c_str());
	handler->AutoPublish(move(topic));

	return true;
	}

bool Manager::AutoUnpublish(const string& topic, Val* event)
	{
	if ( event->Type()->Tag() != TYPE_FUNC )
		{
		reporter->Error("Broker::auto_event_stop must operate on an event");
		return false;
		}

	auto event_val = event->AsFunc();

	if ( event_val->Flavor() != FUNC_FLAVOR_EVENT )
		{
		reporter->Error("Broker::auto_event_stop must operate on an event");
		return false;
		}

	auto handler = event_registry->Lookup(event_val->Name());

	if ( ! handler )
		{
		reporter->Error("Broker::auto_event_stop failed to lookup event '%s'",
		                event_val->Name());
		return false;
		}


	DBG_LOG(DBG_BROKER, "Disabling auto-publishing of event %s to topic %s", handler->Name(), topic.c_str());
	handler->AutoUnpublish(topic);

	return true;
	}

RecordVal* Manager::MakeEvent(val_list* args)
	{
	auto rval = new RecordVal(BifType::Record::Broker::Event);
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
				reporter->Error("1st param of Broker::event_args must be event");
				return rval;
				}

			func = arg_val->AsFunc();

			if ( func->Flavor() != FUNC_FLAVOR_EVENT )
				{
				reporter->Error("1st param of Broker::event_args must be event");
				return rval;
				}

			auto num_args = func->FType()->Args()->NumFields();

			if ( num_args != args->length() - 1 )
				{
				reporter->Error("bad # of Broker::event_args: got %d, expect %d",
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
			reporter->Error("Broker::event_args param %d type mismatch", i);
			return rval;
			}

		auto data_val = make_data_val((*args)[i]);

		if ( ! data_val->Lookup(0) )
			{
			Unref(data_val);
			rval->Assign(0, 0);
			reporter->Error("Broker::event_args unsupported event/params");
			return rval;
			}

		arg_vec->Assign(i - 1, data_val);
		}

	return rval;
	}

bool Manager::Subscribe(const string& topic_prefix)
	{
	DBG_LOG(DBG_BROKER, "Subscribing to topic prefix %s", topic_prefix.c_str());
	endpoint.subscribe(topic_prefix);
	return true;
	}

bool Manager::Unsubscribe(const string& topic_prefix)
	{
	DBG_LOG(DBG_BROKER, "Unsubscribing from topic prefix %s", topic_prefix.c_str());
	endpoint.unsubscribe(topic_prefix);
	return true;
	}

void Manager::GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
                           iosource::FD_Set* except)
	{
	read->Insert(endpoint.mailbox().descriptor());

	for ( auto& x : data_stores )
		read->Insert(x.second->proxy.mailbox().descriptor());
	}

double Manager::NextTimestamp(double* local_network_time)
	{
	if ( next_timestamp < 0 )
		next_timestamp = timer_mgr->Time();

	return next_timestamp;
	}

void Manager::Process()
	{
	while ( ! endpoint.mailbox().empty() )
		{
		auto elem = endpoint.receive();

		if ( auto msg = broker::get_if<broker::message>(elem) )
			{
			// All valid messages have non-empty vector data.
			auto xs = broker::get_if<broker::vector>(msg->data());
			if ( ! xs )
				{
				reporter->Warning("ignoring message with non-vector data");
				continue;
				}

			if ( xs->empty() )
				{
				reporter->Warning("ignoring message with empty vector data");
				continue;
				}

			if ( msg->topic() == "bro/log" )
				ProcessLog(xs);
			else
				ProcessEvent(xs);

			}

		else if ( auto stat = broker::get_if<broker::status>(elem) )
			ProcessStatus(stat);
		else if (auto err = broker::get_if<broker::error>(elem))
			ProcessError(*err);
		else
			reporter->Warning("unknown Broker message type received");
		}

	for ( auto &s : data_stores )
		{
		while ( ! s.second->proxy.mailbox().empty())
			{
			auto response = s.second->proxy.receive();
			ProcessStoreResponse(s.second, move(response));
			}
		}

	next_timestamp = -1;
	}

void Manager::ProcessEvent(const broker::vector* xs)
	{
	DBG_LOG(DBG_BROKER, "Received event: %s", RenderMessage(xs).c_str());

	auto event_name = broker::get_if<string>((*xs)[0]);
	if ( ! event_name )
		{
		reporter->Warning("ignoring message without event name");
		return;
		}

	auto handler = event_registry->Lookup(event_name->c_str());
	if ( ! handler )
		return;

	auto arg_types = handler->FType()->ArgTypes()->Types();
	if ( static_cast<size_t>(arg_types->length()) != xs->size() - 1 )
		{
		reporter->Warning("got event message with invalid # of args,"
				  " got %zd, expected %d", xs->size() - 1,
				  arg_types->length());
		return;
		}

	auto vl = new val_list;

	for ( auto i = 1u; i < xs->size(); ++i )
		{
		auto val = data_to_val(move((*xs)[i]), (*arg_types)[i - 1]);

		if ( val )
			vl->append(val);
		else
			{
			reporter->Warning("failed to convert remote event arg # %d", i - 1);
			break;
			}
		}

	if ( static_cast<size_t>(vl->length()) == xs->size() - 1 )
		mgr.QueueEvent(handler, vl);
	else
		delete_vals(vl);
	}

void Manager::ProcessLog(const broker::vector* xs)
	{
	DBG_LOG(DBG_BROKER, "Received log record: %s", RenderMessage(xs).c_str());

	if ( xs->size() != 2 )
		{
		reporter->Warning("got bad remote log size: %zd (expected 2)",
				  xs->size());
		return;
		}

	if ( ! broker::get_if<broker::enum_value>(xs->front()) )
		{
		reporter->Warning("got remote log w/o stream id");
		return;
		}

	if ( ! broker::get_if<broker::vector>(xs->back()) )
		{
		reporter->Warning("got remote log w/o columns");
		return;
		}

	auto stream_id = data_to_val(move(xs->front()), log_id_type);

	if ( ! stream_id )
		{
		reporter->Warning("failed to unpack remote log stream id");
		return;
		}

	auto columns_type = log_mgr->StreamColumns(stream_id->AsEnumVal());
	if ( ! columns_type )
		{
		reporter->Warning("got remote log for unknown stream: %s",
				  stream_id->Type()->AsEnumType()->Lookup(
									  stream_id->AsEnum()));
		Unref(stream_id);
		return;
		}

	auto columns = data_to_val(move(xs->back()), columns_type, true);
	if ( ! columns )
		{
		reporter->Warning("failed to unpack remote log stream columns"
				  " for stream: %s",
				  stream_id->Type()->AsEnumType()->Lookup(
									  stream_id->AsEnum()));
		Unref(stream_id);
		return;
		}

	log_mgr->Write(stream_id->AsEnumVal(), columns->AsRecordVal());
	Unref(stream_id);
	Unref(columns);
	}

void Manager::ProcessStatus(const broker::status* stat)
	{
	DBG_LOG(DBG_BROKER, "Received status message: %s", RenderMessage(stat).c_str());

	EventHandlerPtr event;
	switch (stat->code()) {
	case broker::sc::unspecified:
		event = Broker::status;
		break;

	case broker::sc::peer_added:
		event = Broker::peer_added;
		break;

	case broker::sc::peer_removed:
		event = Broker::peer_removed;
		break;

	case broker::sc::peer_lost:
		event = Broker::peer_lost;
		break;

	case broker::sc::peer_recovered:
		event = Broker::peer_recovered;
		break;
	}

	auto ei = internal_type("Broker::EndpointInfo")->AsRecordType();
	auto endpoint_info = new RecordVal(ei);

	if ( auto ctx = stat->context<broker::endpoint_info>() )
		{
		auto id = to_string(ctx->node) + to_string(ctx->id);
		endpoint_info->Assign(0, new StringVal(id));

		if ( ctx->network )
			{
			auto ni = internal_type("Broker::NetworkInfo")->AsRecordType();
			auto network_info = new RecordVal(ni);
			network_info->Assign(0, new AddrVal(IPAddr(ctx->network->address)));
			network_info->Assign(1, new PortVal(ctx->network->port, TRANSPORT_TCP));
			endpoint_info->Assign(1, network_info);
			}
		}

	auto str = stat->message();
	auto msg = new StringVal(str ? *str : "");

	auto vl = new val_list;
	vl->append(endpoint_info);
	vl->append(msg);

	mgr.QueueEvent(event, vl);
	}

void Manager::ProcessError(broker::error err)
	{
	if ( err )
		return; // All good, no error.

	DBG_LOG(DBG_BROKER, "Received error message: %s", RenderMessage(err).c_str());

	BifEnum::Broker::ErrorCode ec;
	std::string msg;

	if ( err.category() != caf::atom("broker") )
		{
		msg = caf::to_string(err.context());

		switch ( static_cast<broker::ec>(err.code()) ) {
		case broker::ec::peer_incompatible:
			ec = BifEnum::Broker::ErrorCode::PEER_INCOMPATIBLE;
			break;

		case broker::ec::peer_invalid:
			ec = BifEnum::Broker::ErrorCode::PEER_INVALID;
			break;

		case broker::ec::peer_unavailable:
			ec = BifEnum::Broker::ErrorCode::PEER_UNAVAILABLE;
			break;

		case broker::ec::peer_timeout:
			ec = BifEnum::Broker::ErrorCode::PEER_TIMEOUT;
			break;

		case broker::ec::master_exists:
			ec = BifEnum::Broker::ErrorCode::MASTER_EXISTS;
			break;

		case broker::ec::no_such_master:
			ec = BifEnum::Broker::ErrorCode::NO_SUCH_MASTER;
			break;

		case broker::ec::no_such_key:
			ec = BifEnum::Broker::ErrorCode::NO_SUCH_KEY;
			break;

		case broker::ec::request_timeout:
			ec = BifEnum::Broker::ErrorCode::REQUEST_TIMEOUT;
			break;

		case broker::ec::type_clash:
			ec = BifEnum::Broker::ErrorCode::TYPE_CLASH;
			break;

		case broker::ec::invalid_data:
			ec = BifEnum::Broker::ErrorCode::INVALID_DATA;
			break;

		case broker::ec::backend_failure:
			ec = BifEnum::Broker::ErrorCode::BACKEND_FAILURE;
			break;

		case broker::ec::unspecified: // fall-through
		default:
			ec = BifEnum::Broker::ErrorCode::UNSPECIFIED;
		}
		}

	else
		{
		ec = BifEnum::Broker::ErrorCode::CAF_ERROR;
		msg = fmt("[%s] %s", caf::to_string(err.category()).c_str(), caf::to_string(err.context()).c_str());
		}

	auto vl = new val_list;
	vl->append(new EnumVal(ec, BifType::Enum::Broker::ErrorCode));
	vl->append(new StringVal(msg));
	mgr.QueueEvent(Broker::error, vl);
	}

void Manager::ProcessStoreResponse(StoreHandleVal* s, broker::store::response response)
	{
	// DBG_LOG(DBG_BROKER, "Received store response: %s", RenderMessage(response).c_str());

	auto request = pending_queries.find(response.id);
	if ( request == pending_queries.end() )
		{
		reporter->Warning("unmatched response to query %llu on store %s",
				  response.id, s->store.name().c_str());
		return;
		}

	if ( request->second->Disabled() )
		{
		// Trigger timer must have timed the query out already.
		delete request->second;
		pending_queries.erase(request);
		return;
		}

	if ( response.answer )
		request->second->Result(query_result(make_data_val(*response.answer)));
	else if ( response.answer.error() == broker::ec::request_timeout )
		; // Fine, trigger's timeout takes care of things.
	else if ( response.answer.error() == broker::ec::no_such_key )
		request->second->Result(query_result());
	else
		reporter->InternalWarning("unknown store response status: %s",
					  to_string(response.answer.error()).c_str());

	delete request->second;
	pending_queries.erase(request);
	}

StoreHandleVal* Manager::MakeMaster(const string& name, broker::backend type,
                                    broker::backend_options opts)
	{
	if ( LookupStore(name) )
		return nullptr;

	DBG_LOG(DBG_BROKER, "Creating master for data store %s", name.c_str());

	auto result = endpoint.attach<broker::master>(name, type, move(opts));
	if ( ! result )
		{
		reporter->Error("Failed to attach master store %s:",
		                to_string(result.error()).c_str());
		return nullptr;
		}

	auto handle = new StoreHandleVal{*result};
	Ref(handle);

	data_stores.emplace(name, handle);

	return handle;
	}

StoreHandleVal* Manager::MakeClone(const string& name)
	{
	if ( LookupStore(name) )
		return nullptr;

	DBG_LOG(DBG_BROKER, "Creating clone for data store %s", name.c_str());

	auto result = endpoint.attach<broker::clone>(name);
	if ( ! result )
		{
		reporter->Error("Failed to attach clone store %s:",
		                to_string(result.error()).c_str());
		return nullptr;
		}

	auto handle = new StoreHandleVal{*result};
	Ref(handle);

	data_stores.emplace(name, handle);

	return handle;
	}

StoreHandleVal* Manager::LookupStore(const string& name)
	{
	auto i = data_stores.find(name);
	return i == data_stores.end() ? nullptr : i->second;
	}

bool Manager::CloseStore(const string& name)
	{
	DBG_LOG(DBG_BROKER, "Closing data store %s", name.c_str());

	auto s = data_stores.find(name);
	if ( s == data_stores.end() )
		return false;

	for ( auto i = pending_queries.begin(); i != pending_queries.end(); )
		if ( i->second->Store().name() == name )
			{
			i->second->Abort();
			delete i->second;
			i = pending_queries.erase(i);
			}
	else
		{
		++i;
		}

	Unref(s->second);
	data_stores.erase(s);
	return true;
	}

bool Manager::TrackStoreQuery(broker::request_id id, StoreQueryCallback* cb)
	{
	return pending_queries.emplace(id, cb).second;
	}

Stats Manager::ConsumeStatistics()
	{
	return {}; // TODO
	}

} // namespace bro_broker

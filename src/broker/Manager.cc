
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

namespace atom {
using event = broker::message_type_constant<broker::make_message_type("event")>;
using log_create = broker::message_type_constant<broker::make_message_type("log-create")>;
using log_write = broker::message_type_constant<broker::make_message_type("log-write")>;
}

const broker::endpoint_info Manager::NoPeer{{}, caf::invalid_actor_id, {}};

VectorType* Manager::vector_of_data_type;
EnumType* Manager::log_id_type;
EnumType* Manager::writer_id_type;
int Manager::send_flags_self_idx;
int Manager::send_flags_peers_idx;
int Manager::send_flags_unsolicited_idx;

struct unref_guard {
	unref_guard(Val* v) : val(v) {}
	~unref_guard() { Unref(val); }
	Val* val;
};

#ifdef DEBUG
static std::string RenderMessage(std::string topic, broker::data x)
	{
	return fmt("%s -> %s", broker::to_string(x).c_str(), topic.c_str());
	}

static std::string RenderMessage(const broker::vector* xs)
	{
	return broker::to_string(*xs);
	}

static std::string RenderMessage(const broker::vector& xs)
	{
	return broker::to_string(xs);
	}

static std::string RenderMessage(const broker::status& s)
	{
	return broker::to_string(s.code());
	}

static std::string RenderMessage(const broker::error& e)
	{
	return fmt("%s (%s)", broker::to_string(e.code()).c_str(),
		   caf::to_string(e.context()).c_str());
	}

#endif

Manager::Manager()
	{
	routable = false;
	bound_port = 0;

	next_timestamp = 1;
	SetIdle(true);
	}

Manager::~Manager()
	{
	}

void Manager::InitPostScript()
	{
	DBG_LOG(DBG_BROKER, "Initializing");

	log_id_type = internal_type("Log::ID")->AsEnumType();
	writer_id_type = internal_type("Log::Writer")->AsEnumType();

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

bool Manager::Configure(bool arg_routable, std::string arg_log_topic)
	{
	DBG_LOG(DBG_BROKER, "Configuring endpoint: routable=%s log_topic=%s",
		(routable ? "yes" : "no"), arg_log_topic.c_str());

	routable = arg_routable;
	log_topic = arg_log_topic;

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

void Manager::Peer(const string& addr, uint16_t port, double retry)
	{
	DBG_LOG(DBG_BROKER, "Starting to peer with %s:%" PRIu16,
		addr.c_str(), port);

	if ( retry > 0.0 && retry < 1.0 )
		// Ensure that it doesn't get turned into zero.
		retry = 1.0;

	auto ms = broker::timeout::seconds(static_cast<uint64>(retry));
	endpoint.peer(addr, port, ms);
	}

void Manager::Unpeer(const string& addr, uint16_t port)
	{
	DBG_LOG(DBG_BROKER, "Stopping to peer with %s:%" PRIu16,
		addr.c_str(), port);
	endpoint.unpeer(addr, port);
	}

bool Manager::PublishEvent(string topic, broker::data x)
	{
	DBG_LOG(DBG_BROKER, "Publishing event: %s",
		RenderMessage(topic, x).c_str());
	broker::vector data = {ProtocolVersion, move(x)};
	endpoint.publish(move(topic), atom::event::value, std::move(data));
	return true;
	}

bool Manager::PublishEvent(string topic, RecordVal* args)
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

	DBG_LOG(DBG_BROKER, "Publishing event: %s", RenderMessage(topic, xs).c_str());
	broker::vector data = {ProtocolVersion, move(xs)};
	endpoint.publish(move(topic), atom::event::value, std::move(data));

	return true;
	}

bool Manager::PublishLogCreate(EnumVal* stream, EnumVal* writer,
			       const logging::WriterBackend::WriterInfo& info,
			       int num_fields, const threading::Field* const * fields,
			       const broker::endpoint_info& peer)
	{
	auto stream_name = stream->Type()->AsEnumType()->Lookup(stream->AsEnum());

	if ( ! stream_name )
		{
		reporter->Error("Failed to remotely log: stream %d doesn't have name",
		                stream->AsEnum());
		return false;
		}

	auto writer_name = writer->Type()->AsEnumType()->Lookup(writer->AsEnum());

	if ( ! writer_name )
		{
		reporter->Error("Failed to remotely log: writer %d doesn't have name",
		                writer->AsEnum());
		return false;
		}

	auto writer_info = info.ToBroker();

	broker::vector fields_data;

	for ( auto i = 0; i < num_fields; ++i )
		{
		auto field_data = threading_field_to_data(fields[i]);
		fields_data.push_back(move(field_data));
		}

	// TODO: If peer is given, send message to just that one destination.

	std::string topic = log_topic + stream_name;
	auto bstream_name = broker::enum_value(move(stream_name));
	auto bwriter_name = broker::enum_value(move(writer_name));
	broker::vector xs{move(bstream_name), move(bwriter_name), move(writer_info), move(fields_data)};

	DBG_LOG(DBG_BROKER, "Publishing log creation: %s", RenderMessage(topic, xs).c_str());
	broker::vector data = {ProtocolVersion, move(xs)};
	endpoint.publish(move(topic), atom::log_create::value, move(data));

	return true;
	}

bool Manager::PublishLogWrite(EnumVal* stream, EnumVal* writer, string path, int num_vals, const threading::Value* const * vals)
	{
	auto stream_name = stream->Type()->AsEnumType()->Lookup(stream->AsEnum());

	if ( ! stream_name )
		{
		reporter->Error("Failed to remotely log: stream %d doesn't have name",
		                stream->AsEnum());
		return false;
		}

	auto writer_name = writer->Type()->AsEnumType()->Lookup(writer->AsEnum());

	if ( ! writer_name )
		{
		reporter->Error("Failed to remotely log: writer %d doesn't have name",
		                writer->AsEnum());
		return false;
		}

	broker::vector vals_data;

	for ( auto i = 0; i < num_vals; ++i )
		{
		auto field_data = threading_val_to_data(vals[i]);

		if ( ! field_data )
			{
			reporter->Error("Failed to remotely log stream %s: "
			                "unsupported type for field #%d",
			                stream_name, i);
			return false;
			}

		vals_data.push_back(move(*field_data));
		}

	std::string topic = log_topic + stream_name;
	auto bstream_name = broker::enum_value(move(stream_name));
	auto bwriter_name = broker::enum_value(move(writer_name));

	broker::vector xs{move(bstream_name), move(bwriter_name), move(path), move(vals_data)};

	DBG_LOG(DBG_BROKER, "Publishing log record: %s", RenderMessage(topic, xs).c_str());
	broker::vector data = {ProtocolVersion, move(xs)};
	endpoint.publish(move(topic), atom::log_write::value, move(data));

	return true;
	}

bool Manager::AutoPublishEvent(string topic, Val* event)
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

bool Manager::AutoUnpublishEvent(const string& topic, Val* event)
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
		auto msg = broker::get_if<broker::message>(elem);

		if ( msg )
			{
			// All valid messages have non-empty vector data.
			auto xs = broker::get_if<broker::vector>(msg->data());
			if ( ! xs )
				{
				reporter->Warning("ignoring message with non-vector content");
				continue;
				}

			if ( xs->size() != 2 )
				{
				reporter->Warning("ignoring message without too few fields");
				continue;
				}

			auto version = broker::get_if<broker::count>((*xs)[0]);

			if ( ! version )
				{
				reporter->Warning("ignoring message without version");
				continue;
				}

			if ( *version != ProtocolVersion )
				{
				// Eventually we could do something more
				// clever here to accomodate old versions.
				reporter->Warning("ignoring message with unexpected version (%" PRIu64 ")", *version);
				continue;
				}

			auto ty = msg->type();
			auto xt = broker::get_if<broker::vector>((*xs)[1]);

			if ( ! xt )
				{
				reporter->Warning("ignoring message with non-vector data");
				continue;
				}

			if ( ty == atom::event::value )
				ProcessEvent(std::move(*xt));

			else if ( ty == atom::log_create::value )
				ProcessLogCreate(std::move(*xt));

			else if ( ty == atom::log_write::value )
				ProcessLogWrite(std::move(*xt));

			// We ignore unknown types so that we could add more
			// message in the future if we had too. This included
			// the default type.
			}

		else if ( auto stat = broker::get_if<broker::status>(elem) )
			ProcessStatus(std::move(*stat));

		else if ( auto err = broker::get_if<broker::error>(elem) )
			ProcessError(std::move(*err));
		else
			reporter->InternalWarning("unknown Broker message type received");
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

void Manager::ProcessEvent(const broker::vector xs)
	{
	DBG_LOG(DBG_BROKER, "Received event: %s", RenderMessage(xs).c_str());

	auto event_name = broker::get_if<string>(xs[0]);
	if ( ! event_name )
		{
		reporter->Warning("ignoring message without event name");
		return;
		}

	auto handler = event_registry->Lookup(event_name->c_str());
	if ( ! handler )
		return;

	auto arg_types = handler->FType()->ArgTypes()->Types();
	if ( static_cast<size_t>(arg_types->length()) != xs.size() - 1 )
		{
		reporter->Warning("got event message with invalid # of args,"
				  " got %zd, expected %d", xs.size() - 1,
				  arg_types->length());
		return;
		}

	auto vl = new val_list;

	for ( auto i = 1u; i < xs.size(); ++i )
		{
		auto val = data_to_val(move(xs[i]), (*arg_types)[i - 1]);

		if ( val )
			vl->append(val);
		else
			{
			reporter->Warning("failed to convert remote event arg # %d", i - 1);
			break;
			}
		}

	if ( static_cast<size_t>(vl->length()) == xs.size() - 1 )
		mgr.QueueEvent(handler, vl);
	else
		delete_vals(vl);
	}

bool bro_broker::Manager::ProcessLogCreate(const broker::vector xs)
	{
	DBG_LOG(DBG_BROKER, "Received log-create: %s", RenderMessage(xs).c_str());

	if ( xs.size() != 4 )
		{
		reporter->Warning("got bad remote log create size: %zd (expected 5)",
				  xs.size());
		return false;
		}

	unsigned int idx = 0;

	// Get stream ID.

	if ( ! broker::is<broker::enum_value>(xs[idx]) )
		{
		reporter->Warning("got remote log create w/o stream id");
		return false;
		}

	auto stream_id = data_to_val(move(xs[idx]), log_id_type);

	if ( ! stream_id )
		{
		reporter->Warning("failed to unpack remote log stream id");
		return false;
		}

	unref_guard stream_id_unreffer{stream_id};
	++idx;

	// Get writer ID.

	if ( ! broker::is<broker::enum_value>(xs[idx]) )
		{
		reporter->Warning("got remote log create w/o writer id");
		return false;
		}

	auto writer_id = data_to_val(move(xs[idx]), writer_id_type);

	if ( ! writer_id )
		{
		reporter->Warning("failed to unpack remote log writer id");
		return false;
		}

	unref_guard writer_id_unreffer{writer_id};
	++idx;

	// Get writer info.

	if ( ! broker::is<broker::vector>(xs[idx]) )
		{
		reporter->Warning("got remote log create w/o writer info id");
		return false;
		}

	auto writer_info = std::unique_ptr<logging::WriterBackend::WriterInfo>(new logging::WriterBackend::WriterInfo);

	if ( ! writer_info->FromBroker(std::move(xs[idx])) )
		{
		reporter->Warning("failed to unpack remote log writer info");
		return false;
		}

	++idx;

	// Get log fields.

	auto fields_data = broker::get_if<broker::vector>(xs[idx]);

	if ( ! fields_data )
		{
		reporter->Warning("failed to unpack remote log fields");
		return false;
		}

	auto num_fields = fields_data->size();
	auto fields = new threading::Field* [num_fields];

	for ( auto i = 0u; i < num_fields; ++i )
		{
		if ( auto field = data_to_threading_field((*fields_data)[i]) )
			fields[i] = field;
		else
			{
			reporter->Warning("failed to convert remote log field # %d", i);
			return false;
			}
		}

	if ( ! log_mgr->CreateWriterForRemoteLog(stream_id->AsEnumVal(), writer_id->AsEnumVal(), writer_info.get(), num_fields, fields) )
		{
		ODesc d;
		stream_id->Describe(&d);
		reporter->Warning("failed to create remote log stream for %s locally", d.Description());
		}

	writer_info.release(); // log_mgr took ownership.
	return true;
	}

bool bro_broker::Manager::ProcessLogWrite(const broker::vector xs)
	{
	DBG_LOG(DBG_BROKER, "Received log-write: %s", RenderMessage(xs).c_str());

	if ( xs.size() != 4 )
		{
		reporter->Warning("got bad remote log size: %zd (expected 5)",
				  xs.size());
		return false;
		}

	unsigned int idx = 0;

	// Get stream ID.

	if ( ! broker::is<broker::enum_value>(xs[idx]) )
		{
		reporter->Warning("got remote log w/o stream id");
		return false;
		}

	auto stream_id = data_to_val(move(xs[idx]), log_id_type);

	if ( ! stream_id )
		{
		reporter->Warning("failed to unpack remote log stream id");
		return false;
		}

	unref_guard stream_id_unreffer{stream_id};
	++idx;

	// Get writer ID.

	if ( ! broker::is<broker::enum_value>(xs[idx]) )
		{
		reporter->Warning("got remote log w/o writer id");
		return false;
		}

	auto writer_id = data_to_val(move(xs[idx]), writer_id_type);

	if ( ! writer_id )
		{
		reporter->Warning("failed to unpack remote log writer id");
		return false;
		}

	unref_guard writer_id_unreffer{writer_id};
	++idx;

	// Get path.

	auto path = broker::get_if<std::string>(xs[idx]);

	if ( ! path )
		{
		reporter->Warning("failed to unpack remote log path");
		return false;
		}

	++idx;

	// Get log values.

	auto vals_data = broker::get_if<broker::vector>(xs[idx]);

	if ( ! vals_data )
		{
		reporter->Warning("failed to unpack remote log values");
		return false;
		}

	auto num_vals = vals_data->size();
	auto vals = new threading::Value* [num_vals];

	for ( auto i = 0u; i < num_vals; ++i )
		{
		if ( auto val = data_to_threading_val((*vals_data)[i]) )
			vals[i] = val;
		else
			{
			std::cerr << vals << " | " << (*vals_data)[i] << std::endl;
			reporter->Warning("failed to convert remote log arg # %d", i);
			return false;
			}
		}

	log_mgr->WriteFromRemote(stream_id->AsEnumVal(), writer_id->AsEnumVal(), *path, num_vals, vals);
	return true;
	}

void Manager::ProcessStatus(const broker::status stat)
	{
	DBG_LOG(DBG_BROKER, "Received status message: %s", RenderMessage(stat).c_str());

	auto ctx = stat.context<broker::endpoint_info>();

	EventHandlerPtr event;
	switch (stat.code()) {
	case broker::sc::unspecified:
		event = Broker::status;
		break;

	case broker::sc::peer_added:
	        assert(ctx);
	        log_mgr->SendAllWritersTo(*ctx);
		event = Broker::peer_added;
		break;

	case broker::sc::peer_removed:
		event = Broker::peer_removed;
		break;

	case broker::sc::peer_lost:
		event = Broker::peer_lost;
		break;
	}

	auto ei = internal_type("Broker::EndpointInfo")->AsRecordType();
	auto endpoint_info = new RecordVal(ei);

	if ( ctx )
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

	auto str = stat.message();
	auto msg = new StringVal(str ? *str : "");

	auto vl = new val_list;
	vl->append(endpoint_info);
	vl->append(msg);

	mgr.QueueEvent(event, vl);
	}

void Manager::ProcessError(broker::error err)
	{
	DBG_LOG(DBG_BROKER, "Received error message: %s", RenderMessage(err).c_str());

	BifEnum::Broker::ErrorCode ec;
	std::string msg;

	if ( err.category() == caf::atom("broker") )
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

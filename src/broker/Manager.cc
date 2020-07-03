#include "Manager.h"

#include <broker/broker.hh>
#include <broker/zeek.hh>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include "Func.h"
#include "Data.h"
#include "Store.h"
#include "util.h"
#include "Var.h"
#include "Desc.h"
#include "Reporter.h"
#include "IntrusivePtr.h"
#include "broker/comm.bif.h"
#include "broker/data.bif.h"
#include "broker/messaging.bif.h"
#include "broker/store.bif.h"
#include "logging/Manager.h"
#include "DebugLogger.h"
#include "iosource/Manager.h"
#include "SerializationFormat.h"
#include "Net.h"

using namespace std;

namespace bro_broker {

static inline zeek::Val* get_option(const char* option)
	{
	const auto& id = zeek::detail::global_scope()->Find(option);

	if ( ! (id && id->GetVal()) )
		reporter->FatalError("Unknown Broker option %s", option);

	return id->GetVal().get();
	}

class BrokerConfig : public broker::configuration {
public:
	BrokerConfig(broker::broker_options options)
		: broker::configuration(options)
		{
		openssl_cafile = get_option("Broker::ssl_cafile")->AsString()->CheckString();
		openssl_capath = get_option("Broker::ssl_capath")->AsString()->CheckString();
		openssl_certificate = get_option("Broker::ssl_certificate")->AsString()->CheckString();
		openssl_key = get_option("Broker::ssl_keyfile")->AsString()->CheckString();
		openssl_passphrase = get_option("Broker::ssl_passphrase")->AsString()->CheckString();
		}
};

class BrokerState {
public:
	BrokerState(BrokerConfig config, size_t congestion_queue_size)
		: endpoint(std::move(config)),
		  subscriber(endpoint.make_subscriber({}, congestion_queue_size)),
		  status_subscriber(endpoint.make_status_subscriber(true))
		{
		}

	broker::endpoint endpoint;
	broker::subscriber subscriber;
	broker::status_subscriber status_subscriber;
};

const broker::endpoint_info Manager::NoPeer{{}, {}};

int Manager::script_scope = 0;

struct scoped_reporter_location {
	scoped_reporter_location(zeek::detail::Frame* frame)
		{
		reporter->PushLocation(frame->GetCall()->GetLocationInfo());
		}

	~scoped_reporter_location()
		{
		reporter->PopLocation();
		}
};

#ifdef DEBUG
static std::string RenderMessage(std::string topic, const broker::data& x)
	{
	return fmt("%s -> %s", broker::to_string(x).c_str(), topic.c_str());
	}

static std::string RenderEvent(std::string topic, std::string name, const broker::data& args)
	{
	return fmt("%s(%s) -> %s", name.c_str(), broker::to_string(args).c_str(), topic.c_str());
	}

static std::string RenderMessage(const broker::store::response& x)
	{
	return fmt("%s [id %" PRIu64 "]", (x.answer ? broker::to_string(*x.answer).c_str() : "<no answer>"), x.id);
	}

static std::string RenderMessage(const broker::vector* xs)
	{
	return broker::to_string(*xs);
	}

static std::string RenderMessage(const broker::data& d)
	{
	return broker::to_string(d);
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

Manager::Manager(bool arg_use_real_time)
	{
	bound_port = 0;
	use_real_time = arg_use_real_time;
	after_zeek_init = false;
	peer_count = 0;
	log_batch_size = 0;
	log_topic_func = nullptr;
	log_id_type = nullptr;
	writer_id_type = nullptr;
	}

Manager::~Manager()
	{
	}

void Manager::InitPostScript()
	{
	DBG_LOG(DBG_BROKER, "Initializing");

	log_batch_size = get_option("Broker::log_batch_size")->AsCount();
	default_log_topic_prefix =
	    get_option("Broker::default_log_topic_prefix")->AsString()->CheckString();
	log_topic_func = get_option("Broker::log_topic")->AsFunc();
	log_id_type = zeek::id::find_type("Log::ID")->AsEnumType();
	writer_id_type = zeek::id::find_type("Log::Writer")->AsEnumType();

	opaque_of_data_type = zeek::make_intrusive<zeek::OpaqueType>("Broker::Data");
	opaque_of_set_iterator = zeek::make_intrusive<zeek::OpaqueType>("Broker::SetIterator");
	opaque_of_table_iterator = zeek::make_intrusive<zeek::OpaqueType>("Broker::TableIterator");
	opaque_of_vector_iterator = zeek::make_intrusive<zeek::OpaqueType>("Broker::VectorIterator");
	opaque_of_record_iterator = zeek::make_intrusive<zeek::OpaqueType>("Broker::RecordIterator");
	opaque_of_store_handle = zeek::make_intrusive<zeek::OpaqueType>("Broker::Store");
	vector_of_data_type = zeek::make_intrusive<zeek::VectorType>(zeek::id::find_type("Broker::Data"));

	// Register as a "dont-count" source first, we may change that later.
	iosource_mgr->Register(this, true);

	broker::broker_options options;
	options.disable_ssl = get_option("Broker::disable_ssl")->AsBool();
	options.forward = get_option("Broker::forward_messages")->AsBool();
	options.use_real_time = use_real_time;

	BrokerConfig config{std::move(options)};

	auto scheduler_policy = get_option("Broker::scheduler_policy")->AsString()->CheckString();

	if ( streq(scheduler_policy, "sharing") )
		config.set("scheduler.policy", caf::atom("sharing"));
	else if ( streq(scheduler_policy, "stealing") )
		config.set("scheduler.policy", caf::atom("stealing"));
	else
		reporter->FatalError("Invalid Broker::scheduler_policy: %s", scheduler_policy);

	auto max_threads_env = zeekenv("ZEEK_BROKER_MAX_THREADS");

	if ( max_threads_env )
		config.set("scheduler.max-threads", atoi(max_threads_env));
	else
		config.set("scheduler.max-threads",
		           get_option("Broker::max_threads")->AsCount());

	config.set("work-stealing.moderate-sleep-duration", caf::timespan(
	    static_cast<unsigned>(get_option("Broker::moderate_sleep")->AsInterval() * 1e9)));

	config.set("work-stealing.relaxed-sleep-duration", caf::timespan(
	    static_cast<unsigned>(get_option("Broker::relaxed_sleep")->AsInterval() * 1e9)));

	config.set("work-stealing.aggressive-poll-attempts",
	           get_option("Broker::aggressive_polls")->AsCount());
	config.set("work-stealing.moderate-poll-attempts",
	           get_option("Broker::moderate_polls")->AsCount());

	config.set("work-stealing.aggressive-steal-interval",
	           get_option("Broker::aggressive_interval")->AsCount());
	config.set("work-stealing.moderate-steal-interval",
	           get_option("Broker::moderate_interval")->AsCount());
	config.set("work-stealing.relaxed-steal-interval",
	           get_option("Broker::relaxed_interval")->AsCount());

	auto cqs = get_option("Broker::congestion_queue_size")->AsCount();
	bstate = std::make_shared<BrokerState>(std::move(config), cqs);

	if ( ! iosource_mgr->RegisterFd(bstate->subscriber.fd(), this) )
		reporter->FatalError("Failed to register broker subscriber with iosource_mgr");
	if ( ! iosource_mgr->RegisterFd(bstate->status_subscriber.fd(), this) )
		reporter->FatalError("Failed to register broker status subscriber with iosource_mgr");
	}

void Manager::Terminate()
	{
	FlushLogBuffers();

	iosource_mgr->UnregisterFd(bstate->subscriber.fd(), this);
	iosource_mgr->UnregisterFd(bstate->status_subscriber.fd(), this);

	vector<string> stores_to_close;

	for ( auto& x : data_stores )
		stores_to_close.push_back(x.first);

	for ( auto& x: stores_to_close )
		// This doesn't loop directly over data_stores, because CloseStore
		// modifies the map and invalidates iterators.
		CloseStore(x);

	FlushLogBuffers();

	for ( auto& p : bstate->endpoint.peers() )
		if ( p.peer.network )
			bstate->endpoint.unpeer(p.peer.network->address,
			                        p.peer.network->port);

	bstate->endpoint.shutdown();
	}

bool Manager::Active()
	{
	if ( bstate->endpoint.is_shutdown() )
		return false;

	if ( bound_port > 0 )
		return true;

	return peer_count > 0;
	}

void Manager::AdvanceTime(double seconds_since_unix_epoch)
	{
	if ( bstate->endpoint.is_shutdown() )
		return;

	if ( bstate->endpoint.use_real_time() )
		return;

	auto secs = std::chrono::duration<double>(seconds_since_unix_epoch);
	auto span = std::chrono::duration_cast<broker::timespan>(secs);
	broker::timestamp next_time{span};
	bstate->endpoint.advance_time(next_time);
	}

void Manager::FlushPendingQueries()
	{
	while ( ! pending_queries.empty() )
		{
		// possibly an infinite loop if a query can recursively
		// generate more queries...
		for ( auto& s : data_stores )
			{
			while ( ! s.second->proxy.mailbox().empty() )
				{
				auto response = s.second->proxy.receive();
				ProcessStoreResponse(s.second, move(response));
				}
			}
		}
	}

void Manager::ClearStores()
	{
	FlushPendingQueries();

	for ( const auto& [name, handle] : data_stores )
		handle->store.clear();
	}

uint16_t Manager::Listen(const string& addr, uint16_t port)
	{
	if ( bstate->endpoint.is_shutdown() )
		return 0;

	bound_port = bstate->endpoint.listen(addr, port);

	if ( bound_port == 0 )
		Error("Failed to listen on %s:%" PRIu16,
		      addr.empty() ? "INADDR_ANY" : addr.c_str(), port);

	// Register as a "does-count" source now.
	iosource_mgr->Register(this, false);

	DBG_LOG(DBG_BROKER, "Listening on %s:%" PRIu16,
		addr.empty() ? "INADDR_ANY" : addr.c_str(), port);

	return bound_port;
	}

void Manager::Peer(const string& addr, uint16_t port, double retry)
	{
	if ( bstate->endpoint.is_shutdown() )
		return;

	DBG_LOG(DBG_BROKER, "Starting to peer with %s:%" PRIu16,
		addr.c_str(), port);

	auto e = zeekenv("ZEEK_DEFAULT_CONNECT_RETRY");

	if ( e )
		retry = atoi(e);

	if ( retry > 0.0 && retry < 1.0 )
		// Ensure that it doesn't get turned into zero.
		retry = 1.0;

	auto secs = broker::timeout::seconds(static_cast<uint64_t>(retry));
	bstate->endpoint.peer_nosync(addr, port, secs);

	auto counts_as_iosource = get_option("Broker::peer_counts_as_iosource")->AsBool();

	if ( counts_as_iosource )
		// Register as a "does-count" source now.
		iosource_mgr->Register(this, false);
	}

void Manager::Unpeer(const string& addr, uint16_t port)
	{
	if ( bstate->endpoint.is_shutdown() )
		return;

	DBG_LOG(DBG_BROKER, "Stopping to peer with %s:%" PRIu16,
		addr.c_str(), port);

	FlushLogBuffers();
	bstate->endpoint.unpeer_nosync(addr, port);
	}

std::vector<broker::peer_info> Manager::Peers() const
	{
	if ( bstate->endpoint.is_shutdown() )
		return {};

	return bstate->endpoint.peers();
	}

std::string Manager::NodeID() const
	{
	return to_string(bstate->endpoint.node_id());
	}

bool Manager::PublishEvent(string topic, std::string name, broker::vector args)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( peer_count == 0 )
		return true;

	DBG_LOG(DBG_BROKER, "Publishing event: %s",
		RenderEvent(topic, name, args).c_str());
	broker::zeek::Event ev(std::move(name), std::move(args));
	bstate->endpoint.publish(move(topic), ev.move_data());
	++statistics.num_events_outgoing;
	return true;
	}

bool Manager::PublishEvent(string topic, zeek::RecordVal* args)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( peer_count == 0 )
		return true;

	if ( ! args->GetField(0) )
		return false;

	auto event_name = args->GetField(0)->AsString()->CheckString();
	auto vv = args->GetField(1)->AsVectorVal();
	broker::vector xs;
	xs.reserve(vv->Size());

	for ( auto i = 0u; i < vv->Size(); ++i )
		{
		const auto& val = vv->At(i)->AsRecordVal()->GetField(0);
		auto data_val = static_cast<DataVal*>(val.get());
		xs.emplace_back(data_val->data);
		}

	return PublishEvent(std::move(topic), event_name, std::move(xs));
	}

bool Manager::PublishIdentifier(std::string topic, std::string id)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( peer_count == 0 )
		return true;

	const auto& i = zeek::detail::global_scope()->Find(id);

	if ( ! i )
		return false;

	const auto& val = i->GetVal();

	if ( ! val )
		// Probably could have a special case to also unset the value on the
		// receiving side, but not sure what use that would be.
		return false;

	auto data = val_to_data(val.get());

	if ( ! data )
		{
		Error("Failed to publish ID with unsupported type: %s (%s)",
		      id.c_str(), zeek::type_name(val->GetType()->Tag()));
		return false;
		}

	broker::zeek::IdentifierUpdate msg(move(id), move(*data));
	DBG_LOG(DBG_BROKER, "Publishing id-update: %s",
	        RenderMessage(topic, msg.as_data()).c_str());
	bstate->endpoint.publish(move(topic), msg.move_data());
	++statistics.num_ids_outgoing;
	return true;
	}

bool Manager::PublishLogCreate(zeek::EnumVal* stream, zeek::EnumVal* writer,
                               const logging::WriterBackend::WriterInfo& info,
                               int num_fields, const threading::Field* const * fields,
                               const broker::endpoint_info& peer)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( peer_count == 0 )
		return true;

	auto stream_id = stream->GetType()->AsEnumType()->Lookup(stream->AsEnum());

	if ( ! stream_id )
		{
		reporter->Error("Failed to remotely log: stream %d doesn't have name",
		                stream->AsEnum());
		return false;
		}

	auto writer_id = writer->GetType()->AsEnumType()->Lookup(writer->AsEnum());

	if ( ! writer_id )
		{
		reporter->Error("Failed to remotely log: writer %d doesn't have name",
		                writer->AsEnum());
		return false;
		}

	auto writer_info = info.ToBroker();

	broker::vector fields_data;
	fields_data.reserve(num_fields);

	for ( auto i = 0; i < num_fields; ++i )
		{
		auto field_data = threading_field_to_data(fields[i]);
		fields_data.push_back(move(field_data));
		}

	std::string topic = default_log_topic_prefix + stream_id;
	auto bstream_id = broker::enum_value(move(stream_id));
	auto bwriter_id = broker::enum_value(move(writer_id));
	broker::zeek::LogCreate msg(move(bstream_id), move(bwriter_id), move(writer_info), move(fields_data));

	DBG_LOG(DBG_BROKER, "Publishing log creation: %s", RenderMessage(topic, msg.as_data()).c_str());

	if ( peer.node != NoPeer.node )
		// Direct message.
		bstate->endpoint.publish(peer, move(topic), msg.move_data());
	else
		// Broadcast.
		bstate->endpoint.publish(move(topic), msg.move_data());

	return true;
	}

bool Manager::PublishLogWrite(zeek::EnumVal* stream, zeek::EnumVal* writer, string path,
                              int num_fields, const threading::Value* const * vals)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( peer_count == 0 )
		return true;

	auto stream_id_num = stream->AsEnum();
	auto stream_id = stream->GetType()->AsEnumType()->Lookup(stream_id_num);

	if ( ! stream_id )
		{
		reporter->Error("Failed to remotely log: stream %d doesn't have name",
		                stream->AsEnum());
		return false;
		}

	auto writer_id = writer->GetType()->AsEnumType()->Lookup(writer->AsEnum());

	if ( ! writer_id )
		{
		reporter->Error("Failed to remotely log: writer %d doesn't have name",
		                writer->AsEnum());
		return false;
		}

	BinarySerializationFormat fmt;
	char* data;
	int len;

	fmt.StartWrite();

	bool success = fmt.Write(num_fields, "num_fields");

	if ( ! success )
		{
		reporter->Error("Failed to remotely log stream %s: num_fields serialization failed", stream_id);
		return false;
		}

	for ( int i = 0; i < num_fields; ++i )
		{
		if ( ! vals[i]->Write(&fmt) )
			{
			reporter->Error("Failed to remotely log stream %s: field %d serialization failed", stream_id, i);
			return false;
			}
		}

	len = fmt.EndWrite(&data);
	std::string serial_data(data, len);
	free(data);

	auto v = log_topic_func->Invoke(zeek::IntrusivePtr{zeek::NewRef{}, stream},
	                                zeek::make_intrusive<zeek::StringVal>(path));

	if ( ! v )
		{
		reporter->Error("Failed to remotely log: log_topic func did not return"
		                " a value for stream %s at path %s", stream_id,
		                path.data());
		return false;
		}

	std::string topic = v->AsString()->CheckString();

	auto bstream_id = broker::enum_value(move(stream_id));
	auto bwriter_id = broker::enum_value(move(writer_id));
	broker::zeek::LogWrite msg(move(bstream_id), move(bwriter_id), move(path),
	                          move(serial_data));

	DBG_LOG(DBG_BROKER, "Buffering log record: %s", RenderMessage(topic, msg.as_data()).c_str());

	if ( log_buffers.size() <= (unsigned int)stream_id_num )
		log_buffers.resize(stream_id_num + 1);

	auto& lb = log_buffers[stream_id_num];
	++lb.message_count;
	auto& pending_batch = lb.msgs[topic];
	pending_batch.emplace_back(msg.move_data());

	if ( lb.message_count >= log_batch_size )
		statistics.num_logs_outgoing += lb.Flush(bstate->endpoint, log_batch_size);

	return true;
	}

size_t Manager::LogBuffer::Flush(broker::endpoint& endpoint, size_t log_batch_size)
	{
	if ( endpoint.is_shutdown() )
		return 0;

	if ( ! message_count )
		// No logs buffered for this stream.
		return 0;

	for ( auto& kv : msgs )
		{
		auto& topic = kv.first;
		auto& pending_batch = kv.second;
		broker::vector batch;
		batch.reserve(log_batch_size + 1);
		pending_batch.swap(batch);
		broker::zeek::Batch msg(std::move(batch));
		endpoint.publish(topic, msg.move_data());
		}

	auto rval = message_count;
	message_count = 0;
	return rval;
	}

size_t Manager::FlushLogBuffers()
	{
	DBG_LOG(DBG_BROKER, "Flushing all log buffers");
	auto rval = 0u;

	for ( auto& lb : log_buffers )
		rval += lb.Flush(bstate->endpoint, log_batch_size);

	statistics.num_logs_outgoing += rval;
	return rval;
	}

void Manager::Error(const char* format, ...)
	{
	va_list args;
	va_start(args, format);
	auto msg = vfmt(format, args);
	va_end(args);

	if ( script_scope )
		zeek::emit_builtin_error(msg);
	else
		reporter->Error("%s", msg);
	}

bool Manager::AutoPublishEvent(string topic, zeek::Val* event)
	{
	if ( event->GetType()->Tag() != zeek::TYPE_FUNC )
		{
		Error("Broker::auto_publish must operate on an event");
		return false;
		}

	auto event_val = event->AsFunc();
	if ( event_val->Flavor() != zeek::FUNC_FLAVOR_EVENT )
		{
		Error("Broker::auto_publish must operate on an event");
		return false;
		}

	auto handler = event_registry->Lookup(event_val->Name());
	if ( ! handler )
		{
		Error("Broker::auto_publish failed to lookup event '%s'",
		      event_val->Name());
		return false;
		}

	DBG_LOG(DBG_BROKER, "Enabling auto-publising of event %s to topic %s", handler->Name(), topic.c_str());
	handler->AutoPublish(move(topic));

	return true;
	}

bool Manager::AutoUnpublishEvent(const string& topic, zeek::Val* event)
	{
	if ( event->GetType()->Tag() != zeek::TYPE_FUNC )
		{
		Error("Broker::auto_event_stop must operate on an event");
		return false;
		}

	auto event_val = event->AsFunc();

	if ( event_val->Flavor() != zeek::FUNC_FLAVOR_EVENT )
		{
		Error("Broker::auto_event_stop must operate on an event");
		return false;
		}

	auto handler = event_registry->Lookup(event_val->Name());

	if ( ! handler )
		{
		Error("Broker::auto_event_stop failed to lookup event '%s'",
		      event_val->Name());
		return false;
		}


	DBG_LOG(DBG_BROKER, "Disabling auto-publishing of event %s to topic %s", handler->Name(), topic.c_str());
	handler->AutoUnpublish(topic);

	return true;
	}

zeek::RecordVal* Manager::MakeEvent(val_list* args, zeek::detail::Frame* frame)
	{
	auto rval = new zeek::RecordVal(zeek::BifType::Record::Broker::Event);
	auto arg_vec = zeek::make_intrusive<zeek::VectorVal>(vector_of_data_type);
	rval->Assign(1, arg_vec);
	zeek::Func* func = nullptr;
	scoped_reporter_location srl{frame};

	for ( auto i = 0; i < args->length(); ++i )
		{
		auto arg_val = (*args)[i];

		if ( i == 0 )
			{
			// Event val must come first.

			if ( arg_val->GetType()->Tag() != zeek::TYPE_FUNC )
				{
				Error("attempt to convert non-event into an event type");
				return rval;
				}

			func = arg_val->AsFunc();

			if ( func->Flavor() != zeek::FUNC_FLAVOR_EVENT )
				{
				Error("attempt to convert non-event into an event type");
				return rval;
				}

			auto num_args = func->GetType()->Params()->NumFields();

			if ( num_args != args->length() - 1 )
				{
				Error("bad # of arguments: got %d, expect %d",
				      args->length(), num_args + 1);
				return rval;
				}

			rval->Assign(0, zeek::make_intrusive<zeek::StringVal>(func->Name()));
			continue;
			}

		const auto& got_type = (*args)[i]->GetType();
		const auto& expected_type = func->GetType()->ParamList()->GetTypes()[i - 1];

		if ( ! same_type(got_type, expected_type) )
			{
			rval->Assign(0, nullptr);
			Error("event parameter #%d type mismatch, got %s, expect %s", i,
			      zeek::type_name(got_type->Tag()),
			      zeek::type_name(expected_type->Tag()));
			return rval;
			}

		zeek::RecordValPtr data_val;

		if ( same_type(got_type, bro_broker::DataVal::ScriptDataType()) )
			data_val = {zeek::NewRef{}, (*args)[i]->AsRecordVal()};
		else
			data_val = make_data_val((*args)[i]);

		if ( ! data_val->GetField(0) )
			{
			rval->Assign(0, nullptr);
			Error("failed to convert param #%d of type %s to broker data",
				  i, zeek::type_name(got_type->Tag()));
			return rval;
			}

		arg_vec->Assign(i - 1, std::move(data_val));
		}

	return rval;
	}

bool Manager::Subscribe(const string& topic_prefix)
	{
	DBG_LOG(DBG_BROKER, "Subscribing to topic prefix %s", topic_prefix.c_str());
	bstate->subscriber.add_topic(topic_prefix, ! after_zeek_init);

	// For backward compatibility, we also may receive messages on
	// "bro/" topic prefixes in addition to "zeek/".
	if ( strncmp(topic_prefix.data(), "zeek/", 5) == 0 )
		{
		std::string alt_topic = "bro/" + topic_prefix.substr(5);
		bstate->subscriber.add_topic(std::move(alt_topic), ! after_zeek_init);
		}

	return true;
	}

bool Manager::Forward(string topic_prefix)
	{
	for ( auto i = 0u; i < forwarded_prefixes.size(); ++i )
		if ( forwarded_prefixes[i] == topic_prefix )
			return false;

	DBG_LOG(DBG_BROKER, "Forwarding topic prefix %s", topic_prefix.c_str());
	Subscribe(topic_prefix);
	forwarded_prefixes.emplace_back(std::move(topic_prefix));
	return true;
	}

bool Manager::Unsubscribe(const string& topic_prefix)
	{
	for ( auto i = 0u; i < forwarded_prefixes.size(); ++i )
		if ( forwarded_prefixes[i] == topic_prefix )
			{
			DBG_LOG(DBG_BROKER, "Unforwading topic prefix %s", topic_prefix.c_str());
			forwarded_prefixes.erase(forwarded_prefixes.begin() + i);
			break;
			}

	DBG_LOG(DBG_BROKER, "Unsubscribing from topic prefix %s", topic_prefix.c_str());
	bstate->subscriber.remove_topic(topic_prefix, ! after_zeek_init);
	return true;
	}

void Manager::DispatchMessage(const broker::topic& topic, broker::data msg)
	{
	switch ( broker::zeek::Message::type(msg) ) {
	case broker::zeek::Message::Type::Invalid:
		reporter->Warning("received invalid broker message: %s",
						  broker::to_string(msg).data());
		break;

	case broker::zeek::Message::Type::Event:
		ProcessEvent(topic, std::move(msg));
		break;

	case broker::zeek::Message::Type::LogCreate:
		ProcessLogCreate(std::move(msg));
		break;

	case broker::zeek::Message::Type::LogWrite:
		ProcessLogWrite(std::move(msg));
		break;

	case broker::zeek::Message::Type::IdentifierUpdate:
		ProcessIdentifierUpdate(std::move(msg));
		break;

	case broker::zeek::Message::Type::Batch:
		{
		broker::zeek::Batch batch(std::move(msg));

		if ( ! batch.valid() )
			{
			reporter->Warning("received invalid broker Batch: %s",
			                  broker::to_string(batch).data());
			return;
			}

		for ( auto& i : batch.batch() )
			DispatchMessage(topic, std::move(i));

		break;
		}

	default:
		// We ignore unknown types so that we could add more in the
		// future if we had too.
		reporter->Warning("received unknown broker message: %s",
						  broker::to_string(msg).data());
		break;
	}
	}

void Manager::Process()
	{
	// Ensure that time gets update before processing broker messages, or events
	// based on them might get scheduled wrong.
	net_update_time(current_time());

	bool had_input = false;

	auto status_msgs = bstate->status_subscriber.poll();

	for ( auto& status_msg : status_msgs )
		{
		had_input = true;

		if ( auto stat = caf::get_if<broker::status>(&status_msg) )
			{
			ProcessStatus(std::move(*stat));
			continue;
			}

		if ( auto err = caf::get_if<broker::error>(&status_msg) )
			{
			ProcessError(std::move(*err));
			continue;
			}

		reporter->InternalWarning("ignoring status_subscriber message with unexpected type");
		}

	auto messages = bstate->subscriber.poll();

	for ( auto& message : messages )
		{
		had_input = true;

		auto& topic = broker::get_topic(message);
		auto& msg = broker::get_data(message);

		try
			{
			DispatchMessage(topic, std::move(msg));
			}
		catch ( std::runtime_error& e )
			{
			reporter->Warning("ignoring invalid Broker message: %s", + e.what());
			continue;
			}
		}

	for ( auto& s : data_stores )
		{
		auto num_available = s.second->proxy.mailbox().size();

		if ( num_available > 0 )
			{
			had_input = true;
			auto responses = s.second->proxy.receive(num_available);

			for ( auto& r : responses )
				ProcessStoreResponse(s.second, move(r));
			}
		}

	if ( had_input )
		{
		if ( network_time == 0 )
			// If we're getting Broker messages, but still haven't initialized
			// network_time, may as well do so now because otherwise the
			// broker/cluster logs will end up using timestamp 0.
			net_update_time(current_time());
		}
	}


void Manager::ProcessEvent(const broker::topic& topic, broker::zeek::Event ev)
	{
	if ( ! ev.valid() )
		{
		reporter->Warning("received invalid broker Event: %s",
		                  broker::to_string(ev.as_data()).data());
		return;
		}

	auto name = std::move(ev.name());
	auto args = std::move(ev.args());

	DBG_LOG(DBG_BROKER, "Process event: %s %s",
			name.data(), RenderMessage(args).data());
	++statistics.num_events_incoming;
	auto handler = event_registry->Lookup(name);

	if ( ! handler )
		return;

	auto& topic_string = topic.string();

	for ( auto i = 0u; i < forwarded_prefixes.size(); ++i )
		{
		auto& p = forwarded_prefixes[i];

		if ( p.size() > topic_string.size() )
			continue;

		if ( strncmp(p.data(), topic_string.data(), p.size()) != 0 )
			continue;

		DBG_LOG(DBG_BROKER, "Skip processing of forwarded event: %s %s",
		        name.data(), RenderMessage(args).data());
		return;
		}

	const auto& arg_types = handler->GetType(false)->ParamList()->GetTypes();

	if ( arg_types.size() != args.size() )
		{
		reporter->Warning("got event message '%s' with invalid # of args,"
		                  " got %zd, expected %zu", name.data(), args.size(),
		                  arg_types.size());
		return;
		}

	zeek::Args vl;
	vl.reserve(args.size());

	for ( auto i = 0u; i < args.size(); ++i )
		{
		auto got_type = args[i].get_type_name();
		const auto& expected_type = arg_types[i];
		auto val = data_to_val(std::move(args[i]), expected_type.get());

		if ( val )
			vl.emplace_back(std::move(val));
		else
			{
			auto expected_name = zeek::type_name(expected_type->Tag());

			reporter->Warning("failed to convert remote event '%s' arg #%d,"
					  " got %s, expected %s",
					  name.data(), i, got_type,
					  expected_name);

			// If we got a vector and expected a function this is
			// possibly because of a mismatch between
			// anonymous-function bodies.
			if ( strcmp(expected_name, "func") == 0 && strcmp("vector", got_type) == 0 )
				reporter->Warning("when sending functions the receiver must have access to a"
						  " version of that function.\nFor anonymous functions, that function must have the same body.");

			break;
			}
		}

	if ( vl.size() == args.size() )
		mgr.Enqueue(handler, std::move(vl), SOURCE_BROKER);
	}

bool bro_broker::Manager::ProcessLogCreate(broker::zeek::LogCreate lc)
	{
	DBG_LOG(DBG_BROKER, "Received log-create: %s", RenderMessage(lc.as_data()).c_str());
	if ( ! lc.valid() )
		{
		reporter->Warning("received invalid broker LogCreate: %s",
		                  broker::to_string(lc).data());
		return false;
		}

	auto stream_id = data_to_val(std::move(lc.stream_id()), log_id_type);
	if ( ! stream_id )
		{
		reporter->Warning("failed to unpack remote log stream id");
		return false;
		}

	auto writer_id = data_to_val(std::move(lc.writer_id()), writer_id_type);
	if ( ! writer_id )
		{
		reporter->Warning("failed to unpack remote log writer id");
		return false;
		}

	auto writer_info = std::unique_ptr<logging::WriterBackend::WriterInfo>(new logging::WriterBackend::WriterInfo);
	if ( ! writer_info->FromBroker(std::move(lc.writer_info())) )
		{
		reporter->Warning("failed to unpack remote log writer info");
		return false;
		}

	// Get log fields.
	auto fields_data = caf::get_if<broker::vector>(&lc.fields_data());

	if ( ! fields_data )
		{
		reporter->Warning("failed to unpack remote log fields");
		return false;
		}

	auto num_fields = fields_data->size();
	auto fields = new threading::Field* [num_fields];

	for ( auto i = 0u; i < num_fields; ++i )
		{
		if ( auto field = data_to_threading_field(std::move((*fields_data)[i])) )
			fields[i] = field;
		else
			{
			reporter->Warning("failed to convert remote log field # %d", i);
			delete [] fields;
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

bool bro_broker::Manager::ProcessLogWrite(broker::zeek::LogWrite lw)
	{
	DBG_LOG(DBG_BROKER, "Received log-write: %s", RenderMessage(lw.as_data()).c_str());

	if ( ! lw.valid() )
		{
		reporter->Warning("received invalid broker LogWrite: %s",
		                  broker::to_string(lw).data());
		return false;
		}

	++statistics.num_logs_incoming;
	auto& stream_id_name = lw.stream_id().name;

	// Get stream ID.
	auto stream_id = data_to_val(std::move(lw.stream_id()), log_id_type);

	if ( ! stream_id )
		{
		reporter->Warning("failed to unpack remote log stream id: %s",
		                  stream_id_name.data());
		return false;
		}

	// Get writer ID.
	auto writer_id = data_to_val(std::move(lw.writer_id()), writer_id_type);
	if ( ! writer_id )
		{
		reporter->Warning("failed to unpack remote log writer id for stream: %s", stream_id_name.data());
		return false;
		}

	auto path = caf::get_if<std::string>(&lw.path());

	if ( ! path )
		{
		reporter->Warning("failed to unpack remote log values (bad path variant) for stream: %s", stream_id_name.data());
		return false;
		}

	auto serial_data = caf::get_if<std::string>(&lw.serial_data());

	if ( ! serial_data )
		{
		reporter->Warning("failed to unpack remote log values (bad serial_data variant) for stream: %s", stream_id_name.data());
		return false;
		}

	BinarySerializationFormat fmt;
	fmt.StartRead(serial_data->data(), serial_data->size());

	int num_fields;
	bool success = fmt.Read(&num_fields, "num_fields");

	if ( ! success )
		{
		reporter->Warning("failed to unserialize remote log num fields for stream: %s", stream_id_name.data());
		return false;
		}

	auto vals = new threading::Value* [num_fields];

	for ( int i = 0; i < num_fields; ++i )
		{
		vals[i] = new threading::Value;

		if ( ! vals[i]->Read(&fmt) )
			{
			for ( int j = 0; j <=i; ++j )
				delete vals[j];

			delete [] vals;
			reporter->Warning("failed to unserialize remote log field %d for stream: %s", i, stream_id_name.data());

			return false;
			}
		}

	log_mgr->WriteFromRemote(stream_id->AsEnumVal(), writer_id->AsEnumVal(),
	                         std::move(*path), num_fields, vals);
	fmt.EndRead();
	return true;
	}

bool Manager::ProcessIdentifierUpdate(broker::zeek::IdentifierUpdate iu)
	{
	DBG_LOG(DBG_BROKER, "Received id-update: %s", RenderMessage(iu.as_data()).c_str());

	if ( ! iu.valid() )
		{
		reporter->Warning("received invalid broker IdentifierUpdate: %s",
		                  broker::to_string(iu).data());
		return false;
		}

	++statistics.num_ids_incoming;
	auto id_name = std::move(iu.id_name());
	auto id_value = std::move(iu.id_value());
	const auto& id = zeek::detail::global_scope()->Find(id_name);

	if ( ! id )
		{
		reporter->Warning("Received id-update request for unkown id: %s",
		                 id_name.c_str());
		return false;
		}

	auto val = data_to_val(std::move(id_value), id->GetType().get());

	if ( ! val )
		{
		reporter->Error("Failed to receive ID with unsupported type: %s (%s)",
		                id_name.c_str(), zeek::type_name(id->GetType()->Tag()));
		return false;
		}

	id->SetVal(std::move(val));
	return true;
	}

void Manager::ProcessStatus(broker::status stat)
	{
	DBG_LOG(DBG_BROKER, "Received status message: %s", RenderMessage(stat).c_str());

	auto ctx = stat.context<broker::endpoint_info>();

	EventHandlerPtr event;
	switch (stat.code()) {
	case broker::sc::unspecified:
		event = Broker::status;
		break;

	case broker::sc::peer_added:
		++peer_count;
		assert(ctx);
		log_mgr->SendAllWritersTo(*ctx);
		event = Broker::peer_added;
		break;

	case broker::sc::peer_removed:
		--peer_count;
		event = Broker::peer_removed;
		break;

	case broker::sc::peer_lost:
		--peer_count;
		event = Broker::peer_lost;
		break;

	default:
		reporter->Warning("Unhandled Broker status: %s", to_string(stat).data());
		break;
	}

	if ( ! event )
		return;

	static auto ei = zeek::id::find_type<zeek::RecordType>("Broker::EndpointInfo");
	auto endpoint_info = zeek::make_intrusive<zeek::RecordVal>(ei);

	if ( ctx )
		{
		endpoint_info->Assign(0, zeek::make_intrusive<zeek::StringVal>(to_string(ctx->node)));
		static auto ni = zeek::id::find_type<zeek::RecordType>("Broker::NetworkInfo");
		auto network_info = zeek::make_intrusive<zeek::RecordVal>(ni);

		if ( ctx->network )
			{
			network_info->Assign(0, zeek::make_intrusive<zeek::StringVal>(ctx->network->address.data()));
			network_info->Assign(1, zeek::val_mgr->Port(ctx->network->port, TRANSPORT_TCP));
			}
		else
			{
			// TODO: are there any status messages where the ctx->network
			// is not set and actually could be?
			network_info->Assign(0, zeek::make_intrusive<zeek::StringVal>("<unknown>"));
			network_info->Assign(1, zeek::val_mgr->Port(0, TRANSPORT_TCP));
			}

		endpoint_info->Assign(1, std::move(network_info));
		}

	auto str = stat.message();
	auto msg = zeek::make_intrusive<zeek::StringVal>(str ? *str : "");

	mgr.Enqueue(event, std::move(endpoint_info), std::move(msg));
	}

void Manager::ProcessError(broker::error err)
	{
	DBG_LOG(DBG_BROKER, "Received error message: %s", RenderMessage(err).c_str());

	if ( ! Broker::error )
		return;

	BifEnum::Broker::ErrorCode ec;
	std::string msg;

	if ( err.category() == caf::atom("broker") )
		{
		static auto enum_type = zeek::id::find_type<zeek::EnumType>("Broker::ErrorCode");

		if ( enum_type->Lookup(err.code()) )
			ec = static_cast<BifEnum::Broker::ErrorCode>(err.code());
		else
			{
			reporter->Warning("Unknown Broker error code %u: mapped to unspecificed enum value ", err.code());
			ec = BifEnum::Broker::ErrorCode::UNSPECIFIED;
			}

		msg = caf::to_string(err.context());
		}
	else
		{
		ec = BifEnum::Broker::ErrorCode::CAF_ERROR;
		msg = fmt("[%s] %s", caf::to_string(err.category()).c_str(), caf::to_string(err.context()).c_str());
		}

	mgr.Enqueue(Broker::error,
		zeek::BifType::Enum::Broker::ErrorCode->GetVal(ec),
	            zeek::make_intrusive<zeek::StringVal>(msg)
	);
	}

void Manager::ProcessStoreResponse(StoreHandleVal* s, broker::store::response response)
	{
	DBG_LOG(DBG_BROKER, "Received store response: %s", RenderMessage(response).c_str());

	auto request = pending_queries.find(std::make_pair(response.id, s));

	if ( request == pending_queries.end() )
		{
		reporter->Warning("unmatched response to query %" PRIu64 " on store %s",
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
		request->second->Result(query_result(make_data_val(std::move(*response.answer))));
	else if ( response.answer.error() == broker::ec::request_timeout )
		{
		// Fine, trigger's timeout takes care of things.
		}
	else if ( response.answer.error() == broker::ec::stale_data )
		{
		// It's sort of arbitrary whether to make this type of error successful
		// query with a "fail" status versus going through the when stmt timeout
		// code path.  I think the timeout path is maybe more expected in order
		// for failures like "no such key" to actually be distinguishable from
		// this type of error (which is less easily handled programmatically).
		}
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
	if ( bstate->endpoint.is_shutdown() )
		return nullptr;

	if ( LookupStore(name) )
		return nullptr;

	DBG_LOG(DBG_BROKER, "Creating master for data store %s", name.c_str());

	auto it = opts.find("path");

	if ( it == opts.end() )
		it = opts.emplace("path", "").first;

	if ( it->second == broker::data("") )
		{
		auto suffix = ".store";

		switch ( type ) {
		case broker::backend::sqlite:
			suffix = ".sqlite";
			break;
		case broker::backend::rocksdb:
			suffix = ".rocksdb";
			break;
		default:
			break;
		}

		it->second = name + suffix;
		}

	auto result = bstate->endpoint.attach_master(name, type, move(opts));
	if ( ! result )
		{
		Error("Failed to attach master store %s:",
		      to_string(result.error()).c_str());
		return nullptr;
		}

	auto handle = new StoreHandleVal{*result};
	Ref(handle);

	data_stores.emplace(name, handle);
	iosource_mgr->RegisterFd(handle->proxy.mailbox().descriptor(), this);

	if ( bstate->endpoint.use_real_time() )
		return handle;

	// Wait for master to become available/responsive.
	// Possibly avoids timeouts in scripts during unit tests.
	handle->store.exists("");
	return handle;
	}

StoreHandleVal* Manager::MakeClone(const string& name, double resync_interval,
                                   double stale_interval,
                                   double mutation_buffer_interval)
	{
	if ( bstate->endpoint.is_shutdown() )
		return nullptr;

	if ( LookupStore(name) )
		return nullptr;

	DBG_LOG(DBG_BROKER, "Creating clone for data store %s", name.c_str());

	auto result = bstate->endpoint.attach_clone(name, resync_interval,
	                                            stale_interval,
	                                            mutation_buffer_interval);
	if ( ! result )
		{
		Error("Failed to attach clone store %s:",
		      to_string(result.error()).c_str());
		return nullptr;
		}

	auto handle = new StoreHandleVal{*result};
	Ref(handle);

	data_stores.emplace(name, handle);
	iosource_mgr->RegisterFd(handle->proxy.mailbox().descriptor(), this);

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

	iosource_mgr->UnregisterFd(s->second->proxy.mailbox().descriptor(), this);

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

bool Manager::TrackStoreQuery(StoreHandleVal* handle, broker::request_id id,
                              StoreQueryCallback* cb)
	{
	auto rval = pending_queries.emplace(std::make_pair(id, handle), cb).second;

	if ( bstate->endpoint.use_real_time() )
		return rval;

	FlushPendingQueries();
	return rval;
	}

const Stats& Manager::GetStatistics()
	{
	statistics.num_peers = peer_count;
	statistics.num_stores = data_stores.size();
	statistics.num_pending_queries = pending_queries.size();

	// The other attributes are set as activity happens.

	return statistics;
	}

} // namespace bro_broker

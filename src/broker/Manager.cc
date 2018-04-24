
#include <broker/broker.hh>
#include <broker/bro.hh>
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

// Max number of log messages buffered per stream before we send them out as
// a batch.
static const int LOG_BATCH_SIZE = 400;

// Max secs to buffer log messages before sending the current set out as a
// batch.
static const double LOG_BUFFER_INTERVAL = 1.0;

// Number of buffered messages (at the Broker/CAF layer) after which
// subscribers consider themselves congested.
static const size_t SUBSCRIBER_MAX_QSIZE = 20u;

const broker::endpoint_info Manager::NoPeer{{}, {}};

VectorType* Manager::vector_of_data_type;
EnumType* Manager::log_id_type;
EnumType* Manager::writer_id_type;
int Manager::script_scope = 0;

struct unref_guard {
	unref_guard(Val* v) : val(v) {}
	~unref_guard() { Unref(val); }
	Val* val;
};

struct scoped_reporter_location {
	scoped_reporter_location(Frame* frame)
		{
		reporter->PushLocation(frame->GetCall()->GetLocationInfo());
		}

	~scoped_reporter_location()
		{
		reporter->PopLocation();
		}
};

#ifdef DEBUG
static std::string RenderMessage(std::string topic, broker::data x)
	{
	return fmt("%s -> %s", broker::to_string(x).c_str(), topic.c_str());
	}

static std::string RenderEvent(std::string topic, std::string name, broker::data args)
	{
	return fmt("%s(%s) -> %s", name.c_str(), broker::to_string(args).c_str(), topic.c_str());
	}

static std::string RenderMessage(broker::store::response x)
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

static inline Val* get_option(const char* option)
	{
	auto id = global_scope()->Lookup(option);

	if ( ! (id && id->ID_Val()) )
		reporter->FatalError("Unknown Broker option %s", option);

	return id->ID_Val();
	}

class configuration : public broker::configuration {
public:
	configuration(broker::broker_options options)
		: broker::configuration(options)
		{
		openssl_cafile = get_option("Broker::ssl_cafile")->AsString()->CheckString();
		openssl_capath = get_option("Broker::ssl_capath")->AsString()->CheckString();
		openssl_certificate = get_option("Broker::ssl_certificate")->AsString()->CheckString();
		openssl_key = get_option("Broker::ssl_keyfile")->AsString()->CheckString();
		openssl_passphrase = get_option("Broker::ssl_passphrase")->AsString()->CheckString();
		}
};

Manager::BrokerState::BrokerState(broker::broker_options options)
	: endpoint(configuration(options)),
	  subscriber(endpoint.make_subscriber({}, SUBSCRIBER_MAX_QSIZE)),
	  status_subscriber(endpoint.make_status_subscriber(true))
	{
	}

Manager::Manager(bool reading_pcaps)
	{
	bound_port = 0;

	next_timestamp = 1;
	SetIdle(false);
	this->reading_pcaps = reading_pcaps;
	}

Manager::~Manager()
	{
	}

void Manager::InitPostScript()
	{
	DBG_LOG(DBG_BROKER, "Initializing");

	default_log_topic_prefix =
	    get_option("Broker::default_log_topic_prefix")->AsString()->CheckString();
	log_topic_func = get_option("Broker::log_topic")->AsFunc();
	log_id_type = internal_type("Log::ID")->AsEnumType();
	writer_id_type = internal_type("Log::Writer")->AsEnumType();

	opaque_of_data_type = new OpaqueType("Broker::Data");
	opaque_of_set_iterator = new OpaqueType("Broker::SetIterator");
	opaque_of_table_iterator = new OpaqueType("Broker::TableIterator");
	opaque_of_vector_iterator = new OpaqueType("Broker::VectorIterator");
	opaque_of_record_iterator = new OpaqueType("Broker::RecordIterator");
	opaque_of_store_handle = new OpaqueType("Broker::Store");
	vector_of_data_type = new VectorType(internal_type("Broker::Data")->Ref());

	// Register as a "dont-count" source first, we may change that later.
	iosource_mgr->Register(this, true);

	broker::broker_options options;
	options.disable_ssl = get_option("Broker::disable_ssl")->AsBool();
	options.forward = get_option("Broker::forward_messages")->AsBool();
	options.use_real_time = ! reading_pcaps;

	bstate = std::make_shared<BrokerState>(options);
	}

void Manager::Terminate()
	{
	FlushLogBuffers();

	vector<string> stores_to_close;

	for ( auto& x : data_stores )
		stores_to_close.push_back(x.first);

	for ( auto& x: stores_to_close )
		// This doesn't loop directly over data_stores, because CloseStore
		// modifies the map and invalidates iterators.
		CloseStore(x);

	FlushLogBuffers();

	for ( auto& p : bstate->endpoint.peers() )
		bstate->endpoint.unpeer(p.peer.network->address, p.peer.network->port);

	bstate->endpoint.shutdown();
	}

bool Manager::Active()
	{
	if ( bstate->endpoint.is_shutdown() )
		return false;

	if ( bound_port > 0 )
		return true;

	return bstate->endpoint.peers().size();
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
		Process();
		}
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

	if ( retry > 0.0 && retry < 1.0 )
		// Ensure that it doesn't get turned into zero.
		retry = 1.0;

	auto secs = broker::timeout::seconds(static_cast<uint64>(retry));
	bstate->endpoint.peer_nosync(addr, port, secs);

	// // Register as a "does-count" source now.
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

	if ( ! bstate->endpoint.peers().size() )
		return true;

	DBG_LOG(DBG_BROKER, "Publishing event: %s",
		RenderEvent(topic, name, args).c_str());
	broker::bro::Event ev(std::move(name), std::move(args));
	bstate->endpoint.publish(move(topic), std::move(ev));
	++statistics.num_events_outgoing;
	return true;
	}

bool Manager::PublishEvent(string topic, RecordVal* args)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( ! bstate->endpoint.peers().size() )
		return true;

	if ( ! args->Lookup(0) )
		return false;

	auto event_name = args->Lookup(0)->AsString()->CheckString();
	auto vv = args->Lookup(1)->AsVectorVal();
	broker::vector xs;
	xs.reserve(vv->Size());

	for ( auto i = 0u; i < vv->Size(); ++i )
		{
		auto val = vv->Lookup(i)->AsRecordVal()->Lookup(0);
		auto data_val = static_cast<DataVal*>(val);
		xs.emplace_back(data_val->data);
		}

	return PublishEvent(topic, event_name, std::move(xs));
	}

bool Manager::RelayEvent(std::string first_topic,
                         broker::set relay_topics,
                         std::string name,
                         broker::vector args)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( ! bstate->endpoint.peers().size() )
		return true;

	DBG_LOG(DBG_BROKER, "Publishing relay event: %s",
	        RenderEvent(first_topic, name, args).c_str());
	broker::bro::RelayEvent msg(std::move(relay_topics), std::move(name),
	                            std::move(args));
	bstate->endpoint.publish(std::move(first_topic), std::move(msg));
	++statistics.num_events_outgoing;
	return true;
	}

bool Manager::RelayEvent(std::string first_topic,
                         std::set<std::string> relay_topics,
                         RecordVal* args)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( ! bstate->endpoint.peers().size() )
		return true;

	if ( ! args->Lookup(0) )
		return false;

	auto event_name = args->Lookup(0)->AsString()->CheckString();
	auto vv = args->Lookup(1)->AsVectorVal();
	broker::vector xs;
	xs.reserve(vv->Size());

	for ( auto i = 0u; i < vv->Size(); ++i )
		{
		auto val = vv->Lookup(i)->AsRecordVal()->Lookup(0);
		auto data_val = static_cast<DataVal*>(val);
		xs.emplace_back(data_val->data);
		}

	broker::set topic_set;

	for ( auto& t : relay_topics )
		topic_set.emplace(std::move(t));

	return RelayEvent(first_topic, std::move(topic_set), event_name,
					  std::move(xs));
	}

bool Manager::PublishIdentifier(std::string topic, std::string id)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( ! bstate->endpoint.peers().size() )
		return true;

	ID* i = global_scope()->Lookup(id.c_str());

	if ( ! i )
		return false;

	auto val = i->ID_Val();

	if ( ! val )
		// Probably could have a special case to also unset the value on the
		// receiving side, but not sure what use that would be.
		return false;

	auto data = val_to_data(val);

	if ( ! data )
		{
		Error("Failed to publish ID with unsupported type: %s (%s)",
		      id.c_str(), type_name(val->Type()->Tag()));
		return false;
		}

	broker::bro::IdentifierUpdate msg(move(id), move(*data));
	DBG_LOG(DBG_BROKER, "Publishing id-update: %s",
	        RenderMessage(topic, msg).c_str());
	bstate->endpoint.publish(move(topic), move(msg));
	++statistics.num_ids_outgoing;
	return true;
	}

bool Manager::PublishLogCreate(EnumVal* stream, EnumVal* writer,
			       const logging::WriterBackend::WriterInfo& info,
			       int num_fields, const threading::Field* const * fields,
			       const broker::endpoint_info& peer)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( ! bstate->endpoint.peers().size() )
		return true;

	auto stream_id = stream->Type()->AsEnumType()->Lookup(stream->AsEnum());

	if ( ! stream_id )
		{
		reporter->Error("Failed to remotely log: stream %d doesn't have name",
		                stream->AsEnum());
		return false;
		}

	auto writer_id = writer->Type()->AsEnumType()->Lookup(writer->AsEnum());

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
	broker::bro::LogCreate msg(move(bstream_id), move(bwriter_id), move(writer_info), move(fields_data));

	DBG_LOG(DBG_BROKER, "Publishing log creation: %s", RenderMessage(topic, msg).c_str());

	if ( peer.node != NoPeer.node )
		// Direct message.
		bstate->endpoint.publish(peer, move(topic), move(msg));
	else
		// Broadcast.
		bstate->endpoint.publish(move(topic), move(msg));

	return true;
	}

bool Manager::PublishLogWrite(EnumVal* stream, EnumVal* writer, string path, int num_fields, const threading::Value* const * vals)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( ! bstate->endpoint.peers().size() )
		return true;

	auto stream_id_num = stream->AsEnum();
	auto stream_id = stream->Type()->AsEnumType()->Lookup(stream_id_num);

	if ( ! stream_id )
		{
		reporter->Error("Failed to remotely log: stream %d doesn't have name",
		                stream->AsEnum());
		return false;
		}

	auto writer_id = writer->Type()->AsEnumType()->Lookup(writer->AsEnum());

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

	val_list vl(2);
	vl.append(stream->Ref());
	vl.append(new StringVal(path));
	Val* v = log_topic_func->Call(&vl);

	if ( ! v )
		{
		reporter->Error("Failed to remotely log: log_topic func did not return"
		                " a value for stream %s at path %s", stream_id,
		                path.data());
		return false;
		}

	std::string topic = v->AsString()->CheckString();
	Unref(v);

	auto bstream_id = broker::enum_value(move(stream_id));
	auto bwriter_id = broker::enum_value(move(writer_id));
	broker::bro::LogWrite msg(move(bstream_id), move(bwriter_id), move(path),
	                          move(serial_data));

	DBG_LOG(DBG_BROKER, "Buffering log record: %s", RenderMessage(topic, msg).c_str());

	if ( log_buffers.size() <= (unsigned int)stream_id_num )
		log_buffers.resize(stream_id_num + 1);

	auto& lb = log_buffers[stream_id_num];
	++lb.message_count;
	auto& pending_batch = lb.msgs[topic];
	pending_batch.emplace_back(std::move(msg));

	if ( lb.message_count >= LOG_BATCH_SIZE ||
	     (network_time - lb.last_flush >= LOG_BUFFER_INTERVAL) )
		statistics.num_logs_outgoing += lb.Flush(Endpoint());

	return true;
	}

size_t Manager::LogBuffer::Flush(broker::endpoint& endpoint)
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
		batch.reserve(LOG_BATCH_SIZE + 1);
		pending_batch.swap(batch);
		broker::bro::Batch msg(std::move(batch));
		endpoint.publish(topic, move(msg));
		}

	auto rval = message_count;
	last_flush = network_time;
	message_count = 0;
	return rval;
	}

size_t Manager::FlushLogBuffers()
	{
	DBG_LOG(DBG_BROKER, "Flushing all log buffers");
	auto rval = 0u;

	for ( auto& lb : log_buffers )
		rval += lb.Flush(Endpoint());

	return rval;
	}

void Manager::Error(const char* format, ...)
	{
	va_list args;
	va_start(args, format);
	auto msg = fmt(format, args);
	va_end(args);

	if ( script_scope )
		builtin_error(msg);
	else
		reporter->Error("%s", msg);
	}

bool Manager::AutoPublishEvent(string topic, Val* event)
	{
	if ( event->Type()->Tag() != TYPE_FUNC )
		{
		Error("Broker::auto_publish must operate on an event");
		return false;
		}

	auto event_val = event->AsFunc();
	if ( event_val->Flavor() != FUNC_FLAVOR_EVENT )
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

bool Manager::AutoUnpublishEvent(const string& topic, Val* event)
	{
	if ( event->Type()->Tag() != TYPE_FUNC )
		{
		Error("Broker::auto_event_stop must operate on an event");
		return false;
		}

	auto event_val = event->AsFunc();

	if ( event_val->Flavor() != FUNC_FLAVOR_EVENT )
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

RecordVal* Manager::MakeEvent(val_list* args, Frame* frame)
	{
	auto rval = new RecordVal(BifType::Record::Broker::Event);
	auto arg_vec = new VectorVal(vector_of_data_type);
	rval->Assign(1, arg_vec);
	Func* func = 0;
	scoped_reporter_location srl{frame};

	for ( auto i = 0; i < args->length(); ++i )
		{
		auto arg_val = (*args)[i];

		if ( i == 0 )
			{
			// Event val must come first.

			if ( arg_val->Type()->Tag() != TYPE_FUNC )
				{
				Error("attempt to convert non-event into an event type");
				return rval;
				}

			func = arg_val->AsFunc();

			if ( func->Flavor() != FUNC_FLAVOR_EVENT )
				{
				Error("attempt to convert non-event into an event type");
				return rval;
				}

			auto num_args = func->FType()->Args()->NumFields();

			if ( num_args != args->length() - 1 )
				{
				Error("bad # of arguments: got %d, expect %d",
				      args->length(), num_args + 1);
				return rval;
				}

			rval->Assign(0, new StringVal(func->Name()));
			continue;
			}

		auto got_type = (*args)[i]->Type();
		auto expected_type = (*func->FType()->ArgTypes()->Types())[i - 1];

		if ( ! same_type(got_type, expected_type) )
			{
			rval->Assign(0, 0);
			Error("event parameter #%d type mismatch, got %s, expect %s", i,
			      type_name(got_type->Tag()),
			      type_name(expected_type->Tag()));
			return rval;
			}

		auto data_val = make_data_val((*args)[i]);

		if ( ! data_val->Lookup(0) )
			{
			Unref(data_val);
			rval->Assign(0, 0);
			Error("failed to convert param #%d of type %s to broker data",
				  i, type_name(got_type->Tag()));
			return rval;
			}

		arg_vec->Assign(i - 1, data_val);
		}

	return rval;
	}

bool Manager::Subscribe(const string& topic_prefix)
	{
	DBG_LOG(DBG_BROKER, "Subscribing to topic prefix %s", topic_prefix.c_str());
	bstate->subscriber.add_topic(topic_prefix);
	return true;
	}

bool Manager::Unsubscribe(const string& topic_prefix)
	{
	DBG_LOG(DBG_BROKER, "Unsubscribing from topic prefix %s", topic_prefix.c_str());
	bstate->subscriber.remove_topic(topic_prefix);
	return true;
	}

void Manager::GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
                           iosource::FD_Set* except)
	{
	if ( bstate->status_subscriber.available() || bstate->subscriber.available() )
                SetIdle(false);

	read->Insert(bstate->subscriber.fd());
	read->Insert(bstate->status_subscriber.fd());
	write->Insert(bstate->subscriber.fd());
	write->Insert(bstate->status_subscriber.fd());
	except->Insert(bstate->subscriber.fd());
	except->Insert(bstate->status_subscriber.fd());

	for ( auto& x : data_stores )
		read->Insert(x.second->proxy.mailbox().descriptor());
	}

double Manager::NextTimestamp(double* local_network_time)
	{
	if ( ! IsIdle() )
		return timer_mgr->Time();

	if ( bstate->status_subscriber.available() || bstate->subscriber.available() )
		return timer_mgr->Time();

	for ( auto& s : data_stores )
		{
		if ( ! s.second->proxy.mailbox().empty() )
			return timer_mgr->Time();
		}

	return -1;
	}

void Manager::DispatchMessage(broker::data msg)
	{
	switch ( broker::bro::Message::type(msg) ) {
	case broker::bro::Message::Type::Event:
		ProcessEvent(std::move(msg));
		break;

	case broker::bro::Message::Type::RelayEvent:
		ProcessRelayEvent(std::move(msg));
		break;

	case broker::bro::Message::Type::LogCreate:
		ProcessLogCreate(std::move(msg));
		break;

	case broker::bro::Message::Type::LogWrite:
		ProcessLogWrite(std::move(msg));
		break;

	case broker::bro::Message::Type::IdentifierUpdate:
		ProcessIdentifierUpdate(std::move(msg));
		break;

	case broker::bro::Message::Type::Batch:
		{
		broker::bro::Batch batch(std::move(msg));

		for ( auto& i : batch.batch() )
			DispatchMessage(std::move(i));

		break;
		}

	default:
		// We ignore unknown types so that we could add more in the
		// future if we had too.
		break;
	}
	}

void Manager::Process()
	{
	bool had_input = false;

	auto status_msgs = bstate->status_subscriber.poll();

	for ( auto& status_msg : status_msgs )
		{
		had_input = true;

		if ( auto stat = broker::get_if<broker::status>(status_msg) )
			{
			ProcessStatus(std::move(*stat));
			continue;
			}

		if ( auto err = broker::get_if<broker::error>(status_msg) )
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

		auto& topic = message.first;
		auto& msg = message.second;

		try
			{
			DispatchMessage(std::move(msg));
			}
		catch ( std::runtime_error& e )
			{
			reporter->Warning("ignoring invalid Broker message: %s", + e.what());
			continue;
			}
		}

	for ( auto& s : data_stores )
		{
		while ( ! s.second->proxy.mailbox().empty() )
			{
			had_input = true;
			auto response = s.second->proxy.receive();
			ProcessStoreResponse(s.second, move(response));
			}
		}

	SetIdle(! had_input);
	}

void Manager::ProcessEvent(broker::bro::Event ev)
	{
	DBG_LOG(DBG_BROKER, "Received event: %s", RenderMessage(ev).c_str());

	++statistics.num_events_incoming;

	auto handler = event_registry->Lookup(ev.name().c_str());
	if ( ! handler )
		return;

	auto& args = ev.args();
	auto arg_types = handler->FType(false)->ArgTypes()->Types();

	if ( static_cast<size_t>(arg_types->length()) != args.size() )
		{
		reporter->Warning("got event message '%s' with invalid # of args,"
				  " got %zd, expected %d", ev.name().data(), args.size(),
				  arg_types->length());
		return;
		}

	auto vl = new val_list;

	for ( auto i = 0u; i < args.size(); ++i )
		{
		auto got_type = args[i].get_type_name();
		auto expected_type = (*arg_types)[i];
		auto val = data_to_val(std::move(args[i]), expected_type);

		if ( val )
			vl->append(val);
		else
			{
			reporter->Warning("failed to convert remote event '%s' arg #%d,"
			                  " got %s, expected %s",
			                  ev.name().data(), i, got_type,
			                  type_name(expected_type->Tag()));
			break;
			}
		}

	if ( static_cast<size_t>(vl->length()) == args.size() )
		mgr.QueueEvent(handler, vl, SOURCE_BROKER);
	else
		delete_vals(vl);
	}

void Manager::ProcessRelayEvent(broker::bro::RelayEvent ev)
	{
	DBG_LOG(DBG_BROKER, "Received relay event: %s", RenderMessage(ev).c_str());
	++statistics.num_events_incoming;

	for ( auto& t : ev.topics() )
		PublishEvent(std::move(broker::get<std::string>(t)),
		             std::move(ev.name()),
		             std::move(ev.args()));
	}

bool bro_broker::Manager::ProcessLogCreate(broker::bro::LogCreate lc)
	{
	DBG_LOG(DBG_BROKER, "Received log-create: %s", RenderMessage(lc).c_str());

	auto stream_id = data_to_val(std::move(lc.stream_id()), log_id_type);
	if ( ! stream_id )
		{
		reporter->Warning("failed to unpack remote log stream id");
		return false;
		}

	unref_guard stream_id_unreffer{stream_id};

	auto writer_id = data_to_val(std::move(lc.writer_id()), writer_id_type);
	if ( ! writer_id )
		{
		reporter->Warning("failed to unpack remote log writer id");
		return false;
		}

	unref_guard writer_id_unreffer{writer_id};

	auto writer_info = std::unique_ptr<logging::WriterBackend::WriterInfo>(new logging::WriterBackend::WriterInfo);
	if ( ! writer_info->FromBroker(std::move(lc.writer_info())) )
		{
		reporter->Warning("failed to unpack remote log writer info");
		return false;
		}

	// Get log fields.

	try
		{
		auto fields_data = std::move(broker::get<broker::vector>(lc.fields_data()));
		auto num_fields = fields_data.size();
		auto fields = new threading::Field* [num_fields];

		for ( auto i = 0u; i < num_fields; ++i )
			{
			if ( auto field = data_to_threading_field(std::move(fields_data[i])) )
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

	catch (const broker::bad_variant_access& e)
		{
		reporter->Warning("failed to unpack remote log fields");
		return false;
		}
	}

bool bro_broker::Manager::ProcessLogWrite(broker::bro::LogWrite lw)
	{
	DBG_LOG(DBG_BROKER, "Received log-write: %s", RenderMessage(lw).c_str());

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

	unref_guard stream_id_unreffer{stream_id};

	// Get writer ID.
	auto writer_id = data_to_val(std::move(lw.writer_id()), writer_id_type);
	if ( ! writer_id )
		{
		reporter->Warning("failed to unpack remote log writer id for stream: %s", stream_id_name.data());
		return false;
		}

	unref_guard writer_id_unreffer{writer_id};

	 try
		{
		auto& path = broker::get<std::string>(lw.path());
		auto& serial_data = broker::get<std::string>(lw.serial_data());

		BinarySerializationFormat fmt;
		fmt.StartRead(serial_data.data(), serial_data.size());

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

		log_mgr->WriteFromRemote(stream_id->AsEnumVal(), writer_id->AsEnumVal(), std::move(path), num_fields, vals);
		fmt.EndRead();
		return true;
		}

	catch ( const broker::bad_variant_access& e)
		{
		reporter->Warning("failed to unpack remote log values (bad variant) for stream: %s", stream_id_name.data());
		return false;
		}
	}

bool Manager::ProcessIdentifierUpdate(broker::bro::IdentifierUpdate iu)
	{
	DBG_LOG(DBG_BROKER, "Received id-update: %s", RenderMessage(iu).c_str());
	++statistics.num_ids_incoming;
	auto id_name = std::move(iu.id_name());
	auto id_value = std::move(iu.id_value());
	auto id = global_scope()->Lookup(id_name.c_str());

	if ( ! id )
		{
		reporter->Warning("Received id-update request for unkown id: %s",
		                 id_name.c_str());
		return false;
		}

	auto val = data_to_val(std::move(id_value), id->Type());

	if ( ! val )
		{
		reporter->Error("Failed to receive ID with unsupported type: %s (%s)",
		                id_name.c_str(), type_name(id->Type()->Tag()));
		return false;
		}

	id->SetVal(val);
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
		endpoint_info->Assign(0, new StringVal(to_string(ctx->node)));

		if ( ctx->network )
			{
			auto ni = internal_type("Broker::NetworkInfo")->AsRecordType();
			auto network_info = new RecordVal(ni);
			network_info->Assign(0, new AddrVal(IPAddr(ctx->network->address)));
			network_info->Assign(1, port_mgr->Get(ctx->network->port, TRANSPORT_TCP));
			endpoint_info->Assign(1, network_info);
			}
		else
			{
			// TODO: This happens for all(?) status messages
			// currently because Broker no longer passes the
			// network info along with the status. Once fixed, remove this.
			auto ni = internal_type("Broker::NetworkInfo")->AsRecordType();
			auto network_info = new RecordVal(ni);
			network_info->Assign(0, new AddrVal("0.0.0.0"));
			network_info->Assign(1, port_mgr->Get(0, TRANSPORT_TCP));
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

	if ( ! Broker::error )
		return;

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

		case broker::ec::stale_data:
			ec = BifEnum::Broker::ErrorCode::STALE_DATA;
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
	if ( bstate->endpoint.is_shutdown() )
		statistics.num_peers = 0;
	else
		statistics.num_peers = bstate->endpoint.peers().size();

	statistics.num_stores = data_stores.size();
	statistics.num_pending_queries = pending_queries.size();

	// The other attributes are set as activity happens.

	return statistics;
	}

} // namespace bro_broker

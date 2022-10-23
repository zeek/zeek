#include "zeek/broker/Manager.h"

#include <broker/broker.hh>
#include <broker/configuration.hh>
#include <broker/zeek.hh>
#include <unistd.h>
#include <cstdio>
#include <cstring>

#include "zeek/DebugLogger.h"
#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/SerializationFormat.h"
#include "zeek/Var.h"
#include "zeek/broker/Data.h"
#include "zeek/broker/Store.h"
#include "zeek/broker/comm.bif.h"
#include "zeek/broker/data.bif.h"
#include "zeek/broker/messaging.bif.h"
#include "zeek/broker/store.bif.h"
#include "zeek/iosource/Manager.h"
#include "zeek/logging/Manager.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/util.h"

using namespace std;

namespace
	{

void print_escaped(std::string& buf, std::string_view str)
	{
	buf.push_back('"');
	for ( auto c : str )
		{
		switch ( c )
			{
			default:
				buf.push_back(c);
				break;
			case '\\':
				buf.push_back('\\');
				buf.push_back('\\');
				break;
			case '\b':
				buf.push_back('\\');
				buf.push_back('b');
				break;
			case '\f':
				buf.push_back('\\');
				buf.push_back('f');
				break;
			case '\n':
				buf.push_back('\\');
				buf.push_back('n');
				break;
			case '\r':
				buf.push_back('\\');
				buf.push_back('r');
				break;
			case '\t':
				buf.push_back('\\');
				buf.push_back('t');
				break;
			case '\v':
				buf.push_back('\\');
				buf.push_back('v');
				break;
			case '"':
				buf.push_back('\\');
				buf.push_back('"');
				break;
			}
		}
	buf.push_back('"');
	}

	} // namespace

namespace zeek::Broker
	{

static inline Val* get_option(const char* option)
	{
	const auto& id = zeek::detail::global_scope()->Find(option);

	if ( ! (id && id->GetVal()) )
		reporter->FatalError("Unknown Broker option %s", option);

	return id->GetVal().get();
	}

template <class T> static inline void set_option(const char* option, const T& value)
	{
	const auto& id = zeek::detail::global_scope()->Find(option);

	if ( ! id )
		reporter->FatalError("Unknown Broker option %s", option);

	if constexpr ( std::is_same_v<T, broker::port> )
		{
		switch ( value.type() )
			{
			case broker::port::protocol::tcp:
				id->SetVal(val_mgr->Port(value.number(), TRANSPORT_TCP));
				break;
			case broker::port::protocol::udp:
				id->SetVal(val_mgr->Port(value.number(), TRANSPORT_UDP));
				break;
			case broker::port::protocol::icmp:
				id->SetVal(val_mgr->Port(value.number(), TRANSPORT_ICMP));
				break;
			default:
				id->SetVal(val_mgr->Port(value.number(), TRANSPORT_UNKNOWN));
			}
		}
	else if constexpr ( std::is_same_v<T, broker::timespan> )
		{
		using std::chrono::duration_cast;
		auto ts = duration_cast<broker::fractional_seconds>(value);
		id->SetVal(make_intrusive<IntervalVal>(ts.count()));
		}
	else if constexpr ( std::is_same_v<T, std::vector<std::string>> )
		{
		auto ptr = make_intrusive<VectorVal>(zeek::id::string_vec);
		for ( const auto& str : value )
			ptr->Append(make_intrusive<StringVal>(str));
		id->SetVal(std::move(ptr));
		}
	else
		{
		static_assert(std::is_same_v<T, std::string>);
		id->SetVal(make_intrusive<StringVal>(value));
		}
	}

namespace
	{

struct opt_mapping
	{
	broker::configuration* cfg;
	std::string broker_name;
	const char* zeek_name;

	template <class T> auto broker_read() { return broker::get_as<T>(*cfg, broker_name); }

	template <class T> auto broker_write(T&& val) { cfg->set(broker_name, std::forward<T>(val)); }

	auto zeek_read() { return get_option(zeek_name); }

	template <class T> auto zeek_write(const T& val) { set_option(zeek_name, val); }
	};

#define WITH_OPT_MAPPING(broker_name, zeek_name)                                                   \
	if ( auto opt = opt_mapping{&config, broker_name, zeek_name}; true )

	} // namespace

class BrokerState
	{
public:
	BrokerState(broker::configuration config, size_t congestion_queue_size)
		: endpoint(std::move(config)),
		  subscriber(endpoint.make_subscriber({broker::topic::statuses(), broker::topic::errors()},
	                                          congestion_queue_size))
		{
		}

	broker::endpoint endpoint;
	broker::subscriber subscriber;
	};

const broker::endpoint_info Manager::NoPeer{{}, {}};

int Manager::script_scope = 0;

struct scoped_reporter_location
	{
	scoped_reporter_location(zeek::detail::Frame* frame)
		{
		reporter->PushLocation(frame->GetCallLocation());
		}

	~scoped_reporter_location() { reporter->PopLocation(); }
	};

#ifdef DEBUG
static std::string RenderMessage(std::string topic, const broker::data& x)
	{
	return util::fmt("%s -> %s", broker::to_string(x).c_str(), topic.c_str());
	}

static std::string RenderEvent(std::string topic, std::string name, const broker::data& args)
	{
	return util::fmt("%s(%s) -> %s", name.c_str(), broker::to_string(args).c_str(), topic.c_str());
	}

static std::string RenderMessage(const broker::store::response& x)
	{
	return util::fmt("%s [id %" PRIu64 "]",
	                 (x.answer ? broker::to_string(*x.answer).c_str() : "<no answer>"), x.id);
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

static std::string RenderMessage(broker::status_view s)
	{
	return broker::to_string(s.code());
	}

static std::string RenderMessage(broker::error_view e)
	{
	if ( auto ctx = e.context() )
		return util::fmt("%s (%s)", to_string(e.code()).c_str(), to_string(*ctx).c_str());
	else
		return util::fmt("%s (null)", to_string(e.code()).c_str());
	}

#endif

Manager::Manager(bool arg_use_real_time)
	{
	bound_port = 0;
	use_real_time = arg_use_real_time;
	peer_count = 0;
	log_batch_size = 0;
	log_topic_func = nullptr;
	log_id_type = nullptr;
	writer_id_type = nullptr;
	}

Manager::~Manager() { }

void Manager::InitPostScript()
	{
	DBG_LOG(DBG_BROKER, "Initializing");

	log_batch_size = get_option("Broker::log_batch_size")->AsCount();
	default_log_topic_prefix =
		get_option("Broker::default_log_topic_prefix")->AsString()->CheckString();
	log_topic_func = get_option("Broker::log_topic")->AsFunc();
	log_id_type = id::find_type("Log::ID")->AsEnumType();
	writer_id_type = id::find_type("Log::Writer")->AsEnumType();
	zeek_table_manager = get_option("Broker::table_store_master")->AsBool();
	zeek_table_db_directory =
		get_option("Broker::table_store_db_directory")->AsString()->CheckString();

	detail::opaque_of_data_type = make_intrusive<OpaqueType>("Broker::Data");
	detail::opaque_of_set_iterator = make_intrusive<OpaqueType>("Broker::SetIterator");
	detail::opaque_of_table_iterator = make_intrusive<OpaqueType>("Broker::TableIterator");
	detail::opaque_of_vector_iterator = make_intrusive<OpaqueType>("Broker::VectorIterator");
	detail::opaque_of_record_iterator = make_intrusive<OpaqueType>("Broker::RecordIterator");
	detail::opaque_of_store_handle = make_intrusive<OpaqueType>("Broker::Store");
	vector_of_data_type = make_intrusive<VectorType>(id::find_type("Broker::Data"));

	// Register as a "dont-count" source first, we may change that later.
	iosource_mgr->Register(this, true);

	broker::broker_options options;
	options.disable_ssl = get_option("Broker::disable_ssl")->AsBool();
	options.skip_ssl_init = true;
	options.disable_forwarding = ! get_option("Broker::forward_messages")->AsBool();
	options.use_real_time = use_real_time;

	broker::configuration config{std::move(options)};

	config.openssl_cafile(get_option("Broker::ssl_cafile")->AsString()->CheckString());
	config.openssl_capath(get_option("Broker::ssl_capath")->AsString()->CheckString());
	config.openssl_certificate(get_option("Broker::ssl_certificate")->AsString()->CheckString());
	config.openssl_key(get_option("Broker::ssl_keyfile")->AsString()->CheckString());
	config.openssl_passphrase(get_option("Broker::ssl_passphrase")->AsString()->CheckString());

	auto scheduler_policy = get_option("Broker::scheduler_policy")->AsString()->CheckString();

	if ( util::streq(scheduler_policy, "sharing") )
		config.set("caf.scheduler.policy", "sharing");
	else if ( util::streq(scheduler_policy, "stealing") )
		config.set("caf.scheduler.policy", "stealing");
	else
		reporter->FatalError("Invalid Broker::scheduler_policy: %s", scheduler_policy);

	auto max_threads_env = getenv("ZEEK_BROKER_MAX_THREADS");

	if ( max_threads_env )
		config.set("caf.scheduler.max-threads", atoi(max_threads_env));
	else
		config.set("caf.scheduler.max-threads", get_option("Broker::max_threads")->AsCount());

	config.set("caf.work-stealing.moderate-sleep-duration",
	           broker::timespan(static_cast<unsigned>(
				   get_option("Broker::moderate_sleep")->AsInterval() * 1e9)));

	config.set("caf.work-stealing.relaxed-sleep-duration",
	           broker::timespan(
				   static_cast<unsigned>(get_option("Broker::relaxed_sleep")->AsInterval() * 1e9)));

	config.set("caf.work-stealing.aggressive-poll-attempts",
	           get_option("Broker::aggressive_polls")->AsCount());
	config.set("caf.work-stealing.moderate-poll-attempts",
	           get_option("Broker::moderate_polls")->AsCount());

	config.set("caf.work-stealing.aggressive-steal-interval",
	           get_option("Broker::aggressive_interval")->AsCount());
	config.set("caf.work-stealing.moderate-steal-interval",
	           get_option("Broker::moderate_interval")->AsCount());
	config.set("caf.work-stealing.relaxed-steal-interval",
	           get_option("Broker::relaxed_interval")->AsCount());

	// Before launching Broker, we check whether the configuration contains
	// values for the metric_exporter_* options. If Broker already has picked up
	// values from environment variables (or config files) then we write then
	// back. Otherwise, we forward user-defined values from script land (but
	// ignore defaults).
	WITH_OPT_MAPPING("broker.metrics.port", "Broker::metrics_port")
		{
		if ( auto port = opt.broker_read<uint16_t>() )
			{
			opt.zeek_write(broker::port{*port, broker::port::protocol::tcp});
			}
		else
			{
			auto ptr = opt.zeek_read()->AsPortVal();
			if ( ptr->IsTCP() )
				opt.broker_write(ptr->Port());
			}
		}

	WITH_OPT_MAPPING("broker.metrics.export.interval", "Broker::metrics_export_interval")
		{
		if ( auto ts = opt.broker_read<broker::timespan>() )
			{
			opt.zeek_write(*ts);
			}
		else
			{
			using std::chrono::duration_cast;
			auto val = opt.zeek_read()->AsInterval();
			auto frac_ts = broker::fractional_seconds{val};
			if ( frac_ts.count() > 0.0 )
				opt.broker_write(duration_cast<broker::timespan>(frac_ts));
			}
		}

	WITH_OPT_MAPPING("broker.metrics.export.topic", "Broker::metrics_export_topic")
		{
		if ( auto str = opt.broker_read<std::string>() )
			{
			opt.zeek_write(*str);
			}
		else
			{
			auto ptr = opt.zeek_read()->AsStringVal();
			if ( ptr->Len() > 0 )
				opt.broker_write(ptr->ToStdString());
			}
		}

	WITH_OPT_MAPPING("broker.metrics.endpoint-name", "Broker::metrics_export_endpoint_name")
		{
		if ( auto str = opt.broker_read<std::string>() )
			{
			opt.zeek_write(*str);
			}
		else
			{
			auto ptr = opt.zeek_read()->AsStringVal();
			if ( ptr->Len() > 0 )
				opt.broker_write(ptr->ToStdString());
			}
		}

	WITH_OPT_MAPPING("broker.metrics.export.prefixes", "Broker::metrics_export_prefixes")
		{
		if ( auto str = opt.broker_read<std::vector<std::string>>() )
			{
			opt.zeek_write(*str);
			}
		else
			{
			auto ptr = opt.zeek_read()->AsVectorVal();
			std::vector<std::string> str_ls;
			for ( unsigned index = 0; index < ptr->Size(); ++index )
				str_ls.emplace_back(ptr->StringValAt(index)->ToStdString());
			opt.broker_write(std::move(str_ls));
			}
		}
	WITH_OPT_MAPPING("broker.metrics.import.topics", "Broker::metrics_import_topics")
		{
		if ( auto topics = opt.broker_read<std::vector<std::string>>() )
			{
			opt.zeek_write(*topics);
			}
		else
			{
			auto ptr = opt.zeek_read()->AsVectorVal();
			std::vector<std::string> str_ls;
			for ( unsigned index = 0; index < ptr->Size(); ++index )
				str_ls.emplace_back(ptr->StringValAt(index)->ToStdString());
			opt.broker_write(std::move(str_ls));
			}
		}

	auto cqs = get_option("Broker::congestion_queue_size")->AsCount();
	bstate = std::make_shared<BrokerState>(std::move(config), cqs);

	if ( ! iosource_mgr->RegisterFd(bstate->subscriber.fd(), this) )
		reporter->FatalError("Failed to register broker subscriber with iosource_mgr");

	bstate->subscriber.add_topic(broker::topic::store_events(), true);

	telemetry_mgr->InitPostBrokerSetup(bstate->endpoint);

	InitializeBrokerStoreForwarding();
	}

void Manager::InitializeBrokerStoreForwarding()
	{
	const auto& globals = zeek::detail::global_scope()->Vars();

	for ( const auto& global : globals )
		{
		auto& id = global.second;
		if ( id->HasVal() && id->GetAttr(zeek::detail::ATTR_BACKEND) )
			{
			const auto& attr = id->GetAttr(zeek::detail::ATTR_BACKEND);
			auto e = static_cast<BifEnum::Broker::BackendType>(
				attr->GetExpr()->Eval(nullptr)->AsEnum());
			auto storename = std::string("___sync_store_") + global.first;
			id->GetVal()->AsTableVal()->SetBrokerStore(storename);
			AddForwardedStore(storename, cast_intrusive<TableVal>(id->GetVal()));

			// We only create masters here. For clones, we do all the work of setting up
			// the forwarding - but we do not try to initialize the clone. We can only initialize
			// the clone, once a node has a connection to a master. This is currently done in
			// scriptland in scripts/base/frameworks/cluster/broker-stores.zeek. Once the ALM
			// transport is ready we can change over to doing this here.
			if ( ! zeek_table_manager )
				continue;

			auto backend = detail::to_backend_type(e);
			auto suffix = ".store";

			switch ( backend )
				{
				case broker::backend::sqlite:
					suffix = ".sqlite";
					break;
				default:
					break;
				}

			auto path = zeek_table_db_directory + "/" + storename + suffix;

			MakeMaster(storename, backend, broker::backend_options{{"path", path}});
			}
		}
	}

void Manager::Terminate()
	{
	FlushLogBuffers();

	iosource_mgr->UnregisterFd(bstate->subscriber.fd(), this);

	vector<string> stores_to_close;

	for ( auto& x : data_stores )
		stores_to_close.push_back(x.first);

	for ( auto& x : stores_to_close )
		// This doesn't loop directly over data_stores, because CloseStore
		// modifies the map and invalidates iterators.
		CloseStore(x);

	FlushLogBuffers();
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

uint16_t Manager::Listen(const string& addr, uint16_t port, BrokerProtocol type)
	{
	if ( bstate->endpoint.is_shutdown() )
		return 0;

	switch ( type )
		{
		case BrokerProtocol::Native:
			bound_port = bstate->endpoint.listen(addr, port);
			break;

		case BrokerProtocol::WebSocket:
			bound_port = bstate->endpoint.web_socket_listen(addr, port);
			break;
		}

	if ( bound_port == 0 )
		Error("Failed to listen on %s:%" PRIu16, addr.empty() ? "INADDR_ANY" : addr.c_str(), port);

	// Register as a "does-count" source now.
	iosource_mgr->Register(this, false);

	DBG_LOG(DBG_BROKER, "Listening on %s:%" PRIu16, addr.empty() ? "INADDR_ANY" : addr.c_str(),
	        port);

	return bound_port;
	}

void Manager::Peer(const string& addr, uint16_t port, double retry)
	{
	if ( bstate->endpoint.is_shutdown() )
		return;

	DBG_LOG(DBG_BROKER, "Starting to peer with %s:%" PRIu16 " (retry: %fs)", addr.c_str(), port,
	        retry);

	auto e = getenv("ZEEK_DEFAULT_CONNECT_RETRY");

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

void Manager::PeerNoRetry(const string& addr, uint16_t port)
	{
	if ( bstate->endpoint.is_shutdown() )
		return;

	DBG_LOG(DBG_BROKER, "Starting to peer with %s:%" PRIu16 " (no retry)", addr.c_str(), port);

	bstate->endpoint.peer_nosync(addr, port, broker::timeout::seconds{0});

	auto counts_as_iosource = get_option("Broker::peer_counts_as_iosource")->AsBool();

	if ( counts_as_iosource )
		// Register as a "does-count" source now.
		iosource_mgr->Register(this, false);
	}

void Manager::Unpeer(const string& addr, uint16_t port)
	{
	if ( bstate->endpoint.is_shutdown() )
		return;

	DBG_LOG(DBG_BROKER, "Stopping to peer with %s:%" PRIu16, addr.c_str(), port);

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

	DBG_LOG(DBG_BROKER, "Publishing event: %s", RenderEvent(topic, name, args).c_str());
	broker::zeek::Event ev(std::move(name), std::move(args));
	bstate->endpoint.publish(move(topic), ev.move_data());
	++statistics.num_events_outgoing;
	return true;
	}

bool Manager::PublishEvent(string topic, RecordVal* args)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( peer_count == 0 )
		return true;

	if ( ! args->HasField(0) )
		return false;

	auto event_name = args->GetFieldAs<StringVal>(0)->CheckString();
	auto vv = args->GetFieldAs<VectorVal>(1);
	broker::vector xs;
	xs.reserve(vv->Size());

	for ( auto i = 0u; i < vv->Size(); ++i )
		{
		const auto& val = vv->RecordValAt(i)->GetField(0);
		auto data_val = static_cast<detail::DataVal*>(val.get());
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

	auto data = detail::val_to_data(val.get());

	if ( ! data )
		{
		Error("Failed to publish ID with unsupported type: %s (%s)", id.c_str(),
		      type_name(val->GetType()->Tag()));
		return false;
		}

	broker::zeek::IdentifierUpdate msg(move(id), move(*data));
	DBG_LOG(DBG_BROKER, "Publishing id-update: %s", RenderMessage(topic, msg.as_data()).c_str());
	bstate->endpoint.publish(move(topic), msg.move_data());
	++statistics.num_ids_outgoing;
	return true;
	}

bool Manager::PublishLogCreate(EnumVal* stream, EnumVal* writer,
                               const logging::WriterBackend::WriterInfo& info, int num_fields,
                               const threading::Field* const* fields,
                               const broker::endpoint_info& peer)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( peer_count == 0 )
		return true;

	auto stream_id = stream->GetType()->AsEnumType()->Lookup(stream->AsEnum());

	if ( ! stream_id )
		{
		reporter->Error("Failed to remotely log: stream %d doesn't have name", stream->AsEnum());
		return false;
		}

	auto writer_id = writer->GetType()->AsEnumType()->Lookup(writer->AsEnum());

	if ( ! writer_id )
		{
		reporter->Error("Failed to remotely log: writer %d doesn't have name", writer->AsEnum());
		return false;
		}

	auto writer_info = info.ToBroker();

	broker::vector fields_data;
	fields_data.reserve(num_fields);

	for ( auto i = 0; i < num_fields; ++i )
		{
		auto field_data = detail::threading_field_to_data(fields[i]);
		fields_data.push_back(move(field_data));
		}

	std::string topic = default_log_topic_prefix + stream_id;
	auto bstream_id = broker::enum_value(move(stream_id));
	auto bwriter_id = broker::enum_value(move(writer_id));
	broker::zeek::LogCreate msg(move(bstream_id), move(bwriter_id), move(writer_info),
	                            move(fields_data));

	DBG_LOG(DBG_BROKER, "Publishing log creation: %s", RenderMessage(topic, msg.as_data()).c_str());

	if ( peer.node != NoPeer.node )
		// Direct message.
		bstate->endpoint.publish(peer, move(topic), msg.move_data());
	else
		// Broadcast.
		bstate->endpoint.publish(move(topic), msg.move_data());

	return true;
	}

bool Manager::PublishLogWrite(EnumVal* stream, EnumVal* writer, string path, int num_fields,
                              const threading::Value* const* vals)
	{
	if ( bstate->endpoint.is_shutdown() )
		return true;

	if ( peer_count == 0 )
		return true;

	auto stream_id_num = stream->AsEnum();
	auto stream_id = stream->GetType()->AsEnumType()->Lookup(stream_id_num);

	if ( ! stream_id )
		{
		reporter->Error("Failed to remotely log: stream %d doesn't have name", stream->AsEnum());
		return false;
		}

	auto writer_id = writer->GetType()->AsEnumType()->Lookup(writer->AsEnum());

	if ( ! writer_id )
		{
		reporter->Error("Failed to remotely log: writer %d doesn't have name", writer->AsEnum());
		return false;
		}

	zeek::detail::BinarySerializationFormat fmt;
	char* data;
	int len;

	fmt.StartWrite();

	bool success = fmt.Write(num_fields, "num_fields");

	if ( ! success )
		{
		reporter->Error("Failed to remotely log stream %s: num_fields serialization failed",
		                stream_id);
		return false;
		}

	for ( int i = 0; i < num_fields; ++i )
		{
		if ( ! vals[i]->Write(&fmt) )
			{
			reporter->Error("Failed to remotely log stream %s: field %d serialization failed",
			                stream_id, i);
			return false;
			}
		}

	len = fmt.EndWrite(&data);
	std::string serial_data(data, len);
	free(data);

	auto v = log_topic_func->Invoke(IntrusivePtr{NewRef{}, stream},
	                                make_intrusive<StringVal>(path));

	if ( ! v )
		{
		reporter->Error("Failed to remotely log: log_topic func did not return"
		                " a value for stream %s at path %s",
		                stream_id, path.data());
		return false;
		}

	std::string topic = v->AsString()->CheckString();

	auto bstream_id = broker::enum_value(move(stream_id));
	auto bwriter_id = broker::enum_value(move(writer_id));
	broker::zeek::LogWrite msg(move(bstream_id), move(bwriter_id), move(path), move(serial_data));

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
	auto msg = util::vfmt(format, args);
	va_end(args);

	if ( script_scope )
		emit_builtin_error(msg);
	else
		reporter->Error("%s", msg);
	}

bool Manager::AutoPublishEvent(string topic, Val* event)
	{
	if ( event->GetType()->Tag() != TYPE_FUNC )
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
		Error("Broker::auto_publish failed to lookup event '%s'", event_val->Name());
		return false;
		}

	DBG_LOG(DBG_BROKER, "Enabling auto-publishing of event %s to topic %s", handler->Name(),
	        topic.c_str());
	handler->AutoPublish(move(topic));

	return true;
	}

bool Manager::AutoUnpublishEvent(const string& topic, Val* event)
	{
	if ( event->GetType()->Tag() != TYPE_FUNC )
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
		Error("Broker::auto_event_stop failed to lookup event '%s'", event_val->Name());
		return false;
		}

	DBG_LOG(DBG_BROKER, "Disabling auto-publishing of event %s to topic %s", handler->Name(),
	        topic.c_str());
	handler->AutoUnpublish(topic);

	return true;
	}

RecordVal* Manager::MakeEvent(ValPList* args, zeek::detail::Frame* frame)
	{
	auto rval = new RecordVal(BifType::Record::Broker::Event);
	auto arg_vec = make_intrusive<VectorVal>(vector_of_data_type);
	rval->Assign(1, arg_vec);
	Func* func = nullptr;
	scoped_reporter_location srl{frame};

	for ( auto i = 0; i < args->length(); ++i )
		{
		auto arg_val = (*args)[i];

		if ( i == 0 )
			{
			// Event val must come first.

			if ( arg_val->GetType()->Tag() != TYPE_FUNC )
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

			auto num_args = func->GetType()->Params()->NumFields();

			if ( num_args != args->length() - 1 )
				{
				Error("bad # of arguments: got %d, expect %d", args->length(), num_args + 1);
				return rval;
				}

			rval->Assign(0, func->Name());
			continue;
			}

		const auto& got_type = (*args)[i]->GetType();
		const auto& expected_type = func->GetType()->ParamList()->GetTypes()[i - 1];

		if ( ! same_type(got_type, expected_type) )
			{
			rval->Remove(0);
			Error("event parameter #%d type mismatch, got %s, expect %s", i,
			      type_name(got_type->Tag()), type_name(expected_type->Tag()));
			return rval;
			}

		RecordValPtr data_val;

		if ( same_type(got_type, detail::DataVal::ScriptDataType()) )
			data_val = {NewRef{}, (*args)[i]->AsRecordVal()};
		else
			data_val = detail::make_data_val((*args)[i]);

		if ( ! data_val->HasField(0) )
			{
			rval->Remove(0);
			Error("failed to convert param #%d of type %s to broker data", i,
			      type_name(got_type->Tag()));
			return rval;
			}

		arg_vec->Assign(i - 1, std::move(data_val));
		}

	return rval;
	}

bool Manager::Subscribe(const string& topic_prefix)
	{
	DBG_LOG(DBG_BROKER, "Subscribing to topic prefix %s", topic_prefix.c_str());
	bstate->subscriber.add_topic(topic_prefix, ! run_state::detail::zeek_init_done);

	// For backward compatibility, we also may receive messages on
	// "bro/" topic prefixes in addition to "zeek/".
	if ( strncmp(topic_prefix.data(), "zeek/", 5) == 0 )
		{
		std::string alt_topic = "bro/" + topic_prefix.substr(5);
		bstate->subscriber.add_topic(std::move(alt_topic), ! run_state::detail::zeek_init_done);
		}

	return true;
	}

bool Manager::Forward(string topic_prefix)
	{
	for ( const auto& prefix : forwarded_prefixes )
		if ( prefix == topic_prefix )
			return false;

	DBG_LOG(DBG_BROKER, "Forwarding topic prefix %s", topic_prefix.c_str());
	Subscribe(topic_prefix);
	forwarded_prefixes.emplace_back(std::move(topic_prefix));
	return true;
	}

bool Manager::Unsubscribe(const string& topic_prefix)
	{
	for ( size_t i = 0; i < forwarded_prefixes.size(); ++i )
		if ( forwarded_prefixes[i] == topic_prefix )
			{
			DBG_LOG(DBG_BROKER, "Unforwading topic prefix %s", topic_prefix.c_str());
			forwarded_prefixes.erase(forwarded_prefixes.begin() + i);
			break;
			}

	DBG_LOG(DBG_BROKER, "Unsubscribing from topic prefix %s", topic_prefix.c_str());
	bstate->subscriber.remove_topic(topic_prefix, ! run_state::detail::zeek_init_done);
	return true;
	}

void Manager::DispatchMessage(const broker::topic& topic, broker::data msg)
	{
	switch ( broker::zeek::Message::type(msg) )
		{
		case broker::zeek::Message::Type::Invalid:
			reporter->Warning("received invalid broker message: %s", broker::to_string(msg).data());
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
				                  broker::to_string(batch.as_data()).data());
				return;
				}

			for ( auto& i : batch.batch() )
				DispatchMessage(topic, std::move(i));

			break;
			}

		default:
			// We ignore unknown types so that we could add more in the
			// future if we had too.
			reporter->Warning("received unknown broker message: %s", broker::to_string(msg).data());
			break;
		}
	}

void Manager::Process()
	{
	// Ensure that time gets update before processing broker messages, or events
	// based on them might get scheduled wrong.
	if ( use_real_time )
		run_state::detail::update_network_time(util::current_time());

	auto messages = bstate->subscriber.poll();

	bool had_input = ! messages.empty();

	for ( auto& message : messages )
		{
		auto& topic = broker::get_topic(message);

		if ( broker::is_prefix(topic, broker::topic::statuses_str) )
			{
			if ( auto stat = broker::make_status_view(get_data(message)) )
				{
				ProcessStatus(stat);
				}
			else
				{
				auto str = to_string(message);
				reporter->Warning("ignoring malformed Broker status event: %s", str.c_str());
				}
			continue;
			}

		if ( broker::is_prefix(topic, broker::topic::errors_str) )
			{
			if ( auto err = broker::make_error_view(get_data(message)) )
				{
				ProcessError(err);
				}
			else
				{
				auto str = to_string(message);
				reporter->Warning("ignoring malformed Broker error event: %s", str.c_str());
				}
			continue;
			}

		if ( broker::is_prefix(topic, broker::topic::store_events_str) )
			{
			ProcessStoreEvent(broker::move_data(message));
			continue;
			}

		try
			{
			// Once we call a broker::move_* function, we force Broker to
			// unshare the content of the message, i.e., copy the content to a
			// different memory region if other threads keep references to the
			// message. Since `topic` still points into the original memory
			// region, we may no longer access it after this point.
			auto unshared_topic = broker::move_topic(message);
			DispatchMessage(unshared_topic, broker::move_data(message));
			}
		catch ( std::runtime_error& e )
			{
			reporter->Warning("ignoring invalid Broker message: %s", +e.what());
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
		if ( run_state::network_time == 0 )
			// If we're getting Broker messages, but still haven't initialized
			// run_state::network_time, may as well do so now because otherwise the
			// broker/cluster logs will end up using timestamp 0.
			run_state::detail::update_network_time(util::current_time());
		}
	}

void Manager::ProcessStoreEventInsertUpdate(const TableValPtr& table, const std::string& store_id,
                                            const broker::data& key, const broker::data& data,
                                            const broker::data& old_value, bool insert)
	{
	auto type = "Insert";
	if ( ! insert )
		type = "Update";

	if ( insert )
		{
		DBG_LOG(DBG_BROKER, "Store %s: Insert: %s:%s (%s:%s)", store_id.c_str(),
		        to_string(key).c_str(), to_string(data).c_str(), key.get_type_name(),
		        data.get_type_name());
		}
	else
		{
		DBG_LOG(DBG_BROKER, "Store %s: Update: %s->%s (%s)", store_id.c_str(),
		        to_string(old_value).c_str(), to_string(data).c_str(), data.get_type_name());
		}

	if ( table->GetType()->IsSet() && data.get_type() != broker::data::type::none )
		{
		reporter->Error("ProcessStoreEvent %s got %s when expecting set", type,
		                data.get_type_name());
		return;
		}

	const auto& its = table->GetType()->AsTableType()->GetIndexTypes();
	ValPtr zeek_key;
	if ( its.size() == 1 )
		zeek_key = detail::data_to_val(key, its[0].get());
	else
		zeek_key = detail::data_to_val(key, table->GetType()->AsTableType()->GetIndices().get());

	if ( ! zeek_key )
		{
		reporter->Error(
			"ProcessStoreEvent %s: could not convert key \"%s\" for store \"%s\" while receiving "
			"remote data. This probably means the tables have different types on different nodes.",
			type, to_string(key).c_str(), store_id.c_str());
		return;
		}

	if ( table->GetType()->IsSet() )
		{
		table->Assign(zeek_key, nullptr, false);
		return;
		}

	// it is a table
	auto zeek_value = detail::data_to_val(data, table->GetType()->Yield().get());
	if ( ! zeek_value )
		{
		reporter->Error("ProcessStoreEvent %s: could not convert value \"%s\" for key \"%s\" in "
		                "store \"%s\" while receiving remote data. This probably means the tables "
		                "have different types on different nodes.",
		                type, to_string(data).c_str(), to_string(key).c_str(), store_id.c_str());
		return;
		}

	table->Assign(zeek_key, zeek_value, false);
	}

void Manager::ProcessStoreEvent(broker::data msg)
	{
	if ( auto insert = broker::store_event::insert::make(msg) )
		{
		auto storehandle = broker_mgr->LookupStore(insert.store_id());
		if ( ! storehandle )
			return;

		const auto& table = storehandle->forward_to;
		if ( ! table )
			return;

		// We sent this message. Ignore it.
		if ( insert.publisher() == storehandle->store_pid )
			return;

		ProcessStoreEventInsertUpdate(table, insert.store_id(), insert.key(), insert.value(), {},
		                              true);
		}
	else if ( auto update = broker::store_event::update::make(msg) )
		{
		auto storehandle = broker_mgr->LookupStore(update.store_id());
		if ( ! storehandle )
			return;

		const auto& table = storehandle->forward_to;
		if ( ! table )
			return;

		// We sent this message. Ignore it.
		if ( update.publisher() == storehandle->store_pid )
			return;

		ProcessStoreEventInsertUpdate(table, update.store_id(), update.key(), update.new_value(),
		                              update.old_value(), false);
		}
	else if ( auto erase = broker::store_event::erase::make(msg) )
		{
		auto storehandle = broker_mgr->LookupStore(erase.store_id());
		if ( ! storehandle )
			return;

		auto table = storehandle->forward_to;
		if ( ! table )
			return;

		// We sent this message. Ignore it.
		if ( erase.publisher() == storehandle->store_pid )
			return;

		auto key = erase.key();
		DBG_LOG(DBG_BROKER, "Store %s: Erase key %s", erase.store_id().c_str(),
		        to_string(key).c_str());
		const auto& its = table->GetType()->AsTableType()->GetIndexTypes();
		assert(its.size() == 1);
		auto zeek_key = detail::data_to_val(key, its[0].get());
		if ( ! zeek_key )
			{
			reporter->Error("ProcessStoreEvent: could not convert key \"%s\" for store \"%s\" "
			                "while receiving remote erase. This probably means the tables have "
			                "different types on different nodes.",
			                to_string(key).c_str(), insert.store_id().c_str());
			return;
			}

		table->Remove(*zeek_key, false);
		}
	else if ( auto expire = broker::store_event::expire::make(msg) )
		{
			// We just ignore expiries - expiring information on the Zeek side is handled by Zeek
			// itself.
#ifdef DEBUG
		// let's only debug log for stores that we know.
		auto storehandle = broker_mgr->LookupStore(expire.store_id());
		if ( ! storehandle )
			return;

		auto table = storehandle->forward_to;
		if ( ! table )
			return;

		DBG_LOG(DBG_BROKER, "Store %s: Store expired key %s", expire.store_id().c_str(),
		        to_string(expire.key()).c_str());
#endif /* DEBUG */
		}
	else
		{
		reporter->Error("ProcessStoreEvent: Unhandled event type");
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

	DBG_LOG(DBG_BROKER, "Process event: %s %s", name.data(), RenderMessage(args).data());
	++statistics.num_events_incoming;
	auto handler = event_registry->Lookup(name);

	if ( ! handler )
		return;

	auto& topic_string = topic.string();

	for ( const auto& p : forwarded_prefixes )
		{
		if ( p.size() > topic_string.size() )
			continue;

		if ( strncmp(p.data(), topic_string.data(), p.size()) != 0 )
			continue;

		DBG_LOG(DBG_BROKER, "Skip processing of forwarded event: %s %s", name.data(),
		        RenderMessage(args).data());
		return;
		}

	const auto& arg_types = handler->GetType(false)->ParamList()->GetTypes();

	if ( arg_types.size() != args.size() )
		{
		reporter->Warning("got event message '%s' with invalid # of args,"
		                  " got %zd, expected %zu",
		                  name.data(), args.size(), arg_types.size());
		return;
		}

	Args vl;
	vl.reserve(args.size());

	for ( size_t i = 0; i < args.size(); ++i )
		{
		auto got_type = args[i].get_type_name();
		const auto& expected_type = arg_types[i];
		auto val = detail::data_to_val(args[i], expected_type.get());

		if ( val )
			vl.emplace_back(std::move(val));
		else
			{
			auto expected_name = type_name(expected_type->Tag());
			std::string msg_addl = util::fmt("got %s, expected %s", got_type, expected_name);

			if ( strcmp(expected_name, "record") == 0 && strcmp("vector", got_type) == 0 )
				{
				// This means the vector elements didn't align with the record
				// fields. Produce an error message that shows what we
				// received.
				std::string elements;
				for ( const auto& e : broker::get<broker::vector>(args[i]) )
					{
					if ( ! elements.empty() )
						elements += ", ";

					elements += e.get_type_name();
					}

				msg_addl = util::fmt("got mismatching field types [%s] for record type '%s'",
				                     elements.c_str(), expected_type->GetName().c_str());
				}

			reporter->Warning("failed to convert remote event '%s' arg #%zu, %s", name.data(), i,
			                  msg_addl.c_str());

			// If we got a vector and expected a function this is
			// possibly because of a mismatch between
			// anonymous-function bodies.
			if ( strcmp(expected_name, "func") == 0 && strcmp("vector", got_type) == 0 )
				reporter->Warning("when sending functions the receiver must have access to a"
				                  " version of that function.\nFor anonymous functions, that "
				                  "function must have the same body.");

			break;
			}
		}

	if ( vl.size() == args.size() )
		event_mgr.Enqueue(handler, std::move(vl), util::detail::SOURCE_BROKER);
	}

bool Manager::ProcessLogCreate(broker::zeek::LogCreate lc)
	{
	DBG_LOG(DBG_BROKER, "Received log-create: %s", RenderMessage(lc.as_data()).c_str());
	if ( ! lc.valid() )
		{
		reporter->Warning("received invalid broker LogCreate: %s",
		                  broker::to_string(lc.as_data()).data());
		return false;
		}

	auto stream_id = detail::data_to_val(std::move(lc.stream_id()), log_id_type);
	if ( ! stream_id )
		{
		reporter->Warning("failed to unpack remote log stream id");
		return false;
		}

	auto writer_id = detail::data_to_val(std::move(lc.writer_id()), writer_id_type);
	if ( ! writer_id )
		{
		reporter->Warning("failed to unpack remote log writer id");
		return false;
		}

	auto writer_info = std::make_unique<logging::WriterBackend::WriterInfo>();
	if ( ! writer_info->FromBroker(std::move(lc.writer_info())) )
		{
		reporter->Warning("failed to unpack remote log writer info");
		return false;
		}

	// Get log fields.
	auto fields_data = get_if<broker::vector>(&lc.fields_data());

	if ( ! fields_data )
		{
		reporter->Warning("failed to unpack remote log fields");
		return false;
		}

	auto num_fields = fields_data->size();
	auto fields = new threading::Field*[num_fields];

	for ( size_t i = 0; i < num_fields; ++i )
		{
		if ( auto field = detail::data_to_threading_field(std::move((*fields_data)[i])) )
			fields[i] = field;
		else
			{
			reporter->Warning("failed to convert remote log field # %zu", i);
			delete[] fields;
			return false;
			}
		}

	if ( ! log_mgr->CreateWriterForRemoteLog(stream_id->AsEnumVal(), writer_id->AsEnumVal(),
	                                         writer_info.release(), num_fields, fields) )
		{
		ODesc d;
		stream_id->Describe(&d);
		reporter->Warning("failed to create remote log stream for %s locally", d.Description());
		}

	return true;
	}

bool Manager::ProcessLogWrite(broker::zeek::LogWrite lw)
	{
	DBG_LOG(DBG_BROKER, "Received log-write: %s", RenderMessage(lw.as_data()).c_str());

	if ( ! lw.valid() )
		{
		reporter->Warning("received invalid broker LogWrite: %s",
		                  broker::to_string(lw.as_data()).data());
		return false;
		}

	++statistics.num_logs_incoming;
	auto& stream_id_name = lw.stream_id().name;

	// Get stream ID.
	auto stream_id = detail::data_to_val(std::move(lw.stream_id()), log_id_type);

	if ( ! stream_id )
		{
		reporter->Warning("failed to unpack remote log stream id: %s", stream_id_name.data());
		return false;
		}

	// Get writer ID.
	auto writer_id = detail::data_to_val(std::move(lw.writer_id()), writer_id_type);
	if ( ! writer_id )
		{
		reporter->Warning("failed to unpack remote log writer id for stream: %s",
		                  stream_id_name.data());
		return false;
		}

	auto path = get_if<std::string>(&lw.path());

	if ( ! path )
		{
		reporter->Warning("failed to unpack remote log values (bad path variant) for stream: %s",
		                  stream_id_name.data());
		return false;
		}

	auto serial_data = get_if<std::string>(&lw.serial_data());

	if ( ! serial_data )
		{
		reporter->Warning(
			"failed to unpack remote log values (bad serial_data variant) for stream: %s",
			stream_id_name.data());
		return false;
		}

	zeek::detail::BinarySerializationFormat fmt;
	fmt.StartRead(serial_data->data(), serial_data->size());

	int num_fields;
	bool success = fmt.Read(&num_fields, "num_fields");

	if ( ! success )
		{
		reporter->Warning("failed to unserialize remote log num fields for stream: %s",
		                  stream_id_name.data());
		return false;
		}

	auto vals = new threading::Value*[num_fields];

	for ( int i = 0; i < num_fields; ++i )
		{
		vals[i] = new threading::Value;

		if ( ! vals[i]->Read(&fmt) )
			{
			for ( int j = 0; j <= i; ++j )
				delete vals[j];

			delete[] vals;
			reporter->Warning("failed to unserialize remote log field %d for stream: %s", i,
			                  stream_id_name.data());

			return false;
			}
		}

	log_mgr->WriteFromRemote(stream_id->AsEnumVal(), writer_id->AsEnumVal(), std::move(*path),
	                         num_fields, vals);
	fmt.EndRead();
	return true;
	}

bool Manager::ProcessIdentifierUpdate(broker::zeek::IdentifierUpdate iu)
	{
	DBG_LOG(DBG_BROKER, "Received id-update: %s", RenderMessage(iu.as_data()).c_str());

	if ( ! iu.valid() )
		{
		reporter->Warning("received invalid broker IdentifierUpdate: %s",
		                  broker::to_string(iu.as_data()).data());
		return false;
		}

	++statistics.num_ids_incoming;
	auto id_name = std::move(iu.id_name());
	auto id_value = std::move(iu.id_value());
	const auto& id = zeek::detail::global_scope()->Find(id_name);

	if ( ! id )
		{
		reporter->Warning("Received id-update request for unkown id: %s", id_name.c_str());
		return false;
		}

	auto val = detail::data_to_val(std::move(id_value), id->GetType().get());

	if ( ! val )
		{
		reporter->Error("Failed to receive ID with unsupported type: %s (%s)", id_name.c_str(),
		                type_name(id->GetType()->Tag()));
		return false;
		}

	id->SetVal(std::move(val));
	return true;
	}

void Manager::ProcessStatus(broker::status_view stat)
	{
	DBG_LOG(DBG_BROKER, "Received status message: %s", RenderMessage(stat).c_str());

	auto ctx = stat.context();

	EventHandlerPtr event;
	switch ( stat.code() )
		{
		case broker::sc::unspecified:
			event = ::Broker::status;
			break;

		case broker::sc::peer_added:
			++peer_count;
			assert(ctx);
			log_mgr->SendAllWritersTo(*ctx);
			event = ::Broker::peer_added;
			break;

		case broker::sc::peer_removed:
			--peer_count;
			event = ::Broker::peer_removed;
			break;

		case broker::sc::peer_lost:
			--peer_count;
			event = ::Broker::peer_lost;
			break;

		case broker::sc::endpoint_discovered:
			event = ::Broker::endpoint_discovered;
			break;

		case broker::sc::endpoint_unreachable:
			event = ::Broker::endpoint_unreachable;
			break;

		default:
			reporter->Warning("Unhandled Broker status: %s", to_string(stat).data());
			break;
		}

	if ( ! event )
		return;

	static auto ei = id::find_type<RecordType>("Broker::EndpointInfo");
	auto endpoint_info = make_intrusive<RecordVal>(ei);

	if ( ctx )
		{
		endpoint_info->Assign(0, to_string(ctx->node));
		static auto ni = id::find_type<RecordType>("Broker::NetworkInfo");
		auto network_info = make_intrusive<RecordVal>(ni);

		if ( ctx->network )
			{
			network_info->Assign(0, ctx->network->address.data());
			network_info->Assign(1, val_mgr->Port(ctx->network->port, TRANSPORT_TCP));
			}
		else
			{
			// TODO: are there any status messages where the ctx->network
			// is not set and actually could be?
			network_info->Assign(0, "<unknown>");
			network_info->Assign(1, val_mgr->Port(0, TRANSPORT_TCP));
			}

		endpoint_info->Assign(1, std::move(network_info));
		}

	auto str = stat.message();
	auto msg = make_intrusive<StringVal>(str ? *str : "");

	event_mgr.Enqueue(event, std::move(endpoint_info), std::move(msg));
	}

void Manager::ProcessError(broker::error_view err)
	{
	DBG_LOG(DBG_BROKER, "Received error message: %s", RenderMessage(err).c_str());

	if ( ! ::Broker::error )
		return;

	auto int_code = static_cast<uint8_t>(err.code());

	BifEnum::Broker::ErrorCode ec;
	static auto enum_type = id::find_type<EnumType>("Broker::ErrorCode");
	if ( enum_type->Lookup(int_code) )
		ec = static_cast<BifEnum::Broker::ErrorCode>(int_code);
	else
		{

		reporter->Warning("Unknown Broker error code %u: mapped to unspecificed enum value ",
		                  static_cast<unsigned>(int_code));
		ec = BifEnum::Broker::ErrorCode::UNSPECIFIED;
		}

	std::string msg;
	// Note: we could also use to_string, but that would change the log output
	// and we would have to update all baselines relying on this format.
	if ( auto ctx = err.context() )
		{
		msg += '(';
		msg += broker::to_string(ctx->node);
		msg += ", ";
		msg += broker::to_string(ctx->network);
		msg += ", ";
		if ( auto what = err.message() )
			print_escaped(msg, *what);
		else
			msg += R"_("")_";
		msg += ')';
		}
	else
		msg = "(null)";

	event_mgr.Enqueue(::Broker::error, BifType::Enum::Broker::ErrorCode->GetEnumVal(ec),
	                  make_intrusive<StringVal>(msg));
	}

void Manager::ProcessStoreResponse(detail::StoreHandleVal* s, broker::store::response response)
	{
	DBG_LOG(DBG_BROKER, "Received store response: %s", RenderMessage(response).c_str());

	auto request = pending_queries.find(std::make_pair(response.id, s));

	if ( request == pending_queries.end() )
		{
		reporter->Warning("unmatched response to query %" PRIu64 " on store %s", response.id,
		                  s->store.name().c_str());
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
		request->second->Result(
			detail::query_result(detail::make_data_val(std::move(*response.answer))));
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
		request->second->Result(detail::query_result());
	else
		reporter->InternalWarning("unknown store response status: %s",
		                          to_string(response.answer.error()).c_str());

	delete request->second;
	pending_queries.erase(request);
	}

detail::StoreHandleVal* Manager::MakeMaster(const string& name, broker::backend type,
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

		switch ( type )
			{
			case broker::backend::sqlite:
				suffix = ".sqlite";
				break;
			default:
				break;
			}

		it->second = name + suffix;
		}

	auto result = bstate->endpoint.attach_master(name, type, move(opts));
	if ( ! result )
		{
		Error("Failed to attach master store %s:", to_string(result.error()).c_str());
		return nullptr;
		}

	auto handle = new detail::StoreHandleVal{*result};
	Ref(handle);

	data_stores.emplace(name, handle);
	if ( ! iosource_mgr->RegisterFd(handle->proxy.mailbox().descriptor(), this) )
		reporter->FatalError(
			"Failed to register broker master mailbox descriptor with iosource_mgr");

	PrepareForwarding(name);

	if ( ! bstate->endpoint.use_real_time() )
		// Wait for master to become available/responsive.
		// Possibly avoids timeouts in scripts during unit tests.
		handle->store.exists("");

	BrokerStoreToZeekTable(name, handle);

	return handle;
	}

void Manager::BrokerStoreToZeekTable(const std::string& name, const detail::StoreHandleVal* handle)
	{
	if ( ! handle->forward_to )
		return;

	auto keys = handle->store.keys();
	if ( ! keys )
		return;

	auto set = get_if<broker::set>(&(keys->get_data()));
	auto table = handle->forward_to;
	const auto& its = table->GetType()->AsTableType()->GetIndexTypes();
	bool is_set = table->GetType()->IsSet();

	// disable &on_change notifications while filling the table.
	table->DisableChangeNotifications();

	for ( const auto& key : *set )
		{
		ValPtr zeek_key;
		if ( its.size() == 1 )
			zeek_key = detail::data_to_val(key, its[0].get());
		else
			zeek_key = detail::data_to_val(key,
			                               table->GetType()->AsTableType()->GetIndices().get());

		if ( ! zeek_key )
			{
			reporter->Error("Failed to convert key \"%s\" while importing broker store to table "
			                "for store \"%s\". Aborting import.",
			                to_string(key).c_str(), name.c_str());
			// just abort - this probably means the types are incompatible
			table->EnableChangeNotifications();
			return;
			}

		if ( is_set )
			{
			table->Assign(zeek_key, nullptr, false);
			continue;
			}

		auto value = handle->store.get(key);
		if ( ! value )
			{
			reporter->Error(
				"Failed to load value for key %s while importing Broker store %s to table",
				to_string(key).c_str(), name.c_str());
			table->EnableChangeNotifications();
			continue;
			}

		auto zeek_value = detail::data_to_val(*value, table->GetType()->Yield().get());
		if ( ! zeek_value )
			{
			reporter->Error("Could not convert %s to table value while trying to import Broker "
			                "store %s. Aborting import.",
			                to_string(value).c_str(), name.c_str());
			table->EnableChangeNotifications();
			return;
			}

		table->Assign(zeek_key, zeek_value, false);
		}

	table->EnableChangeNotifications();
	return;
	}

detail::StoreHandleVal* Manager::MakeClone(const string& name, double resync_interval,
                                           double stale_interval, double mutation_buffer_interval)
	{
	if ( bstate->endpoint.is_shutdown() )
		return nullptr;

	if ( LookupStore(name) )
		return nullptr;

	DBG_LOG(DBG_BROKER, "Creating clone for data store %s", name.c_str());

	auto result = bstate->endpoint.attach_clone(name, resync_interval, stale_interval,
	                                            mutation_buffer_interval);
	if ( ! result )
		{
		Error("Failed to attach clone store %s:", to_string(result.error()).c_str());
		return nullptr;
		}

	auto handle = new detail::StoreHandleVal{*result};
	Ref(handle);

	data_stores.emplace(name, handle);
	if ( ! iosource_mgr->RegisterFd(handle->proxy.mailbox().descriptor(), this) )
		reporter->FatalError(
			"Failed to register broker clone mailbox descriptor with iosource_mgr");
	PrepareForwarding(name);
	return handle;
	}

detail::StoreHandleVal* Manager::LookupStore(const string& name)
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

	s->second->have_store = false;
	s->second->store_pid = {};
	s->second->proxy = {};
	s->second->store = {};
	Unref(s->second);
	data_stores.erase(s);
	return true;
	}

bool Manager::TrackStoreQuery(detail::StoreHandleVal* handle, broker::request_id id,
                              detail::StoreQueryCallback* cb)
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

bool Manager::AddForwardedStore(const std::string& name, TableValPtr table)
	{
	if ( forwarded_stores.find(name) != forwarded_stores.end() )
		{
		reporter->Error("same &broker_store %s specified for two different variables",
		                name.c_str());
		return false;
		}

	DBG_LOG(DBG_BROKER, "Adding table forward for data store %s", name.c_str());
	forwarded_stores.emplace(name, std::move(table));

	PrepareForwarding(name);
	return true;
	}

void Manager::PrepareForwarding(const std::string& name)
	{
	auto handle = LookupStore(name);
	if ( ! handle )
		return;

	if ( forwarded_stores.find(name) == forwarded_stores.end() )
		return;

	handle->forward_to = forwarded_stores.at(name);
	DBG_LOG(DBG_BROKER, "Resolved table forward for data store %s", name.c_str());
	}

void Manager::SetMetricsExportInterval(double value)
	{
	using dbl_seconds = std::chrono::duration<double>;
	auto ts = std::chrono::duration_cast<broker::timespan>(dbl_seconds{value});
	bstate->endpoint.metrics_exporter().set_interval(ts);
	}

void Manager::SetMetricsExportTopic(std::string value)
	{
	bstate->endpoint.metrics_exporter().set_target(std::move(value));
	}

void Manager::SetMetricsImportTopics(std::vector<std::string> topics)
	{
	bstate->endpoint.metrics_exporter().set_import_topics(std::move(topics));
	}

void Manager::SetMetricsExportEndpointName(std::string value)
	{
	bstate->endpoint.metrics_exporter().set_id(std::move(value));
	}

void Manager::SetMetricsExportPrefixes(std::vector<std::string> filter)
	{
	bstate->endpoint.metrics_exporter().set_prefixes(std::move(filter));
	}

	} // namespace zeek::Broker

// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/broker/Manager.h"

#include <broker/config.hh>
#include <broker/configuration.hh>
#include <broker/endpoint.hh>
#include <broker/event.hh>
#include <broker/event_observer.hh>
#include <broker/logger.hh>
#include <broker/time.hh>
#include <broker/variant.hh>
#include <broker/zeek.hh>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

#include "zeek/DebugLogger.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/Flare.h"
#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Scope.h"
#include "zeek/SerializationFormat.h"
#include "zeek/Type.h"
#include "zeek/Var.h"
#include "zeek/broker/Data.h"
#include "zeek/broker/Store.h"
#include "zeek/broker/comm.bif.h"
#include "zeek/broker/messaging.bif.h"
#include "zeek/broker/store.bif.h"
#include "zeek/cluster/Telemetry.h"
#include "zeek/cluster/serializer/broker/Serializer.h"
#include "zeek/iosource/Manager.h"
#include "zeek/logging/Manager.h"
#include "zeek/logging/Types.h"
#include "zeek/plugin/Manager.h"
#include "zeek/plugin/Plugin.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/util.h"

#include "const.bif.netvar_h"

using namespace std;

namespace {

broker::vector broker_vector_from(const broker::variant& arg) {
    auto tmp = arg.to_data();
    return std::move(broker::get<broker::vector>(tmp));
}

void print_escaped(std::string& buf, std::string_view str) {
    buf.push_back('"');
    for ( auto c : str ) {
        switch ( c ) {
            default: buf.push_back(c); break;
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

// Track metrics for a given peering's send buffer.
class PeerBufferState {
public:
    struct Stats {
        // The rendered peer ID. Storing this here helps reuse.
        // Note that we only ever touch this from Zeek's main thread, not
        // any of Broker's.
        zeek::StringValPtr peer_id;

        // Whether Broker has removed the peer, and this instance still
        // needs to be removed.
        bool is_zombie = false;

        // Number of messages queued locally in the send buffer.
        uint32_t queued = 0;

        // Maximum number queued in the last Broker::buffer_stats_reset_interval.
        // This improces visibility into message bursts since instantaneous
        // queueing (captured above) can be short-lived.
        uint32_t max_queued_recently = 0;

        // Number of times the buffer overflowed at send time.  For the
        // "disconnect" overflow policy (via Broker::peer_overflow_policy), this
        // count will at most be 1 since Broker will remove the peering upon
        // overflow. The existing Zeek-level metric for tracking disconnects
        // (see frameworks/broker/broker-backpressure.zeek) covers this one more
        // permanently. For the "drop_newest" and "drop_oldest" policies it
        // equals a count of the number of messages lost, since the peering
        // continues.
        uint64_t overflows = 0;

        // When we last started a stats-tracking interval for this peering.
        double last_interval = 0;
    };

    // For per-peering tracking, map endpoint IDs to the above state.
    using EndpointMetricMap = std::unordered_map<broker::endpoint_id, Stats>;

    PeerBufferState(size_t a_buffer_size, double a_stats_reset_interval)
        : buffer_size(a_buffer_size), stats_reset_interval(a_stats_reset_interval) {
        stats_table =
            zeek::make_intrusive<zeek::TableVal>(zeek::id::find_type<zeek::TableType>("BrokerPeeringStatsTable"));
        stats_record_type = zeek::id::find_type<zeek::RecordType>("BrokerPeeringStats");
    }

    void SetEndpoint(const broker::endpoint* a_endpoint) { endpoint = a_endpoint; }

    // Update the peering's stats. This runs in Broker's execution context.
    // Broker does not expose send-buffer/queue state explicitly, so track
    // arrivals (a push, is_push == true) and departures (a pull, is_push ==
    // false) as they happen. Note that this must not touch Zeek-side Vals.
    void Observe(const broker::endpoint_id& peer, bool is_push) {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = stats_map.find(peer);

        if ( it == stats_map.end() ) {
            stats_map.emplace(peer, Stats());
            it = stats_map.find(peer);
        }

        auto& stats = it->second;

        // Stick to Broker's notion of time here.
        double now{0};
        if ( endpoint != nullptr )
            broker::convert(endpoint->now(), now);

        if ( now - stats.last_interval > stats_reset_interval ) {
            stats.last_interval = now;
            stats.max_queued_recently = stats.queued;
        }

        if ( stats.queued == 0 ) {
            // Watch for underflows. We could report somehow. Note that this
            // runs in the context of Broker's threads.
            assert(is_push);
        }

        if ( is_push && stats.queued == buffer_size )
            stats.overflows += 1;
        else {
            stats.queued += is_push ? 1 : -1;
            if ( stats.queued > stats.max_queued_recently )
                stats.max_queued_recently = stats.queued;
        }
    }

    // Updates the internal table[string] of BrokerPeeringStats and returns it.
    const zeek::TableValPtr& GetPeeringStatsTable() {
        std::lock_guard<std::mutex> lock(mutex);

        for ( auto it = stats_map.begin(); it != stats_map.end(); ) {
            auto& peer = it->first;
            auto& stats = it->second;

            if ( stats.peer_id == nullptr )
                stats.peer_id = PeerIdToStringVal(peer);

            // Broker told us the peer is gone, in RemovePeer() below. Remove it
            // now from both tables. We add/remove from stats_table only here,
            // not in Observer() and/or RemovePeer(), to ensure we only touch
            // the Zeek-side Table from Zeek's main thread.
            if ( stats.is_zombie ) {
                stats_table->Remove(*stats.peer_id);
                it = stats_map.erase(it);
                continue;
            }

            auto stats_v = stats_table->Find(stats.peer_id);

            if ( stats_v == nullptr ) {
                stats_v = zeek::make_intrusive<zeek::RecordVal>(stats_record_type);
                stats_table->Assign(stats.peer_id, stats_v);
            }

            // We may get here more than stats_reset_interval after the last
            // Observe(), in which case the max_queued_recently value is now
            // stale. Update if so.
            double now{0};
            if ( endpoint != nullptr )
                broker::convert(endpoint->now(), now);

            if ( now - stats.last_interval > stats_reset_interval ) {
                stats.last_interval = now;
                stats.max_queued_recently = stats.queued;
            }

            int n = 0;
            stats_v->AsRecordVal()->Assign(n++, zeek::val_mgr->Count(stats.queued));
            stats_v->AsRecordVal()->Assign(n++, zeek::val_mgr->Count(stats.max_queued_recently));
            stats_v->AsRecordVal()->Assign(n++, zeek::val_mgr->Count(stats.overflows));

            ++it;
        }

        return stats_table;
    }

    void RemovePeer(const broker::endpoint_id& peer) {
        std::lock_guard<std::mutex> lock(mutex);
        if ( auto it = stats_map.find(peer); it != stats_map.end() )
            it->second.is_zombie = true;
    }

private:
    zeek::StringValPtr PeerIdToStringVal(const broker::endpoint_id& peer) const {
        std::string peer_s;
        broker::convert(peer, peer_s);
        return zeek::make_intrusive<zeek::StringVal>(peer_s);
    }

    // The maximum number of messages queueable for transmission to a peer,
    // see Broker::peer_buffer_size and Broker::web_socket_buffer_size.
    size_t buffer_size;

    // Seconds after which we reset stats tracked per time window.
    double stats_reset_interval;

    EndpointMetricMap stats_map;
    zeek::TableValPtr stats_table;
    zeek::RecordTypePtr stats_record_type;

    mutable std::mutex mutex;
    const broker::endpoint* endpoint = nullptr;
};

using PeerBufferStatePtr = std::shared_ptr<PeerBufferState>;

class LoggerQueue {
public:
    void Push(broker::event_ptr event) {
        std::list<broker::event_ptr> tmp;
        tmp.emplace_back(std::move(event));
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.splice(queue_.end(), tmp);
            if ( queue_.size() == 1 ) {
                flare_.Fire();
            }
        }
    }

    auto Drain() {
        std::list<broker::event_ptr> events;
        std::lock_guard<std::mutex> lock(mutex_);
        if ( ! queue_.empty() ) {
            queue_.swap(events);
            flare_.Extinguish();
        }
        return events;
    }

    auto FlareFd() const noexcept { return flare_.FD(); }

private:
    std::mutex mutex_;
    zeek::detail::Flare flare_;
    std::list<broker::event_ptr> queue_;
};

using LoggerQueuePtr = std::shared_ptr<LoggerQueue>;

using BrokerSeverityLevel = broker::event::severity_level;

class Observer : public broker::event_observer {
public:
    using LogSeverityLevel = broker::event::severity_level;

    explicit Observer(LogSeverityLevel severity, LoggerQueuePtr queue, PeerBufferStatePtr pbstate)
        : severity_(severity), queue_(std::move(queue)), pbstate_(std::move(pbstate)) {}

    void on_peer_buffer_push(const broker::endpoint_id& peer, const broker::node_message&) override {
        pbstate_->Observe(peer, true);
    }

    void on_peer_buffer_pull(const broker::endpoint_id& peer, const broker::node_message&) override {
        pbstate_->Observe(peer, false);
    }

    void on_peer_disconnect(const broker::endpoint_id& peer, const broker::error&) override {
        pbstate_->RemovePeer(peer);
    }

    void observe(broker::event_ptr what) override { queue_->Push(std::move(what)); }

    bool accepts(LogSeverityLevel severity, broker::event::component_type) const override {
        return severity <= severity_;
    }

private:
    LogSeverityLevel severity_;
    LoggerQueuePtr queue_;
    PeerBufferStatePtr pbstate_;
};

} // namespace

namespace zeek::Broker {
static inline Val* get_option(const char* option) {
    const auto& id = zeek::detail::global_scope()->Find(option);

    if ( ! (id && id->GetVal()) )
        reporter->FatalError("Unknown Broker option %s", option);

    return id->GetVal().get();
}

template<class T>
static inline void set_option(const char* option, const T& value) {
    const auto& id = zeek::detail::global_scope()->Find(option);

    if ( ! id )
        reporter->FatalError("Unknown Broker option %s", option);

    if constexpr ( std::is_same_v<T, broker::port> ) {
        switch ( value.type() ) {
            case broker::port::protocol::tcp: id->SetVal(val_mgr->Port(value.number(), TRANSPORT_TCP)); break;
            case broker::port::protocol::udp: id->SetVal(val_mgr->Port(value.number(), TRANSPORT_UDP)); break;
            case broker::port::protocol::icmp: id->SetVal(val_mgr->Port(value.number(), TRANSPORT_ICMP)); break;
            default: id->SetVal(val_mgr->Port(value.number(), TRANSPORT_UNKNOWN));
        }
    }
    else if constexpr ( std::is_same_v<T, broker::timespan> ) {
        using std::chrono::duration_cast;
        auto ts = duration_cast<broker::fractional_seconds>(value);
        id->SetVal(make_intrusive<IntervalVal>(ts.count()));
    }
    else if constexpr ( std::is_same_v<T, std::vector<std::string>> ) {
        auto ptr = make_intrusive<VectorVal>(zeek::id::string_vec);
        for ( const auto& str : value )
            ptr->Append(make_intrusive<StringVal>(str));
        id->SetVal(std::move(ptr));
    }
    else {
        static_assert(std::is_same_v<T, std::string>);
        id->SetVal(make_intrusive<StringVal>(value));
    }
}

namespace {

struct opt_mapping {
    broker::configuration* cfg;
    std::string broker_name;
    const char* zeek_name;

    template<class T>
    auto broker_read() {
        return broker::get_as<T>(*cfg, broker_name);
    }

    template<class T>
    auto broker_write(T&& val) {
        cfg->set(broker_name, std::forward<T>(val));
    }

    auto zeek_read() { return get_option(zeek_name); }

    template<class T>
    auto zeek_write(const T& val) {
        set_option(zeek_name, val);
    }
};

} // namespace

class BrokerState {
public:
    using LogSeverityLevel = Observer::LogSeverityLevel;

    BrokerState(broker::configuration config, LoggerQueuePtr queue, PeerBufferStatePtr pbstate)
        : endpoint(std::move(config), telemetry_mgr->GetRegistry()),
          subscriber(endpoint.make_subscriber({broker::topic::statuses(), broker::topic::errors()})),
          loggerQueue(std::move(queue)),
          peerBufferState(std::move(pbstate)) {
        peerBufferState->SetEndpoint(&endpoint);
    }

    broker::endpoint endpoint;
    broker::subscriber subscriber;
    LoggerQueuePtr loggerQueue;
    PeerBufferStatePtr peerBufferState;
    LogSeverityLevel logSeverity = LogSeverityLevel::critical;
    LogSeverityLevel stderrSeverity = LogSeverityLevel::critical;
    std::unordered_set<broker::network_info> outbound_peerings;
};

const broker::endpoint_info Manager::NoPeer{{}, {}};

int Manager::script_scope = 0;

struct scoped_reporter_location {
    scoped_reporter_location(zeek::detail::Frame* frame) { reporter->PushLocation(frame->GetCallLocation()); }

    ~scoped_reporter_location() { reporter->PopLocation(); }
};

#ifdef DEBUG
namespace {

std::string RenderMessage(const broker::variant& d) { return util::json_escape_utf8(broker::to_string(d)); }

std::string RenderMessage(const broker::variant_list& d) { return util::json_escape_utf8(broker::to_string(d)); }

std::string RenderMessage(const broker::store::response& x) {
    return util::fmt("%s [id %" PRIu64 "]", (x.answer ? broker::to_string(*x.answer).c_str() : "<no answer>"), x.id);
}

std::string RenderMessage(const broker::status& s) { return broker::to_string(s.code()); }

std::string RenderMessage(const broker::error& e) {
    if ( auto ctx = e.context() )
        return util::fmt("%s (%s)", broker::to_string(e.code()).c_str(), to_string(*ctx).c_str());
    else
        return util::fmt("%s (null)", broker::to_string(e.code()).c_str());
}

std::string RenderMessage(const std::string& topic, const broker::variant& x) {
    return util::fmt("%s -> %s", RenderMessage(x).c_str(), topic.c_str());
}

template<class VariantOrList>
std::string RenderEvent(const std::string& topic, const std::string& name, const VariantOrList& args) {
    return util::fmt("%s(%s) -> %s", name.c_str(), RenderMessage(args).c_str(), topic.c_str());
}

} // namespace
#endif

Manager::Manager(bool arg_use_real_time) : Backend("Broker", nullptr, nullptr, nullptr), iosource::IOSource(true) {
    bound_port = 0;
    use_real_time = arg_use_real_time;
    peer_count = 0;
    hub_count = 0;
    log_batch_size = 0;
    log_topic_func = nullptr;
    log_id_type = nullptr;
    writer_id_type = nullptr;
}

void Manager::DoInitPostScript() {
    DBG_LOG(DBG_BROKER, "Initializing");

    log_batch_size = get_option("Broker::log_batch_size")->AsCount();
    default_log_topic_prefix = get_option("Broker::default_log_topic_prefix")->AsString()->CheckString();
    log_topic_func = get_option("Broker::log_topic")->AsFunc();
    log_id_type = id::find_type("Log::ID")->AsEnumType();
    writer_id_type = id::find_type("Log::Writer")->AsEnumType();
    zeek_table_manager = get_option("Broker::table_store_master")->AsBool();
    zeek_table_db_directory = get_option("Broker::table_store_db_directory")->AsString()->CheckString();

    // If Zeek's forwarding of network time to wallclock time was disabled,
    // assume that also Broker does not use realtime and instead receives
    // time via explicit AdvanceTime() calls.
    if ( ! get_option("allow_network_time_forward")->AsBool() )
        use_real_time = false;

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

    options.peer_buffer_size = get_option("Broker::peer_buffer_size")->AsCount();
    auto peer_overflow_policy = get_option("Broker::peer_overflow_policy")->AsString()->CheckString();
    if ( util::streq(peer_overflow_policy, "disconnect") ) {
        options.peer_overflow_policy = broker::overflow_policy::disconnect;
    }
    else if ( util::streq(peer_overflow_policy, "drop_oldest") ) {
        options.peer_overflow_policy = broker::overflow_policy::drop_oldest;
    }
    else if ( util::streq(peer_overflow_policy, "drop_newest") ) {
        options.peer_overflow_policy = broker::overflow_policy::drop_newest;
    }
    else {
        reporter->FatalError("Invalid Broker::peer_overflow_policy: %s", peer_overflow_policy);
    }

    options.web_socket_buffer_size = get_option("Broker::web_socket_buffer_size")->AsCount();
    auto web_socket_overflow_policy = get_option("Broker::web_socket_overflow_policy")->AsString()->CheckString();
    if ( util::streq(web_socket_overflow_policy, "disconnect") ) {
        options.web_socket_overflow_policy = broker::overflow_policy::disconnect;
    }
    else if ( util::streq(web_socket_overflow_policy, "drop_oldest") ) {
        options.web_socket_overflow_policy = broker::overflow_policy::drop_oldest;
    }
    else if ( util::streq(web_socket_overflow_policy, "drop_newest") ) {
        options.web_socket_overflow_policy = broker::overflow_policy::drop_newest;
    }
    else {
        reporter->FatalError("Invalid Broker::web_socket_overflow_policy: %s", web_socket_overflow_policy);
    }

    broker::configuration config{options};

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
               broker::timespan(static_cast<unsigned>(get_option("Broker::moderate_sleep")->AsInterval() * 1e9)));

    config.set("caf.work-stealing.relaxed-sleep-duration",
               broker::timespan(static_cast<unsigned>(get_option("Broker::relaxed_sleep")->AsInterval() * 1e9)));

    config.set("caf.work-stealing.aggressive-poll-attempts", get_option("Broker::aggressive_polls")->AsCount());
    config.set("caf.work-stealing.moderate-poll-attempts", get_option("Broker::moderate_polls")->AsCount());

    config.set("caf.work-stealing.aggressive-steal-interval", get_option("Broker::aggressive_interval")->AsCount());
    config.set("caf.work-stealing.moderate-steal-interval", get_option("Broker::moderate_interval")->AsCount());
    config.set("caf.work-stealing.relaxed-steal-interval", get_option("Broker::relaxed_interval")->AsCount());

    // Hook up the logger.
    auto checkLogSeverity = [](int level) {
        if ( level < 0 || level > static_cast<int>(BrokerSeverityLevel::debug) ) {
            reporter->FatalError("Invalid Broker::log_severity_level: %d", level);
        }
    };
    auto logSeverityVal = static_cast<int>(get_option("Broker::log_severity_level")->AsEnum());
    checkLogSeverity(logSeverityVal);
    auto stderrSeverityVal = static_cast<int>(get_option("Broker::log_stderr_severity_level")->AsEnum());
    checkLogSeverity(stderrSeverityVal);
    auto adapterVerbosity = static_cast<BrokerSeverityLevel>(std::max(logSeverityVal, stderrSeverityVal));
    auto queue = std::make_shared<LoggerQueue>();
    auto pbstate = std::make_shared<PeerBufferState>(get_option("Broker::peer_buffer_size")->AsCount(),
                                                     get_option("Broker::buffer_stats_reset_interval")->AsDouble());
    auto observer = std::make_shared<Observer>(adapterVerbosity, queue, pbstate);
    broker::logger(observer); // *must* be called before creating the BrokerState

    bstate = std::make_shared<BrokerState>(std::move(config), queue, pbstate);
    bstate->logSeverity = static_cast<BrokerSeverityLevel>(logSeverityVal);
    bstate->stderrSeverity = static_cast<BrokerSeverityLevel>(stderrSeverityVal);

    if ( ! iosource_mgr->RegisterFd(bstate->subscriber.fd(), this) )
        reporter->FatalError("Failed to register broker subscriber with iosource_mgr");

    if ( ! iosource_mgr->RegisterFd(queue->FlareFd(), this) )
        reporter->FatalError("Failed to register broker logger with iosource_mgr");

    bstate->subscriber.add_topic(broker::topic::store_events(), true);

    SetNodeId(broker::to_string(bstate->endpoint.node_id()));

    InitializeBrokerStoreForwarding();

    num_peers_metric =
        telemetry_mgr->GaugeInstance("zeek", "broker_peers", {}, "Current number of peers connected via broker", "",
                                     []() { return static_cast<double>(broker_mgr->peer_count); });

    num_stores_metric =
        telemetry_mgr->GaugeInstance("zeek", "broker_stores", {}, "Current number of stores connected via broker", "",
                                     []() { return static_cast<double>(broker_mgr->data_stores.size()); });

    num_pending_queries_metric =
        telemetry_mgr->GaugeInstance("zeek", "broker_pending_queries", {}, "Current number of pending broker queries",
                                     "", []() { return static_cast<double>(broker_mgr->pending_queries.size()); });

    num_events_incoming_metric = telemetry_mgr->CounterInstance("zeek", "broker_incoming_events", {},
                                                                "Total number of incoming events via broker");
    num_events_outgoing_metric = telemetry_mgr->CounterInstance("zeek", "broker_outgoing_events", {},
                                                                "Total number of outgoing events via broker");
    num_logs_incoming_metric =
        telemetry_mgr->CounterInstance("zeek", "broker_incoming_logs", {}, "Total number of incoming logs via broker");
    num_logs_outgoing_metric =
        telemetry_mgr->CounterInstance("zeek", "broker_outgoing_logs", {}, "Total number of outgoing logs via broker");
    num_ids_incoming_metric =
        telemetry_mgr->CounterInstance("zeek", "broker_incoming_ids", {}, "Total number of incoming ids via broker");
    num_ids_outgoing_metric =
        telemetry_mgr->CounterInstance("zeek", "broker_outgoing_ids", {}, "Total number of outgoing ids via broker");
}

void Manager::InitializeBrokerStoreForwarding() {
    const auto& globals = zeek::detail::global_scope()->Vars();

    for ( const auto& global : globals ) {
        auto& id = global.second;
        if ( id->HasVal() && id->GetAttr(zeek::detail::ATTR_BACKEND) ) {
            const auto& attr = id->GetAttr(zeek::detail::ATTR_BACKEND);
            auto e = static_cast<BifEnum::Broker::BackendType>(attr->GetExpr()->Eval(nullptr)->AsEnum());
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

            switch ( backend ) {
                case broker::backend::sqlite: suffix = ".sqlite"; break;
                default: break;
            }

            auto path = zeek_table_db_directory + "/" + storename + suffix;

            MakeMaster(storename, backend, broker::backend_options{{"path", path}});
        }
    }
}

void Manager::DoTerminate() {
    FlushLogBuffers();

    iosource_mgr->UnregisterFd(bstate->subscriber.fd(), this);

    iosource_mgr->UnregisterFd(bstate->loggerQueue->FlareFd(), this);

    vector<string> stores_to_close;
    stores_to_close.reserve(data_stores.size());

    for ( auto& x : data_stores )
        stores_to_close.push_back(x.first);

    for ( auto& x : stores_to_close )
        // This doesn't loop directly over data_stores, because CloseStore
        // modifies the map and invalidates iterators.
        CloseStore(x);

    ProcessLogEvents();

    FlushLogBuffers();
}

bool Manager::Active() {
    if ( bstate->endpoint.is_shutdown() )
        return false;

    if ( bound_port > 0 )
        return true;

    return peer_count > 0 || hub_count > 0;
}

void Manager::AdvanceTime(double seconds_since_unix_epoch) {
    if ( bstate->endpoint.is_shutdown() )
        return;

    if ( bstate->endpoint.use_real_time() )
        return;

    auto secs = std::chrono::duration<double>(seconds_since_unix_epoch);
    auto span = std::chrono::duration_cast<broker::timespan>(secs);
    broker::timestamp next_time{span};
    bstate->endpoint.advance_time(next_time);
}

void Manager::FlushPendingQueries() {
    while ( ! pending_queries.empty() ) {
        // possibly an infinite loop if a query can recursively
        // generate more queries...
        for ( auto& s : data_stores ) {
            while ( ! s.second->proxy.mailbox().empty() ) {
                auto response = s.second->proxy.receive();
                ProcessStoreResponse(s.second, std::move(response));
            }
        }
    }
}

void Manager::ClearStores() {
    FlushPendingQueries();

    for ( const auto& [name, handle] : data_stores )
        handle->store.clear();
}

uint16_t Manager::Listen(const string& addr, uint16_t port, BrokerProtocol type) {
    if ( bstate->endpoint.is_shutdown() )
        return 0;

    switch ( type ) {
        case BrokerProtocol::Native: bound_port = bstate->endpoint.listen(addr, port); break;

        case BrokerProtocol::WebSocket: bound_port = bstate->endpoint.web_socket_listen(addr, port); break;
    }

    if ( bound_port == 0 )
        Error("Failed to listen on %s:%" PRIu16, addr.empty() ? "INADDR_ANY" : addr.c_str(), port);

    // Register as a "does-count" source now.
    iosource_mgr->Register(this, false);

    DBG_LOG(DBG_BROKER, "Listening on %s:%" PRIu16, addr.empty() ? "INADDR_ANY" : addr.c_str(), port);

    return bound_port;
}

void Manager::Peer(const string& addr, uint16_t port, double retry) {
    if ( bstate->endpoint.is_shutdown() )
        return;

    DBG_LOG(DBG_BROKER, "Starting to peer with %s:%" PRIu16 " (retry: %fs)", addr.c_str(), port, retry);

    auto e = getenv("ZEEK_DEFAULT_CONNECT_RETRY");

    if ( e )
        retry = atoi(e);

    if ( retry > 0.0 && retry < 1.0 )
        // Ensure that it doesn't get turned into zero.
        retry = 1.0;

    auto secs = broker::timeout::seconds(static_cast<uint64_t>(retry));
    bstate->endpoint.peer_nosync(addr, port, secs);
    bstate->outbound_peerings.emplace(addr, port);

    auto counts_as_iosource = get_option("Broker::peer_counts_as_iosource")->AsBool();

    if ( counts_as_iosource )
        // Register as a "does-count" source now.
        iosource_mgr->Register(this, false);
}

void Manager::PeerNoRetry(const string& addr, uint16_t port) {
    if ( bstate->endpoint.is_shutdown() )
        return;

    DBG_LOG(DBG_BROKER, "Starting to peer with %s:%" PRIu16 " (no retry)", addr.c_str(), port);

    bstate->endpoint.peer_nosync(addr, port, broker::timeout::seconds{0});

    auto counts_as_iosource = get_option("Broker::peer_counts_as_iosource")->AsBool();

    if ( counts_as_iosource )
        // Register as a "does-count" source now.
        iosource_mgr->Register(this, false);
}

void Manager::Unpeer(const string& addr, uint16_t port) {
    if ( bstate->endpoint.is_shutdown() )
        return;

    DBG_LOG(DBG_BROKER, "Stopping to peer with %s:%" PRIu16, addr.c_str(), port);

    FlushLogBuffers();
    bstate->endpoint.unpeer_nosync(addr, port);
    bstate->outbound_peerings.erase(broker::network_info(addr, port));
}

bool Manager::IsOutboundPeering(const string& addr, uint16_t port) const {
    return bstate->outbound_peerings.find(broker::network_info(addr, port)) != bstate->outbound_peerings.end();
}

bool Manager::IsOutboundPeering(const broker::network_info& ni) const {
    return bstate->outbound_peerings.find(ni) != bstate->outbound_peerings.end();
}

std::vector<broker::peer_info> Manager::Peers() const {
    if ( bstate->endpoint.is_shutdown() )
        return {};

    return bstate->endpoint.peers();
}

bool Manager::DoPublishEvent(const std::string& topic, cluster::Event& event) {
    bool do_publish = PLUGIN_HOOK_WITH_RESULT(HOOK_PUBLISH_EVENT, HookPublishEvent(*this, topic, event), true);
    if ( ! do_publish )
        return true;

    auto maybe_ev = zeek::cluster::detail::to_broker_event(event);
    if ( ! maybe_ev )
        return false;

    auto& ev = maybe_ev.value();

    size_t size = ev.as_data().shared_envelope()->raw_bytes().second;
    Telemetry().OnOutgoingEvent(topic, event.HandlerName(), cluster::detail::SerializationInfo{size});

    DBG_LOG(DBG_BROKER, "Publishing event: %s", RenderEvent(topic, std::string(ev.name()), ev.args()).c_str());
    bstate->endpoint.publish(topic, ev.move_data());
    num_events_outgoing_metric->Inc();
    return true;
}

bool Manager::PublishEvent(string topic, std::string name, broker::vector args, double ts) {
    if ( bstate->endpoint.is_shutdown() )
        return true;

    if ( peer_count == 0 && hub_count == 0 )
        return true;

    broker::vector meta;
    if ( BifConst::EventMetadata::add_network_timestamp ) {
        broker::vector entry{static_cast<broker::count>(zeek::detail::MetadataType::NetworkTimestamp),
                             broker::to_timestamp(ts)};
        meta.emplace_back(std::move(entry));
    }

    broker::zeek::Event ev(name, args, meta);

    size_t size = ev.as_data().shared_envelope()->raw_bytes().second;
    Telemetry().OnOutgoingEvent(topic, name, cluster::detail::SerializationInfo{size});

    DBG_LOG(DBG_BROKER, "Publishing event: %s", RenderEvent(topic, std::string(ev.name()), ev.args()).c_str());
    bstate->endpoint.publish(std::move(topic), ev.move_data());
    num_events_outgoing_metric->Inc();
    return true;
}

bool Manager::PublishEvent(string topic, RecordVal* args) {
    if ( bstate->endpoint.is_shutdown() )
        return true;

    if ( peer_count == 0 && hub_count == 0 )
        return true;

    if ( ! args->HasField(0) )
        return false;

    auto event_name = args->GetFieldAs<StringVal>(0)->CheckString();
    auto vv = args->GetFieldAs<VectorVal>(1);
    broker::vector xs;
    xs.reserve(vv->Size());

    for ( auto i = 0u; i < vv->Size(); ++i ) {
        const auto& val = vv->RecordValAt(i)->GetField(0);
        auto data_val = static_cast<detail::DataVal*>(val.get());
        xs.emplace_back(data_val->data);
    }

    // At this point we come from script-land. This means that publishing of the event was
    // explicitly triggered. Hence, the timestamp is set to the current event's time. This
    // also means that timestamping cannot be manipulated from script-land for now.
    auto ts = event_mgr.CurrentEventTime();
    return PublishEvent(std::move(topic), event_name, std::move(xs), ts);
}

bool Manager::PublishIdentifier(std::string topic, std::string id) {
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

    auto data = BrokerData{};

    if ( ! data.Convert(val) ) {
        Error("Failed to publish ID with unsupported type: %s (%s)", id.c_str(), type_name(val->GetType()->Tag()));
        return false;
    }

    broker::zeek::IdentifierUpdate msg(std::move(id), data.value_);
    DBG_LOG(DBG_BROKER, "Publishing id-update: %s", RenderMessage(topic, msg.as_data()).c_str());
    bstate->endpoint.publish(std::move(topic), msg.move_data());
    num_ids_outgoing_metric->Inc();
    return true;
}

bool Manager::PublishLogCreate(EnumVal* stream, EnumVal* writer, const logging::WriterBackend::WriterInfo& info,
                               int num_fields, const threading::Field* const* fields,
                               const broker::endpoint_info& peer) {
    if ( bstate->endpoint.is_shutdown() )
        return true;

    if ( peer_count == 0 )
        return true;

    auto stream_id = stream->GetType()->AsEnumType()->Lookup(stream->AsEnum());

    if ( ! stream_id ) {
        reporter->Error("Failed to remotely log: stream %" PRId64 " doesn't have name", stream->AsEnum());
        return false;
    }

    auto writer_id = writer->GetType()->AsEnumType()->Lookup(writer->AsEnum());

    if ( ! writer_id ) {
        reporter->Error("Failed to remotely log: writer %" PRId64 " doesn't have name", writer->AsEnum());
        return false;
    }

    auto writer_info = info.ToBroker();

    broker::vector fields_data;
    fields_data.reserve(num_fields);

    for ( auto i = 0; i < num_fields; ++i ) {
        auto field_data = detail::threading_field_to_data(fields[i]);
        fields_data.push_back(std::move(field_data));
    }

    std::string topic = default_log_topic_prefix + stream_id;
    auto bstream_id = broker::enum_value(stream_id);
    auto bwriter_id = broker::enum_value(writer_id);
    broker::zeek::LogCreate msg(bstream_id, bwriter_id, writer_info, fields_data);

    DBG_LOG(DBG_BROKER, "Publishing log creation: %s", RenderMessage(topic, msg.as_data()).c_str());

    if ( peer.node != NoPeer.node )
        // Direct message.
        bstate->endpoint.publish(peer, std::move(topic), msg.move_data());
    else
        // Broadcast.
        bstate->endpoint.publish(std::move(topic), msg.move_data());

    return true;
}

bool Manager::PublishLogWrite(EnumVal* stream, EnumVal* writer, const string& path,
                              const logging::detail::LogRecord& rec) {
    if ( bstate->endpoint.is_shutdown() )
        return true;

    if ( peer_count == 0 )
        return true;

    auto stream_id_num = stream->AsEnum();
    auto stream_id = stream->GetType()->AsEnumType()->Lookup(stream_id_num);

    if ( ! stream_id ) {
        reporter->Error("Failed to remotely log: stream %" PRId64 " doesn't have name", stream->AsEnum());
        return false;
    }

    auto writer_id = writer->GetType()->AsEnumType()->Lookup(writer->AsEnum());

    if ( ! writer_id ) {
        reporter->Error("Failed to remotely log: writer %" PRId64 " doesn't have name", writer->AsEnum());
        return false;
    }

    zeek::detail::BinarySerializationFormat fmt;
    char* data;
    int len;

    fmt.StartWrite();

    // Cast to int for binary compatibility.
    bool success = fmt.Write(static_cast<int>(rec.size()), "num_fields");

    if ( ! success ) {
        reporter->Error("Failed to remotely log stream %s: num_fields serialization failed", stream_id);
        return false;
    }

    for ( size_t i = 0; i < rec.size(); ++i ) {
        if ( ! rec[i].Write(&fmt) ) {
            reporter->Error("Failed to remotely log stream %s: field %zu serialization failed", stream_id, i);
            return false;
        }
    }

    len = fmt.EndWrite(&data);
    std::string serial_data(data, len);
    free(data);

    auto v = log_topic_func->Invoke(IntrusivePtr{NewRef{}, stream}, make_intrusive<StringVal>(path));

    if ( ! v ) {
        reporter->Error(
            "Failed to remotely log: log_topic func did not return"
            " a value for stream %s at path %s",
            stream_id, std::string{path}.c_str());
        return false;
    }

    std::string topic = v->AsString()->CheckString();

    auto bstream_id = broker::enum_value(stream_id);
    auto bwriter_id = broker::enum_value(writer_id);
    broker::zeek::LogWrite msg(bstream_id, bwriter_id, std::move(path), std::move(serial_data));

    DBG_LOG(DBG_BROKER, "Buffering log record: %s", RenderMessage(topic, msg.as_data()).c_str());

    if ( log_buffers.size() <= (unsigned int)stream_id_num )
        log_buffers.resize(stream_id_num + 1);

    auto& lb = log_buffers[stream_id_num];
    ++lb.message_count;
    lb.msgs[topic].add(std::move(msg));

    if ( lb.message_count >= log_batch_size ) {
        auto outgoing_logs = static_cast<double>(lb.Flush(bstate->endpoint, log_batch_size));
        num_logs_outgoing_metric->Inc(outgoing_logs);
    }

    return true;
}

size_t Manager::LogBuffer::Flush(broker::endpoint& endpoint, size_t log_batch_size) {
    if ( endpoint.is_shutdown() )
        return 0;

    if ( ! message_count )
        // No logs buffered for this stream.
        return 0;

    for ( auto& [topic, pending_batch] : msgs ) {
        if ( ! pending_batch.empty() )
            endpoint.publish(topic, pending_batch.build());
    }

    auto rval = message_count;
    message_count = 0;
    return rval;
}

size_t Manager::FlushLogBuffers() {
    DBG_LOG(DBG_BROKER, "Flushing all log buffers");
    auto rval = 0u;

    for ( auto& lb : log_buffers )
        rval += lb.Flush(bstate->endpoint, log_batch_size);

    num_logs_outgoing_metric->Inc(rval);

    return rval;
}

void Manager::Error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    auto msg = util::vfmt(format, args);
    va_end(args);

    if ( script_scope )
        emit_builtin_error(msg);
    else
        reporter->Error("%s", msg);
}

zeek::RecordValPtr Manager::MakeEvent(ArgsSpan args, zeek::detail::Frame* frame) {
    scoped_reporter_location srl{frame};
    auto rval = zeek::make_intrusive<RecordVal>(BifType::Record::Broker::Event);
    auto arg_vec = make_intrusive<VectorVal>(vector_of_data_type);
    rval->Assign(1, arg_vec);
    const Func* func = nullptr;

    for ( size_t index = 0; index < args.size(); index++ ) {
        const auto& arg_val = args[index];
        if ( index == 0 ) {
            // Event val must come first.

            if ( arg_val->GetType()->Tag() != TYPE_FUNC ) {
                Error("attempt to convert non-event into an event type (%s)",
                      zeek::obj_desc_short(arg_val.get()).c_str());
                return rval;
            }

            func = arg_val->AsFunc();

            if ( func->Flavor() != FUNC_FLAVOR_EVENT ) {
                Error("attempt to convert non-event into an event type");
                return rval;
            }

            auto num_args = static_cast<size_t>(func->GetType()->Params()->NumFields());

            if ( num_args != args.size() - 1 ) {
                Error("bad # of arguments: got %zu, expect %zu", args.size() - 1, num_args);
                return rval;
            }

            rval->Assign(0, func->GetName());
            continue;
        }

        auto got_type = arg_val->GetType();
        const auto& expected_type = func->GetType()->ParamList()->GetTypes()[index - 1];

        // If called with an unspecified table or set, adopt the expected type.
        if ( got_type->Tag() == TYPE_TABLE && got_type->AsTableType()->IsUnspecifiedTable() )
            if ( expected_type->Tag() == TYPE_TABLE && got_type->IsSet() == expected_type->IsSet() )
                got_type = expected_type;

        if ( ! same_type(got_type, expected_type) ) {
            rval->Remove(0);
            Error("event parameter #%zu type mismatch, got %s, expect %s", index,
                  obj_desc_short(got_type.get()).c_str(), obj_desc_short(expected_type.get()).c_str());
            return rval;
        }

        RecordValPtr data_val;

        if ( same_type(got_type, detail::DataVal::ScriptDataType()) )
            data_val = {NewRef{}, arg_val->AsRecordVal()};
        else
            data_val = BrokerData::ToRecordVal(arg_val);

        if ( ! data_val->HasField(0) ) {
            rval->Remove(0);
            Error("failed to convert param #%zu of type %s to broker data", index, type_name(got_type->Tag()));
            return rval;
        }

        arg_vec->Assign(index - 1, std::move(data_val));
    }

    return rval;
}

bool Manager::DoSubscribe(const string& topic_prefix, SubscribeCallback cb) {
    DBG_LOG(DBG_BROKER, "Subscribing to topic prefix %s", topic_prefix.c_str());
    bstate->subscriber.add_topic(topic_prefix, ! run_state::detail::zeek_init_done);

    if ( cb )
        cb(topic_prefix, {CallbackStatus::NotImplemented});

    return true;
}

bool Manager::Forward(string topic_prefix) {
    for ( const auto& prefix : forwarded_prefixes )
        if ( prefix == topic_prefix )
            return false;

    DBG_LOG(DBG_BROKER, "Forwarding topic prefix %s", topic_prefix.c_str());
    Subscribe(topic_prefix);
    forwarded_prefixes.emplace_back(std::move(topic_prefix));
    return true;
}

bool Manager::DoUnsubscribe(const string& topic_prefix) {
    for ( size_t i = 0; i < forwarded_prefixes.size(); ++i )
        if ( forwarded_prefixes[i] == topic_prefix ) {
            DBG_LOG(DBG_BROKER, "Unforwarding topic prefix %s", topic_prefix.c_str());
            forwarded_prefixes.erase(forwarded_prefixes.begin() + i);
            break;
        }

    DBG_LOG(DBG_BROKER, "Unsubscribing from topic prefix %s", topic_prefix.c_str());
    bstate->subscriber.remove_topic(topic_prefix, ! run_state::detail::zeek_init_done);
    return true;
}

void Manager::ProcessMessages() {
    auto messages = bstate->subscriber.poll();

    for ( auto& message : messages ) {
        auto&& topic = broker::get_topic(message);

        if ( broker::is_prefix(topic, broker::topic::statuses_str) ) {
            if ( auto stat = broker::to<broker::status>(get_data(message)) ) {
                ProcessStatus(*stat);
            }
            else {
                auto str = to_string(message);
                reporter->Warning("ignoring malformed Broker status event: %s", str.c_str());
            }
            continue;
        }

        if ( broker::is_prefix(topic, broker::topic::errors_str) ) {
            if ( auto err = broker::to<broker::error>(get_data(message)) ) {
                ProcessError(*err);
            }
            else {
                auto str = to_string(message);
                reporter->Warning("ignoring malformed Broker error event: %s", str.c_str());
            }
            continue;
        }

        if ( broker::is_prefix(topic, broker::topic::store_events_str) ) {
            ProcessStoreEvent(broker::get_data(message).to_data());
            continue;
        }

        try {
            // Once we call a broker::move_* function, we force Broker to
            // unshare the content of the message, i.e., copy the content to a
            // different memory region if other threads keep references to the
            // message. Since `topic` still points into the original memory
            // region, we may no longer access it after this point.
            auto topic_str = broker::get_topic_str(message);
            broker::zeek::visit_as_message([this, topic_str](auto& msg) { ProcessMessage(topic_str, msg); }, message);
        } catch ( std::runtime_error& e ) {
            reporter->Warning("ignoring invalid Broker message: %s", +e.what());
            continue;
        }
    }
}

namespace {

// Note: copied from Stmt.cc, might be worth to move to a common place.
EnumValPtr lookup_enum_val(const char* module_name, const char* name) {
    const auto& id = zeek::detail::lookup_ID(name, module_name);
    assert(id);
    assert(id->IsEnumConst());

    EnumType* et = id->GetType()->AsEnumType();

    int index = et->Lookup(module_name, name);
    assert(index >= 0);

    return et->GetEnumVal(index);
}

} // namespace

void Manager::ProcessLogEvents() {
    static auto ev_critical = lookup_enum_val("Broker", "LOG_CRITICAL");
    static auto ev_error = lookup_enum_val("Broker", "LOG_ERROR");
    static auto ev_warning = lookup_enum_val("Broker", "LOG_WARNING");
    static auto ev_info = lookup_enum_val("Broker", "LOG_INFO");
    static auto ev_verbose = lookup_enum_val("Broker", "LOG_VERBOSE");
    static auto ev_debug = lookup_enum_val("Broker", "LOG_DEBUG");

    auto evType = [](BrokerSeverityLevel lvl) {
        switch ( lvl ) {
            case BrokerSeverityLevel::critical: return ev_critical;
            case BrokerSeverityLevel::error: return ev_error;
            case BrokerSeverityLevel::warning: return ev_warning;
            case BrokerSeverityLevel::info: return ev_info;
            case BrokerSeverityLevel::verbose: return ev_verbose;
            default: return ev_debug;
        }
    };

    constexpr const char* severity_names_tbl[] = {"critical", "error", "warning", "info", "verbose", "debug"};

    auto events = bstate->loggerQueue->Drain();
    for ( auto& event : events ) {
        auto severity = event->severity;
        if ( bstate->logSeverity >= severity ) {
            auto args = Args{};
            args.reserve(3);
            args.emplace_back(evType(severity));
            args.emplace_back(make_intrusive<StringVal>(event->identifier));
            args.emplace_back(make_intrusive<StringVal>(event->description));
            event_mgr.Enqueue(::Broker::internal_log_event, std::move(args));
        }
        if ( bstate->stderrSeverity >= severity ) {
            // Formatting the event->identifier string_view using "%.*s" - the explicit
            // precision ".*" allows specifying the length of the following char* argument
            // as string_views in general are not guaranteed to be null terminated.
            fprintf(stderr, "[BROKER/%s] %.*s: %s\n", severity_names_tbl[static_cast<int>(severity)],
                    static_cast<int>(event->identifier.size()), event->identifier.data(), event->description.c_str());
        }
    }
}

void Manager::ProcessDataStore(detail::StoreHandleVal* store) {
    auto num_available = store->proxy.mailbox().size();

    if ( num_available > 0 ) {
        auto responses = store->proxy.receive(num_available);

        for ( auto& r : responses )
            ProcessStoreResponse(store, std::move(r));
    }
}

void Manager::ProcessDataStores() {
    for ( auto& kvp : data_stores ) {
        ProcessDataStore(kvp.second);
    }
}

void Manager::ProcessFd(int fd, int flags) {
    if ( fd == bstate->subscriber.fd() ) {
        ProcessMessages();
    }
    else if ( fd == bstate->loggerQueue->FlareFd() ) {
        ProcessLogEvents();
    }
    else {
        for ( auto& kvp : data_stores ) {
            if ( fd == kvp.second->proxy.mailbox().descriptor() ) {
                ProcessDataStore(kvp.second);
                return;
            }
        }
    }
}

void Manager::Process() {
    ProcessMessages();
    ProcessLogEvents();
    ProcessDataStores();
}

void Manager::ProcessStoreEventInsertUpdate(const TableValPtr& table, const std::string& store_id,
                                            const broker::data& key, const broker::data& data,
                                            const broker::data& old_value, bool insert) {
    auto type = "Insert";
    if ( ! insert )
        type = "Update";

    if ( insert ) {
        DBG_LOG(DBG_BROKER, "Store %s: Insert: %s:%s (%s:%s)", store_id.c_str(), to_string(key).c_str(),
                to_string(data).c_str(), key.get_type_name(), data.get_type_name());
    }
    else {
        DBG_LOG(DBG_BROKER, "Store %s: Update: %s->%s (%s)", store_id.c_str(), to_string(old_value).c_str(),
                to_string(data).c_str(), data.get_type_name());
    }

    if ( table->GetType()->IsSet() && data.get_type() != broker::data::type::none ) {
        reporter->Error("ProcessStoreEvent %s got %s when expecting set", type, data.get_type_name());
        return;
    }

    const auto& its = table->GetType()->AsTableType()->GetIndexTypes();
    ValPtr zeek_key;
    auto key_copy = key;
    if ( its.size() == 1 )
        zeek_key = detail::data_to_val(key_copy, its[0].get());
    else
        zeek_key = detail::data_to_val(key_copy, table->GetType()->AsTableType()->GetIndices().get());

    if ( ! zeek_key ) {
        reporter->Error(
            "ProcessStoreEvent %s: could not convert key \"%s\" for store \"%s\" while receiving "
            "remote data. This probably means the tables have different types on different nodes.",
            type, to_string(key).c_str(), store_id.c_str());
        return;
    }

    if ( table->GetType()->IsSet() ) {
        table->Assign(zeek_key, nullptr, false);
        return;
    }

    // it is a table
    auto data_copy = data;
    auto zeek_value = detail::data_to_val(data_copy, table->GetType()->Yield().get());
    if ( ! zeek_value ) {
        reporter->Error(
            "ProcessStoreEvent %s: could not convert value \"%s\" for key \"%s\" in "
            "store \"%s\" while receiving remote data. This probably means the tables "
            "have different types on different nodes.",
            type, to_string(data).c_str(), to_string(key).c_str(), store_id.c_str());
        return;
    }

    table->Assign(zeek_key, zeek_value, false);
}

void Manager::ProcessStoreEvent(broker::data msg) {
    if ( auto insert = broker::store_event::insert::make(msg) ) {
        auto storehandle = broker_mgr->LookupStore(insert.store_id());
        if ( ! storehandle )
            return;

        const auto& table = storehandle->forward_to;
        if ( ! table )
            return;

        // We sent this message. Ignore it.
        if ( insert.publisher() == storehandle->store_pid )
            return;

        ProcessStoreEventInsertUpdate(table, insert.store_id(), insert.key(), insert.value(), {}, true);
    }
    else if ( auto update = broker::store_event::update::make(msg) ) {
        auto storehandle = broker_mgr->LookupStore(update.store_id());
        if ( ! storehandle )
            return;

        const auto& table = storehandle->forward_to;
        if ( ! table )
            return;

        // We sent this message. Ignore it.
        if ( update.publisher() == storehandle->store_pid )
            return;

        ProcessStoreEventInsertUpdate(table, update.store_id(), update.key(), update.new_value(), update.old_value(),
                                      false);
    }
    else if ( auto erase = broker::store_event::erase::make(msg) ) {
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
        DBG_LOG(DBG_BROKER, "Store %s: Erase key %s", erase.store_id().c_str(), to_string(key).c_str());

        const auto& its = table->GetType()->AsTableType()->GetIndexTypes();
        ValPtr zeek_key;
        if ( its.size() == 1 )
            zeek_key = detail::data_to_val(key, its[0].get());
        else
            zeek_key = detail::data_to_val(key, table->GetType()->AsTableType()->GetIndices().get());

        if ( ! zeek_key ) {
            reporter->Error(
                "ProcessStoreEvent: could not convert key \"%s\" for store \"%s\" "
                "while receiving remote erase. This probably means the tables have "
                "different types on different nodes.",
                to_string(key).c_str(), insert.store_id().c_str());
            return;
        }

        table->Remove(*zeek_key, false);
    }
    else if ( auto expire = broker::store_event::expire::make(msg) ) {
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
    else {
        reporter->Error("ProcessStoreEvent: Unhandled event type");
    }
}

void Manager::ProcessMessage(std::string_view topic, broker::zeek::Invalid& ev) {
    reporter->Warning("received invalid broker message: %s", broker::to_string(ev).c_str());
}

void Manager::ProcessMessage(std::string_view topic, broker::zeek::Batch& ev) {
    ev.for_each([this, topic](auto& inner) { ProcessMessage(topic, inner); });
}

void Manager::ProcessMessage(std::string_view topic, broker::zeek::Event& ev) {
    if ( ! ev.valid() ) {
        reporter->Warning("received invalid broker Event: %s", broker::to_string(ev.as_data()).c_str());
        return;
    }

    auto&& name = ev.name();
    auto&& args = ev.args();
    auto meta = cluster::detail::metadata_vector_from_broker_event(ev);

    DBG_LOG(DBG_BROKER, "Process event: %s (with %zu metadata entries) %s", std::string{name}.c_str(),
            meta ? meta->size() : 0, RenderMessage(args).c_str());
    num_events_incoming_metric->Inc();
    size_t size = ev.as_data().shared_envelope()->raw_bytes().second;
    Telemetry().OnIncomingEvent(topic, name, cluster::detail::SerializationInfo{size});
    auto handler = event_registry->Lookup(name);

    if ( ! handler )
        return;

    for ( const auto& p : forwarded_prefixes ) {
        if ( p.size() > topic.size() )
            continue;

        if ( strncmp(p.data(), topic.data(), p.size()) != 0 ) // NOLINT(bugprone-suspicious-stringview-data-usage)
            continue;

        DBG_LOG(DBG_BROKER, "Skip processing of forwarded event: %s %s", std::string{name}.c_str(),
                RenderMessage(args).c_str());
        return;
    }

    const auto& arg_types = handler->GetType(false)->ParamList()->GetTypes();

    if ( arg_types.size() != args.size() ) {
        reporter->Warning(
            "got event message '%s' with invalid # of args,"
            " got %zd, expected %zu",
            std::string{name}.c_str(), args.size(), arg_types.size());
        return;
    }

    Args vl;
    vl.reserve(args.size());

    for ( size_t i = 0; i < args.size(); ++i ) {
        auto got_type = args[i].get_type_name();
        const auto& expected_type = arg_types[i];
        auto arg = args[i].to_data();
        auto val = detail::data_to_val(arg, expected_type.get());

        if ( val )
            vl.emplace_back(std::move(val));
        else {
            auto expected_name = type_name(expected_type->Tag());
            std::string msg_addl = util::fmt("got %s, expected %s", got_type, expected_name);

            if ( strcmp(expected_name, "record") == 0 && strcmp("vector", got_type) == 0 ) {
                // This means the vector elements didn't align with the record
                // fields. Produce an error message that shows what we
                // received.
                std::string elements;
                for ( auto&& e : broker_vector_from(args[i]) ) {
                    if ( ! elements.empty() )
                        elements += ", ";

                    elements += e.get_type_name();
                }

                msg_addl = util::fmt("got mismatching field types [%s] for record type '%s'", elements.c_str(),
                                     expected_type->GetName().c_str());
            }

            reporter->Warning("failed to convert remote event '%s' arg #%zu, %s", std::string{name}.c_str(), i + 1,
                              msg_addl.c_str());

            // If we got a vector and expected a function this is
            // possibly because of a mismatch between
            // anonymous-function bodies.
            if ( strcmp(expected_name, "func") == 0 && strcmp("vector", got_type) == 0 )
                reporter->Warning(
                    "when sending functions the receiver must have access to a"
                    " version of that function.\nFor anonymous functions, that "
                    "function must have the same body.");

            break;
        }
    }

    if ( vl.size() == args.size() )
        event_mgr.Enqueue(std::move(meta), handler, std::move(vl), util::detail::SOURCE_BROKER);
}

bool Manager::ProcessMessage(std::string_view, broker::zeek::LogCreate& lc) {
    DBG_LOG(DBG_BROKER, "Received log-create: %s", RenderMessage(lc.as_data()).c_str());
    if ( ! lc.valid() ) {
        reporter->Warning("received invalid broker LogCreate: %s", broker::to_string(lc.as_data()).c_str());
        return false;
    }

    auto wrapped_stream_id = broker::data{lc.stream_id()};
    auto stream_id = detail::data_to_val(wrapped_stream_id, log_id_type);
    if ( ! stream_id ) {
        reporter->Warning("failed to unpack remote log stream id");
        return false;
    }

    auto wrapped_writer_id = broker::data{lc.writer_id()};
    auto writer_id = detail::data_to_val(wrapped_writer_id, writer_id_type);
    if ( ! writer_id ) {
        reporter->Warning("failed to unpack remote log writer id");
        return false;
    }

    auto writer_info = std::make_unique<logging::WriterBackend::WriterInfo>();
    if ( ! writer_info->FromBroker(lc.writer_info().to_data()) ) {
        reporter->Warning("failed to unpack remote log writer info");
        return false;
    }

    // Get log fields.
    if ( ! lc.fields_data().is_list() ) {
        reporter->Warning("failed to unpack remote log fields");
        return false;
    }
    auto&& fields_data = broker_vector_from(lc.fields_data());

    auto num_fields = fields_data.size();
    auto fields = new threading::Field*[num_fields];

    for ( size_t i = 0; i < num_fields; ++i ) {
        if ( auto field = detail::data_to_threading_field(fields_data[i]) )
            fields[i] = field;
        else {
            reporter->Warning("failed to convert remote log field #%zu: %s", i,
                              broker::to_string(fields_data[i]).c_str());
            delete[] fields;
            return false;
        }
    }

    if ( ! log_mgr->CreateWriterForRemoteLog(stream_id->AsEnumVal(), writer_id->AsEnumVal(), writer_info.release(),
                                             num_fields, fields) ) {
        ODesc d;
        stream_id->Describe(&d);
        reporter->Warning("failed to create remote log stream for %s locally", d.Description());
    }

    return true;
}

bool Manager::ProcessMessage(std::string_view, broker::zeek::LogWrite& lw) {
    DBG_LOG(DBG_BROKER, "Received log-write: %s", RenderMessage(lw.as_data()).c_str());

    if ( ! lw.valid() ) {
        reporter->Warning("received invalid broker LogWrite: %s", broker::to_string(lw.as_data()).c_str());
        return false;
    }

    num_logs_incoming_metric->Inc();
    auto&& stream_id_name = lw.stream_id().name;

    // Get stream ID.
    auto wrapped_stream_id = broker::data{lw.stream_id()};
    auto stream_id = detail::data_to_val(wrapped_stream_id, log_id_type);

    if ( ! stream_id ) {
        reporter->Warning("failed to unpack remote log stream id: %s", std::string{stream_id_name}.c_str());
        return false;
    }

    // Get writer ID.
    auto wrapped_writer_id = broker::data{lw.writer_id()};
    auto writer_id = detail::data_to_val(wrapped_writer_id, writer_id_type);
    if ( ! writer_id ) {
        reporter->Warning("failed to unpack remote log writer id for stream: %s", std::string{stream_id_name}.c_str());
        return false;
    }

    auto path = std::string{lw.path_str()};

    auto serial_data = lw.serial_data_str();

    zeek::detail::BinarySerializationFormat fmt;
    fmt.StartRead(serial_data.data(), serial_data.size());

    int num_fields;
    bool success = fmt.Read(&num_fields, "num_fields");

    if ( ! success ) {
        reporter->Warning("failed to unserialize remote log num fields for stream: %s",
                          std::string{stream_id_name}.c_str());
        return false;
    }

    logging::detail::LogRecord rec(num_fields);

    for ( int i = 0; i < num_fields; ++i ) {
        if ( ! rec[i].Read(&fmt) ) {
            reporter->Warning("failed to unserialize remote log field %d for stream: %s", i,
                              std::string{stream_id_name}.c_str());

            return false;
        }
    }

    log_mgr->WriteFromRemote(stream_id->AsEnumVal(), writer_id->AsEnumVal(), path, std::move(rec));
    fmt.EndRead();
    return true;
}

bool Manager::ProcessMessage(std::string_view, broker::zeek::IdentifierUpdate& iu) {
    DBG_LOG(DBG_BROKER, "Received id-update: %s", RenderMessage(iu.as_data()).c_str());

    if ( ! iu.valid() ) {
        reporter->Warning("received invalid broker IdentifierUpdate: %s", broker::to_string(iu.as_data()).c_str());
        return false;
    }

    num_ids_incoming_metric->Inc();
    auto id_name = std::string{iu.id_name()};
    auto id_value = iu.id_value().to_data();
    const auto& id = zeek::detail::global_scope()->Find(id_name);

    if ( ! id ) {
        reporter->Warning("Received id-update request for unknown id: %s", id_name.c_str());
        return false;
    }

    auto val = detail::data_to_val(id_value, id->GetType().get());

    if ( ! val ) {
        reporter->Error("Failed to receive ID with unsupported type: %s (%s)", id_name.c_str(),
                        type_name(id->GetType()->Tag()));
        return false;
    }

    id->SetVal(std::move(val));
    return true;
}

void Manager::ProcessStatus(broker::status& stat) {
    DBG_LOG(DBG_BROKER, "Received status message: %s", RenderMessage(stat).c_str());

    auto ctx = stat.context();

    EventHandlerPtr event;
    switch ( stat.code() ) {
        case broker::sc::unspecified: event = ::Broker::status; break;

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

        case broker::sc::endpoint_discovered: event = ::Broker::endpoint_discovered; break;

        case broker::sc::endpoint_unreachable: event = ::Broker::endpoint_unreachable; break;

        default: reporter->Warning("Unhandled Broker status: %s", to_string(stat).c_str()); break;
    }

    if ( ! event )
        return;

    static auto ei = id::find_type<RecordType>("Broker::EndpointInfo");
    auto endpoint_info = make_intrusive<RecordVal>(ei);

    if ( ctx ) {
        endpoint_info->Assign(0, to_string(ctx->node));
        static auto ni = id::find_type<RecordType>("Broker::NetworkInfo");
        auto network_info = make_intrusive<RecordVal>(ni);

        if ( ctx->network ) {
            network_info->Assign(0, ctx->network->address.c_str());
            network_info->Assign(1, val_mgr->Port(ctx->network->port, TRANSPORT_TCP));
        }
        else {
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

void Manager::ProcessError(broker::error& err) {
    DBG_LOG(DBG_BROKER, "Received error message: %s", RenderMessage(err).c_str());

    if ( ! ::Broker::error )
        return;

    auto int_code = static_cast<uint8_t>(err.code());

    BifEnum::Broker::ErrorCode ec;
    static auto enum_type = id::find_type<EnumType>("Broker::ErrorCode");
    if ( enum_type->Lookup(int_code) )
        ec = static_cast<BifEnum::Broker::ErrorCode>(int_code);
    else {
        reporter->Warning("Unknown Broker error code %u: mapped to unspecified enum value ",
                          static_cast<unsigned>(int_code));
        ec = BifEnum::Broker::ErrorCode::UNSPECIFIED;
    }

    std::string msg;
    // Note: we could also use to_string, but that would change the log output
    // and we would have to update all baselines relying on this format.
    if ( auto ctx = err.context() ) {
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

void Manager::ProcessStoreResponse(detail::StoreHandleVal* s, broker::store::response response) {
    DBG_LOG(DBG_BROKER, "Received store response: %s", RenderMessage(response).c_str());

    auto request = pending_queries.find(std::make_pair(response.id, s));

    if ( request == pending_queries.end() ) {
        reporter->Warning("unmatched response to query %" PRIu64 " on store %s", response.id, s->store.name().c_str());
        return;
    }

    if ( request->second->Disabled() ) {
        // Trigger timer must have timed the query out already.
        delete request->second;
        pending_queries.erase(request);
        return;
    }

    if ( response.answer ) {
        BrokerData tmp{std::move(*response.answer)};
        request->second->Result(detail::query_result(std::move(tmp).ToRecordVal()));
    }
    else if ( response.answer.error() == broker::ec::request_timeout ) { // NOLINT(bugprone-branch-clone)
        // Fine, trigger's timeout takes care of things.
    }
    else if ( response.answer.error() == broker::ec::stale_data ) {
        // It's sort of arbitrary whether to make this type of error successful
        // query with a "fail" status versus going through the when stmt timeout
        // code path.  I think the timeout path is maybe more expected in order
        // for failures like "no such key" to actually be distinguishable from
        // this type of error (which is less easily handled programmatically).
    }
    else if ( response.answer.error() == broker::ec::no_such_key )
        request->second->Result(detail::query_result());
    else
        reporter->InternalWarning("unknown store response status: %s", to_string(response.answer.error()).c_str());

    delete request->second;
    pending_queries.erase(request);
}

detail::StoreHandleVal* Manager::MakeMaster(const string& name, broker::backend type, broker::backend_options opts) {
    if ( ! bstate ) {
        if ( zeek::detail::current_scope() == zeek::detail::global_scope() )
            reporter->Error("Broker stores cannot be created at the global scope");

        return nullptr;
    }

    if ( bstate->endpoint.is_shutdown() )
        return nullptr;

    if ( LookupStore(name) )
        return nullptr;

    DBG_LOG(DBG_BROKER, "Creating master for data store %s", name.c_str());

    auto it = opts.find("path");

    if ( it == opts.end() )
        it = opts.emplace("path", "").first;

    if ( it->second == broker::data("") ) {
        auto suffix = ".store";

        switch ( type ) {
            case broker::backend::sqlite: suffix = ".sqlite"; break;
            default: break;
        }

        it->second = name + suffix;
    }

    auto result = bstate->endpoint.attach_master(name, type, std::move(opts));
    if ( ! result ) {
        Error("Failed to attach master store %s:", to_string(result.error()).c_str());
        return nullptr;
    }

    auto handle = new detail::StoreHandleVal{*result};
    Ref(handle);

    data_stores.emplace(name, handle);
    if ( ! iosource_mgr->RegisterFd(handle->proxy.mailbox().descriptor(), this) )
        reporter->FatalError("Failed to register broker master mailbox descriptor with iosource_mgr");

    PrepareForwarding(name);

    if ( ! bstate->endpoint.use_real_time() )
        // Wait for master to become available/responsive.
        // Possibly avoids timeouts in scripts during unit tests.
        handle->store.exists("");

    BrokerStoreToZeekTable(name, handle);

    return handle;
}

void Manager::BrokerStoreToZeekTable(const std::string& name, const detail::StoreHandleVal* handle) {
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

    for ( const auto& key : *set ) {
        auto zeek_key = ValPtr{};
        auto key_copy = key;
        if ( its.size() == 1 )
            zeek_key = detail::data_to_val(key_copy, its[0].get());
        else
            zeek_key = detail::data_to_val(key_copy, table->GetType()->AsTableType()->GetIndices().get());

        if ( ! zeek_key ) {
            reporter->Error(
                "Failed to convert key \"%s\" while importing broker store to table "
                "for store \"%s\". Aborting import.",
                to_string(key).c_str(), name.c_str());
            // just abort - this probably means the types are incompatible
            table->EnableChangeNotifications();
            return;
        }

        if ( is_set ) {
            table->Assign(zeek_key, nullptr, false);
            continue;
        }

        auto value = handle->store.get(key);
        if ( ! value ) {
            reporter->Error("Failed to load value for key %s while importing Broker store %s to table",
                            to_string(key).c_str(), name.c_str());
            table->EnableChangeNotifications();
            continue;
        }

        auto zeek_value = detail::data_to_val(*value, table->GetType()->Yield().get());
        if ( ! zeek_value ) {
            reporter->Error(
                "Could not convert %s to table value while trying to import Broker "
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

detail::StoreHandleVal* Manager::MakeClone(const string& name, double resync_interval, double stale_interval,
                                           double mutation_buffer_interval) {
    if ( bstate->endpoint.is_shutdown() )
        return nullptr;

    if ( LookupStore(name) )
        return nullptr;

    DBG_LOG(DBG_BROKER, "Creating clone for data store %s", name.c_str());

    auto result = bstate->endpoint.attach_clone(name, resync_interval, stale_interval, mutation_buffer_interval);
    if ( ! result ) {
        Error("Failed to attach clone store %s:", to_string(result.error()).c_str());
        return nullptr;
    }

    auto handle = new detail::StoreHandleVal{*result};

    if ( ! handle->proxy.valid() ) {
        reporter->Error("Failed to create clone for data store %s", name.c_str());
        delete handle;
        return nullptr;
    }

    Ref(handle);

    data_stores.emplace(name, handle);
    if ( ! iosource_mgr->RegisterFd(handle->proxy.mailbox().descriptor(), this) )
        reporter->FatalError("Failed to register broker clone mailbox descriptor with iosource_mgr");
    PrepareForwarding(name);
    return handle;
}

detail::StoreHandleVal* Manager::LookupStore(const string& name) {
    auto i = data_stores.find(name);
    return i == data_stores.end() ? nullptr : i->second;
}

bool Manager::CloseStore(const string& name) {
    DBG_LOG(DBG_BROKER, "Closing data store %s", name.c_str());

    auto s = data_stores.find(name);
    if ( s == data_stores.end() )
        return false;

    iosource_mgr->UnregisterFd(s->second->proxy.mailbox().descriptor(), this);

    for ( auto i = pending_queries.begin(); i != pending_queries.end(); )
        if ( i->second->Store().name() == name ) {
            i->second->Abort();
            delete i->second;
            i = pending_queries.erase(i);
        }
        else {
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

bool Manager::TrackStoreQuery(detail::StoreHandleVal* handle, broker::request_id id, detail::StoreQueryCallback* cb) {
    auto rval = pending_queries.emplace(std::make_pair(id, handle), cb).second;

    if ( bstate->endpoint.use_real_time() )
        return rval;

    FlushPendingQueries();
    return rval;
}

const Stats& Manager::GetStatistics() {
    statistics.num_peers = peer_count;
    statistics.num_stores = data_stores.size();
    statistics.num_pending_queries = pending_queries.size();

    statistics.num_events_incoming = static_cast<size_t>(num_events_incoming_metric->Value());
    statistics.num_events_outgoing = static_cast<size_t>(num_events_outgoing_metric->Value());
    statistics.num_logs_incoming = static_cast<size_t>(num_logs_incoming_metric->Value());
    statistics.num_logs_outgoing = static_cast<size_t>(num_logs_outgoing_metric->Value());
    statistics.num_ids_incoming = static_cast<size_t>(num_ids_incoming_metric->Value());
    statistics.num_ids_outgoing = static_cast<size_t>(num_ids_outgoing_metric->Value());

    return statistics;
}

TableValPtr Manager::GetPeeringStatsTable() { return bstate->peerBufferState->GetPeeringStatsTable(); }

bool Manager::AddForwardedStore(const std::string& name, TableValPtr table) {
    if ( forwarded_stores.find(name) != forwarded_stores.end() ) {
        reporter->Error("same &broker_store %s specified for two different variables", name.c_str());
        return false;
    }

    DBG_LOG(DBG_BROKER, "Adding table forward for data store %s", name.c_str());
    forwarded_stores.emplace(name, std::move(table));

    PrepareForwarding(name);
    return true;
}

void Manager::PrepareForwarding(const std::string& name) {
    auto handle = LookupStore(name);
    if ( ! handle )
        return;

    if ( forwarded_stores.find(name) == forwarded_stores.end() )
        return;

    handle->forward_to = forwarded_stores.at(name);
    DBG_LOG(DBG_BROKER, "Resolved table forward for data store %s", name.c_str());
}

broker::hub Manager::MakeHub(broker::filter_type ft) {
    ++hub_count;
    return bstate->endpoint.make_hub(std::move(ft));
}

void Manager::DestroyHub(broker::hub&& hub) { --hub_count; }

} // namespace zeek::Broker

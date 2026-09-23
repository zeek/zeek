// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include <broker/backend.hh>
#include <broker/backend_options.hh>
#include <broker/detail/hash.hh>
#include <broker/endpoint_info.hh>
#include <broker/hub.hh>
#include <broker/peer_info.hh>
#include <broker/zeek.hh>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include "zeek/IntrusivePtr.h"
#include "zeek/broker/Data.h"
#include "zeek/cluster/Backend.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/logging/Types.h"
#include "zeek/logging/WriterBackend.h"

namespace broker {

class data;
class error;
class endpoint;

} // namespace broker

namespace zeek {

class Func;
class VectorType;
class TableVal;
using VectorTypePtr = IntrusivePtr<VectorType>;
using TableValPtr = IntrusivePtr<TableVal>;

namespace telemetry {
class Gauge;
class Counter;
using GaugePtr = std::shared_ptr<Gauge>;
using CounterPtr = std::shared_ptr<Counter>;
} // namespace telemetry

namespace detail {
class Frame;
}

namespace Broker {

class BrokerState;

/**
 * Communication statistics.
 */
struct Stats {
    // Number of active peer connections.
    size_t num_peers = 0;
    // Number of total log messages received.
    size_t num_events_incoming = 0;
    // Number of total log messages sent.
    size_t num_events_outgoing = 0;
    // Number of total log records received.
    size_t num_logs_incoming = 0;
    // Number of total log records sent.
    size_t num_logs_outgoing = 0;
    // Number of total identifiers received.
    size_t num_ids_incoming = 0;
    // Number of total identifiers sent.
    size_t num_ids_outgoing = 0;
};

/**
 * Manages various forms of communication between peer Zeek processes
 * or other external applications via use of the Broker messaging library.
 */
class Manager : public zeek::cluster::Backend, public iosource::IOSource {
public:
    static const broker::endpoint_info NoPeer;

    /**
     * Constructor.
     */
    Manager(bool use_real_time);

    /**
     * Returns true if any Broker communication is currently active.
     */
    bool Active();

    /**
     * Advances time.  Broker data store expiration is driven by this
     * simulated time instead of real/wall time.
     */
    void AdvanceTime(double seconds_since_unix_epoch);

    /**
     * Listen for remote connections.
     * @param port the TCP port to listen on.
     * @param addr an address string on which to accept connections, e.g.
     * "127.0.0.1".  The empty string refers to @p INADDR_ANY.
     * @param protocol protocol to speak on accepted connections
     * @return 0 on failure or the bound port otherwise. If *port* != 0, then the
     * return value equals *port* on success. If *port* equals 0, then the
     * return values represents the bound port as chosen by the OS.
     */
    uint16_t Listen(const std::string& addr, uint16_t port);

    /**
     * Initiate a peering with a remote endpoint.
     * @param addr an address to connect to, e.g. "localhost" or "127.0.0.1".
     * @param port the TCP port on which the remote side is listening.
     * @param retry If non-zero, the time after which to retry if
     * connection cannot be established, or breaks.  ZEEK_DEFAULT_CONNECT_RETRY
     * environment variable overrides this value.
     */
    void Peer(const std::string& addr, uint16_t port, double retry = 10.0);

    /**
     * Initiate a peering with a remote endpoint but tries only once.
     * This function is only intended for testing purposes.
     * @param addr an address to connect to, e.g. "localhost" or "127.0.0.1".
     * @param port the TCP port on which the remote side is listening.
     */
    void PeerNoRetry(const std::string& addr, uint16_t port);

    /**
     * Remove a remote peering.
     * @param addr the address used in zeek::Broker::Manager::Peer().
     * @param port the port used in zeek::Broker::Manager::Peer().
     */
    void Unpeer(const std::string& addr, uint16_t port);

    /**
     * Whether the local node originally initiated the peering with the
     * given endpoint.
     * @param addr the address used in zeek::Broker::Manager::Peer().
     * @param port the port used in zeek::Broker::Manager::Peer().
     */
    bool IsOutboundPeering(const std::string& addr, uint16_t port) const;

    /**
     * Whether the local node originally initiated the peering with the
     * given endpoint.
     * @param ni the address and port used in zeek::Broker::Manager::Peer().
     */
    bool IsOutboundPeering(const broker::network_info& ni) const;

    /**
     * @return a list of peer endpoints.
     */
    std::vector<broker::peer_info> Peers() const;

    /**
     * Send an identifier's value to interested peers.
     * @param topic a topic string associated with the message.
     * @param id the name of the identifier to send.
     * @return true if the message is sent successfully.
     */
    bool PublishIdentifier(std::string topic, std::string id);

    /**
     * Send an event to any interested peers.
     * @param topic a topic string associated with the message.
     * Peers advertise interest by registering a subscription to some prefix
     * of this topic name.
     * @param name the name of the event
     * @param args the event's arguments
     * @param ts the timestamp the event is intended to be executed
     * @return true if the message is sent successfully.
     */
    bool PublishEvent(std::string topic, const std::string& name, const broker::vector& args,
                      double ts = run_state::network_time);

    /**
     * @copydoc PublishEvent(std::string, std::string, broker::vector, double)
     */
    bool PublishEvent(std::string topic, const std::string& name, BrokerData args,
                      double ts = run_state::network_time) {
        if ( ! args.AsView().IsList() )
            return false;
        return PublishEvent(std::move(topic), name, broker::get<broker::vector>(args.value_), ts);
    }

    using cluster::Backend::PublishEvent;

    /**
     * Send an event to any interested peers.
     * @param topic a topic string associated with the message.
     * Peers advertise interest by registering a subscription to some prefix
     * of this topic name.
     * @param ev the event and its arguments to send to peers, in the form of
     * a Broker::Event record type. The timestamp for the event is set to the
     * current network time.
     * @return true if the message is sent successfully.
     */
    bool PublishEvent(std::string topic, RecordVal* ev);

    /**
     * Send a message to create a log stream to any interested peers.
     * The log stream may or may not already exist on the receiving side.
     * The topic name used is implicitly "bro/log/<stream-name>".
     * @param stream the stream to which the log entry belongs.
     * @param writer the writer to use for outputting this log entry.
     * @param info backend initialization information for the writer.
     * @param num_fields the number of fields the log has.
     * @param fields the log's fields, of size num_fields.
     * See the Broker::SendFlags record type.
     * @param peer If given, send the message only to this peer.
     * @return true if the message is sent successfully.
     */
    bool PublishLogCreate(EnumVal* stream, EnumVal* writer, const logging::WriterBackend::WriterInfo& info,
                          int num_fields, const threading::Field* const* fields,
                          const broker::endpoint_info& peer = NoPeer);

    /**
     * Send a log entry to any interested peers.
     *
     * @param stream the stream to which the log entry belongs.
     * @param writer the writer to use for outputting this log entry.
     * @param path the log path to output the log entry to.
     * @param rec the log record.
     * @return true if the message is sent successfully.
     */
    bool PublishLogWrite(EnumVal* stream, EnumVal* writer, const std::string& path,
                         const logging::detail::LogRecord& rec);

    using ArgsSpan = std::span<const ValPtr>;

    /**
     * Create an `Event` record value from an event and its arguments.
     * @param args A span pointing at the event arguments.
     * @param frame the calling frame, used to report location info upon error
     * @return an `Event` record value.  If an invalid event or arguments
     * were supplied the optional "name" field will not be set.
     */
    zeek::RecordValPtr MakeEvent(ArgsSpan args, zeek::detail::Frame* frame);

    /**
     * Register interest in peer event messages that use a certain topic prefix,
     * but that should not be raised locally, just forwarded to any subscribing
     * peers.
     * @param topic_prefix a prefix to match against remote message topics.
     * e.g. an empty prefix will match everything and "a" will match "alice"
     * and "amy" but not "bob".
     * @return true if it's a new event forward/subscription and it is now registered.
     */
    bool Forward(std::string topic_prefix);

    /**
     * Send all pending log write messages.
     * @return the number of messages sent.
     */
    size_t FlushLogBuffers();

    /**
     * @return communication statistics.
     */
    const Stats& GetStatistics();

    /**
     * Returns a table[string] of BrokerPeeringStats, with each peering's
     * send-buffer stats filled in. The keys are Broker node IDs identifying the
     * current peers.
     * @return Each peering's send-buffer statistics.
     */
    TableValPtr GetPeeringStatsTable();

    /**
     * Creating an instance of this struct simply helps the manager
     * keep track of whether calls into its API are coming from script
     * layer BIFs so that error messages can emit useful call site info.
     */
    struct ScriptScopeGuard {
        ScriptScopeGuard() { ++script_scope; }
        ~ScriptScopeGuard() { --script_scope; }
    };

private:
    // Register interest in peer event messages that use a certain topic prefix.
    bool DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) override;

    // Unregister interest in peer event messages.
    bool DoUnsubscribe(const std::string& topic_prefix) override;

    // Initialization of the manager. This is called late during Zeek's
    // initialization after any scripts are processed.
    void DoInitPostScript() override;

    // Broker doesn't do anything during Broker::Backend::init().
    bool DoInit() override { return true; }

    // Shuts Broker down at termination.
    void DoTerminate() override;

    // Broker overrides this to do its own serialization.
    bool DoPublishEvent(const std::string& topic, cluster::Event& event) override;

    // This should never be reached, broker itself doesn't call this and overrides
    // the generic DoPublishEvent() method that would call this.
    bool DoPublishEvent(const std::string& topic, const std::string& format, const byte_buffer& buf) override {
        throw std::logic_error("not implemented");
    }

    // WriterFrontend instances are broker-aware and never call this
    // method and instead call the existing PublishLogWrite() method.
    //
    // TODO: Move log buffering out of broker and implement.
    bool DoPublishLogWrites(const logging::detail::LogWriteHeader& header,
                            std::span<logging::detail::LogRecord> records) override {
        // Not implemented by broker.
        throw std::logic_error("not implemented");
    }

    bool DoPublishLogWrites(const logging::detail::LogWriteHeader& header, const std::string& format,
                            byte_buffer& buf) override {
        // Not implemented by broker.
        throw std::logic_error("not implemented");
    }

    void ProcessMessage(std::string_view topic, broker::zeek::Batch& ev);
    void ProcessMessage(std::string_view topic, broker::zeek::Event& ev);
    void ProcessMessage(std::string_view topic, broker::zeek::Invalid& ev);
    bool ProcessMessage(std::string_view topic, broker::zeek::LogCreate& lc);
    bool ProcessMessage(std::string_view topic, broker::zeek::LogWrite& lw);
    bool ProcessMessage(std::string_view topic, broker::zeek::IdentifierUpdate& iu);
    void ProcessStatus(broker::status& stat);
    void ProcessError(broker::error& err);

    void Error(const char* format, ...) __attribute__((format(printf, 2, 3)));

    // Processes events from the Broker message queue.
    void ProcessMessages();

    // Process events from Broker logger.
    void ProcessLogEvents();

    // IOSource interface overrides:
    void ProcessFd(int fd, int flags) override;
    void Process() override;
    const char* Tag() override { return "Broker::Manager"; }
    double GetNextTimeout() override;


    // Allow WebSocketShim access to MakeHub() and DestroyHub()
    friend class WebSocketState;

    // Create a hub for WebSocket clients.
    broker::hub MakeHub();

    // This hub is to be destroyed.
    void DestroyHub(broker::hub&& hub);

    struct LogBuffer {
        // Indexed by topic string.
        std::unordered_map<std::string, broker::zeek::BatchBuilder> msgs;
        size_t message_count;

        size_t Flush(broker::endpoint& endpoint, size_t batch_size);
    };

    std::vector<LogBuffer> log_buffers; // Indexed by stream ID enum.
    std::string default_log_topic_prefix;
    std::shared_ptr<BrokerState> bstate;
    std::vector<std::string> forwarded_prefixes;

    Stats statistics;

    uint16_t bound_port;
    bool use_real_time;
    int peer_count;
    int hub_count;

    size_t log_batch_size;
    Func* log_topic_func;
    VectorTypePtr vector_of_data_type;
    EnumType* log_id_type;
    EnumType* writer_id_type;
    bool zeek_table_manager = false;
    std::string zeek_table_db_directory;
    bool enable_identifier_updates = false;

    static int script_scope;

    telemetry::GaugePtr num_peers_metric;
    telemetry::GaugePtr num_pending_queries_metric;
    telemetry::CounterPtr num_events_incoming_metric;
    telemetry::CounterPtr num_events_outgoing_metric;
    telemetry::CounterPtr num_logs_incoming_metric;
    telemetry::CounterPtr num_logs_outgoing_metric;
    telemetry::CounterPtr num_ids_incoming_metric;
    telemetry::CounterPtr num_ids_outgoing_metric;
}; // namespace zeek

} // namespace Broker

ZEEK_EXTERN_DATA Broker::Manager* broker_mgr;

} // namespace zeek

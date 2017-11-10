#ifndef BRO_COMM_MANAGER_H
#define BRO_COMM_MANAGER_H

#include <broker/broker.hh>
#include <broker/bro.hh>
#include <memory>
#include <string>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include "broker/Store.h"
#include "Reporter.h"
#include "iosource/IOSource.h"
#include "Val.h"

namespace bro_broker {

/**
 * Communication statistics.
 */
struct Stats {
	// Number of active peer connections.
	size_t num_peers = 0;
	// Number of active data stores.
	size_t num_stores = 0;
	// Number of pending data store queries.
	size_t num_pending_queries = 0;
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
 * Manages various forms of communication between peer Bro processes
 * or other external applications via use of the Broker messaging library.
 */
class Manager : public iosource::IOSource {
public:
        static const broker::endpoint_info NoPeer;

	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.  Any still-pending data store queries are aborted.
	 */
	~Manager();

	/**
	 * Initialization of the manager. This is called late during Bro's
	 * initialization after any scripts are processed.
	 */
	void InitPostScript();

	/**
	 * Shuts Broker down at termination.
	 */
	void Terminate();

	/**
	 * Returns true if any Broker communincation is currently active.
	 */
	bool Active();

	/**
	 * Listen for remote connections.
	 * @param port the TCP port to listen on.
	 * @param addr an address string on which to accept connections, e.g.
	 * "127.0.0.1".  The empty string refers to @p INADDR_ANY.
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
	 * connection cannot be established, or breaks.
	 */
	void Peer(const std::string& addr, uint16_t port, double retry = 10.0);

	/**
	 * Remove a remote peering.
	 * @param addr the address used in bro_broker::Manager::Peer().
	 * @param port the port used in bro_broker::Manager::Peer().
	 */
	void Unpeer(const std::string& addr, uint16_t port);

	/**
	 * @return a list of peer endpoints.
	 */
	std::vector<broker::peer_info> Peers() const;

	/**
	 * @return a unique identifier for this broker endpoint.
	 */
	std::string NodeID() const;

	/**
	 * Send an event to any interested peers.
	 * @param topic a topic string associated with the message.
	 * Peers advertise interest by registering a subscription to some prefix
	 * of this topic name.
	 * @param name the name of the event
	 * @param  the event's arguments
	 * @return true if the message is sent successfully.
	 */
	bool PublishEvent(std::string topic, std::string name, broker::vector args);

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
	 * @param ev the event and its arguments to send to peers, in the form of
	 * a Broker::Event record type.
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
			      int num_fields, const threading::Field* const * fields, const broker::endpoint_info& peer = NoPeer);

	/**
	 * Send a log entry to any interested peers.  The topic name used is
	 * implicitly "bro/log/<stream-name>".
	 * @param stream the stream to which the log entry belongs.
	 * @param writer the writer to use for outputting this log entry.
	 * @param path the log path to output the log entry to.
	 * @param num_vals the number of fields to log.
	 * @param vals the log values to log, of size num_vals.
	 * See the Broker::SendFlags record type.
	 * @return true if the message is sent successfully.
	 */
	bool PublishLogWrite(EnumVal* stream, EnumVal* writer, string path, int num_vals,
			     const threading::Value* const * vals);

	/**
	 * Automatically send an event to any interested peers whenever it is
	 * locally dispatched (e.g. using "event my_event(...);" in a script).
	 * @param topic a topic string associated with the event message.
	 * Peers advertise interest by registering a subscription to some prefix
	 * of this topic name.
	 * @param event a Bro event value.
	 * @return true if automatic event sending is now enabled.
	 */
	bool AutoPublishEvent(std::string topic, Val* event);

	/**
	 * Stop automatically sending an event to peers upon local dispatch.
	 * @param topic a topic originally given to bro_broker::Manager::AutoPublish().
	 * @param event an event originally given to bro_broker::Manager::AutoPublish().
	 * @return true if automatic events will no occur for the topic/event pair.
	 */
	bool AutoUnpublishEvent(const std::string& topic, Val* event);

	/**
	 * Create an `Event` record value from an event and its arguments.
	 * @param args the event and its arguments.  The event is always the first
	 * elements in the list.
	 * @return an `Event` record value.  If an invalid event or arguments
	 * were supplied the optional "name" field will not be set.
	 */
	RecordVal* MakeEvent(val_list* args);

	/**
	 * Register interest in peer event messages that use a certain topic prefix.
	 * @param topic_prefix a prefix to match against remote message topics.
	 * e.g. an empty prefix will match everything and "a" will match "alice"
	 * and "amy" but not "bob".
	 * @return true if it's a new event subscription and it is now registered.
	 */
	bool Subscribe(const std::string& topic_prefix);

	/**
	 * Unregister interest in peer event messages.
	 * @param topic_prefix a prefix previously supplied to a successful call
	 * to bro_broker::Manager::Subscribe().
	 * @return true if interest in topic prefix is no longer advertised.
	 */
	bool Unsubscribe(const std::string& topic_prefix);

	/**
	 * Create a new *master* data store.
	 * @param name The name of the store.
	 * @param type The backend type.
	 * @param opts The backend options.
	 * @return a pointer to the newly created store a nullptr on failure.
	 */
	StoreHandleVal* MakeMaster(const std::string& name, broker::backend type,
				   broker::backend_options opts);

	/**
	 * Create a new *clone* data store.
	 * @param name The name of the store.
	 * @return a pointer to the newly created store a nullptr on failure.
	 */
	StoreHandleVal* MakeClone(const std::string& name);

	/**
	 * Lookup a data store by it's identifier name and type.
	 * @param name the store's name.
	 * @return a pointer to the store handle if it exists else nullptr.
	 */
	StoreHandleVal* LookupStore(const std::string& name);

	/**
	 * Close and unregister a data store.  Any existing references to the
	 * store handle will not be able to be used for any data store operations.
	 * @param name the stores' name.
	 * @return true if such a store existed and is now closed.
	 */
	bool CloseStore(const std::string& name);

	/**
	 * Register a data store query callback.
	 * @param cb the callback info to use when the query completes or times out.
	 * @return true if now tracking a data store query.
	 */
	bool TrackStoreQuery(broker::request_id id, StoreQueryCallback* cb);

	/**
	 * @return communication statistics.
	 */
	const Stats& GetStatistics();

private:

	class BrokerState {
	public:
		BrokerState(broker::broker_options options);
		broker::endpoint endpoint;
		broker::subscriber subscriber;
		broker::status_subscriber status_subscriber;
	};

	void DispatchMessage(broker::data&& msg);
	void ProcessEvent(const broker::bro::Event le);
	bool ProcessLogCreate(const broker::bro::LogCreate lc);
	bool ProcessLogWrite(const broker::bro::LogWrite lw);
	bool ProcessIdentifierUpdate(const broker::bro::IdentifierUpdate iu);
	void ProcessStatus(const broker::status stat);
	void ProcessError(broker::error err);
	void ProcessStoreResponse(StoreHandleVal*, broker::store::response response);
	void FlushLogBuffer(int stream_id_num = -1);

	// IOSource interface overrides:
	void GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
	            iosource::FD_Set* except) override;

	double NextTimestamp(double* local_network_time) override;

	void Process() override;

	const char* Tag() override
		{ return "Broker::Manager"; }

	broker::endpoint& Endpoint()
		{ assert(bstate); return bstate->endpoint; }

	std::string log_topic;
	uint16_t bound_port;

	std::shared_ptr<BrokerState> bstate;

	struct LogBuffer {
	        broker::vector msgs;
		double last_flush;
	};

	// Indexed by stream ID enum.
	std::vector<LogBuffer> log_buffers;

	// Data stores
	std::unordered_map<std::string, StoreHandleVal*> data_stores;
	std::unordered_map<broker::request_id, StoreQueryCallback*> pending_queries;

	Stats statistics;
	double next_timestamp;

	static VectorType* vector_of_data_type;
	static EnumType* log_id_type;
	static EnumType* writer_id_type;
	static int send_flags_self_idx;
	static int send_flags_peers_idx;
	static int send_flags_unsolicited_idx;
};

} // namespace bro_broker

extern bro_broker::Manager* broker_mgr;

#endif // BRO_COMM_MANAGER_H

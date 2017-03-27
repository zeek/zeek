#ifndef BRO_COMM_MANAGER_H
#define BRO_COMM_MANAGER_H

#include <broker/broker.hh>
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
 * Communication statistics.  Some are tracked in relation to last
 * sample (bro_broker::Manager::ConsumeStatistics()).
 */
struct Stats {
	// Number of outgoing peer connections (at time of sample).
	size_t outgoing_peer_count = 0;
	// Number of data stores (at time of sample).
	size_t data_store_count = 0;
	// Number of pending data store queries (at time of sample).
	size_t pending_query_count = 0;
	// Number of data store responses received (since last sample).
	size_t response_count = 0;
	// Number of outgoing connection updates received (since last sample).
	size_t outgoing_conn_status_count = 0;
	// Number of incoming connection updates received (since last sample).
	size_t incoming_conn_status_count = 0;
	// Number of broker report messages (e.g. debug, warning, errors) received
	// (since last sample).
	size_t report_count = 0;
	// Number of print messages received per topic-prefix (since last sample).
	std::map<std::string, size_t> print_count;
	// Number of event messages received per topic-prefix (since last sample).
	std::map<std::string, size_t> event_count;
	// Number of log messages received per topic-prefix (since last sample).
	std::map<std::string, size_t> log_count;
};

/**
 * Manages various forms of communication between peer Bro processes
 * or other external applications via use of the Broker messaging library.
 */
class Manager : public iosource::IOSource {
public:

	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.  Any still-pending data store queries are aborted.
	 */
	~Manager();

	/**
	 * Enable use of communication.
	 * @param name The name of the endpoint.
	 * @param routable Whether the context of this endpoint routes messages not
	 * destined to itself.
	 * @return true if communication is successfully initialized.
	 */
	bool Enable(std::string name = "", bool routable = false);

	/**
	 * @return true if bro_broker::Manager::Enable() has previously been called and
	 * it succeeded.
	 */
	bool Enabled()
		{ return log_id_type != nullptr; }

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
	 */
	void Peer(const std::string& addr, uint16_t port);

	/**
	 * Remove a remote peering.
	 * @param addr the address used in bro_broker::Manager::Peer().
	 * @param port the port used in bro_broker::Manager::Peer().
	 */
	void Unpeer(const std::string& addr, uint16_t port);

	/**
	 * Send an event to any interested peers.
	 * @param msg The message (topic-data) pair to publish to the peers.
	 * @return true if the message is sent successfully.
	 */
	bool Publish(broker::message msg);

	/**
	 * Send an event to any interested peers.
	 * @param topic a topic string associated with the print message.
	 * Peers advertise interest by registering a subscription to some prefix
	 * of this topic name.
	 * @param x the event to send to peers, which is the name of the event
	 * as a string followed by all of its arguments.
	 * @return true if the message is sent successfully.
	 */
	bool Publish(std::string topic, broker::data x);

	/**
	 * Send an event to any interested peers.
	 * @param topic a topic string associated with the print message.
	 * Peers advertise interest by registering a subscription to some prefix
	 * of this topic name.
	 * @param args the event and its arguments to send to peers.  See the
	 * Broker::Event record type.
	 * @return true if the message is sent successfully.
	 */
	bool Publish(std::string topic, RecordVal* args);

	/**
	 * Send a log entry to any interested peers.  The topic name used is
	 * implicitly "bro/log/<stream-name>".
	 * @param stream_id the stream to which the log entry belongs.
	 * @param columns the data which comprises the log entry.
	 * @param info the record type corresponding to the log's columns.
	 * @return true if the message is sent successfully.
	 */
	bool Publish(EnumVal* stream_id, RecordVal* columns, RecordType* info);

	/**
	 * Automatically send an event to any interested peers whenever it is
	 * locally dispatched (e.g. using "event my_event(...);" in a script).
	 * @param topic a topic string associated with the event message.
	 * Peers advertise interest by registering a subscription to some prefix
	 * of this topic name.
	 * @param event a Bro event value.
	 * @return true if automatic event sending is now enabled.
	 */
	bool AutoPublish(std::string topic, Val* event);

	/**
	 * Stop automatically sending an event to peers upon local dispatch.
	 * @param topic a topic originally given to bro_broker::Manager::AutoPublish().
	 * @param event an event originally given to bro_broker::Manager::AutoPublish().
	 * @return true if automatic events will no occur for the topic/event pair.
	 */
	bool AutoUnpublish(const std::string& topic, Val* event);

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
	Stats ConsumeStatistics();

private:

	// IOSource interface overrides:
	void GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
	            iosource::FD_Set* except) override;

	double NextTimestamp(double* local_network_time) override;

	void Process() override;

	const char* Tag() override
		{ return "Broker::Manager"; }

	broker::endpoint& Endpoint()
		{ return endpoint; }

  std::string name;
  broker::context context;
  broker::blocking_endpoint endpoint;

	// Data stores
	std::unordered_map<std::string, StoreHandleVal*> data_stores;
	std::unordered_map<broker::request_id, StoreQueryCallback*> pending_queries;

	Stats statistics;
	double next_timestamp;

	static VectorType* vector_of_data_type;
	static EnumType* log_id_type;
};

} // namespace bro_broker

extern bro_broker::Manager* broker_mgr;

#endif // BRO_COMM_MANAGER_H

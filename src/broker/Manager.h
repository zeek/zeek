#ifndef BRO_COMM_MANAGER_H
#define BRO_COMM_MANAGER_H

#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <memory>
#include <string>
#include <map>
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
friend class StoreHandleVal;
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
	 * @param flags used to tune the local Broker endpoint's behavior.
	 * See the BrokerComm::EndpointFlags record type.
	 * @return true if communication is successfully initialized.
	 */
	bool Enable(Val* flags);

	/**
	 * Changes endpoint flags originally supplied to bro_broker::Manager::Enable().
	 * @param flags the new behavior flags to use.
	 * @return true if flags were changed.
	 */
	bool SetEndpointFlags(Val* flags);

	/**
	 * @return true if bro_broker::Manager::Enable() has previously been called and
	 * it succeeded.
	 */
	bool Enabled()
		{ return endpoint != nullptr; }

	/**
	 * Listen for remote connections.
	 * @param port the TCP port to listen on.
	 * @param addr an address string on which to accept connections, e.g.
	 * "127.0.0.1".  A nullptr refers to @p INADDR_ANY.
	 * @param reuse_addr equivalent to behavior of SO_REUSEADDR.
	 * @return true if the local endpoint is now listening for connections.
	 */
	bool Listen(uint16_t port, const char* addr = nullptr,
	            bool reuse_addr = true);

	/**
	 * Initiate a remote connection.
	 * @param addr an address to connect to, e.g. "localhost" or "127.0.0.1".
	 * @param port the TCP port on which the remote side is listening.
	 * @param retry_interval an interval at which to retry establishing the
	 * connection with the remote peer.
	 * @return true if it's possible to try connecting with the peer and
	 * it's a new peer.  The actual connection may not be established until a
	 * later point in time.
	 */
	bool Connect(std::string addr, uint16_t port,
	             std::chrono::duration<double> retry_interval);

	/**
	 * Remove a remote connection.
	 * @param addr the address used in bro_broker::Manager::Connect().
	 * @param port the port used in bro_broker::Manager::Connect().
	 * @return true if the arguments match a previously successful call to
	 * bro_broker::Manager::Connect().
	 */
	bool Disconnect(const std::string& addr, uint16_t port);

	/**
	 * Print a simple message to any interested peers.
	 * @param topic a topic string associated with the print message.
	 * Peers advertise interest by registering a subscription to some prefix
	 * of this topic name.
	 * @param msg the string to send to peers.
	 * @param flags tune the behavior of how the message is send.
	 * See the BrokerComm::SendFlags record type.
	 * @return true if the message is sent successfully.
	 */
	bool Print(std::string topic, std::string msg, Val* flags);

	/**
	 * Send an event to any interested peers.
	 * @param topic a topic string associated with the print message.
	 * Peers advertise interest by registering a subscription to some prefix
	 * of this topic name.
	 * @param msg the event to send to peers, which is the name of the event
	 * as a string followed by all of its arguments.
	 * @param flags tune the behavior of how the message is send.
	 * See the BrokerComm::SendFlags record type.
	 * @return true if the message is sent successfully.
	 */
	bool Event(std::string topic, broker::message msg, int flags);

	/**
	 * Send an event to any interested peers.
	 * @param topic a topic string associated with the print message.
	 * Peers advertise interest by registering a subscription to some prefix
	 * of this topic name.
	 * @param args the event and its arguments to send to peers.  See the
	 * BrokerComm::EventArgs record type.
	 * @param flags tune the behavior of how the message is send.
	 * See the BrokerComm::SendFlags record type.
	 * @return true if the message is sent successfully.
	 */
	bool Event(std::string topic, RecordVal* args, Val* flags);

	/**
	 * Send a log entry to any interested peers.  The topic name used is
	 * implicitly "bro/log/<stream-name>".
	 * @param stream_id the stream to which the log entry belongs.
	 * @param columns the data which comprises the log entry.
	 * @param info the record type corresponding to the log's columns.
	 * @param flags tune the behavior of how the message is send.
	 * See the BrokerComm::SendFlags record type.
	 * @return true if the message is sent successfully.
	 */
	bool Log(EnumVal* stream_id, RecordVal* columns, RecordType* info,
	         int flags);

	/**
	 * Automatically send an event to any interested peers whenever it is
	 * locally dispatched (e.g. using "event my_event(...);" in a script).
	 * @param topic a topic string associated with the event message.
	 * Peers advertise interest by registering a subscription to some prefix
	 * of this topic name.
	 * @param event a Bro event value.
	 * @param flags tune the behavior of how the message is send.
	 * See the BrokerComm::SendFlags record type.
	 * @return true if automatic event sending is now enabled.
	 */
	bool AutoEvent(std::string topic, Val* event, Val* flags);

	/**
	 * Stop automatically sending an event to peers upon local dispatch.
	 * @param topic a topic originally given to bro_broker::Manager::AutoEvent().
	 * @param event an event originally given to bro_broker::Manager::AutoEvent().
	 * @return true if automatic events will no occur for the topic/event pair.
	 */
	bool AutoEventStop(const std::string& topic, Val* event);

	/**
	 * Create an EventArgs record value from an event and its arguments.
	 * @param args the event and its arguments.  The event is always the first
	 * elements in the list.
	 * @return an EventArgs record value.  If an invalid event or arguments
	 * were supplied the optional "name" field will not be set.
	 */
	RecordVal* MakeEventArgs(val_list* args);

	/**
	 * Register interest in peer print messages that use a certain topic prefix.
	 * @param topic_prefix a prefix to match against remote message topics.
	 * e.g. an empty prefix will match everything and "a" will match "alice"
	 * and "amy" but not "bob".
	 * @return true if it's a new print subscriptions and it is now registered.
	 */
	bool SubscribeToPrints(std::string topic_prefix);

	/**
	 * Unregister interest in peer print messages.
	 * @param topic_prefix a prefix previously supplied to a successful call
	 * to bro_broker::Manager::SubscribeToPrints().
	 * @return true if interest in topic prefix is no longer advertised.
	 */
	bool UnsubscribeToPrints(const std::string& topic_prefix);

	/**
	 * Register interest in peer event messages that use a certain topic prefix.
	 * @param topic_prefix a prefix to match against remote message topics.
	 * e.g. an empty prefix will match everything and "a" will match "alice"
	 * and "amy" but not "bob".
	 * @return true if it's a new event subscription and it is now registered.
	 */
	bool SubscribeToEvents(std::string topic_prefix);

	/**
	 * Unregister interest in peer event messages.
	 * @param topic_prefix a prefix previously supplied to a successful call
	 * to bro_broker::Manager::SubscribeToEvents().
	 * @return true if interest in topic prefix is no longer advertised.
	 */
	bool UnsubscribeToEvents(const std::string& topic_prefix);

	/**
	 * Register interest in peer log messages that use a certain topic prefix.
	 * @param topic_prefix a prefix to match against remote message topics.
	 * e.g. an empty prefix will match everything and "a" will match "alice"
	 * and "amy" but not "bob".
	 * @return true if it's a new log subscription and it is now registered.
	 */
	bool SubscribeToLogs(std::string topic_prefix);

	/**
	 * Unregister interest in peer log messages.
	 * @param topic_prefix a prefix previously supplied to a successful call
	 * to bro_broker::Manager::SubscribeToLogs().
	 * @return true if interest in topic prefix is no longer advertised.
	 */
	bool UnsubscribeToLogs(const std::string& topic_prefix);

	/**
	 * Allow sending messages to peers if associated with the given topic.
	 * This has no effect if auto publication behavior is enabled via the flags
	 * supplied to bro_broker::Manager::Enable() or bro_broker::Manager::SetEndpointFlags().
	 * @param t a topic to allow messages to be published under.
	 * @return true if successful.
	 */
	bool PublishTopic(broker::topic t);

	/**
	 * Disallow sending messages to peers if associated with the given topic.
	 * This has no effect if auto publication behavior is enabled via the flags
	 * supplied to bro_broker::Manager::Enable() or bro_broker::Manager::SetEndpointFlags().
	 * @param t a topic to disallow messages to be published under.
	 * @return true if successful.
	 */
	bool UnpublishTopic(broker::topic t);

	/**
	 * Allow advertising interest in the given topic to peers.
	 * This has no effect if auto advertise behavior is enabled via the flags
	 * supplied to bro_broker::Manager::Enable() or bro_broker::Manager::SetEndpointFlags().
	 * @param t a topic to allow advertising interest/subscription to peers.
	 * @return true if successful.
	 */
	bool AdvertiseTopic(broker::topic t);

	/**
	 * Disallow advertising interest in the given topic to peers.
	 * This has no effect if auto advertise behavior is enabled via the flags
	 * supplied to bro_broker::Manager::Enable() or bro_broker::Manager::SetEndpointFlags().
	 * @param t a topic to disallow advertising interest/subscription to peers.
	 * @return true if successful.
	 */
	bool UnadvertiseTopic(broker::topic t);

	/**
	 * Register the availability of a data store.
	 * @param handle the data store.
	 * @return true if the store was valid and not already away of it.
	 */
	bool AddStore(StoreHandleVal* handle);

	/**
	 * Lookup a data store by it's identifier name and type.
	 * @param id the store's name.
	 * @param type the type of data store.
	 * @return a pointer to the store handle if it exists else nullptr.
	 */
	StoreHandleVal* LookupStore(const broker::store::identifier& id, StoreType type);

	/**
	 * Close and unregister a data store.  Any existing references to the
	 * store handle will not be able to be used for any data store operations.
	 * @param id the stores' name.
	 * @param type the type of the data store.
	 * @return true if such a store existed and is now closed.
	 */
	bool CloseStore(const broker::store::identifier& id, StoreType type);

	/**
	 * Register a data store query callback.
	 * @param cb the callback info to use when the query completes or times out.
	 * @return true if now tracking a data store query.
	 */
	bool TrackStoreQuery(StoreQueryCallback* cb);

	/**
	 * @return communication statistics.
	 */
	Stats ConsumeStatistics();

	/**
	 * Convert BrokerComm::SendFlags to int flags for use with broker::send().
	 */
	static int send_flags_to_int(Val* flags);

private:

	// IOSource interface overrides:
	void GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
	            iosource::FD_Set* except) override;

	double NextTimestamp(double* local_network_time) override;

	void Process() override;

	const char* Tag() override
		{ return "BrokerComm::Manager"; }

	broker::endpoint& Endpoint()
		{ return *endpoint; }

	struct QueueWithStats {
		broker::message_queue q;
		size_t received = 0;
	};

	std::unique_ptr<broker::endpoint> endpoint;
	std::map<std::pair<std::string, uint16_t>, broker::peering> peers;
	std::map<std::string, QueueWithStats> print_subscriptions;
	std::map<std::string, QueueWithStats> event_subscriptions;
	std::map<std::string, QueueWithStats> log_subscriptions;

	std::map<std::pair<broker::store::identifier, StoreType>,
	         StoreHandleVal*> data_stores;
	std::unordered_set<StoreQueryCallback*> pending_queries;

	Stats statistics;
	double next_timestamp;

	static VectorType* vector_of_data_type;
	static EnumType* log_id_type;
	static int send_flags_self_idx;
	static int send_flags_peers_idx;
	static int send_flags_unsolicited_idx;
};

} // namespace bro_broker

extern bro_broker::Manager* broker_mgr;

#endif // BRO_COMM_MANAGER_H

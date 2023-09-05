// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <netdb.h>
#include <list>
#include <map>
#include <queue>
#include <utility>
#include <variant>

#include "zeek/EventHandler.h"
#include "zeek/IPAddr.h"
#include "zeek/List.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/util.h"

// These are defined in ares headers but we don't want to have to include
// those headers here and create install dependencies on them.
struct ares_channeldata;
typedef struct ares_channeldata* ares_channel;
#ifndef T_PTR
#define T_PTR 12
#endif

#ifndef T_TXT
#define T_TXT 16
#endif

namespace zeek
	{
class Val;
class ListVal;
class TableVal;
class StringVal;

template <class T> class IntrusivePtr;
using ValPtr = IntrusivePtr<Val>;
using ListValPtr = IntrusivePtr<ListVal>;
using TableValPtr = IntrusivePtr<TableVal>;
using StringValPtr = IntrusivePtr<StringVal>;

	} // namespace zeek

namespace zeek::detail
	{
class DNS_Mapping;
using DNS_MappingPtr = std::shared_ptr<DNS_Mapping>;
class DNS_Request;

enum DNS_MgrMode
	{
	DNS_PRIME, // used to prime the cache
	DNS_FORCE, // internal error if cache miss
	DNS_DEFAULT, // lookup names as they're requested
	DNS_FAKE, // don't look up names, just return dummy results
	};

class DNS_Mgr : public iosource::IOSource
	{
public:
	/**
	 * Base class for callback handling for asynchronous lookups.
	 */
	class LookupCallback
		{
	public:
		virtual ~LookupCallback() = default;

		/**
		 * Called when an address lookup finishes.
		 *
		 * @param name The resulting name from the lookup.
		 */
		virtual void Resolved(const std::string& name){};

		/**
		 * Called when a name lookup finishes.
		 *
		 * @param addrs A table of the resulting addresses from the lookup.
		 */
		virtual void Resolved(TableValPtr addrs){};

		/**
		 * Generic callback method for all request types.
		 *
		 * @param val A Val containing the data from the query.
		 */
		virtual void Resolved(ValPtr data, int request_type) { }

		/**
		 * Called when a timeout request occurs.
		 */
		virtual void Timeout() = 0;
		};

	explicit DNS_Mgr(DNS_MgrMode mode);
	~DNS_Mgr() override;

	/**
	 * Finalizes the source when it's being closed.
	 */
	void Done() override;

	/**
	 * Finalizes the manager initialization. This should be called only after all
	 * of the scripts have been parsed at startup.
	 */
	void InitPostScript();

	/**
	 * Attempts to process one more round of requests and then flushes the
	 * mapping caches.
	 */
	void Flush();

	/**
	 * Looks up the address(es) of a given host and returns a set of addresses.
	 * This is a shorthand method for doing A/AAAA requests. This is a
	 * synchronous request and will block until the request completes or times
	 * out.
	 *
	 * @param host The hostname to lookup an address for.
	 * @return A set of addresses for the host.
	 */
	TableValPtr LookupHost(const std::string& host);

	/**
	 * Looks up the hostname of a given address. This is a shorthand method for
	 * doing PTR requests. This is a synchronous request and will block until
	 * the request completes or times out.
	 *
	 * @param host The addr to lookup a hostname for.
	 * @return The hostname for the address.
	 */
	StringValPtr LookupAddr(const IPAddr& addr);

	/**
	 * Performs a generic request to the DNS server. This is a synchronous
	 * request and will block until the request completes or times out.
	 *
	 * @param name The name or address to make a request for. If this is an
	 * address it should be in arpa format (x.x.x.x.in-addr.arpa or x-*.ip6.arpa).
	 * Note that calling LookupAddr for PTR requests does this conversion
	 * automatically.
	 * @param request_type The type of request to make. This should be one of
	 * the type values defined in arpa/nameser.h or ares_nameser.h.
	 * @return The requested data.
	 */
	ValPtr Lookup(const std::string& name, int request_type);

	/**
	 * Looks up the address(es) of a given host. This is a shorthand method
	 * for doing A/AAAA requests. This is an asynchronous request. The
	 * response will be handled via the provided callback object.
	 *
	 * @param host The hostname to lookup an address for.
	 * @param callback A callback object for handling the response.
	 */
	void LookupHost(const std::string& host, LookupCallback* callback);

	/**
	 * Looks up the hostname of a given address. This is a shorthand method for
	 * doing PTR requests. This is an asynchronous request. The response will
	 * be handled via the provided callback object.
	 *
	 * @param host The addr to lookup a hostname for.
	 * @param callback A callback object for handling the response.
	 */
	void LookupAddr(const IPAddr& addr, LookupCallback* callback);

	/**
	 * Performs a generic request to the DNS server. This is an asynchronous
	 * request. The response will be handled via the provided callback
	 * object.
	 *
	 * @param name The name or address to make a request for. If this is an
	 * address it should be in arpa format (x.x.x.x.in-addr.arpa or x-*.ip6.arpa).
	 * Note that calling LookupAddr for PTR requests does this conversion
	 * automatically.
	 * @param request_type The type of request to make. This should be one of
	 * the type values defined in arpa/nameser.h or ares_nameser.h.
	 * @param callback A callback object for handling the response.
	 */
	void Lookup(const std::string& name, int request_type, LookupCallback* callback);

	/**
	 * Sets the directory where to store DNS data when Save() is called.
	 */
	void SetDir(const std::string& arg_dir) { dir = arg_dir; }

	/**
	 * Waits for responses to become available or a timeout to occur,
	 * and handles any responses.
	 */
	void Resolve();

	/**
	 * Saves the current name and address caches to disk.
	 */
	bool Save();

	struct Stats
		{
		unsigned long requests; // These count only async requests.
		unsigned long successful;
		unsigned long failed;
		unsigned long pending;
		unsigned long cached_hosts;
		unsigned long cached_addresses;
		unsigned long cached_texts;
		unsigned long cached_total;
		};

	/**
	 * Returns the current statistics for the DNS_Manager.
	 *
	 * @param stats A pointer to a stats object to return the data in.
	 */
	void GetStats(Stats* stats);

	/**
	 * Adds a result from a request to the caches. This is public so that the
	 * callback methods can call it from outside of the DNS_Mgr class.
	 *
	 * @param dr The request associated with the result.
	 * @param h A hostent structure containing the actual result data.
	 * @param ttl A ttl value contained in the response from the server.
	 * @param merge A flag for whether these results should be merged into
	 * an existing mapping. If false, AddResult will attempt to replace the
	 * existing mapping with the new data and delete the old mapping.
	 */
	void AddResult(DNS_Request* dr, struct hostent* h, uint32_t ttl, bool merge = false);

	/**
	 * Returns an empty set of addresses, used in various error cases and during
	 * cache priming.
	 */
	static TableValPtr empty_addr_set();

	/**
	 * Returns the full path to the file used to store the DNS cache.
	 */
	std::string CacheFile() const { return cache_name; }

	/**
	 * Used by the c-ares socket call back to register/unregister a socket file descriptor.
	 */
	void RegisterSocket(int fd, bool read, bool write);

	ares_channel& GetChannel() { return channel; }

protected:
	friend class LookupCallback;
	friend class DNS_Request;

	StringValPtr LookupAddrInCache(const IPAddr& addr, bool cleanup_expired = false,
	                               bool check_failed = false);
	TableValPtr LookupNameInCache(const std::string& name, bool cleanup_expired = false,
	                              bool check_failed = false);
	StringValPtr LookupOtherInCache(const std::string& name, int request_type,
	                                bool cleanup_expired = false);

	// Finish the request if we have a result.  If not, time it out if
	// requested.
	void CheckAsyncAddrRequest(const IPAddr& addr, bool timeout);
	void CheckAsyncHostRequest(const std::string& host, bool timeout);
	void CheckAsyncOtherRequest(const std::string& host, bool timeout, int request_type);

	void Event(EventHandlerPtr e, const DNS_MappingPtr& dm);
	void Event(EventHandlerPtr e, const DNS_MappingPtr& dm, ListValPtr l1, ListValPtr l2);
	void Event(EventHandlerPtr e, const DNS_MappingPtr& old_dm, DNS_MappingPtr new_dm);

	ValPtr BuildMappingVal(const DNS_MappingPtr& dm);

	void CompareMappings(const DNS_MappingPtr& prev_dm, const DNS_MappingPtr& new_dm);
	ListValPtr AddrListDelta(ListValPtr al1, ListValPtr al2);

	using MappingKey = std::variant<IPAddr, std::pair<int, std::string>>;
	using MappingMap = std::map<MappingKey, DNS_MappingPtr>;
	void LoadCache(const std::string& path);
	void Save(FILE* f, const MappingMap& m);

	// Issue as many queued async requests as slots are available.
	void IssueAsyncRequests();

	// IOSource interface.
	void Process() override;
	void ProcessFd(int fd, int flags) override;
	void InitSource() override;
	const char* Tag() override { return "DNS_Mgr"; }
	double GetNextTimeout() override;

	DNS_MgrMode mode;

	MappingMap all_mappings;

	std::string cache_name;
	std::string dir; // directory in which cache_name resides

	bool did_init = false;
	int asyncs_pending = 0;

	RecordTypePtr dm_rec;

	ares_channel channel{};

	using CallbackList = std::list<LookupCallback*>;

	struct AsyncRequest
		{
		double time = 0.0;
		IPAddr addr;
		std::string host;
		CallbackList callbacks;
		int type = 0;
		bool processed = false;

		AsyncRequest(std::string host, int request_type) : host(std::move(host)), type(request_type)
			{
			}
		AsyncRequest(const IPAddr& addr) : addr(addr), type(T_PTR) { }

		void Resolved(const std::string& name);
		void Resolved(TableValPtr addrs);
		void Timeout();
		};

	struct AsyncRequestCompare
		{
		bool operator()(const AsyncRequest* a, const AsyncRequest* b) { return a->time > b->time; }
		};

	using AsyncRequestMap = std::map<MappingKey, AsyncRequest*>;
	AsyncRequestMap asyncs;

	using QueuedList = std::list<AsyncRequest*>;
	QueuedList asyncs_queued;

	unsigned long num_requests = 0;
	unsigned long successful = 0;
	unsigned long failed = 0;

	std::set<int> socket_fds;
	std::set<int> write_socket_fds;

	bool shutting_down = false;
	};

extern DNS_Mgr* dns_mgr;

	} // namespace zeek::detail

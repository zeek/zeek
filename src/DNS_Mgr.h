  // See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <list>
#include <map>
#include <queue>
#include <utility>

#include "zeek/List.h"
#include "zeek/EventHandler.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/IPAddr.h"
#include "zeek/util.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(EventHandler, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(DNS_Mgr_Request, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(RecordType, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(ListVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TableVal, zeek);

namespace zeek {
template <class T> class IntrusivePtr;
using ValPtr = IntrusivePtr<Val>;
using ListValPtr = IntrusivePtr<ListVal>;
using TableValPtr = IntrusivePtr<TableVal>;
}

// Defined in nb_dns.h
struct nb_dns_info;
struct nb_dns_result;

namespace zeek::detail {

using DNS_mgr_request_list = PList<DNS_Mgr_Request>;

class DNS_Mapping;

enum DNS_MgrMode {
	DNS_PRIME,	// used to prime the cache
	DNS_FORCE,	// internal error if cache miss
	DNS_DEFAULT,	// lookup names as they're requested
	DNS_FAKE,	// don't look up names, just return dummy results
};

// Number of seconds we'll wait for a reply.
#define DNS_TIMEOUT 5

class DNS_Mgr final : public iosource::IOSource {
public:
	explicit DNS_Mgr(DNS_MgrMode mode);
	~DNS_Mgr() override;

	void InitPostScript();
	void Flush();

	// Looks up the address or addresses of the given host, and returns
	// a set of addr.
	TableValPtr LookupHost(const char* host);

	ValPtr LookupAddr(const IPAddr& addr);

	// Define the directory where to store the data.
	void SetDir(const char* arg_dir)	{ dir = util::copy_string(arg_dir); }

	void Verify();
	void Resolve();
	bool Save();

	const char* LookupAddrInCache(const IPAddr& addr);
	TableValPtr LookupNameInCache(const std::string& name);
	const char* LookupTextInCache(const std::string& name);

	// Support for async lookups.
	class LookupCallback {
	public:
		LookupCallback()	{ }
		virtual ~LookupCallback()	{ }

		virtual void Resolved(const char* name)	{ };
		virtual void Resolved(TableVal* addrs)	{ };
		virtual void Timeout() = 0;
	};

	void AsyncLookupAddr(const IPAddr& host, LookupCallback* callback);
	void AsyncLookupName(const std::string& name, LookupCallback* callback);
	void AsyncLookupNameText(const std::string& name, LookupCallback* callback);

	struct Stats {
		unsigned long requests;	// These count only async requests.
		unsigned long successful;
		unsigned long failed;
		unsigned long pending;
		unsigned long cached_hosts;
		unsigned long cached_addresses;
		unsigned long cached_texts;
	};

	void GetStats(Stats* stats);

	void Terminate();

protected:
	friend class LookupCallback;
	friend class DNS_Mgr_Request;

	void Event(EventHandlerPtr e, DNS_Mapping* dm);
	void Event(EventHandlerPtr e, DNS_Mapping* dm,
	           ListValPtr l1, ListValPtr l2);
	void Event(EventHandlerPtr e, DNS_Mapping* old_dm, DNS_Mapping* new_dm);

	ValPtr BuildMappingVal(DNS_Mapping* dm);

	void AddResult(DNS_Mgr_Request* dr, struct nb_dns_result* r);
	void CompareMappings(DNS_Mapping* prev_dm, DNS_Mapping* new_dm);
	ListValPtr AddrListDelta(ListVal* al1, ListVal* al2);
	void DumpAddrList(FILE* f, ListVal* al);

	typedef std::map<std::string, std::pair<DNS_Mapping*, DNS_Mapping*> > HostMap;
	typedef std::map<IPAddr, DNS_Mapping*> AddrMap;
	typedef std::map<std::string, DNS_Mapping*> TextMap;
	void LoadCache(FILE* f);
	void Save(FILE* f, const AddrMap& m);
	void Save(FILE* f, const HostMap& m);

	// Selects on the fd to see if there is an answer available (timeout
	// is secs). Returns 0 on timeout, -1 on EINTR or other error, and 1
	// if answer is ready.
	int AnswerAvailable(int timeout);

	// Issue as many queued async requests as slots are available.
	void IssueAsyncRequests();

	// Finish the request if we have a result.  If not, time it out if
	// requested.
	void CheckAsyncAddrRequest(const IPAddr& addr, bool timeout);
	void CheckAsyncHostRequest(const char* host, bool timeout);
	void CheckAsyncTextRequest(const char* host, bool timeout);

	// IOSource interface.
	void Process() override;
	void InitSource() override;
	const char* Tag() override	{ return "DNS_Mgr"; }
	double GetNextTimeout() override;

	DNS_MgrMode mode;

	HostMap host_mappings;
	AddrMap addr_mappings;
	TextMap text_mappings;

	DNS_mgr_request_list requests;

	nb_dns_info* nb_dns;
	char* cache_name;
	char* dir;	// directory in which cache_name resides

	bool did_init;

	RecordTypePtr dm_rec;

	typedef std::list<LookupCallback*> CallbackList;

	struct AsyncRequest {
		double time;
		IPAddr host;
		std::string name;
		CallbackList callbacks;
		bool is_txt;
		bool processed;

		AsyncRequest() : time(0.0), is_txt(false), processed(false) { }

		bool IsAddrReq() const	{ return name.empty(); }

		void Resolved(const char* name)
			{
			for ( CallbackList::iterator i = callbacks.begin();
			      i != callbacks.end(); ++i )
				{
				(*i)->Resolved(name);
				delete *i;
				}
			callbacks.clear();
			processed = true;
			}

		void Resolved(TableVal* addrs)
			{
			for ( CallbackList::iterator i = callbacks.begin();
			      i != callbacks.end(); ++i )
				{
				(*i)->Resolved(addrs);
				delete *i;
				}
			callbacks.clear();
			processed = true;
			}

		void Timeout()
			{
			for ( CallbackList::iterator i = callbacks.begin();
			      i != callbacks.end(); ++i )
				{
				(*i)->Timeout();
				delete *i;
				}
			callbacks.clear();
			processed = true;
			}

	};

	typedef std::map<IPAddr, AsyncRequest*> AsyncRequestAddrMap;
	AsyncRequestAddrMap asyncs_addrs;

	typedef std::map<std::string, AsyncRequest*> AsyncRequestNameMap;
	AsyncRequestNameMap asyncs_names;

	typedef std::map<std::string, AsyncRequest*> AsyncRequestTextMap;
	AsyncRequestTextMap asyncs_texts;

	typedef std::list<AsyncRequest*> QueuedList;
	QueuedList asyncs_queued;

	struct AsyncRequestCompare {
		bool operator()(const AsyncRequest* a, const AsyncRequest* b)
			{
			return a->time > b->time;
			}
	};

	typedef std::priority_queue<AsyncRequest*, std::vector<AsyncRequest*>, AsyncRequestCompare> TimeoutQueue;
	TimeoutQueue asyncs_timeouts;

	int asyncs_pending;

	unsigned long num_requests;
	unsigned long successful;
	unsigned long failed;
};

extern DNS_Mgr* dns_mgr;

} // namespace zeek::detail
